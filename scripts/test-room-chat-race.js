#!/usr/bin/env node
'use strict';
/**
 * Проверка гонки в чате комнаты (public/room.html) через управляемые
 * промисы вместо реального сетевого тайминга.
 *
 * Почему так: ручная проверка двумя вкладками не может воспроизвести по
 * заказу конкретный порядок прибытия событий — эхо чата приходит через
 * LiveKit data-channel, POST /chat через отдельный HTTP round-trip, и на
 * практике не получится гарантированно заставить один обогнать другой.
 * Именно в этом окне живёт I1 (гейт дедупликации может съесть собственное
 * эхо) — двумя вкладками эту гонку не поймать, только рассуждением о
 * таймингах, которому ревью справедливо не доверяет.
 *
 * Вместо этого скрипт подменяет window.fetch для /voice/rooms/*\/chat
 * управляемыми промисами (см. addInitScript) и эмулирует прибытие эха
 * через room.emit('dataReceived', ...) — тем же методом, которым сам
 * LiveKit SDK доставляет событие внутри room.on(RoomEvent.DataReceived).
 * room по-прежнему настоящий (реальный логин, реальная temporary-комната,
 * реальный connect() к LiveKit) — подменяется только сетевой уровень
 * /chat, а не сам чат.
 *
 * Прогоняет все четыре порядка, о которых просило ревью:
 *   1. эхо раньше ответа на POST      (обычный путь, но именно ЭТОТ порядок
 *                                       вызвал первый заход, C1-C3 раунда 2)
 *   2. ответ раньше эха               (M1 — эхо приходит ПОЗЖЕ, уже избыточно)
 *   3. история раньше эха             (I1 — гейт дедупликации мог съесть эхо)
 *   4. отказ POST-а раньше эха        (I2 — эхо всё же подтверждает доставку)
 *
 * Запуск:
 *   node scripts/test-room-chat-race.js
 * Переменные окружения (необязательные, дефолты — DEV):
 *   ROOM_BASE_URL   (по умолчанию https://staging.id.taler.tirol)
 *   TEST_EMAIL      (по умолчанию integration_test@taler-test.com)
 *   TEST_PASSWORD
 *   TEST_TOKEN      — если задан, пропускает логин (обходит лимит nginx
 *                     10 запросов/мин на /auth/login при повторных прогонах)
 *
 * Новых зависимостей не требует: playwright резолвится через обычный
 * require() из родительских node_modules окружения (require.resolve
 * подтверждён отдельно, в package.json ничего добавлять не нужно).
 */

const https = require('https');
const { chromium } = require('playwright');

const BASE_URL = process.env.ROOM_BASE_URL || 'https://staging.id.taler.tirol';
const EMAIL = process.env.TEST_EMAIL || 'integration_test@taler-test.com';
const PASSWORD = process.env.TEST_PASSWORD || 'IntegrationTest123!';

function httpJson(method, url, body, headers) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const u = new URL(url);
    const req = https.request(
      {
        hostname: u.hostname,
        path: u.pathname + u.search,
        method,
        headers: Object.assign(
          { 'Content-Type': 'application/json' },
          headers || {},
          data ? { 'Content-Length': Buffer.byteLength(data) } : {}
        ),
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => {
          let parsed = raw;
          try {
            parsed = raw ? JSON.parse(raw) : null;
          } catch (_) {
            /* leave as raw string */
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

let passed = 0;
let failed = 0;
const failures = [];
function assert(cond, msg) {
  if (cond) {
    passed++;
    console.log('  OK    ' + msg);
  } else {
    failed++;
    failures.push(msg);
    console.log('  FAIL  ' + msg);
  }
}
function info(msg) {
  console.log('  ..    ' + msg);
}

/** Внутри page: пометить очередной перехваченный вызов fetch('.../chat', ...)
 *  как разрешённый, вернув {ok,status,json}. matcherSrc — строка с телом
 *  функции-предиката (method, url, bodyObj) => boolean, сериализуем как
 *  строку, потому что evaluate не передаёт живые функции по каналу CDP
 *  вместе с замыканиями произвольной сложности. */
async function resolveChatFetch(page, matcherSrc, status, body) {
  const ok = await page.evaluate(
    ({ matcherSrc, status, body }) => {
      // eslint-disable-next-line no-new-func
      const matcher = new Function('method', 'url', 'bodyObj', 'return (' + matcherSrc + ')(method, url, bodyObj);');
      const idx = window.__pendingChatFetches.findIndex((f) => matcher(f.method, f.url, f.bodyObj));
      if (idx === -1) return false;
      const [item] = window.__pendingChatFetches.splice(idx, 1);
      item.resolve({ ok: status >= 200 && status < 300, status, json: async () => body });
      return true;
    },
    { matcherSrc, status, body }
  );
  return ok;
}

async function waitForPendingChatFetch(page, matcherSrc, timeout) {
  await page.waitForFunction(
    (matcherSrc) => {
      // eslint-disable-next-line no-new-func
      const matcher = new Function('method', 'url', 'bodyObj', 'return (' + matcherSrc + ')(method, url, bodyObj);');
      return window.__pendingChatFetches.some((f) => matcher(f.method, f.url, f.bodyObj));
    },
    matcherSrc,
    { timeout: timeout || 10000 }
  );
}

async function emitChatEcho(page, { clientMsgId, msgId, name, text }) {
  await page.evaluate(
    ({ clientMsgId, msgId, name, text }) => {
      const payload = encoder.encode(
        JSON.stringify({ type: 'chat_message', clientMsgId, msgId, name, text, ts: Date.now() })
      );
      room.emit('dataReceived', payload, undefined);
    },
    { clientMsgId, msgId, name, text }
  );
}

async function triggerSend(page, text) {
  await page.evaluate((text) => {
    document.getElementById('chat-input').value = text;
    window.__lastSend = sendChatMessage();
  }, text);
}

async function awaitLastSend(page) {
  await page.evaluate(() => window.__lastSend);
}

async function readState(page, textFragment) {
  return page.evaluate((textFragment) => {
    const msgs = document.getElementById('chat-messages');
    const matches = Array.from(msgs.children).filter((el) => el.textContent.includes(textFragment));
    return {
      bubbleCount: matches.length,
      bubbles: matches.map((el) => ({
        className: el.className,
        msgId: el.dataset.msgId || null,
        hasRetry: !!el.querySelector('.chat-msg-retry'),
      })),
      pendingSize: _pendingChatMsgs.size,
    };
  }, textFragment);
}

async function main() {
  console.log('== Логин и создание временной комнаты ==');
  let token = process.env.TEST_TOKEN;
  if (!token) {
    const loginRes = await httpJson('POST', BASE_URL + '/auth/login', { email: EMAIL, password: PASSWORD });
    if (loginRes.status < 200 || loginRes.status >= 300) {
      throw new Error('login failed: ' + JSON.stringify(loginRes));
    }
    token = loginRes.body.accessToken;
  }
  const roomRes = await httpJson(
    'POST',
    BASE_URL + '/voice/rooms/temporary',
    { title: 'race-test' },
    { Authorization: 'Bearer ' + token }
  );
  if (roomRes.status < 200 || roomRes.status >= 300) {
    throw new Error('room creation failed: ' + JSON.stringify(roomRes));
  }
  const roomCode = roomRes.body.code;
  console.log('  room: ' + BASE_URL + '/room/' + roomCode);

  const browser = await chromium.launch({
    args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'],
  });
  const context = await browser.newContext({ permissions: ['camera', 'microphone'] });
  const page = await context.newPage();
  page.on('pageerror', (e) => console.log('  [pageerror] ' + e.message));

  // Подменяем fetch для .../chat ДО навигации — чтобы захватить в том числе
  // самый первый loadChatHistory(), который стартует сразу после connect(),
  // раньше любого нашего кода в этой же странице.
  await page.addInitScript(() => {
    window.__pendingChatFetches = [];
    const realFetch = window.fetch.bind(window);
    window.fetch = (url, opts) => {
      const method = (opts && opts.method) || 'GET';
      const urlStr = String(url);
      if (urlStr.includes('/chat') && !urlStr.includes('/chat/')) {
        let bodyObj = null;
        try {
          bodyObj = opts && opts.body ? JSON.parse(opts.body) : null;
        } catch (_) {
          /* not JSON, leave null */
        }
        return new Promise((resolve, reject) => {
          window.__pendingChatFetches.push({ url: urlStr, method, bodyObj, resolve, reject });
        });
      }
      return realFetch(url, opts);
    };
  });

  try {
    await page.goto(BASE_URL + '/room/' + roomCode);
    await page.getByRole('textbox', { name: 'Ваше имя' }).fill('RaceBot');
    await page.getByRole('button', { name: 'Войти в комнату' }).click();
    // room — это `let room = null;` на верхнем уровне обычного (не module)
    // инлайнового <script>: такие привязки НЕ становятся свойствами
    // window (в отличие от var), поэтому проверяем голый идентификатор.
    await page.waitForFunction(() => typeof room !== 'undefined' && room && room.localParticipant, {
      timeout: 20000,
    });
    info('подключились к комнате как ' + (await page.evaluate(() => room.localParticipant.identity)));

    // Первый автоматический loadChatHistory() (из connectToRoom) уже висит
    // на нашем fetch-моке — отпускаем его пустой историей, чтобы не мешать
    // сценариям 1/2/4 (историю с содержимым собираем отдельно в сценарии 3).
    await waitForPendingChatFetch(page, '(method, url) => method === "GET"');
    await resolveChatFetch(page, '(method, url) => method === "GET"', 200, { messages: [], seq: 0 });

    // ── Сценарий 1: эхо раньше ответа на POST ──────────────────────────
    console.log('\n== Сценарий 1: эхо раньше ответа ==');
    {
      const text = 'race-1 echo-before-response ' + Date.now();
      await triggerSend(page, text);
      await waitForPendingChatFetch(page, '(method) => method === "POST"');
      const clientMsgId = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST').bodyObj.clientMsgId
      );
      assert(!!clientMsgId, 'clientMsgId сгенерирован и уехал в теле POST');
      const msgId = 'c_scenario1_' + clientMsgId;

      // Эхо приходит ДО того, как мы разрешили сам POST.
      await emitChatEcho(page, { clientMsgId, msgId, name: 'RaceBot', text });
      await resolveChatFetch(page, '(method) => method === "POST"', 201, { ts: Date.now(), seq: 1, msgId });
      await awaitLastSend(page);

      const state = await readState(page, text);
      assert(state.bubbleCount === 1, 'ровно один пузырь (не задвоилось)');
      assert(state.bubbles[0] && state.bubbles[0].className === 'chat-msg own', 'пузырь стилизован как own');
      assert(state.bubbles[0] && state.bubbles[0].msgId === msgId, 'пузырь дотегирован настоящим msgId от эха');
      assert(!state.bubbles[0] || !state.bubbles[0].hasRetry, 'нет пометки "не отправлено"');
      assert(state.pendingSize === 0, '_pendingChatMsgs пуст — запись не зависла');
    }

    // ── Сценарий 2: ответ раньше эха (эхо приходит позже, уже избыточно) ─
    console.log('\n== Сценарий 2: ответ раньше эха ==');
    {
      const text = 'race-2 response-before-echo ' + Date.now();
      await triggerSend(page, text);
      await waitForPendingChatFetch(page, '(method) => method === "POST"');
      const clientMsgId = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST').bodyObj.clientMsgId
      );
      const msgId = 'c_scenario2_' + clientMsgId;

      // Отвечаем на POST СРАЗУ, эха ещё не было — M1 должен сам забрать
      // подтверждение из тела ответа.
      await resolveChatFetch(page, '(method) => method === "POST"', 201, { ts: Date.now(), seq: 2, msgId });
      await awaitLastSend(page);

      const midState = await readState(page, text);
      assert(midState.bubbleCount === 1, 'M1: пузырь подтверждён из тела ответа, эхо ещё не приходило');
      assert(midState.bubbles[0] && midState.bubbles[0].msgId === msgId, 'M1: msgId проставлен из тела ответа');
      assert(midState.pendingSize === 0, 'M1: запись в _pendingChatMsgs уже снята ответом на POST');

      // Эхо приходит ПОЗЖЕ — избыточное (тот же msgId). Раньше это не
      // регистрировалось в _processedMsgIds на пути M1 и рисовалось как
      // "чужое" сообщение с собственным именем — проверяем, что теперь нет.
      await emitChatEcho(page, { clientMsgId: 'irrelevant-' + Math.random(), msgId, name: 'RaceBot', text });
      const finalState = await readState(page, text);
      assert(finalState.bubbleCount === 1, 'позднее избыточное эхо не создало второй ("чужой") пузырь');
    }

    // ── Сценарий 3: история раньше эха ──────────────────────────────────
    console.log('\n== Сценарий 3: история раньше эха (I1) ==');
    {
      const text = 'race-3 history-before-echo ' + Date.now();
      await triggerSend(page, text);
      await waitForPendingChatFetch(page, '(method) => method === "POST"');
      const clientMsgId = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST').bodyObj.clientMsgId
      );
      const msgId = 'c_scenario3_' + clientMsgId;

      // Вызываем loadChatHistory() второй раз (тот же код, что срабатывает
      // автоматически в connectToRoom) — GET отвечает историей, которая уже
      // содержит ЭТО сообщение (сервер успел положить его в ленту раньше,
      // чем пришло эхо или ответ на POST — воспроизводим сценарий I1 из
      // ревью буквально: "история приходит раньше эха и уже содержит
      // сообщение"). Бэкенд отдаёт clientMsgId отдельным полем для таких
      // сообщений (backend-фикс после раунда 3) — включаем его в мок.
      await page.evaluate(() => {
        window.__historyReload = loadChatHistory();
      });
      await waitForPendingChatFetch(page, '(method) => method === "GET"');
      await resolveChatFetch(page, '(method) => method === "GET"', 200, {
        messages: [{ msgId, clientMsgId, name: 'RaceBot', text, ts: Date.now(), own: true }],
        seq: 3,
      });
      await page.evaluate(() => window.__historyReload);

      // История уже должна была сама подтвердить сообщение по clientMsgId —
      // проверяем ДО прихода эха, что дубля нет и пузырь дотегирован.
      const afterHistory = await readState(page, text);
      assert(afterHistory.bubbleCount === 1, 'I1: история распознала своё сообщение — пузырь один, а не два');
      assert(
        afterHistory.bubbles[0] && afterHistory.bubbles[0].msgId === msgId,
        'I1: история дотегировала пузырь настоящим msgId сама, не дожидаясь эха'
      );
      assert(afterHistory.pendingSize === 0, 'I1: история сняла запись из _pendingChatMsgs — эхо ей для этого не нужно');

      // Эхо всё равно приходит следом (сервер шлёт его независимо от того,
      // что клиент уже сам всё выяснил через историю) — избыточное, не
      // должно ничего задвоить или сломать.
      await emitChatEcho(page, { clientMsgId, msgId, name: 'RaceBot', text });
      await resolveChatFetch(page, '(method) => method === "POST"', 201, { ts: Date.now(), seq: 3, msgId });
      await awaitLastSend(page);

      const state = await readState(page, text);
      assert(state.bubbleCount === 1, 'I1: после последующего избыточного эха пузырь всё ещё ровно один');
      assert(state.pendingSize === 0, 'I1: _pendingChatMsgs остаётся пустым');
      assert(state.bubbles[0] && !state.bubbles[0].hasRetry, 'I1: пузырь не помечен как неотправленный');
    }

    // ── Сценарий 4: отказ POST-а раньше эха ─────────────────────────────
    console.log('\n== Сценарий 4: отказ раньше эха (I2) ==');
    {
      const text = 'race-4 failure-before-echo ' + Date.now();
      await triggerSend(page, text);
      await waitForPendingChatFetch(page, '(method) => method === "POST"');
      const clientMsgId = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST').bodyObj.clientMsgId
      );
      const msgId = 'c_scenario4_' + clientMsgId;

      const inputBefore = await page.evaluate(() => document.getElementById('chat-input').value);
      await resolveChatFetch(page, '(method) => method === "POST"', 502, {});
      await awaitLastSend(page);

      const failedState = await readState(page, text);
      assert(failedState.bubbleCount === 1, 'I2: пузырь остаётся на месте после отказа (не убран)');
      assert(
        failedState.bubbles[0] && failedState.bubbles[0].className === 'chat-msg own failed',
        'I2: пузырь помечен failed'
      );
      assert(failedState.bubbles[0] && failedState.bubbles[0].hasRetry, 'I2: есть кнопка повтора');
      const inputAfter = await page.evaluate(() => document.getElementById('chat-input').value);
      assert(inputAfter === inputBefore, 'M4: текст НЕ возвращён в поле ввода (пузырь сам черновик)');

      // Эхо всё же приходит: сервер разослал, а обратный путь ответа
      // (502) был отдельной неудачей. Проверяем, что пометка снимается,
      // а не остаётся дубль/зависшая ошибка.
      await emitChatEcho(page, { clientMsgId, msgId, name: 'RaceBot', text });
      const reconciledState = await readState(page, text);
      assert(reconciledState.bubbleCount === 1, 'I2: после позднего эха всё ещё один пузырь');
      assert(
        reconciledState.bubbles[0] && reconciledState.bubbles[0].className === 'chat-msg own',
        'I2: пометка "не отправлено" снята после позднего эха'
      );
      assert(reconciledState.bubbles[0] && !reconciledState.bubbles[0].hasRetry, 'I2: кнопка повтора убрана');
      assert(reconciledState.bubbles[0] && reconciledState.bubbles[0].msgId === msgId, 'I2: дотегирован настоящим msgId');
      assert(reconciledState.pendingSize === 0, 'I2: запись в _pendingChatMsgs снята');
    }

    // ── C1: crypto.randomUUID отсутствует (небезопасный контекст, iOS
    // Safari < 15.4, старые WebView) ────────────────────────────────────
    console.log('\n== C1: crypto.randomUUID недоступен ==');
    {
      const text = 'race-c1 no-randomuuid ' + Date.now();
      // Убираем randomUUID НА УЖЕ ПОДКЛЮЧЁННОЙ странице — это не мешает
      // работе комнаты (randomUUID для _msgPrefix уже вычислен при загрузке
      // скрипта), но проверяет именно вызов внутри doSendChat().
      await page.evaluate(() => {
        window.__realRandomUUID = crypto.randomUUID;
        crypto.randomUUID = undefined;
      });
      let threw = false;
      try {
        await triggerSend(page, text);
        await waitForPendingChatFetch(page, '(method) => method === "POST"');
      } catch (e) {
        threw = true;
      }
      assert(!threw, 'C1: sendChatMessage не бросает исключение без crypto.randomUUID');
      const pendingReq = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST' && f.bodyObj)
      );
      assert(!!pendingReq, 'C1: POST всё равно ушёл (не потерялся молча)');
      const fallbackClientMsgId = pendingReq && pendingReq.bodyObj.clientMsgId;
      assert(
        !!fallbackClientMsgId && /^[A-Za-z0-9_-]{1,64}$/.test(fallbackClientMsgId),
        'C1: clientMsgId из запасного варианта (String(Math.random())) годится под формат сервера [A-Za-z0-9_-]{1,64}'
      );
      const msgId = 'c_scenarioC1_' + fallbackClientMsgId;
      await emitChatEcho(page, { clientMsgId: fallbackClientMsgId, msgId, name: 'RaceBot', text });
      await resolveChatFetch(page, '(method) => method === "POST"', 201, { ts: Date.now(), seq: 99, msgId });
      await awaitLastSend(page);
      const state = await readState(page, text);
      assert(state.bubbleCount === 1, 'C1: сообщение всё равно нарисовалось и подтвердилось');
      await page.evaluate(() => {
        crypto.randomUUID = window.__realRandomUUID;
      });
    }
  } catch (e) {
    console.log('\nОШИБКА ВО ВРЕМЯ ПРОГОНА: ' + (e && e.stack ? e.stack : e));
    failed++;
    failures.push('исключение во время прогона: ' + (e && e.message ? e.message : e));
  } finally {
    await browser.close();
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  if (failures.length) {
    console.log('Провалы:');
    failures.forEach((f) => console.log('  - ' + f));
  }
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
