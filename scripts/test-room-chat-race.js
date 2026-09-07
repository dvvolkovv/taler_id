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
 * Сценарии:
 *   1. эхо раньше ответа на POST      (обычный путь, но именно ЭТОТ порядок
 *                                       вызвал первый заход, C1-C3 раунда 2)
 *   2. ответ раньше эха               (M1 — эхо приходит ПОЗЖЕ, уже избыточно)
 *   3. история раньше эха, бэкенд с clientMsgId в ответе (раунд 4 — история
 *      сама снимает ожидание, до всякого гейта; НЕ проверяет I1 конкретно —
 *      реконсиляция тут происходит через отдельную ветку по clientMsgId, а
 *      не через починку после гейта, см. сценарий 4)
 *   4. история раньше эха, БЕЗ clientMsgId в ответе (I1 — так отвечают
 *      TEST/PROD прямо сейчас, где раунда 4 ещё нет: гейт дедупликации
 *      успевает увидеть msgId раньше эха, и именно это тестирует, что
 *      реконсиляция по clientMsgId в DataReceived стоит НЕ ниже гейта)
 *   5. отказ POST-а раньше эха        (I2 — эхо всё же подтверждает доставку)
 *   6. повтор после отказа            (I3 — переиспользует тот же clientMsgId,
 *                                       что и исходная попытка, см. I-5)
 *   C1. crypto.randomUUID недоступен  (небезопасный контекст / старый движок)
 *
 * Запуск:
 *   npm run test:room-chat
 *   (или напрямую: node scripts/test-room-chat-race.js)
 * Переменные окружения (необязательные, дефолты — DEV):
 *   ROOM_BASE_URL   (по умолчанию https://staging.id.taler.tirol)
 *   TEST_EMAIL      (по умолчанию integration_test@taler-test.com)
 *   TEST_PASSWORD
 *   TEST_TOKEN      — если задан, пропускает логин (обходит лимит nginx
 *                     10 запросов/мин на /auth/login при повторных прогонах)
 *
 * Зависимость: playwright — в devDependencies (npm install/ci ставит его
 * как обычно). Раньше скрипт резолвил его через require() из родительских
 * node_modules конкретной машины разработчика — работало только там, на
 * DEV/бот-сервере/у коллеги было бы MODULE_NOT_FOUND.
 *
 * ВАЖНО: скрипт проверяет страницу, которую ОТДАЁТ СЕРВЕР по ROOM_BASE_URL,
 * а не файл public/room.html из рабочего дерева. Перед прогоном своей
 * правки скопируй файл на DEV и верни обратно после:
 *   scp public/room.html dvolkov@89.169.55.217:~/taler-id/public/room.html
 *   npm run test:room-chat
 *   ssh dvolkov@89.169.55.217 'cd ~/taler-id && git checkout public/room.html'
 * Скрипт сверяет отданную страницу с опорными строками текущей реализации
 * перед прогоном сценариев и падает отдельным сообщением, если их нет —
 * но это не отменяет необходимость самому не забыть про scp: зелёный
 * прогон означает «то, что задеплоено, работает», а не «то, что лежит в
 * рабочем дереве, работает» — это разные утверждения.
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

function httpText(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => resolve({ status: res.statusCode, text: raw }));
      })
      .on('error', reject);
  });
}

/**
 * Опорные строки текущей реализации в public/room.html. Не номер версии —
 * этот файл его не несёт — а буквальные фрагменты кода, которых не может
 * быть без соответствующей правки. Список должен расти вместе со схемой:
 * при следующей структурной правке чата добавь сюда новый отличительный
 * фрагмент, а не полагайся на старые (иначе прекешек будет проверять
 * позапрошлый раунд, а не текущий).
 */
const REQUIRED_CODE_MARKERS = [
  '_pendingChatMsgs', // раунд 2: оптимистичная отправка + учёт ожидания эха
  "'clientMsgId' in m && _pendingChatMsgs.has(m.clientMsgId)", // раунд 4: история как третий путь реконсиляции
  'await doSendChat(clientMsgId, pending.text, pending.name, pending.el);', // раунд 5 (I-5): повтор переиспользует тот же clientMsgId
];

/**
 * Проверяет, что СЕРВЕР (не рабочее дерево) отдаёт код, который дальше
 * будут проверять сценарии. Без этой проверки зелёный прогон против
 * страницы без нужного кода означает «на сервере то, что там есть, не
 * падает» — а читается как «мои правки работают», что не одно и то же
 * (ровно так один раз и запутались: после git checkout на сервере остался
 * прошлый раунд, а тест этого не заметил и тихо проверил его).
 */
async function assertServerHasCodeUnderTest(pageUrl) {
  const res = await httpText(pageUrl);
  if (res.status < 200 || res.status >= 300) {
    throw new Error('не удалось получить страницу комнаты (' + res.status + '): ' + pageUrl);
  }
  const missing = REQUIRED_CODE_MARKERS.filter((marker) => !res.text.includes(marker));
  if (missing.length) {
    console.error(
      '\nСЕРВЕР ОТДАЁТ СТРАНИЦУ БЕЗ ПРОВЕРЯЕМОГО КОДА — сценарии не запускаются.\n' +
        'Не найдены опорные строки:\n' +
        missing.map((m) => '  - ' + m).join('\n') +
        '\n\n' +
        pageUrl +
        ' раздаёт другую версию public/room.html, чем та, что в рабочем\n' +
        'дереве/ветке (например, DEV откачен на предыдущий круг ревью git checkout\n' +
        'после чужой проверки). Выкатите изменения или скопируйте файл вручную:\n' +
        '  scp public/room.html dvolkov@89.169.55.217:~/taler-id/public/room.html\n' +
        'и верните после прогона:\n' +
        '  ssh dvolkov@89.169.55.217 \'cd ~/taler-id && git checkout public/room.html\'\n\n' +
        'Список провалов сценариев ниже был бы про логику, которой на сервере\n' +
        'просто нет, — поэтому его не будет.'
    );
    // Бросаем, а не process.exit() напрямую: это внутри main()'s try, и
    // временную комнату всё равно нужно удалить в finally (см. I-4) — сразу
    // exit() пропустил бы cleanup.
    throw new Error('сервер отдаёт страницу без кода под тестом (полное сообщение выше)');
  }
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
  // Раньше это значение возвращалось и никем не проверялось: если подходящий
  // запрос не находился, сценарий тихо продолжал ждать (или падал на
  // awaitLastSend с невнятным таймаутом) вместо явного "не нашли что
  // резолвить". Бросаем сразу, с указанием, по какому предикату искали.
  if (!ok) throw new Error('resolveChatFetch: не нашли ожидающий запрос по предикату: ' + matcherSrc);
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

  // browser объявлен здесь (не внутри try), чтобы finally ниже могло его
  // закрыть независимо от того, на каком шаге всё пошло не так — включая
  // отказ прекешека до того, как браузер вообще запущен.
  let browser = null;
  try {
    console.log('\n== Проверка: сервер отдаёт код, который мы собираемся тестировать ==');
    await assertServerHasCodeUnderTest(BASE_URL + '/room/' + roomCode);
    console.log('  OK    опорные строки текущей реализации найдены в отданной странице');

    browser = await chromium.launch({
      args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'],
    });
    const context = await browser.newContext({ permissions: ['camera', 'microphone'] });
    const page = await context.newPage();
    // Необработанная ошибка на странице — это провал прогона, а не просто
    // строка в логе: без этого пропущенное исключение молча не считается
    // нигде, и итоговое "N passed, 0 failed" может соврать.
    page.on('pageerror', (e) => {
      console.log('  [pageerror] ' + e.message);
      failed++;
      failures.push('необработанная ошибка на странице: ' + e.message);
    });

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
    // сценариям 1/2/5/6 (историю с содержимым собираем отдельно в
    // сценариях 3 и 4).
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
      assert(state.bubbles.length > 0 && !state.bubbles[0].hasRetry, 'нет пометки "не отправлено"');
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

    // ── Сценарий 3: история раньше эха, бэкенд отдаёт clientMsgId (раунд 4) ──
    console.log('\n== Сценарий 3: история раньше эха, есть clientMsgId (раунд 4) ==');
    {
      const text = 'race-3 history-with-clientmsgid ' + Date.now();
      await triggerSend(page, text);
      await waitForPendingChatFetch(page, '(method) => method === "POST"');
      const clientMsgId = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST').bodyObj.clientMsgId
      );
      const msgId = 'c_scenario3_' + clientMsgId;

      // Вызываем loadChatHistory() второй раз (тот же код, что срабатывает
      // автоматически в connectToRoom) — GET отвечает историей, которая уже
      // содержит ЭТО сообщение, вместе с clientMsgId отдельным полем (так
      // отдаёт бэкенд после раунда 4). Это НЕ тест I1: реконсиляция здесь
      // идёт через отдельную ветку по clientMsgId прямо в loadChatHistory,
      // общий гейт _processedMsgIds не успевает вмешаться раньше нужного
      // момента. Тест именно I1 — следующий сценарий, где этого поля нет.
      await page.evaluate(() => {
        window.__historyReload = loadChatHistory();
      });
      await waitForPendingChatFetch(page, '(method, url) => method === "GET"');
      await resolveChatFetch(page, '(method, url) => method === "GET"', 200, {
        messages: [{ msgId, clientMsgId, name: 'RaceBot', text, ts: Date.now(), own: true }],
        seq: 3,
      });
      await page.evaluate(() => window.__historyReload);

      // История уже должна была сама подтвердить сообщение по clientMsgId —
      // проверяем ДО прихода эха, что дубля нет и пузырь дотегирован.
      const afterHistory = await readState(page, text);
      assert(afterHistory.bubbleCount === 1, 'раунд 4: история распознала своё сообщение — пузырь один, а не два');
      assert(
        afterHistory.bubbles.length > 0 && afterHistory.bubbles[0].msgId === msgId,
        'раунд 4: история дотегировала пузырь настоящим msgId сама, не дожидаясь эха'
      );
      assert(
        afterHistory.pendingSize === 0,
        'раунд 4: история сняла запись из _pendingChatMsgs — эхо ей для этого не нужно'
      );

      // Эхо всё равно приходит следом (сервер шлёт его независимо от того,
      // что клиент уже сам всё выяснил через историю) — избыточное, не
      // должно ничего задвоить или сломать.
      await emitChatEcho(page, { clientMsgId, msgId, name: 'RaceBot', text });
      await resolveChatFetch(page, '(method) => method === "POST"', 201, { ts: Date.now(), seq: 3, msgId });
      await awaitLastSend(page);

      const state = await readState(page, text);
      assert(state.bubbleCount === 1, 'раунд 4: после последующего избыточного эха пузырь всё ещё ровно один');
      assert(state.pendingSize === 0, 'раунд 4: _pendingChatMsgs остаётся пустым');
      assert(state.bubbles.length > 0 && !state.bubbles[0].hasRetry, 'раунд 4: пузырь не помечен как неотправленный');
    }

    // ── Сценарий 4: история раньше эха, БЕЗ clientMsgId (I1, легаси) ──────
    console.log('\n== Сценарий 4: история раньше эха, без clientMsgId (I1, легаси-бэкенд) ==');
    {
      const text = 'race-4 history-without-clientmsgid ' + Date.now();
      await triggerSend(page, text);
      await waitForPendingChatFetch(page, '(method) => method === "POST"');
      const clientMsgId = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST').bodyObj.clientMsgId
      );
      const msgId = 'c_scenario4_' + clientMsgId;

      // Так отвечают TEST и PROD прямо сейчас (раунда 4 там ещё нет): поля
      // clientMsgId в записи истории попросту нет. Ветка по clientMsgId в
      // loadChatHistory его не подхватывает — сообщение проходит по общему
      // пути: гейт _processedMsgIds регистрирует msgId, рисуется НОВЫЙ
      // пузырь (own:true), отдельный от уже стоящего оптимистично. Это
      // задвоение здесь ожидаемо — не то, что чинит I1 (сравни со
      // сценарием 3: разница ровно в отсутствии этого поля). I1 отвечает
      // за то, что происходит ПОСЛЕ: без сверки по clientMsgId выше общего
      // гейта в DataReceived эхо этого сообщения было бы отсечено гейтом,
      // который уже видел msgId от истории, — и запись в _pendingChatMsgs
      // повисла бы навсегда, а оптимистичный пузырь остался бы непомеченным
      // и по факту неотличимым от подвисшего. Именно это здесь и проверяем.
      await page.evaluate(() => {
        window.__historyReload = loadChatHistory();
      });
      await waitForPendingChatFetch(page, '(method, url) => method === "GET"');
      await resolveChatFetch(page, '(method, url) => method === "GET"', 200, {
        messages: [{ msgId, name: 'RaceBot', text, ts: Date.now(), own: true }], // намеренно без clientMsgId
        seq: 4,
      });
      await page.evaluate(() => window.__historyReload);

      // Эхо приходит следом — гейт _processedMsgIds уже видел msgId (от
      // истории), но сверка по clientMsgId в _pendingChatMsgs стоит выше
      // этого гейта (I1) и должна дойти до реконсиляции несмотря на это.
      await emitChatEcho(page, { clientMsgId, msgId, name: 'RaceBot', text });
      await resolveChatFetch(page, '(method) => method === "POST"', 201, { ts: Date.now(), seq: 4, msgId });
      await awaitLastSend(page);

      const state = await readState(page, text);
      // Ожидаемо ДВА пузыря (клиент раунда 4 против бэкенда без него) — это
      // не баг и не то, что здесь проверяется, только честная фиксация
      // побочного эффекта: клиент нельзя катить впереди бэкенда.
      assert(
        state.bubbleCount === 2,
        'легаси-бэкенд без clientMsgId: ожидаемо два пузыря (история нарисовала свой, плюс наш оптимистичный) — не больше и не меньше'
      );
      assert(
        state.pendingSize === 0,
        'I1: запись в _pendingChatMsgs не зависла навсегда, хотя гейт уже видел msgId от истории'
      );
      assert(
        state.bubbles.length === 2 && state.bubbles.every((b) => b.msgId === msgId),
        'I1: оба пузыря дотегированы одним и тем же настоящим msgId — эхо реконсилировало оптимистичный, а не потерялось из-за гейта'
      );
      assert(
        state.bubbles.every((b) => !b.hasRetry),
        'I1: ни один из двух пузырей не висит с пометкой "не отправлено"'
      );
    }

    // ── Сценарий 5: отказ POST-а раньше эха ─────────────────────────────
    console.log('\n== Сценарий 5: отказ раньше эха (I2) ==');
    {
      const text = 'race-5 failure-before-echo ' + Date.now();
      await triggerSend(page, text);
      await waitForPendingChatFetch(page, '(method) => method === "POST"');
      const clientMsgId = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST').bodyObj.clientMsgId
      );
      const msgId = 'c_scenario5_' + clientMsgId;

      // M4: пока POST ещё висит, человек мог начать печатать следующее
      // сообщение — отказ не должен его затереть. Раньше эта проверка
      // сравнивала поле ввода само с собой (оно читалось уже ПОСЛЕ того,
      // как sendChatMessage синхронно его очистила — до и после всегда
      // были пустой строкой, вне зависимости от того, есть баг или нет).
      // Явно кладём сюда сентинел, который отказ обязан не тронуть.
      const typedMeanwhile = 'typed meanwhile ' + Date.now();
      await page.evaluate((v) => {
        document.getElementById('chat-input').value = v;
      }, typedMeanwhile);

      await resolveChatFetch(page, '(method) => method === "POST"', 502, {});
      await awaitLastSend(page);

      const failedState = await readState(page, text);
      assert(failedState.bubbleCount === 1, 'I2: пузырь остаётся на месте после отказа (не убран)');
      assert(
        failedState.bubbles.length > 0 && failedState.bubbles[0].className === 'chat-msg own failed',
        'I2: пузырь помечен failed'
      );
      assert(failedState.bubbles.length > 0 && failedState.bubbles[0].hasRetry, 'I2: есть кнопка повтора');
      const inputAfter = await page.evaluate(() => document.getElementById('chat-input').value);
      assert(
        inputAfter === typedMeanwhile,
        'M4: набранное параллельно не затёрто отказом (упавший текст остаётся только в пузыре-черновике)'
      );

      // Эхо всё же приходит: сервер разослал, а обратный путь ответа
      // (502) был отдельной неудачей. Проверяем, что пометка снимается,
      // а не остаётся дубль/зависшая ошибка.
      await emitChatEcho(page, { clientMsgId, msgId, name: 'RaceBot', text });
      const reconciledState = await readState(page, text);
      assert(reconciledState.bubbleCount === 1, 'I2: после позднего эха всё ещё один пузырь');
      assert(
        reconciledState.bubbles.length > 0 && reconciledState.bubbles[0].className === 'chat-msg own',
        'I2: пометка "не отправлено" снята после позднего эха'
      );
      assert(
        reconciledState.bubbles.length > 0 && !reconciledState.bubbles[0].hasRetry,
        'I2: кнопка повтора убрана'
      );
      assert(
        reconciledState.bubbles.length > 0 && reconciledState.bubbles[0].msgId === msgId,
        'I2: дотегирован настоящим msgId'
      );
      assert(reconciledState.pendingSize === 0, 'I2: запись в _pendingChatMsgs снята');
    }

    // ── Сценарий 6: повтор после отказа (I3) ────────────────────────────
    console.log('\n== Сценарий 6: повтор после отказа (I3) ==');
    {
      const text = 'race-6 retry-after-failure ' + Date.now();
      await triggerSend(page, text);
      await waitForPendingChatFetch(page, '(method) => method === "POST"');
      const clientMsgId = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST').bodyObj.clientMsgId
      );
      await resolveChatFetch(page, '(method) => method === "POST"', 502, {});
      await awaitLastSend(page);

      const failedState = await readState(page, text);
      assert(
        failedState.bubbleCount === 1 && failedState.bubbles[0].hasRetry,
        'I3: после отказа пузырь один и с кнопкой повтора'
      );

      // Двойной клик по пузырю — не "маловероятен", а невозможен: onclick
      // снимается синхронно внутри unmarkChatBubbleFailed, до какого-либо
      // await. Проверяем это напрямую: два click() подряд без ожидания
      // между ними должны породить ровно один новый POST, а не два.
      await page.evaluate((textFragment) => {
        const el = Array.from(document.getElementById('chat-messages').children).find(
          (e) => e.textContent.includes(textFragment) && e.classList.contains('failed')
        );
        if (!el) throw new Error('не нашли failed-пузырь для "' + textFragment + '"');
        el.click();
        el.click(); // второй клик — к этому моменту onclick уже должен быть null
      }, text);
      await waitForPendingChatFetch(page, '(method) => method === "POST"');
      const pendingPosts = await page.evaluate(
        () => window.__pendingChatFetches.filter((f) => f.method === 'POST').length
      );
      assert(pendingPosts === 1, 'I3: двойной клик по failed-пузырю породил ровно один POST, а не два');

      const retryClientMsgId = await page.evaluate(
        () => window.__pendingChatFetches.find((f) => f.method === 'POST').bodyObj.clientMsgId
      );
      assert(
        retryClientMsgId === clientMsgId,
        'I-5: повтор переиспользует тот же clientMsgId, что и исходная попытка (не минтит новый)'
      );

      // Пока повтор ещё в полёте, приходит эхо ИСХОДНОЙ попытки — раньше
      // для этого был отдельный механизм (pending.superseded); после I-5
      // это просто тот же clientMsgId, и реконсиляция должна пройти как
      // обычно, не испортив узел, на котором уже вторая попытка.
      const msgId = 'c_scenario6_' + clientMsgId;
      await emitChatEcho(page, { clientMsgId, msgId, name: 'RaceBot', text });

      const midState = await readState(page, text);
      assert(midState.bubbleCount === 1, 'I3: эхо исходной попытки, пришедшее во время повтора, не задвоило пузырь');
      assert(
        midState.bubbles.length > 0 && midState.bubbles[0].msgId === msgId,
        'I3: эхо исходной попытки корректно дотегировало пузырь (тот же msgId, что получил бы и повтор)'
      );
      assert(midState.pendingSize === 0, 'I3: запись в _pendingChatMsgs снята после эха исходной попытки');

      // Сам повтор потом резолвится (например, сервер тоже принял его —
      // лишняя строка в Redis, которую никто не увидит) — не должен ничего
      // сломать, раз echo уже всё подтвердил.
      await resolveChatFetch(page, '(method) => method === "POST"', 201, { ts: Date.now(), seq: 6, msgId });
      await awaitLastSend(page);
      const finalState = await readState(page, text);
      assert(finalState.bubbleCount === 1, 'I3: резолв самого повтора (уже избыточный) не создал второй пузырь');
      assert(finalState.pendingSize === 0, 'I3: _pendingChatMsgs остаётся пустым');
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
    if (browser) await browser.close();
    // Комната создаётся на каждый прогон и никогда не прунится сама —
    // expiresAt выставляется, но нигде не читается (нет job-а, который бы
    // деактивировал протухшие public rooms). Без явного удаления строки в
    // БД DEV копятся навсегда. Best-effort: неудача очистки не должна
    // маскировать реальный результат прогона выше, поэтому только warn.
    try {
      const delRes = await httpJson('DELETE', BASE_URL + '/voice/rooms/temporary/' + roomCode, null, {
        Authorization: 'Bearer ' + token,
      });
      if (delRes.status < 200 || delRes.status >= 300) {
        console.log('  [warn] не удалось удалить временную комнату ' + roomCode + ': ' + JSON.stringify(delRes));
      } else {
        console.log('  временная комната ' + roomCode + ' удалена');
      }
    } catch (e2) {
      console.log('  [warn] не удалось удалить временную комнату ' + roomCode + ': ' + (e2 && e2.message ? e2.message : e2));
    }
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
