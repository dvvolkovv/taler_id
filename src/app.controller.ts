import { Controller, Get, Header, Param, Query, Redirect, Res } from '@nestjs/common';
import type { Response } from 'express';
import { join } from 'path';

@Controller()
export class AppController {
  @Get()
  @Redirect('/ui/index.html')
  root() {}

  // Guest invite landing for a voice call room — served on /room/<code>
  // so links shared from the mobile call screen open the LiveKit web client
  // (public/room.html) for users without the app installed.
  @Get('room/:code')
  roomPage(@Param('code') _code: string, @Res() res: Response) {
    res.sendFile(join(__dirname, '..', 'public', 'room.html'));
  }

  @Get('health')
  health() {
    return { status: 'ok', timestamp: new Date().toISOString() };
  }

  @Get('.well-known/openid-configuration')
  @Redirect('/oauth/.well-known/openid-configuration')
  openidConfiguration() {}

  @Get('.well-known/apple-app-site-association')
  @Header('Content-Type', 'application/json')
  appleAppSiteAssociation() {
    const paths = ['/oauth/authorize', '/room/*', '/ui/invite*', '/invite*'];
    return {
      applinks: {
        apps: [],
        details: [
          {
            appID: 'MG58MDUNZ2.tirol.taler.talerIdMobile',
            paths,
          },
          {
            appID: 'MG58MDUNZ2.tirol.taler.talerIdMobile.dev',
            paths,
          },
        ],
      },
    };
  }

  @Get('.well-known/assetlinks.json')
  @Header('Content-Type', 'application/json')
  androidAssetLinks() {
    return [
      {
        relation: ['delegate_permission/common.handle_all_urls'],
        target: {
          namespace: 'android_app',
          package_name: 'tirol.taler.taler_id_mobile',
          sha256_cert_fingerprints: [
            '55:08:99:75:33:25:B9:D6:1B:71:70:FD:77:0A:13:B5:82:D6:EE:41:3C:6F:25:C0:C8:D9:AF:87:9E:0C:44:99',
          ],
        },
      },
      {
        relation: ['delegate_permission/common.handle_all_urls'],
        target: {
          namespace: 'android_app',
          package_name: 'tirol.taler.taler_id_mobile.dev',
          sha256_cert_fingerprints: [
            '55:08:99:75:33:25:B9:D6:1B:71:70:FD:77:0A:13:B5:82:D6:EE:41:3C:6F:25:C0:C8:D9:AF:87:9E:0C:44:99',
            'CE:F2:7D:2C:83:A4:F7:0E:7D:6A:2F:D0:61:79:01:96:B2:72:07:78:02:41:00:BC:2A:BB:58:16:37:E1:04:51',
          ],
        },
      },
    ];
  }

  @Get('app/version')
  appVersion(@Query('flavor') flavor?: string) {
    const isDev = flavor === 'dev';
    const env = process.env;
    // Env-overridable so the DO/talerid build advertises its own track + APK URL;
    // defaults preserve aeza (prod/dev) behaviour when these vars are unset.
    const latest = {
      version: env.APP_LATEST_VERSION || '1.0.97',
      build: parseInt(env.APP_LATEST_BUILD || '194', 10),
    };
    const androidUrl =
      env.APP_UPDATE_URL_ANDROID ||
      (isDev
        ? 'https://id.taler.tirol/download/taler-id-dev.apk'
        : 'https://id.taler.tirol/download/taler-id.apk');
    const iosUrl =
      env.APP_UPDATE_URL_IOS ||
      'https://apps.apple.com/app/taler-id/id6741208498';
    return {
      ios: { ...latest, required: false },
      android: { ...latest, required: false },
      updateUrl: { ios: iosUrl, android: androidUrl },
      releases: APP_RELEASES,
    };
  }
}

// Append entries on top whenever a new version ships.
// Keep notes user-facing (no internal jargon, no commit hashes).
const APP_RELEASES = [
  {
    version: '1.0.97',
    build: 194,
    date: '2026-06-21',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.97 — Informer V2.\n\n' +
      'Этот релиз только для 4 операторов GsmSoft с включённым доступом informerAccess. Обычные пользователи никаких отличий не заметят.\n\n' +
      'Цветные бейджи в Informer-чате. ' +
      'Markdown-рендерер теперь понимает цветные теги: hot-кошельки помечаются красным бейджем, cold — синим, low-balance — жёлтым, OK — зелёным. Балансы в hot-роли подкрашены красным, в cold — синим. Раньше всё было чёрно-белым и приходилось вчитываться чтобы найти проблему. Цвета помогают глазом сразу увидеть «где плохо». Поддерживается и в сообщениях существующих ботов AI Аналитик / AI Обзвон — если они когда-то начнут эмитить цветные теги, отрендерится автоматически.\n\n' +
      'Авто-алёрт «Hot нужно пополнить».\n' +
      'Каждые 5 минут бэкенд считает: суммарный pending withdrawal по сети-токену против текущего баланса hot-кошелька. Если pending больше 90% от hot (т.е. не хватит даже с 10% буфером) — каждый из 4 операторов получает в Informer-чате алёрт:\n' +
      '🔴 **Refill needed** [STAGE 1] — список затронутых пар, сколько надо пополнить.\n' +
      'Если через 30 минут дефицит не закрыт — приходит follow-up [STAGE 2 — UNRESOLVED]. Ещё через час — [STAGE 3 — ESCALATED]. Дальше тишина (чтобы не спамить).\n' +
      'Под алёртом четыре кнопки управления:\n' +
      '• ✅ Понял, работаю — алёрты этой цепочки уходят на 30 минут\n' +
      '• 🔕 Заглушить 1 час — на час\n' +
      '• 🔕 До утра 9:00 — до следующего 9:00 по Берлину (DST-aware: зимой UTC+1, летом UTC+2)\n' +
      '• 🔇 Совсем отключить — алёрты больше не приходят пока не нажмёшь Включить обратно\n' +
      'Управление per-user: один оператор нажал «Понял» — у других эскалация продолжается.\n\n' +
      'Кнопка ⚙️ Настройки алёртов в welcome-сообщении показывает текущее состояние (Активно / Заглушено до X / Отключено) и даёт переключатели.\n\n' +
      'Дашборд балансов в евро.\n' +
      'Новая кнопка [💶 Балансы в евро] в Informer-чате выдаёт сводку:\n' +
      '• Mini-acquiring — total в евро + breakdown по сетям, HOT/COLD строки с цветом\n' +
      '• Gateway — total + breakdown\n' +
      '• Total per pool в зелёном бейдже если > €10 000, в жёлтом если меньше\n' +
      'Курсы тянутся из CoinGecko (USDT/USDC/BTC/ETH/BNB/TRX), для TAL зашит фиксированный курс 1 TAL = €10 800. Кэш на 15 минут — повторное нажатие моментальное. Кнопка 🔄 Обновить курсы принудительно сбрасывает кэш.\n' +
      'Если CoinGecko недоступен — показываем последний удачный кэш с пометкой «из старого кэша N минут назад», в худшем случае — только native (BTC, ETH и т.д.) без EUR.\n\n' +
      'Также: накопились непубликованные изменения с 1.0.89 — звонки через TURN для CIS-сегмента (turn.talerid.io), мгновенный экран «Calling…» при тапе на звонок (без dead-tap паузы).',
    notes_en:
      'Release 1.0.97 — Informer V2.\n\n' +
      'This release is only relevant for the 4 GsmSoft operators with the informerAccess flag enabled. Regular users will see no difference.\n\n' +
      'Coloured badges in the Informer chat. ' +
      'The markdown renderer now understands colour tags: hot wallets get a red badge, cold gets blue, low-balance yellow, OK green. Balances inside the hot role are tinted red, cold are blue. Previously the chat was monochrome and you had to read every row to spot a problem. Colours give an at-a-glance signal of where the trouble is. The renderer also activates for AI Analyst / AI Outbound bot messages — if they ever start emitting colour tags, they render automatically.\n\n' +
      'Automatic "Hot needs refill" alerts.\n' +
      'Every 5 minutes the backend computes total pending withdrawals per (network, token) against the current hot-wallet balance. If pending exceeds 90% of hot (i.e. cannot be served even with a 10% buffer), each of the 4 operators receives an Informer-chat alert:\n' +
      '🔴 **Refill needed** [STAGE 1] — list of affected pairs and how much to top up.\n' +
      'If the deficit is still there after 30 minutes, a follow-up [STAGE 2 — UNRESOLVED] follows. Another hour later — [STAGE 3 — ESCALATED]. Then silence (so we never spam).\n' +
      'Each alert ships with four control buttons:\n' +
      '• ✅ Acknowledged — snoozes this chain for 30 minutes\n' +
      '• 🔕 Snooze 1 hour\n' +
      '• 🔕 Until 9 AM — snoozes until the next 09:00 Berlin time (DST-aware: CET in winter, CEST in summer)\n' +
      '• 🔇 Disable completely — no more alerts until you tap Enable again\n' +
      'Per-user state: one operator pressing Acknowledged does not reset the escalation timer for the others.\n\n' +
      'A ⚙️ Alert settings button in the welcome message shows current state (Active / Snoozed until X / Disabled) and toggle controls.\n\n' +
      'EUR balances dashboard.\n' +
      'New [💶 EUR balances] button in the Informer chat returns a digest:\n' +
      '• Mini-acquiring — EUR total + per-chain breakdown, HOT/COLD rows colour-coded\n' +
      '• Gateway — total + breakdown\n' +
      '• Per-pool total in a green badge if above €10 000, yellow otherwise\n' +
      'Rates pulled from CoinGecko (USDT/USDC/BTC/ETH/BNB/TRX); for TAL a hardcoded 1 TAL = €10 800 is used. Cache is 15 minutes — repeat taps are instant. 🔄 Refresh rates button forcibly invalidates the cache.\n' +
      'If CoinGecko is unreachable, the digest shows the last successful cache with a "stale by N minutes" banner; worst case — native only (BTC, ETH, etc.) without EUR.\n\n' +
      'Also: backlog since 1.0.89 — calls via TURN for CIS segments (turn.talerid.io), and an instant "Calling…" screen on tap (no dead-tap pause).',
  },
  {
    version: '1.0.89',
    build: 186,
    date: '2026-06-16',
    flavor: 'both',
    notes_ru:
      'Hotfix 1.0.89\n\n' +
      'Звонки — пропущенный звонок больше не дублируется в чате.\n' +
      'Симптом: один реальный звонок, который никто не взял, оставлял в переписке **два** одинаковых сообщения «📞 Пропущенный звонок» (и заодно «Нет ответа» в шапке вызова показывалось дважды). Причина: при разрыве звонка клиент рассылал событие call_ended по нескольким каналам (socket + HTTP fallback, плюс по триггерам от CallKit/LiveKit/кнопки), а на сервере проверка «уже обработали?» делалась неатомарно — оба обработчика проходили, оба создавали системное сообщение.\n\n' +
      'Что починили:\n' +
      '• Сервер: атомарный SETNX-гейт на roomName — первое событие call_ended делает всё (запись endedAt, missed-call сообщение, FCM-пуш), последующие игнорируются как дубликаты.\n' +
      '• Мобила: добавили per-screen флаг — call_ended уходит на бэкенд ровно один раз за весь жизненный цикл экрана звонка, даже если за время разрыва успели сработать и CallKit-событие, и кнопка «отбой», и room.disconnected от LiveKit.',
    notes_en:
      'Hotfix 1.0.89\n\n' +
      'Calls — missed-call message no longer duplicates in the chat.\n' +
      'Symptom: one missed call left TWO "📞 Missed call" system messages in the conversation, and the call screen showed "No answer" twice. Root cause: client sent call_ended via several paths (socket + HTTP fallback, plus triggers from CallKit / LiveKit / red button), and the server check on "already processed?" was a non-atomic check-then-act — both handlers passed the gate and both ran the side effects.\n\n' +
      'Fixes:\n' +
      '• Server: atomic SETNX gate per roomName — only the first call_ended runs side effects (endedAt update, missed-call message insert, FCM cancel push); subsequent duplicates are ignored.\n' +
      '• Mobile: per-screen flag ensures call_ended is sent to the backend exactly once for the lifetime of the call screen, regardless of how many triggers fire during hangup.',
  },
  {
    version: '1.0.88',
    build: 185,
    date: '2026-06-16',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.88\n\n' +
      'iOS — звонок больше не рвётся после отклонённого WhatsApp.\n' +
      'Сценарий: ты в звонке Taler ID, на iPhone приходит входящий по WhatsApp/Telegram, ты его отклоняешь — раньше после этого аудио в нашем звонке могло пропасть до самого конца, перезайти в звонок не помогало. Причина: при восстановлении аудио-сессии терялся флаг сосуществования с другими VoIP-приложениями, и iOS сразу заново «перетягивал» звук на CallKit того другого приложения. Теперь восстановление повторяет конфигурацию активного звонка один-в-один.\n\n' +
      'Informer Bot — новый бот в мессенджере. Виден только у 4 операторов GsmSoft с включённым доступом (флаг informerAccess на профиле). Показывает: кошельки, требующие действия оператора; балансы mini-acquiring (cold/hot/gas по сетям); системные кошельки crypto-gateway. ' +
      'Кнопки прямо в чате — нажал, через несколько секунд приходит markdown-сводка. ' +
      'Раз в 5 минут бэк сам проверяет API: если появился новый кошелёк, ждущий оператора — сразу алёрт в личный чат каждому из 4-х. Никакого общего канала: каждый видит у себя, читает в своём темпе. ' +
      'Источник данных — Informer API GsmSoft (HMAC-SHA256 подпись, окно ±30с по NTP).',
    notes_en:
      'Release 1.0.88\n\n' +
      'iOS — voice call no longer dies after a declined WhatsApp/Telegram ring.\n' +
      'Scenario: you are in a Taler ID call, a WhatsApp/Telegram VoIP call comes in on iPhone, you decline it — previously the audio of our call could vanish for the rest of the session, even rejoining did not help. Root cause: the AVAudioSession restore path dropped the .mixWithOthers flag, so iOS treated our session as exclusive and immediately reassigned audio to the other app\'s CallKit. Restore path now mirrors the active-call configuration exactly.\n\n' +
      'Informer bot — new messenger bot, visible only to 4 GsmSoft operators with the informerAccess flag on their profile. ' +
      'Shows: operator-required wallets, mini-acquiring balances (cold/hot/gas per chain), gateway system wallets. ' +
      'Buttons in chat — tap and get a markdown snapshot in seconds. ' +
      'Backend polls the API every 5 minutes and pushes a new-wallet alert into each operator\'s personal chat. ' +
      'Data source — GsmSoft Informer API (HMAC-SHA256 signed, ±30s NTP window).',
  },
  {
    version: '1.0.87',
    build: 180,
    date: '2026-06-16',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.87\n\n' +
      'Заметки — починили «зомби-заметки», которые возвращались после удаления.\n' +
      'Симптом: удаляешь заметку из списка, делаешь pull-to-refresh — заметка снова в списке. Со второй попытки удаляется как надо. Причина: pull-to-refresh успевал притянуть актуальный список с сервера ДО того как DELETE-запрос на удаление туда долетал, и локально заметка восстанавливалась обратно. Теперь refresh пропускает сущности с неотправленными outbox-операциями.\n\n' +
      'Синхронный перевод в звонке:\n' +
      '• Появилась явная кнопка «Выключить переводчик» в выпадашке выбора языка (раньше для отключения нужно было тапнуть текущий язык второй раз — не очевидно).\n' +
      '• Громкость голоса собеседника автоматически приглушается до 25% пока работает переводчик, а голос переводчика поднимается до 100%. Когда переводчик выключаешь — громкость собеседника возвращается в норму.',
    notes_en:
      'Release 1.0.87\n\n' +
      'Notes — fixed "zombie notes" that reappeared after deletion.\n' +
      'Symptom: you delete a note from the list, pull-to-refresh — and the note is back. Deleting it a second time works. Root cause: pull-to-refresh fetched the up-to-date server list BEFORE the queued DELETE request reached the server, so the still-present server copy was upserted back locally. refresh() now skips entities with pending/inflight outbox ops.\n\n' +
      'Synchronous call translation:\n' +
      '• New explicit "Turn off translator" entry in the language picker bottom sheet (previously the only way to disable was to tap the already-selected language a second time — undiscoverable).\n' +
      '• While the translator is active, peer voices are auto-ducked to 25% volume and the translator track is boosted to 100% so the translation is intelligible. Turning the translator off restores peer volume to 100%.',
  },
  {
    version: '1.0.86',
    build: 179,
    date: '2026-06-15',
    flavor: 'both',
    notes_ru:
      'Hotfix 1.0.86\n\n' +
      'Мессенджер — починили «фантомные» сообщения, которые отправлялись от твоего имени после смены аккаунта или повторного логина.\n' +
      'Симптом: открываешь приложение, а в чатах с твоего телефона уходят какие-то старые черновики, которых ты сейчас не писал. На Android было заметно особенно — телефон выступал инициатором.\n\n' +
      'Что было: локальная очередь неотправленных сообщений (черновики, которые ставились в очередь при потере сети) переживала logout. На следующем логине очередь сливалась под токеном нового аккаунта.\n\n' +
      'Что сделали:\n' +
      '• При logout очередь черновиков теперь полностью очищается\n' +
      '• На реконнекте сокета учитываем кому реально принадлежит черновик — чужие выкидываются, не отправляются\n' +
      '• Черновики старше 7 дней автоматически удаляются\n' +
      '• Подтверждение от сервера теперь надёжно снимает запись из очереди даже для файловых сообщений и отредактированного текста (раньше там была хрупкая дедупликация по содержимому)',
    notes_en:
      'Hotfix 1.0.86\n\n' +
      'Messenger — fixed "phantom" messages that were being sent under your account after a logout or re-login.\n' +
      'Symptom: you open the app and see your device sending old drafts you didn\'t write right now. Especially visible on Android — the phone showed up as initiator.\n\n' +
      'Root cause: the local outgoing-message queue (drafts saved while offline) survived logout. On the next sign-in it was flushed under the new account\'s JWT.\n\n' +
      'Changes:\n' +
      '• On logout the draft queue is fully wiped\n' +
      '• Socket reconnect now checks draft ownership — drafts from a previous account are evicted, never transmitted\n' +
      '• Drafts older than 7 days are removed automatically\n' +
      '• Server-side acknowledgement now reliably drains the queue even for file messages and edited bodies (previously dedup relied on a fragile content match)',
  },
  {
    version: '1.0.85',
    build: 178,
    date: '2026-06-10',
    flavor: 'both',
    notes_ru:
      'Hotfix 1.0.85\n\n' +
      'Контакты — починили подтверждение запроса в дружбу из вкладки «Контакты».\n' +
      'Раньше: если ты нажимал «Принять» во вкладке Контакты, локально запрос отмечался принятым, но фактически на сервер не уходил — отправитель не видел, что его приняли. Обходной путь был один: открыть профиль через чат и принять оттуда.\n\n' +
      'Теперь:\n' +
      '• Подтверждение/отклонение из вкладки Контакты сразу долетает до бэка\n' +
      '• Любые операции, которые попали в локальную очередь синхронизации, дополнительно дренируются при возвращении из фона — на случай, если ты успел свернуть приложение до того, как они ушли\n\n' +
      'Авторизация — для пользователей с заглавными буквами в email (например, Name@mail.com) восстановление пароля и вход теперь работают в любом регистре. Раньше можно было войти только если ты вводил email точно как при регистрации.',
    notes_en:
      'Hotfix 1.0.85\n\n' +
      'Contacts — fixed accepting a friend request from the Contacts tab.\n' +
      'Previously: tapping "Accept" inside the Contacts tab marked the request accepted locally but never reached the server — the sender did not see the acceptance. The only workaround was to open the profile via Chat and accept from there.\n\n' +
      'Now:\n' +
      '• Accepting/rejecting from the Contacts tab reaches the backend immediately\n' +
      '• Any operations queued in the local sync outbox are additionally drained when the app comes back from the background — in case you backgrounded before they had a chance to flush\n\n' +
      'Authentication — for accounts whose email contains capital letters (e.g. Name@mail.com), password recovery and login now accept any letter case. Previously you could only log in with the exact casing you used at sign-up.',
  },
  {
    version: '1.0.84',
    build: 177,
    date: '2026-06-10',
    flavor: 'both',
    notes_ru:
      'Hotfix 1.0.84\n\n' +
      'Android — починили белый экран при первом запуске после обновления.\n' +
      'У части пользователей после установки 1.0.83 приложение открывалось пустым белым экраном и не реагировало. Причина: системный ключ шифрования (AndroidKeyStore) на устройстве становился невалидным после некоторых системных событий (биометрия, смена пароля, бэкап/рестор), и приложение не могло прочитать сохранённые данные → падало до отрисовки UI.\n\n' +
      'Теперь:\n' +
      '• При обнаружении испорченных данных secure storage автоматически очищается и приложение продолжает запуск\n' +
      '• Пользователю может потребоваться повторный вход (логин + пароль) — это часть фикса\n' +
      '• Цена компромисса: один раз залогиниться заново; альтернатива — белый экран до переустановки',
    notes_en:
      'Hotfix 1.0.84\n\n' +
      'Android — fixed white screen on first launch after update.\n' +
      'Some users saw a blank white screen after updating to 1.0.83. Cause: the system encryption key (AndroidKeyStore) was invalidated by certain system events (biometric re-enroll, lock-screen change, backup/restore), so the app couldn\'t read its saved data → crashed before rendering UI.\n\n' +
      'Now:\n' +
      '• When corrupted secure-storage data is detected, it is wiped automatically and the app continues launching\n' +
      '• You may need to log in again (email + password) — that is part of the fix\n' +
      '• Trade-off: one extra login; alternative was a white screen requiring reinstall',
  },
  {
    version: '1.0.83',
    build: 175,
    date: '2026-06-09',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.83\n\n' +
      'Android — починили обновление приложения.\n' +
      'Раньше при апдейте бывала мутная ошибка «Приложение не установлено, так как оно конфликтует с другим пакетом» — без подсказки что делать. Теперь:\n' +
      '• Когда такая проблема возникает, приложение показывает понятную инструкцию: «Удали старую версию через Настройки → Приложения → Taler ID, открой папку Загрузки в файловом менеджере и тапни talerid-X.Y.Z.apk». Этот шаг нужен один раз.\n' +
      '• Сам APK обновления автоматически кладётся в публичную папку «Загрузки» — можно установить вручную из любого файлового менеджера, если автоматическая установка не пошла.\n' +
      '• Установка идёт через системный установщик Android с понятными сообщениями об ошибках, а не через сторонний просмотрщик файлов.\n\n' +
      'Проверка личности (KYC) — теперь открывается во встроенном WebView, а не через отдельную нативную библиотеку. Пользовательский опыт тот же: документы, селфи, анкета.',
    notes_en:
      'Release 1.0.83\n\n' +
      'Android — fixed app update flow.\n' +
      'Previously app updates could fail with an opaque "App not installed because it conflicts with another package" error — no hint how to recover. Now:\n' +
      '• When this happens, the app shows clear instructions: "Uninstall via Settings → Apps → Taler ID, open the Downloads folder in your file manager, and tap talerid-X.Y.Z.apk." This step is only needed once.\n' +
      '• The update APK is now automatically saved to your public Downloads folder — you can install it manually from any file manager if the in-app install doesn\'t work.\n' +
      '• Installation now goes through Android\'s system installer with clear error messages, instead of a third-party file opener.\n\n' +
      'Identity verification (KYC) — now opens in an embedded WebView instead of a separate native library. Same user experience: documents, selfie, questionnaire.',
  },
  {
    version: '1.0.82',
    build: 174,
    date: '2026-06-08',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.82\n\n' +
      'Новое:\n' +
      '• Подтверждение email — на экране Профиля появилась плашка для тех, у кого email ещё не подтверждён. ' +
      'Нажми «Подтвердить» — придёт 6-значный код на твою почту, введи его, и плашка исчезнет. ' +
      'Подтверждение нужно, чтобы можно было восстановить пароль и получать сервисные уведомления.',
    notes_en:
      'Release 1.0.82\n\n' +
      'New:\n' +
      '• Email verification — Profile now shows a banner if your email is not yet verified. ' +
      'Tap "Verify", a 6-digit code arrives in your inbox; enter it and the banner clears. ' +
      'Verification is required for password recovery and service notifications.',
  },
  {
    version: '1.0.81',
    build: 173,
    date: '2026-05-25',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.81\n\n' +
      'Исправления:\n' +
      '• iOS: восстановление пароля теперь работает на iPhone с iOS 26 — ' +
      'устранили зависание при вводе email (мешала автозаполнение iOS 26, блокировавшая запрос).',
    notes_en:
      'Release 1.0.81\n\n' +
      'Bug fixes:\n' +
      '• iOS: password recovery now works on iPhone with iOS 26 — ' +
      'fixed a freeze when entering email (iOS 26 AutoFill discovery was blocking the request).',
  },
  {
    version: '1.0.80',
    build: 172,
    date: '2026-05-26',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.80\n\n' +
      'Биллинг — закрыли утечку с «висящими» сессиями ассистента:\n' +
      '• Если приложение упало или потерялась сеть прямо во время разговора с AI-ассистентом, ' +
      'на сервере оставалась «активная» сессия — сервер продолжал каждые 10 секунд списывать с баланса, ' +
      'хотя пользователя уже не было. У отдельных аккаунтов накопилось до 10 параллельных таких сессий ' +
      'возрастом до месяца. На проде в момент выкатки разово закрыто ~190 таких зомби-сессий.\n' +
      'Что починили:\n' +
      '  (1) когда WebSocket рвётся, сервер сразу закрывает биллинг-сессию;\n' +
      '  (2) если по какой-то причине не закрылась — серверный «жнец» добивает её принудительно по таймауту ' +
      '(2 часа для голосового ассистента, 1 час для AI-двойника и outbound-звонков).',
    notes_en:
      'Release 1.0.80\n\n' +
      'Billing — closed a leak with "stuck" assistant sessions:\n' +
      '• If the app crashed or the network dropped mid-conversation with the AI assistant, ' +
      'the server kept the session marked active and the cron kept debiting the wallet every 10 s ' +
      'long after the user was gone. Some accounts accumulated up to 10 parallel stuck sessions ' +
      'as old as a month. ~190 such zombies were swept at rollout on PROD.\n' +
      'What we fixed:\n' +
      '  (1) WebSocket drop now ends the billing session immediately on the server;\n' +
      '  (2) hard server-side cap as a safety net — 2 h for voice assistant, 1 h for AI twin ' +
      'and outbound calls.',
  },
  {
    version: '1.0.79',
    build: 171,
    date: '2026-05-25',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.79\n\n' +
      'Десктоп-фиксы:\n' +
      '• Входящие звонки на macOS/Linux/Windows теперь показывают диалог с кнопками «Ответить» / «Отклонить». ' +
      'Раньше сокет получал call_invite, но UI был только в мобильном dashboard — на десктопе пропускали звонок молча.\n' +
      '• Правый клик по сообщению в чате открывает меню действий (ответить, скопировать, переслать, удалить и т.д.). ' +
      'Раньше работал только long-press, которого на десктопе с мышкой нет.\n\n' +
      'Исправления:\n' +
      '• На экране сброса и смены пароля показывалась ошибка «PIN-коды не совпадают» вместо «Пароли не совпадают». Поправили.\n' +
      '• Гостевая ссылка на комнату звонка вида /room/<код> снова открывается в браузере — раньше из браузера выдавалось «Комната не найдена».\n' +
      '• В окне звонка имя собеседника берётся из username, если в профиле не заполнены имя и фамилия. Раньше показывался UUID.',
    notes_en:
      'Release 1.0.79\n\n' +
      'Desktop fixes:\n' +
      '• Incoming calls on macOS/Linux/Windows now show an in-app dialog with Accept / Decline. ' +
      'Previously the socket received call_invite but the UI was only wired in the mobile dashboard — ' +
      'desktop missed calls silently.\n' +
      '• Right-click on a chat message now opens the actions sheet (reply, copy, forward, delete, etc.). ' +
      'Previously only long-press worked, which mice cannot trigger on desktop.\n\n' +
      'Fixes:\n' +
      '• Reset-password and change-password screens showed "PINs don\'t match" instead of "Passwords don\'t match". Fixed.\n' +
      '• Guest link to a call room /room/<code> opens in the browser again — previously the web client showed "Room not found".\n' +
      '• In-call participant name now falls back to username when first/last name are empty, instead of showing the UUID.',
  },
  {
    version: '1.0.78',
    build: 170,
    date: '2026-05-20',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.78\n\n' +
      '🌍 22 новых языка интерфейса:\n' +
      '中文 (китайский), हिन्दी (хинди), Español, العربية (арабский), বাংলা (бенгали), ' +
      'Português, اردو (урду), Bahasa Indonesia, Deutsch, 日本語, Français, मराठी (маратхи), ' +
      'తెలుగు (телугу), Türkçe, தமிழ் (тамильский), Tiếng Việt, 한국어, Italiano, ' +
      'فارسی (фарси), ਪੰਜਾਬੀ (панджаби), Hausa (хауса, Нигерия), Slovenčina.\n' +
      'Всего 24 языка интерфейса (было 2). Меняется в Настройки → Язык.\n\n' +
      '🎙️ AI-ассистент следует языку приложения:\n' +
      'Раньше ассистент всегда говорил по-русски (если ru) или по-английски (для всех остальных). ' +
      'Теперь промпт динамический — выбираешь Español в настройках, ассистент отвечает на испанском. ' +
      'Whisper-транскрипция и до этого корректно подхватывала локаль — теперь обратная сторона тоже выровнена.\n\n' +
      'Качество переводов:\n' +
      'Переводы машинные (GPT-4o) — для первого шипа OK, перед следующим релизом будут полированы носителями. ' +
      'Названия брендов (Taler ID, KYC, Gmail, WhatsApp и т.д.) и плейсхолдеры в строках сохранены как есть.',
    notes_en:
      'Release 1.0.78\n\n' +
      '🌍 22 new UI languages:\n' +
      '中文 (Mandarin), हिन्दी (Hindi), Español, العربية (Arabic), বাংলা (Bengali), ' +
      'Português, اردو (Urdu), Bahasa Indonesia, Deutsch, 日本語, Français, मराठी (Marathi), ' +
      'తెలుగు (Telugu), Türkçe, தமிழ் (Tamil), Tiếng Việt, 한국어, Italiano, ' +
      'فارسی (Persian), ਪੰਜਾਬੀ (Punjabi), Hausa (Nigeria), Slovenčina.\n' +
      '24 UI languages total (was 2). Settings → Language.\n\n' +
      '🎙️ AI assistant follows the app language:\n' +
      'Previously the assistant always responded in Russian (locale ru) or English (everything else). ' +
      'Now the system prompt is locale-aware — pick Español in settings and the assistant replies in Spanish. ' +
      'Whisper input was already pinned to the app locale — this completes the round-trip.\n\n' +
      'Translation quality:\n' +
      'Translations are machine-generated (GPT-4o) — good enough to ship, will be reviewed by native ' +
      'speakers before the next release. Brand names (Taler ID, KYC, Gmail, WhatsApp etc.) and string ' +
      'placeholders preserved verbatim.',
  },
  {
    version: '1.0.77',
    build: 169,
    date: '2026-05-20',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.77\n\n' +
      'AI-ассистент дотягивается до соседних мессенджеров и почты:\n' +
      '• Android: ассистент видит уведомления WhatsApp и Telegram и может ' +
      'на них отвечать за тебя (только после ручного включения доступа к уведомлениям в системе).\n' +
      '• Gmail: ассистент подключается через OAuth и работает со всеми твоими почтами — ' +
      'может читать письма, искать по теме/отправителю/телу, отвечать и отправлять новые.\n' +
      '• Бот «Ассистент» в чатах получил кнопку микрофона в шапке — мгновенный переход в голосовой режим.\n\n' +
      'Десктоп:\n' +
      '• Тап по «Ассистент» в левой панели сразу запускает голосовую сессию (без промежуточного «колеса»).\n' +
      '• В левую панель добавлены Notes, Contacts, Profile — теперь вся навигация в одном месте.\n' +
      '• В чате Enter отправляет сообщение, Cmd/Ctrl+Enter переносит строку.\n' +
      '• Сообщения в мессенджере подгружаются сразу при открытии экрана (без переключения вкладок).\n' +
      '• Новый онбординг под десктоп с кликабельными подсказками для системных настроек.\n\n' +
      'AI-аналитик:\n' +
      '• Сгенерированные PDF/отчёты теперь правильно прикладываются к сообщению ' +
      '(раньше ассистент говорил «приложил», а файла не было).',
    notes_en:
      'Release 1.0.77\n\n' +
      'AI assistant reaches into neighbouring messengers and email:\n' +
      '• Android: the assistant sees WhatsApp and Telegram notifications and can reply on your behalf ' +
      '(after you grant notification access in system settings).\n' +
      '• Gmail: the assistant connects via OAuth and works across all your inboxes — ' +
      'read messages, search by subject/sender/body, reply and compose new mail.\n' +
      '• The Assistant bot in chats got a microphone button in the title bar — one-tap into voice mode.\n\n' +
      'Desktop:\n' +
      '• Clicking "Assistant" in the left rail starts a voice session immediately (no more orbital wheel).\n' +
      '• Notes, Contacts and Profile are now in the left rail — all navigation in one place.\n' +
      '• In chat, Enter sends, Cmd/Ctrl+Enter inserts a newline.\n' +
      '• Messages now load instantly when you open the messenger tab.\n' +
      '• New desktop onboarding with clickable links to system settings.\n\n' +
      'AI analyst:\n' +
      '• Generated PDFs and reports are now correctly attached to the message ' +
      '(previously the assistant claimed to attach a file but nothing came through).',
  },
  {
    version: '1.0.76',
    build: 168,
    date: '2026-05-18',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.76\n\n' +
      'Выход из аккаунта:\n' +
      '• На logout стираются все следы прошлого пользователя — отзывается FCM-токен, ' +
      'снимаются зависшие CallKit оверлеи, очищаются маппинги контактов в mesh и ' +
      'локальная история сообщений. Перелогин под другой аккаунт больше не показывает ' +
      'имена предыдущего юзера в списке контактов и групповых звонках.\n\n' +
      'AI-ассистент:\n' +
      '• Бэкенд /voice/session переехал на GA Realtime API.\n' +
      '• Модель ассистента обновлена до gpt-realtime-mini-2025-12-15.',
    notes_en:
      'Release 1.0.76\n\n' +
      'Sign-out cleanup:\n' +
      '• Logout now wipes every trace of the previous user — FCM token is revoked, ' +
      'stuck CallKit overlays are dismissed, mesh contact mappings are cleared, ' +
      "and local message history is purged. Re-login under a different account no longer " +
      "shows the prior user's names in contacts or group calls.\n\n" +
      'AI assistant:\n' +
      '• Backend /voice/session migrated to the GA Realtime API.\n' +
      '• Assistant model upgraded to gpt-realtime-mini-2025-12-15.',
  },
  {
    version: '1.0.74',
    build: 167,
    date: '2026-05-15',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.74\n\n' +
      'Десктоп:\n' +
      '• Первый официальный релиз приложений для macOS, Windows и Linux. ' +
      'Скачать на https://id.taler.tirol\n\n' +
      'Обновления внутри приложения:\n' +
      '• Когда выходит новая версия, баннер показывает changelog ' +
      '(а не просто "доступно обновление").\n' +
      '• На Android APK теперь скачивается прямо из приложения без перехода в браузер.\n' +
      '• Эндпоинт /app/version отдаёт релизы с раздельным таргетом для dev/prod флейворов.\n\n' +
      'AI-ассистент:\n' +
      '• Знает о текущей версии и changelog — можно спросить "что нового в этой версии?".',
    notes_en:
      'Release 1.0.74\n\n' +
      'Desktop:\n' +
      '• First official release of macOS, Windows and Linux desktop apps. ' +
      'Download from https://id.taler.tirol\n\n' +
      'In-app updates:\n' +
      '• Update banner now shows the changelog when a new version is available, ' +
      'instead of a generic "update available" prompt.\n' +
      '• Android APK now downloads in-app without bouncing through the browser.\n' +
      '• /app/version endpoint returns releases with per-flavor (dev/prod) update target.\n\n' +
      'AI assistant:\n' +
      '• Knows the current version and changelog — ask "what is new in this release?".',
  },
  {
    version: '1.0.73',
    build: 178,
    date: '2026-05-15',
    flavor: 'dev',
    notes_ru:
      'Релиз 1.0.73 (тестовая сборка)\n\n' +
      'Групповые звонки по локальной сети (mesh):\n' +
      '• Стабилизация аудио в групповых звонках iOS↔Android\n' +
      '• Дозапись микрофона в фиксированные 20-мс блоки против щелчков\n' +
      '• Авто-восстановление аудиосессии после CallKit\n\n' +
      'Сообщения:\n' +
      '• Размер шрифта плитки «Избранное» выровнен с остальными чатами',
    notes_en:
      'Release 1.0.73 (beta)\n\n' +
      'Mesh group calls:\n' +
      '• Audio stability across iOS↔Android peers\n' +
      '• Mic capture rebuffered into fixed 20 ms chunks to remove clicks\n' +
      '• Audio session auto-recovery after CallKit cycles\n\n' +
      'Messenger:\n' +
      '• Saved chat tile typography aligned with the rest of the chat list',
  },
  {
    version: '1.0.72',
    build: 165,
    date: '2026-05-14',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.72\n\n' +
      'Чат:\n' +
      '• Новое: время в сети\n' +
      '  — В шапке чата и в профиле собеседника: «в сети» или «был(а) в сети 15 мин назад»\n' +
      '  — Обновляется автоматически каждые 30 секунд\n' +
      '  — Настройка приватности в «Изменить профиль → Конфиденциальность»: Все / Только контакты / Никто',
    notes_en:
      'Release 1.0.72\n\n' +
      'Chat:\n' +
      '• New: last-seen indicator\n' +
      '  — Chat header and user profile show "online" or "last seen 15 min ago"\n' +
      '  — Auto-refresh every 30 seconds\n' +
      '  — Privacy controls in "Edit profile → Privacy": Everyone / Contacts / Nobody',
  },
  {
    version: '1.0.71',
    build: 164,
    date: '2026-05-14',
    flavor: 'both',
    notes_ru:
      'Релиз 1.0.71\n\n' +
      'Офлайн-режим:\n' +
      '• Заметки — создание, редактирование, удаление работают без интернета\n' +
      '• Календарь — события создаются/редактируются офлайн, конфликты решаются через диалог\n' +
      '• Контакты — приём и отклонение заявок работают офлайн\n' +
      '• Избранное — мгновенный вход в Сохранённые после первого онлайн-открытия\n\n' +
      'Мессенджер:\n' +
      '• AI-ассистент: ответы фоновых задач доставляются через delta-sync, нет потерь при кратком офлайне\n' +
      '• Чат: переподключение сокета при перелогине в другой аккаунт\n\n' +
      'Звонки (групповые mesh):\n' +
      '• Mesh group voice room v1 — групповой звонок 2–5 участников по локальной сети\n' +
      '• Late-joiner audio isolation, per-peer Noise сессии\n' +
      '• Стабильность: CallKit роутинг, lobby flow, GMCEnded маршруты',
    notes_en:
      'Release 1.0.71\n\n' +
      'Offline mode:\n' +
      '• Notes — create, edit, delete work offline\n' +
      '• Calendar — events create/edit offline, conflicts resolved via dialog\n' +
      '• Contacts — accept and reject requests work offline\n' +
      '• Favorites — instant entry into Saved Messages after first online open\n\n' +
      'Messenger:\n' +
      '• AI assistant: background-task replies delivered via delta-sync, no loss after brief offline\n' +
      '• Chat: socket reconnect on relogin into a different account\n\n' +
      'Mesh group calls:\n' +
      '• Mesh group voice room v1 — 2-5 peers over LAN\n' +
      '• Late-joiner audio isolation, per-peer Noise sessions\n' +
      '• Stability: CallKit routing, lobby flow, GMCEnded routes',
  },
];
