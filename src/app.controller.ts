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
    const latest = isDev
      ? { version: '1.0.82', build: 174 }
      : { version: '1.0.82', build: 174 };
    return {
      ios: { ...latest, required: false },
      android: { ...latest, required: false },
      updateUrl: {
        ios: 'https://apps.apple.com/app/taler-id/id6741208498',
        android: isDev
          ? 'https://id.taler.tirol/download/taler-id-dev.apk'
          : 'https://id.taler.tirol/download/taler-id.apk',
      },
      releases: APP_RELEASES,
    };
  }
}

// Append entries on top whenever a new version ships.
// Keep notes user-facing (no internal jargon, no commit hashes).
const APP_RELEASES = [
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
