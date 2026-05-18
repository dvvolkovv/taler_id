import { Controller, Get, Header, Query, Redirect } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  @Redirect('/ui/index.html')
  root() {}

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
      ? { version: '1.0.76', build: 168 }
      : { version: '1.0.76', build: 168 };
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
