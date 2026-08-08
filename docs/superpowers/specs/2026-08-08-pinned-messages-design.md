# Закреплённые сообщения (pinned messages) — Design

**Date:** 2026-08-08
**Status:** Approved (design), pending implementation plan
**Scope:** бэкенд (`taler-id`) + мобилка/десктоп (`taler_id_mobile`) + e2e-набор (`taler_id_tests`).
Первое применение — объявление «это TEST, переходите на PROD» в системном канале на TEST + перенастройка TEST update-баннера на PROD-артефакты.

## Цель

Дать чатам закреплённые сообщения по образцу Telegram: несколько пинов на беседу, плашка сверху чата с переключением между ними, экран со списком, «открепить всё», скрытие плашки лично для себя, сервисное сообщение и push при новом закрепе.

Непосредственный повод: в системном канале «Taler ID — Новости» на TEST нужно повесить объявление, что это тестовая среда и надо переходить на PROD (iOS TestFlight `https://testflight.apple.com/join/UB3D5Dcd`, Android `https://talerid.io/download/talerid.apk`). Закрепа в продукте не существовало — ни поля в схеме, ни API, ни UI.

## Ключевые решения

| Вопрос | Решение |
|--------|---------|
| Где работает | Во всех беседах: `CHANNEL`, `GROUP`, `DIRECT`, `SAVED`, `AI_*` |
| Сколько пинов | Несколько на беседу, порядок — по времени закрепа (новые сверху) |
| Хранение | Поля на `Message` (`pinnedAt`, `pinnedById`), НЕ отдельная таблица |
| Права | `CHANNEL`/`GROUP` — только OWNER/ADMIN; все остальные типы — любой участник |
| Системный канал | Живых админов нет (владелец — системный юзер) → админ-эндпоинты: флаг `pin` у `POST /admin/system-channel/post` + `POST /admin/system-channel/pin`\|`unpin` |
| Скрытие плашки | `ConversationParticipant.pinsDismissedAt`; плашка возвращается при пине с `pinnedAt > pinsDismissedAt` |
| Сервисное сообщение | Существующий механизм `Message.isSystem` + JSON-контент `{action:'message_pinned', …}` |
| Push о закрепе | Бесплатно: сервисное сообщение идёт обычным `deliverNewMessage`; отдельного пуш-канала нет |
| Удаление закреплённого сообщения | Пин исчезает сам (состояние живёт на самом сообщении) |

### Почему поля на `Message`, а не таблица `PinnedMessage`

- Мобилка и так грузит сообщения — `pinnedAt` в payload сообщения бесплатен, отдельный join в списке бесед не нужен.
- Удаление/скрытие сообщения автоматически снимает пин; отдельная таблица потребовала бы чистки висяков.
- Миграция — две колонки + индекс.

Цена решения: нет истории «кто когда пинил и отпинил» и нет ручного порядка пинов. Обе возможности не нужны: порядок по времени — ровно телеграмное поведение, а аудит закрепов никто не запрашивал. Отброшен также вариант с массивом `pinnedMessageIds` на `Conversation` — в нём негде хранить «кто/когда» и он плохо индексируется.

## Архитектура

### 1. Данные

```prisma
model Message {
  // …
  pinnedAt   DateTime?
  pinnedById String?

  @@index([conversationId, pinnedAt])
}

model ConversationParticipant {
  // …
  pinsDismissedAt DateTime?
}
```

Список пинов беседы: `where { conversationId, pinnedAt: { not: null }, deletedAt: null } orderBy { pinnedAt: 'desc' }`.

Плашка показывается, если существует пин с `pinnedAt > pinsDismissedAt` (или `pinsDismissedAt = null`).

### 2. Права (единая проверка `assertCanPin`)

- `CHANNEL`, `GROUP` → участник с ролью `OWNER` или `ADMIN`, иначе `ForbiddenException`.
- `DIRECT`, `SAVED`, `AI_ANALYST`, `AI_INFORMER`, `AI_ASSISTANT`, `AI_OUTBOUND` → любой участник беседы (это личные чаты, где участник и есть хозяин).
- Не-участник → `ForbiddenException` (существующий `assertParticipant`).
- Системный канал через обычный API недоступен никому (у живых юзеров роль `SUBSCRIBER`) — только через админ-эндпоинты.

### 3. REST API (`messenger.controller.ts`)

| Метод | Путь | Ответ / смысл |
|-------|------|---------------|
| `POST` | `/messenger/conversations/:id/messages/:msgId/pin` | `{ pinnedAt, pinnedCount }` |
| `DELETE` | `/messenger/conversations/:id/messages/:msgId/pin` | `{ pinnedCount }` |
| `GET` | `/messenger/conversations/:id/pinned?limit&offset` | список закреплённых сообщений (полный payload сообщения + `pinnedAt`, `pinnedById`) |
| `DELETE` | `/messenger/conversations/:id/pinned` | открепить всё |
| `POST` | `/messenger/conversations/:id/pinned/dismiss` | `pinsDismissedAt = now()` для текущего юзера |

Повторный пин уже закреплённого сообщения идемпотентен (`pinnedAt` не переписывается, возвращается текущее состояние) — иначе двойной тап поднимал бы пин наверх и слал второй push.

Расширение существующих payload'ов:
- сообщение → `pinnedAt`, `pinnedById`;
- беседа (`getConversations`, `GET /messenger/sync`, `GET /messenger/channels/:id`) → `pinnedCount`, `topPinned { id, content, senderName, sentAt, pinnedAt }`, `pinsDismissedAt`.

`topPinned.content` обрезается до 200 символов — плашке больше не нужно, а системные посты бывают длинными.

### 4. Админ-путь для системного канала

- `POST /admin/system-channel/post` получает необязательный `pin?: boolean`. При `pin: true` пост создаётся и сразу закрепляется от имени системного юзера, **без** сервисного сообщения — иначе подписчики получают два push подряд («объявление» и «Taler ID закрепил сообщение»).
- `POST /admin/system-channel/pin` `{ messageId }` и `POST /admin/system-channel/unpin` `{ messageId }` — закрепить/открепить существующий пост.
- `SystemChannelService.postNews` возвращает `messageId` уже сейчас — этого достаточно, дополнительных изменений в сигнатуре не нужно.

### 5. Реалтайм и уведомления

Socket-события в комнату беседы:
- `message_pinned` — `{ conversationId, messageId, pinnedById, pinnedAt, pinnedCount }`
- `message_unpinned` — `{ conversationId, messageId, pinnedCount }`
- `pins_cleared` — `{ conversationId }`

Сервисное сообщение создаётся через существующий `_createSystemMessage` ([messenger.service.ts:1209](../../../src/messenger/messenger.service.ts#L1209)) — в его `switch` добавляется ветка `message_pinned` с контентом `JSON.stringify({ action: 'message_pinned', actor, preview })`. Оно же обеспечивает push: доставка идёт обычным `deliverNewMessage`, mute уважается как у любого сообщения.

Сервисное сообщение НЕ создаётся при: откреплении, «открепить всё», админском посте с `pin: true`.

### 6. Мобилка / десктоп

1. **`PinnedBanner`** — плашка сверху в `Column` тела чата, туда же, где `_ConnectivityBanner` и `_ActiveCallBanner` ([chat_room_screen.dart:2305](../../../../Downloads/taler_id_mobile/lib/features/messenger/presentation/screens/chat_room_screen.dart#L2305)): вертикальный индикатор «2 из 3», превью в одну строку, тап → прыжок к сообщению через существующий `_scrollToChronIndex`, следующий тап → следующий пин по кругу, «×» → dismiss, иконка списка → экран закреплённых.
2. **`PinnedMessagesScreen`** — список закреплённых, тап → возврат в чат с прыжком к сообщению (переиспользует `highlightMessageId`), у OWNER/ADMIN — «Открепить всё».
3. **Пункт меню** «Закрепить» / «Открепить» в длинном тапе по сообщению, показывается по правам.
4. **Bloc** — обработчики трёх socket-событий + оптимистичное обновление при своих действиях.
5. **Рендер сервисного сообщения** — ветка `message_pinned` в существующих switch'ах ([chat_room_screen.dart:3955](../../../../Downloads/taler_id_mobile/lib/features/messenger/presentation/screens/chat_room_screen.dart#L3955), [conversations_screen.dart:1565](../../../../Downloads/taler_id_mobile/lib/features/messenger/presentation/screens/conversations_screen.dart#L1565)).
6. **i18n** ru/en для всех новых строк.

Плашка живёт в отдельном файле-виджете, не внутри и без того шеститысячестрочного `chat_room_screen.dart`.

### 7. Ассистент (правило «Assistant-first»)

Добавить в набор tools ассистента `pin_message` / `unpin_message` / `list_pinned` поверх тех же сервисных методов — по правилу «каждая новая функция доступна голосом» из CLAUDE.md.

## Тестирование

**Бэкенд (unit):**
- права: `SUBSCRIBER` не может, `ADMIN`/`OWNER` может, в `DIRECT` может любой участник, не-участник получает 403;
- идемпотентность повторного пина;
- dismiss-семантика: после `dismiss` плашка скрыта, после нового пина — снова видна;
- удаление сообщения убирает его из списка закреплённых;
- админский `post` с `pin: true` не создаёт сервисного сообщения.

**E2E (`taler_id_tests`, новый `npm run test:pins`)** по образцу `test:channels`: закрепить → список → счётчик в payload беседы → dismiss → новый пин возвращает плашку → открепить → открепить всё → негативы по правам. Добавить набор в обязательную батарею перед деплоем (секция «🧪 ОБЯЗАТЕЛЬНЫЕ ТЕСТЫ» в CLAUDE.md) и в `:prod`-прогон для TEST.

**Flutter:** виджет-тест плашки (счётчик, переключение, dismiss) + прогон `flutter test` и интеграционного `app_test.dart`.

## Выкатка

1. Бэкенд на DEV (`npx prisma migrate deploy` + `npx prisma generate` — без них деплой выглядит успешным, а эндпоинт отдаёт 500; обжигались 2026-08-03) → полная батарея тестов.
2. Бэкенд на TEST → батарея `:prod`.
3. Бэкенд на PROD (DO, rolling через `infra/do/provision/deploy.sh`) → `test:talerid`.
4. Мобильный релиз: bump `pubspec.yaml`, сборки dev / TEST / talerid + iOS×3, release notes, запись в `APP_RELEASES`, обновление `latest` в `app.controller.ts` и `APP_LATEST_VERSION`/`APP_LATEST_BUILD` в `.env` обеих DO-нод. Порядок жёсткий: сначала артефакты, потом объявление версии.
5. Пост объявления в системный канал TEST: `POST /admin/system-channel/post` с `type: 'news'`, `pin: true`.
6. Перенастройка TEST update-баннера на PROD (см. ниже).

## Первое применение: объявление на TEST

**Текст поста** (RU + EN секциями, как принято в системном канале):

> ⚠️ Это тестовая версия Taler ID
>
> Приложение, которым вы пользуетесь, работает на тестовой среде (`id.taler.tirol`). Она нужна для проверки новых функций и может работать нестабильно.
>
> Пожалуйста, перейдите на основную версию:
> • iOS (TestFlight): https://testflight.apple.com/join/UB3D5Dcd
> • Android (APK): https://talerid.io/download/talerid.apk
>
> Продакшн — отдельная среда: если аккаунт не найдётся, зарегистрируйтесь заново.

**Update-баннер на TEST.** `/app/version` уже env-overridable ([app.controller.ts](../../../src/app.controller.ts)) — правка `~/taler-id/.env` на `138.124.61.221` без изменения кода:

```
APP_UPDATE_URL_ANDROID=https://talerid.io/download/talerid.apk
APP_UPDATE_URL_IOS=https://testflight.apple.com/join/UB3D5Dcd
APP_LATEST_VERSION=<версия PROD-релиза>
APP_LATEST_BUILD=<build PROD-релиза>
```

`APP_LATEST_*` держим равными версии PROD-сборки — она по определению не ниже TEST-сборки (релиз общий), поэтому баннер висит у всех, кто остался на TEST. На 2026-08-08 все три окружения отдают 1.1.24+225, то есть значение = версия ближайшего релиза из шага 4.

Переключение делается **сразу после поста**, не откладывается: цель — увести людей с TEST, а не раздать им ещё один TEST-билд. Следствие принято осознанно (см. риск ниже).

**Смежная починка на PROD.** Там `updateUrl.ios` до сих пор ведёт на aeza-листинг `id6741208498` (задокументированный пробел в CLAUDE.md) — чинится тем же `APP_UPDATE_URL_IOS=https://testflight.apple.com/join/UB3D5Dcd` в `.env` обеих DO app-нод.

## Риски

- **Пин на TEST увидят немногие.** Плашка требует нового TEST-билда, а сразу после поста баннер начинает вести на PROD, то есть TEST-обновление больше не рекламируется. До людей реально доносят пост с push и баннер; пин — долгоиграющая часть, ценная прежде всего на DEV/PROD как продуктовая фича.
- **Fan-out в системном канале.** Сервисное сообщение о закрепе — это ещё один push десяткам тысяч подписчиков. Поэтому админский `pin: true` его подавляет.
- **Миграция на PROD.** Patroni-кластер, деплой rolling — миграция должна быть аддитивной (только новые nullable-колонки), чтобы нода со старым кодом продолжала работать во время выкатки.
