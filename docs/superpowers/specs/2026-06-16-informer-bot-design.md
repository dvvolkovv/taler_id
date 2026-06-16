# Informer Bot — Design

Бот в мессенджере Taler ID, который читает GsmSoft Informer API и доставляет
сводки/алёрты по криптокошелькам четверым операторам.

- **Доступ:** только пользователи с `Profile.informerAccess = true`. На старте — `@vdv`, `@trientes`, `@NARAYANA`, `@VKoval`.
- **Тип чата:** `ConvType.AI_INFORMER` (один чат на юзера, как у `AI_ANALYST`).
- **Источник данных:** Informer API `https://apiadmin.test.gsmsoft.eu/informer/v1` с HMAC-SHA256 авторизацией (см. `docs/informer-integration-guide.md` в репо `gsmsoft1/exchange/admin-api`).
- **Режимы:**
  - **Pull:** юзер жмёт одну из 3 кнопок в чате → бот вызывает соответствующий endpoint Informer'а и присылает форматированный ответ.
  - **Push (алёрты):** cron каждые 5 минут опрашивает `operator-required-wallets`; при появлении нового адреса шлёт всем юзерам с доступом персональное сообщение в их `AI_INFORMER`-чат.

## 1. Архитектура

```
┌─────────────────┐  open chat  ┌────────────────────────────────────────┐
│ Mobile (Flutter)│ ──────────► │ NestJS backend                          │
│ Pinned tile     │             │  src/informer-bot/                      │
│ "Informer"      │ ◄── markdown│   ├─ informer-bot.controller.ts         │
│ + ACTION btns   │  + ACTION   │   │    POST /informer-bot               │
└─────────────────┘    buttons  │   │      → { conversationId }           │
                                │   ├─ informer-bot.service.ts            │
                                │   │    getOrCreateChat(userId)          │
                                │   │    handleAction(userId, convId, code)│
                                │   ├─ informer.client.ts                 │
                                │   │    HMAC-SHA256 sign + GET           │
                                │   ├─ informer.formatters.ts             │
                                │   │    pure md formatters per endpoint  │
                                │   ├─ informer.types.ts (zod schemas)    │
                                │   └─ informer.watcher.ts                │
                                │       @Cron every INFORMER_POLL_..._MS  │
                                │                                          │
                                │  src/messenger/messenger.gateway.ts     │
                                │   handleMessage(): AI_INFORMER →        │
                                │     informerBotService.handleAction()   │
                                └─────────────────────────────────────────┘
                                       ▲
                                       │ HMAC-SHA256 (key+secret из .env)
                                       │
                                ┌──────┴──────────────────────────────┐
                                │ https://apiadmin.test.gsmsoft.eu    │
                                │  /informer/v1/...                   │
                                └─────────────────────────────────────┘
```

## 2. Backend: Informer API client

`src/informer-bot/informer.client.ts` — типизированная обёртка над 4 GET-эндпоинтами:

| Метод клиента | Endpoint | Возвращает |
|---|---|---|
| `getOperatorRequiredCount()` | `GET /operator-required-wallets/count` | `{ count: number }` |
| `getOperatorRequiredList(page, perPage)` | `GET /operator-required-wallets?page&per_page` | `{ items[], total, page, per_page }` |
| `getMiniAcquiringBalances()` | `GET /mini-acquiring/balances` | `{ chains[] }` |
| `getGatewaySystemWalletBalances()` | `GET /gateway/system-wallet-balances` | `{ items[] }` |

### Подпись

На каждый вызов:

```ts
const ts = Math.floor(Date.now() / 1000).toString();
const nonce = randomUUID().replace(/-/g, '');
const body = ''; // GET, тело пустое
const bodyHashHex = createHash('sha256').update(body).digest('hex');
// для пустого тела всегда e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
const signingString = `GET\n${requestUri}\n${ts}\n${bodyHashHex}`;
const signature = createHmac('sha256', secret).update(signingString).digest('hex');
```

Заголовки:
- `X-Informer-Key` — из env
- `X-Informer-Timestamp` — `ts`
- `X-Informer-Nonce` — новый UUID-hex на КАЖДЫЙ вызов, включая ретраи
- `X-Informer-Signature` — `signature`

`requestUri` берётся из готовой `URL.pathname + URL.search` объекта (не из шаблона), чтобы гарантированно совпасть с тем, что увидит сервер.

### Таймауты и ошибки

- **Таймаут** 25 секунд (`mini-acquiring/balances` ходит on-chain — может быть медленным).
- **Ретраев в клиенте нет.** Решение о ретрае — у вызывающего кода.
- **Типизированные ошибки:**
  - `InformerAuthError` — `401`. Логируем ERROR, не ретраим.
  - `InformerNotConfiguredError` — `404` или `503 ... not configured`. Логируем ERROR, не ретраим.
  - `InformerNonceStoreError` — `503 nonce store unavailable`. Можно ретраить.
  - `InformerUnavailableError` — `502` JSON или HTML, `503` неизвестный. Можно ретраить.
  - `InformerTimeoutError` — fetch timeout. Можно ретраить.

### Env vars (DEV + PROD `.env`)

```
INFORMER_API_BASE_URL=https://apiadmin.test.gsmsoft.eu
INFORMER_API_KEY=monitoring-test
INFORMER_API_SECRET=<секрет, не в git>
INFORMER_POLL_INTERVAL_MS=300000
INFORMER_WATCHER_ENABLED=true
INFORMER_DEBUG_TICK=false  # только DEV, открывает админ-эндпоинт ручного тика для тестов
```

Если `INFORMER_API_KEY` или `INFORMER_API_SECRET` пусты — `InformerBotModule` не регистрируется, логируется WARN при старте. `/profile/me` отдаёт `availableBots.informer=false`, мобила тайл не рисует.

## 3. Prisma: схема и whitelist

### Миграция 1 — `informerAccess` на профиле

```prisma
model Profile {
  // ...
  informerAccess Boolean @default(false)
}
```

После миграции — вручную через psql проставить флаг четверым:

```sql
UPDATE "Profile"
SET "informerAccess" = true
WHERE "userId" IN (
  SELECT id FROM "User"
  WHERE username IN ('vdv', 'trientes', 'NARAYANA', 'VKoval')
);
```

Делается отдельно на DEV-БД и на PROD-БД при выкатке.

### Миграция 2 — состояние watcher'а

```prisma
model InformerSeenWallet {
  id          String   @id @default(cuid())
  address     String
  network     String
  token       String
  amount      String   // строка как пришло из API
  firstSeenAt DateTime @default(now())
  notifiedAt  DateTime @default(now())

  @@unique([address, network, token])
  @@index([firstSeenAt])
}
```

- Уникальный ключ `(address, network, token)` исключает дубль-алёрты.
- `firstSeenAt` хранится навсегда (с TTL 30 дней через ежедневный cleanup), чтобы оператор после обработки кошелька не получил повторный алёрт, если адрес снова появится в API из-за лагов.

### Миграция 3 — новый `ConvType`

```prisma
enum ConvType {
  PERSONAL
  GROUP
  CHANNEL
  AI_ANALYST
  AI_OUTBOUND
  AI_INFORMER
}
```

## 4. Backend: сервис, контроллер, хук в gateway

### `src/informer-bot/informer-bot.service.ts`

Зеркало `ai-analyst.service.ts`, но без LLM.

**`getOrCreateChat(userId): Promise<{ conversationId: string }>`**
1. Проверка: `Profile.informerAccess === true` для `userId` → иначе `ForbiddenException`.
2. Поиск существующего `Conversation` с `type = AI_INFORMER` и `userId` в участниках. Если есть — вернуть его id.
3. Иначе — создать `Conversation` + `ConversationParticipant(userId)`. Отправить welcome-сообщение:
   ```
   Я бот мониторинга Informer. Что нужно проверить?

   [ACTION:OPERATOR_WALLETS] 📋 Кошельки, требующие оператора
   [ACTION:MINI_ACQUIRING] 💰 Балансы mini-acquiring
   [ACTION:GATEWAY_WALLETS] 🏦 Системные кошельки gateway
   ```
   Сообщение помечается `isSystem: true`.

**`handleAction(userId, conversationId, actionCode): Promise<void>`**
1. Access-check (тот же `informerAccess`).
2. Anti-flood throttle in-memory: `Map<userId+actionCode, lastCallAt>`, окно 3 сек. Повтор — игнор + WARN в лог.
3. `switch(actionCode)`:
   - `OPERATOR_WALLETS` → `client.getOperatorRequiredList(1, 50)` → `formatters.operatorWalletsList(data)`.
   - `MINI_ACQUIRING` → `client.getMiniAcquiringBalances()` → `formatters.miniAcquiringBalances(data)`.
   - `GATEWAY_WALLETS` → `client.getGatewaySystemWalletBalances()` → `formatters.gatewayWallets(data)`.
4. `messengerGateway.publishSystemMessage(conversationId, markdown)` — пишет в БД `Message{ isSystem: true, text: markdown }` и эмитит Socket.IO `new_message`.
5. При ошибке клиента — единое сообщение `⚠️ Informer недоступен: <human-readable>` + кнопка `[ACTION:RETRY:<actionCode>]`.

### `src/informer-bot/informer-bot.controller.ts`

Один эндпоинт:

```
POST /informer-bot
Auth: JwtAuthGuard
Body: {}
Response: { conversationId: string }
```

Под `JwtAuthGuard`. Внутри вызывает `service.getOrCreateChat(req.user.id)`.

При `INFORMER_DEBUG_TICK=true` дополнительно регистрируется:

```
POST /informer-bot/debug/tick
Auth: JwtAuthGuard
Response: { newCount: number, totalSeen: number }
```

Дёргает watcher вручную (для E2E-тестов).

### Хук в `messenger.gateway.ts`

В существующем `handleMessage`:

```ts
if (conversation.type === ConvType.AI_INFORMER) {
  const actionCode = parseActionCode(payload.text);
  if (actionCode) {
    await this.informerBotService.handleAction(userId, conversationId, actionCode);
  } else {
    await this.informerBotService.replyWithButtonsOnly(userId, conversationId);
  }
  return;
}
```

`parseActionCode(text)` — общий хелпер (вынести из outbound-bot если ещё не вынесен), парсит формат `[ACTION:CODE]` или `[ACTION:CODE:ARG]`.

`replyWithButtonsOnly()` — system-сообщение «Я понимаю только кнопки 👇» + повтор панели из welcome.

## 5. Backend: Watcher (cron)

`src/informer-bot/informer.watcher.ts` — NestJS `@Cron('*/5 * * * *')` (или `setInterval(INFORMER_POLL_INTERVAL_MS)`, если интервал не кратен минуте).

### Алгоритм `tick()`

```
1. IF !INFORMER_WATCHER_ENABLED → return
2. lock = pg_try_advisory_lock(<unique-id>)
   IF !lock → return  // другой инстанс уже тикает
   try {
     3. response = client.getOperatorRequiredList(1, 500)
        catch InformerAuthError | InformerNotConfiguredError → ERROR log, return
        catch InformerUnavailableError | InformerTimeoutError | InformerNonceStoreError
          → WARN log, increment consecutive_5xx counter
          IF counter >= 3 (~15 min downtime)
            → publishSystemMessageToAllUsersWithAccess(
                "⚠️ Informer API недоступен 15+ минут"
              )
          return

     4. consecutive_5xx counter = 0

     5. isBootstrapping = redis.get('informer:bootstrapped') == null
        IF isBootstrapping:
          insert all response.items into InformerSeenWallet (без алёртов)
          redis.set('informer:bootstrapped', '1', EX: 30 days)
          return

     6. FOR EACH item IN response.items:
          key = (item.withdraw_address, item.withdraw_network, item.withdraw_token)
          IF NOT EXISTS InformerSeenWallet WHERE key:
            INSERT InformerSeenWallet { ...item, firstSeenAt: now, notifiedAt: now }
            FOR EACH userId IN profilesWithInformerAccess():
              conversationId = informerBotService.getOrCreateChat(userId).conversationId
              messengerGateway.publishSystemMessage(conversationId, formatAlert(item))
   } finally {
     pg_advisory_unlock(<unique-id>)
   }
```

### Cold-start guard

Первый `tick()` после старта процесса (флаг `informer:bootstrapped` в Redis отсутствует) — только заполняет `InformerSeenWallet`, никаких алёртов. Иначе при первом запуске 13 уже существующих кошельков уйдут лавиной в чаты. TTL флага 30 дней (если бэк не рестартил месяц — у нас всё равно проблемы покрупнее).

### Cleanup

Отдельный `@Cron('0 4 * * *')` (раз в сутки в 04:00): `DELETE FROM InformerSeenWallet WHERE firstSeenAt < now() - interval '30 days'`.

### Формат алёрта

```markdown
🚨 **Новый кошелёк ждёт оператора**

Сеть: `tron`
Токен: `usdt`
Адрес: `TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG`
Сумма: `1.258494593554098`
Создан: 02 июня, 12:49 UTC

[ACTION:OPERATOR_WALLETS] 📋 Все ожидающие
[ACTION:GATEWAY_WALLETS] 🏦 Балансы gateway
```

## 6. Backend: расширение `/profile/me`

В DTO ответа `/profile/me` добавить:

```ts
availableBots: {
  analyst: boolean,   // всегда true
  outbound: boolean,  // всегда true
  informer: boolean,  // = profile.informerAccess
}
```

Это публичная фича-сигнатура: мобила полагается на неё, чтобы решить, что рендерить. Не плодим N отдельных булевых полей.

## 7. Mobile: UI

### `lib/features/messenger/presentation/screens/conversations_screen.dart`

**Фильтр основного списка** (line ~643): добавить `AI_INFORMER` к существующим исключениям:

```dart
if (c.type == 'AI_ANALYST' || c.type == 'AI_OUTBOUND' || c.type == 'AI_INFORMER') {
  return false;
}
```

**Pinned-секция** (line ~978-1036): третий тайл после AI Аналитика и AI Обзвона. Видимость:

```dart
if (profile.availableBots.informer) {
  // SliverToBoxAdapter с InformerBotTile
}
```

**`InformerBotTile`** — копия паттерна `AiAnalystTile`:

| Параметр | Значение |
|---|---|
| Аватар-икона | `Icons.monitoring` |
| Градиент | amber/orange (`Colors.amber.shade700` → `Colors.deepOrange.shade400`) |
| Glow (BoxShadow) | amber, blur 10 |
| Border (2px) | `Theme.of(context).colorScheme.tertiary` или amber-700 |
| Title | `AppLocalizations.of(context)!.informerBotTitle` |
| Subtitle | `AppLocalizations.of(context)!.informerBotSubtitle` |
| Tap handler | `POST /informer-bot` → `{conversationId}` → `context.push('/chat/$conversationId')` |

### ARB-строки

`lib/l10n/app_ru.arb`:
```json
"informerBotTitle": "Informer",
"informerBotSubtitle": "Мониторинг кошельков и балансов"
```

`lib/l10n/app_en.arb`:
```json
"informerBotTitle": "Informer",
"informerBotSubtitle": "Wallet and balance monitoring"
```

### Внутри чата

Стандартный `chat_room_screen` — никаких новых виджетов. Action-кнопки `[ACTION:OPERATOR_WALLETS]` и т.д. отрендерятся существующим парсером, который уже работает у AI Обзвона.

### Сообщения от бота

Только русский в первой версии (как и алёрты `@taleridbot` мониторинга). Локализация — отдельным шагом если понадобится.

## 8. Обработка ошибок

| Что вернул Informer | Что пишем в чат | Действие watcher'а |
|---|---|---|
| `200` `ERCD0000` | Отформатированный ответ | OK |
| `401` | `⚠️ Informer: ошибка аутентификации. Сообщи администратору` | ERROR log, выход |
| `404 /informer/v1/*` | `ℹ️ Informer на этом стенде не настроен` | ERROR log, выход |
| `503 nonce store unavailable` | `⚠️ Временная ошибка, попробуй снова` + `[ACTION:RETRY:...]` | WARN, increment 5xx counter |
| `503 ... not configured` | `ℹ️ Informer бэкенд не сконфигурирован` | ERROR log, выход |
| `502 JSON ... unavailable` | `⚠️ Informer недоступен, попробуй через минуту` + `[ACTION:RETRY:...]` | WARN, increment 5xx counter |
| HTML `502 Bad Gateway` | То же что 502 JSON | WARN, separate signal в логи «admin-api down» |
| `fetch timeout` (25c) | `⚠️ Informer не ответил вовремя` + `[ACTION:RETRY:...]` | WARN, increment 5xx counter |
| 3 подряд 5xx (~15 мин) | — | один общий алёрт всем юзерам |

## 9. Тестирование

### 9.1 Юнит-тесты (`src/informer-bot/__tests__/`)

- **`informer.client.spec.ts`:**
  - Подпись для фиксированных входов (METHOD, URI, ts, секрет) совпадает с ручным расчётом из docs §2.1.
  - На каждый запрос — новый nonce (генерится в момент вызова, не закеширован).
  - `requestUri` берётся из URL.pathname+search готового объекта, не из шаблона.
  - Маппинг HTTP статусов → типизированные ошибки.

- **`informer.watcher.spec.ts`:**
  - Мокаем `InformerClient`. Первый `tick()` после `redis.bootstrapped=null` → N INSERT'ов в фейковую `InformerSeenWallet`, **0 publish** (cold-start), флаг bootstrapped установлен.
  - Второй `tick()` те же N items → 0 INSERT, 0 publish.
  - Третий `tick()` N+1 items (новый адрес) → 1 INSERT, K publish (K = число юзеров с `informerAccess=true`).
  - 3 подряд 5xx → emit downtime-алёрта, четвёртый 5xx молчит.
  - На `InformerAuthError` watcher не пытается следующий `tick()` пока процесс не рестартанёт.

- **`informer.formatters.spec.ts`:**
  - Snapshot-тесты markdown по фикстурам ответов из docs §4.1–4.4. Любое изменение формы — diff в PR.

### 9.2 E2E на DEV (`taler_id_tests/test/informer.test.js`)

Новый smoke-набор, добавляется в готовый `taler_id_tests/`:

1. Логин юзером **без** `informerAccess` → `POST /informer-bot` возвращает `403`.
2. SQL `UPDATE Profile SET informerAccess=true WHERE userId = '<integration_test>'`.
3. Логин ещё раз → `POST /informer-bot` возвращает `200` + `conversationId`.
4. Open Socket.IO → send message с `text: '[ACTION:OPERATOR_WALLETS]'` → ждём `new_message` от `isSystem=true` в течение 30с, проверяем markdown содержит ожидаемые поля.
5. `POST /informer-bot/debug/tick` (включён через `INFORMER_DEBUG_TICK=true`) → проверяем что watcher отработал.
6. Откатить флаг: `UPDATE Profile SET informerAccess=false WHERE userId = '<integration_test>'`. Следующий `[ACTION:...]` → 403.

Добавить в `taler_id_tests/package.json`:
```json
"test:informer": "mocha test/informer.test.js --timeout 60000"
```

### 9.3 Обновление CLAUDE.md

В раздел «🧪 ОБЯЗАТЕЛЬНЫЕ ТЕСТЫ ПЕРЕД ДЕПЛОЕМ» добавить пункт 13:

```
### 13. Informer бот (DEV)
cd ~/Downloads/taler_id_tests && npm run test:informer
```

В пост-PROD-секцию: `npm run test:informer:prod`.

## 10. Деплой

### Шаг 1 — DEV (89.169.55.217)

1. PR в `taler-id` ветка `dev` (или `feature/informer-bot`):
   - новый модуль `src/informer-bot/*`
   - Prisma миграции (`informerAccess`, `InformerSeenWallet`, `AI_INFORMER`)
   - расширение `/profile/me` DTO
   - обновление `.env.example`
2. На сервере: добавить ключи в `~/taler-id/.env` (`INFORMER_API_KEY`, `INFORMER_API_SECRET`, остальные с дефолтами).
3. Backend deploy:
   ```
   ssh dvolkov@89.169.55.217
   cd ~/taler-id && git pull && npm install && npx prisma migrate deploy && npm run build && pm2 restart taler-id-dev
   ```
4. SQL: `UPDATE Profile SET informerAccess=true WHERE userId IN (...)` для 4 пользователей (плюс `integration_test@taler-test.com` для тестов).
5. PR в `taler_id_mobile` ветка `dev`:
   - `conversations_screen.dart`, ARB-файлы
   - bump pubspec, например `version: 1.0.75+168`
6. **Обновить `/app/version`** в `~/taler-id/src/app.controller.ts`: `latest.android.dev`, новая запись в `APP_RELEASES`. Передеплоить backend.
7. Smoke-тесты на DEV:
   ```
   cd ~/Downloads/taler_id_tests
   npm test && npm run test:voice && npm run test:assistant && npm run test:files \
     && npm run test:channels && npm run test:billing && npm run test:recording \
     && npm run test:voice-session && npm run test:translator && npm run test:informer
   ```
8. Собрать dev-APK на 138.124.61.221 ветка `dev`, опубликовать как `taler-id-dev.apk`.

### Шаг 2 — PROD (138.124.61.221)

**Только по явной команде «выкатывай на PROD».**

1. Merge `dev → main` в backend → PROD deploy + миграции + SQL для 4 юзеров на PROD-БД.
2. Merge `dev → main` в мобиле → bump `latest.android.prod` и `latest.ios.prod` + новая запись `APP_RELEASES` (флаги prod). Передеплой backend на DEV+PROD.
3. APK prod + iOS prod ipa в TestFlight + release notes на русском через App Store Connect API.
4. `:prod` версии всех тестов.

### Обратимость

- `INFORMER_WATCHER_ENABLED=false` — гасит cron, кнопки работают.
- `INFORMER_API_KEY=` (пусто) — гасит весь модуль; контроллер не регистрируется, `/profile/me` отдаёт `availableBots.informer=false`, мобила тайл не рисует.
- Откат миграций не нужен. Флаг `informerAccess` безвреден, `InformerSeenWallet` пустая.

## 11. Компромиссы дизайна

- **PG для `InformerSeenWallet` вместо Redis** — переживает рестарты бэкенда; Redis-flush не приведёт к лавине дубль-алёртов.
- **Кнопки в чате вместо отдельного меню/команд** — переиспользуем `[ACTION:CODE]`-парсер, который юзеры уже знают по AI Обзвону. Ноль обучения.
- **Один cron на всех 4 юзеров** — 1 запрос/5 мин, дедупликация по таблице. На каждого юзера отдельный polling — избыточно.
- **Cold-start guard через флаг в Redis** — простая подстраховка от лавины при первом старте. 30-дневный TTL покрывает все разумные сценарии.
- **Watcher шлёт каждому юзеру в его персональный чат, а не в один общий канал** — личное сообщение даёт push/бейдж и читается в своём темпе. Минус: координация «кто обработал» не видна между юзерами. Принимаемый риск: их 4, договорятся вне бота.
- **Только русский язык в сообщениях бота** — все 4 юзера русскоговорящие. Локализация — отдельный шаг при необходимости.
- **3 кнопки, не 4** — `operator-required-wallets/count` отдельной кнопкой не нужен; `list`-эндпоинт уже отдаёт `total`. Сводим к одной кнопке.
