# Мессенджер Taler ID для продуктов-партнёров — API

Для разработчиков партнёра (первый — **nadi**): как автоматически заводить своих людей в Taler ID и дать им переписываться в вашем интерфейсе через мессенджер Taler ID.

## Как это устроено

1. **Ваш бэкенд** с ключом партнёра заводит человека в Taler ID (`POST /partner/v1/users`) и переносит вашу «дружбу» в контакты Taler ID (`PUT /partner/v1/contacts/{a}/{b}`).
2. **Ваше приложение** просит токен мессенджера у вашего бэкенда, тот берёт его у Taler ID (`POST /partner/v1/users/{externalId}/token`). Токен живёт 15 минут.
3. С этим токеном приложение само работает с REST `/messenger/*` и Socket.IO `/messenger` Taler ID: личные чаты, группы, файлы, ответы, реакции, прочтения — в реальном времени.
4. Если у получателя не открыт чат, Taler ID присылает на ваш бэкенд подписанный вебхук `message.created`, и вы отправляете пуш своими ключами.

**Ключ партнёра живёт только на вашем сервере.** В приложение, в логи и в репозиторий он не попадает.

## Окружения

| | База | Для чего |
|---|---|---|
| DEV | `https://staging.id.taler.tirol` | разработка и отладка |
| PROD | `https://api.talerid.io` | живые пользователи; партнёрский API — только с IP вашего сервера |

Ключ партнёра и секрет вебхука у каждого окружения свои и передаются вне чатов.

## Ключ партнёра

Каждый запрос к `/partner/v1/*` — с заголовком `Authorization: Bearer tidp_<slug>_<секрет>`.

| Ответ | Когда |
|---|---|
| `401 invalid_partner_key` | ключа нет, формат не тот или ключ не подходит |
| `401 ip_not_allowed` | запрос не с разрешённого IP (список — точные адреса, без масок) |
| `403 partner_disabled` | партнёр выключен |
| `403 partner_api_disabled` | партнёрский API выключен на этом окружении |
| `429 rate_limited` + `retryAfter` | больше 600 выдач токена или 120 прочих запросов в минуту |
| `429 too_many_auth_failures` + `retryAfter` | больше 30 отказов из строк выше с одного адреса за минуту |

У любого `429` в партнёрском API есть заголовок `Retry-After` — столько же секунд, сколько в `retryAfter` тела ответа. Это касается не только двух кодов из таблицы выше, но и `429 too_many_requests` у кода из письма (раздел ниже) — заголовок общий для всего партнёрского API.

Формат ошибок общий для Taler ID: машинный код в поле `message`. В норме `message` — **строка**: так отвечают проверка пути URL (например, `externalId` в `/users/{externalId}/...` — его проверяет `assertExternalId`) и любой отказ, брошенный по ходу дела вручную, например `same_user` у `PUT /contacts/{a}/{b}`. Только у полей, которые проверяет общий `ValidationPipe` (тело или query, размеченные `class-validator`: `POST /users`, `PATCH /users/{externalId}`, `.../link-code/verify`, `DELETE /users/{externalId}?deleteAccount=`), `message` — **массив** кодов, даже если не прошла проверка только одного поля, например `400` с `message: ["invalid_email"]`. Из-за этого один и тот же код приходит в обеих формах: `invalid_external_id` — строкой, если не прошёл `externalId` в URL, и элементом массива, если не прошло поле `externalId` в теле `POST /users`. Коды таких DTO-полей: `invalid_external_id`, `invalid_email`, `invalid_first_name`, `invalid_last_name`, `invalid_locale`, `invalid_code`, `invalid_delete_account`. Проверяйте код так, чтобы работали обе формы: `Array.isArray(m) ? m.includes(code) : m === code`.

Рядом с кодом бывают дополнительные поля (`attemptsLeft`, `retryAfter`, `userIds`). Лишних полей в тело не кладите: неизвестное поле — тоже `400`, но в массиве будет фраза `property <имя> should not exist`, а не код.

## Люди

`externalId` — стабильный id человека у вас (у nadi — id участника): 1–128 символов `[A-Za-z0-9._:-]`, но не только из точек (`.`, `..` и подобные — такое значение запрещено отдельно, даже если по набору символов подходит).

### Завести или привязать — `POST /partner/v1/users`

```bash
curl -X POST https://staging.id.taler.tirol/partner/v1/users \
  -H "Authorization: Bearer $TALERID_PARTNER_KEY" -H 'Content-Type: application/json' \
  -d '{"externalId":"cm1abc","email":"ivan@example.com","firstName":"Іван","lastName":"Петренко","locale":"uk"}'
```

```json
{ "status": "active", "talerUserId": "0b7c3c1e-…", "created": true }
```

| Ответ | Что значит |
|---|---|
| `active`, `created: true` | почта была свободна — аккаунт Taler ID создан |
| `active`, `created: false` | связка уже есть; повтор безопасен |
| `confirmation_required`, `talerUserId: null` | у почты уже есть аккаунт Taler ID — нужен код из письма (ниже) |
| `409 user_linked_to_other_external_id` | этот аккаунт уже привязан к вам под другим `externalId` — снимите старую связку (`DELETE`) |
| `409 email_unavailable` | почта принадлежит аккаунту, заблокированному в Taler ID; завести второй на тот же адрес нельзя |
| `409 email_unverified` | у найденного по почте аккаунта не подтверждена почта — человеку нужно самому войти в Taler ID и подтвердить её (в профиле), затем повторить запрос |
| `503 link_busy` | параллельные запросы про того же человека не разошлись; повторите через секунду |
| `503 revocation_unavailable` | чтобы переиспользовать отозванную связку, Taler ID доотзывает её токены и не достучался до своего хранилища; повторите |

- Почту **вы обязаны проверить сами** до вызова (у nadi это вход по коду): Taler ID помечает её подтверждённой.
- Почта нужна только при первой привязке. Потом человека определяет `externalId`, и смена почты у вас на Taler ID не влияет.
- Писем этот вызов не шлёт — можно спокойно загрузить всех людей разом.
- `locale`: `ru` и `en` сохраняются в профиле Taler ID, остальное (`uk` и т.д.) становится `en`.

### «У вас уже есть аккаунт Taler ID» — код из письма

1. Покажите экран, например: «Ця пошта вже має акаунт Taler ID. Щоб бачити тут ваші чати, підтвердіть: надішлемо код на пошту». Кнопка «Надіслати код».
2. `POST /partner/v1/users/{externalId}/link-code` → `{ "sent": true, "expiresIn": 600 }`.
   - Не чаще раза в минуту и не больше 5 раз в час, иначе `429 too_many_requests` + `retryAfter` (секунды). Плюс общий потолок на вас: 1000 писем и 3000 проверок кода в сутки, ответ тот же.
   - `404 not_linked` — такого `externalId` у вас нет, связка отозвана или аккаунт удалён.
   - `409 not_pending` — связка уже подтверждена или кода не ждёт.
   - `409 email_unverified` — у аккаунта не подтверждена почта; человеку нужно самому войти в Taler ID и подтвердить её (в профиле), затем повторить — письмо с кодом в этом случае не отправляется и ни одно из окон (минута/час/сутки) не тратится.
   - `503 email_send_failed` — письмо не ушло, можно сразу повторить; `503 rate_limiter_unavailable` — лимит сейчас не проверить, повторите через минуту.
3. Человек вводит 6 цифр: `POST /partner/v1/users/{externalId}/link-code/verify` `{"code":"123456"}` → `{ "status": "active", "talerUserId": "…" }`.
   - `404 not_linked` — тот же смысл, что у `/link-code` выше (нет `externalId`, связка отозвана или аккаунт удалён);
   - `409 email_unverified` — то же самое, что у `/link-code` выше; попытка не тратится;
   - `400 invalid_code` + `attemptsLeft` — неверный код;
   - `410 code_expired` — код истёк (10 минут) или сожжён после 5 ошибок: отправьте новый;
   - `429 too_many_requests` + `retryAfter` — ваш суточный потолок проверок; `503 rate_limiter_unavailable` — повторите через минуту.

Письмо приходит от Taler ID на языке аккаунта и прямо говорит, что приложение получит доступ к личным чатам и группам человека.

### Статус — `GET /partner/v1/users/{externalId}`

```json
{ "status": "active", "talerUserId": "…", "managed": true, "linkedAt": "2026-10-01T10:00:00.000Z" }
```

- `status`: `active`, `confirmation_required` или `revoked` (в том числе если человек удалил аккаунт в Taler ID, а вы были к нему допущены); `404 not_linked` — такого `externalId` у вас нет, или связка так и не была подтверждена, а аккаунт удалён, или вы сами отвязали человека до того, как он удалил аккаунт (в том числе своим `DELETE ?deleteAccount=true`).
- `managed: true` — аккаунт создали вы, и человек ни разу не задавал пароль Taler ID. Только такой аккаунт вы можете переименовать и удалить.

### Имя — `PATCH /partner/v1/users/{externalId}`

Тело `{"firstName": "…", "lastName": "…"}`, любое из полей; `null` стирает поле. Только для `managed`, иначе `409 profile_not_managed`; связка не `active` — `404 not_linked`.

### Отвязать — `DELETE /partner/v1/users/{externalId}` → `204`

Все выданные токены гаснут сразу, открытые сокеты рвутся. Аккаунт Taler ID остаётся за человеком.

`?deleteAccount=true` — ещё и удалить аккаунт, для случая «человек удалился у вас и просит стереть данные». Параметр — только `true` или `false`, иначе `400 invalid_delete_account`. Только для `managed`, иначе `409 account_not_managed`, и тогда не меняется ничего. Повтор безопасен: уже удалённый аккаунт второй раз не удаляется, ответ снова `204`.

Если на отзыве Taler ID не достучался до своего хранилища токенов — `503 revocation_unavailable`; повторите запрос, связка останется в прежнем состоянии или будет доотозвана.

### Токен мессенджера — `POST /partner/v1/users/{externalId}/token`

```json
{ "accessToken": "…", "tokenType": "Bearer", "expiresIn": 900, "talerUserId": "…" }
```

| Ответ | Что значит |
|---|---|
| `404 not_linked` | связки нет или она отозвана (в том числе прямо во время этого запроса) |
| `409 confirmation_required` | связка ждёт кода из письма |
| `410 account_deleted` | человек удалил аккаунт в Taler ID или аккаунт заблокирован; связка отозвана. **Не заводите человека заново сами** — только если он снова попросит подключить переписку: он мог удалить аккаунт именно затем, чтобы данных в Taler ID не было |
| `503 link_busy` | редкая гонка параллельных запросов токена; повторите через секунду |
| `503 revocation_unavailable` | аккаунт удалён, а отозвать связку не удалось — хранилище токенов недоступно; повторите |

Refresh-токена нет: истёк — попросите новый.

## Контакты — это ваша «дружба»

Личный чат в Taler ID возможен только между контактами, группа — только из своих контактов. Проверяет это сервер Taler ID, а кто с кем дружит, сообщаете вы.

- `PUT /partner/v1/contacts/{a}/{b}` (оба — `externalId`, порядок не важен) → `{ "contact": true, "created": true }`.
  - `409 blocked` — кто-то из двоих заблокировал другого; блокировку вы не снимаете.
  - `409 link_not_active` — одна из связок не `active`; `400 same_user`.
- `DELETE /partner/v1/contacts/{a}/{b}` → `{ "contact": false }`. Снимается только контакт, который завели вы. Если эти двое были контактами в Taler ID раньше, они ими останутся (`contact: true`). Обе связки должны быть `active`, иначе `409 link_not_active`. Поэтому дружбы снимайте **до** `DELETE /partner/v1/users/{externalId}`: после отзыва связки контакты, которые вы завели, останутся в Taler ID.

Зовите `PUT`, когда дружба принята, и `DELETE`, когда снята. При первом запуске пройдите по уже существующим дружбам.

## Приложение: токен и сокет

- Токен приложение получает у **вашего** бэкенда (вашей авторизацией), держит в памяти до `expiresIn` и берёт новый при `401` от Taler ID.
- Сокет — Socket.IO, namespace `/messenger`, путь `/socket.io`, токен — в `auth.token`:

```dart
import 'package:socket_io_client/socket_io_client.dart' as io;

io.Socket connectMessenger(String baseUrl, String accessToken) {
  final socket = io.io(
    '$baseUrl/messenger',
    io.OptionBuilder()
        .setTransports(['websocket'])
        .setAuth({'token': accessToken})
        .disableAutoConnect()
        .build(),
  );
  socket.connect();
  return socket;
}
```

- Taler ID сам закрывает сокет, когда истекает его токен. На `disconnect` возьмите новый токен и создайте новый сокет.
- Неподходящий токен сервер отключает сразу, без текста ошибки.

## Мессенджер: что доступно

Запросы — с `Authorization: Bearer <accessToken>` к той же базе. Доступны только личные чаты (`DIRECT`) и группы (`GROUP`), всё остальное отвечает `403 not_available_for_partner`.

### REST

| Метод и путь | Что делает |
|---|---|
| `GET /messenger/conversations` | список бесед |
| `POST /messenger/conversations` `{participantId}` | открыть или создать личный чат с контактом; блокировка → `403 blocked`, не контакт (и нет старой беседы) → `403 not_a_contact` |
| `GET /messenger/sync?cursor=&limit=` | новые сообщения во всех беседах; курсор `ISO-время\|id` из прошлого ответа |
| `GET /messenger/conversations/{id}/messages?cursor=&limit=` | история, новые сверху; курсор — id сообщения |
| `GET /messenger/conversations/{id}/media` | общие медиа беседы |
| `GET /messenger/read-state`, `GET /messenger/conversations/{id}/read-state` | прочтения |
| `GET /messenger/messages/{id}/readers` | кто прочитал сообщение |
| `GET /messenger/messages/search?q=` | поиск по своим сообщениям |
| `POST /messenger/conversations/group` `{name, participantIds}` | создать группу; не-контакт → `403 not_a_contact` + `userIds` |
| `GET` / `POST /messenger/conversations/{id}/members` (`{userIds}`) | участники; добавить (только контакты) |
| `DELETE /messenger/conversations/{id}/members/{userId}` | убрать участника |
| `PATCH /messenger/conversations/{id}/members/{userId}/role` | сменить роль |
| `PATCH /messenger/conversations/{id}` | изменить группу |
| `POST /messenger/conversations/{id}/mute`, `/unmute`, `/leave`; `DELETE /messenger/conversations/{id}` | без звука, выйти, удалить группу |
| `POST /messenger/conversations/{id}/forward` `{messageIds}` | переслать в эту беседу |
| `POST` / `DELETE /messenger/conversations/{id}/messages/{messageId}/pin`; `GET` / `DELETE /messenger/conversations/{id}/pinned`; `POST /messenger/conversations/{id}/pinned/dismiss` | закрепы |
| `GET` / `POST /messenger/conversations/{id}/messages/{messageId}/thread` | тред |
| `POST /messenger/files` (multipart, поле `file`, до 100 МБ) | загрузить файл |
| `POST /messenger/files/init`, `/files/chunk`, `/files/complete`; `DELETE /messenger/files/{uploadId}` | загрузка по частям |
| `GET /messenger/files/url?key=` | свежий адрес файла |
| `GET /messenger/link-preview?url=` | превью ссылки |
| `GET /messenger/contacts/check/{userId}` | контакт ли |
| `POST` / `DELETE` / `GET /messenger/contacts/{userId}/block` | заблокировать, снять блокировку, проверить |

Закрыто: запросы в контакты, глобальный поиск людей, звонки, каналы, приглашения по ссылке, опросы, темы, отложенные сообщения, черновик, архив и закреп беседы в списке чатов (не путать с закрепом сообщений — он открыт, см. таблицу выше), расшифровка голосовых сообщений, «Избранное», AI.

### Отправить файл

1. `POST /messenger/files` → `{ fileUrl, fileName, fileSize, fileType, s3Key, thumbnailSmallUrl?, thumbnailMediumUrl?, thumbnailLargeUrl?, fileRecordId }`.
2. Сокет `message` с этими полями и `content` — подписью, она может быть пустой.

### Сокет: от приложения

| Событие | Тело |
|---|---|
| `join` | `{conversationId}` — «этот чат открыт на экране»: события беседы (правки, «печатает…», прочтения) и **никаких вебхуков по нему**, пока сокет не отключится. Делайте `join` только в чат, который сейчас на экране |
| `message` | `{conversationId, content, clientTempId?, replyToId?, silent?, fileUrl?, fileName?, fileSize?, fileType?, s3Key?, thumbnailSmallUrl?, thumbnailMediumUrl?, thumbnailLargeUrl?}` |
| `edit_message` | `{conversationId, messageId, content}` |
| `delete_message` | `{conversationId, messageId, scope}`; `scope` — `self` или `all` |
| `typing` | `{conversationId, isTyping}` |
| `react_message` | `{conversationId, messageId, emoji}` |
| `mark_read` | `{conversationId, upToMessageId?, upToSentAt?}` |
| `thread_reply` | `{conversationId, threadParentId, content}` |

Любое другое событие, id не строкой и беседа или сообщение, которых нет либо которые вам не видны, — ответ `error` `{message: "not_available_for_partner", event}`.

Сокет живёт не дольше токена: в момент истечения сервер его закрывает (`disconnect` с причиной `io server disconnect`). После такого закрытия socket.io-client **сам не переподключается** — получите свежий токен у своего бэкенда, положите его в `socket.auth` и вызовите `socket.connect()`. Так же сокет закрывается при отзыве связки (тогда новый токен не выдадут — `404`/`410` на `/token`).

`clientTempId` — ваш id черновика: повтор с тем же id в течение 24 часов не создаёт дубль, а снова присылает `message_acked`.

### Сокет: от сервера

| Событие | Когда |
|---|---|
| `new_message` | новое сообщение; приходит и без `join` |
| `message_acked` `{clientTempId, messageId}` | ваше сообщение сохранено |
| `message_updated` | правка, «доставлено» |
| `message_deleted`, `message_reaction_updated`, `typing`, `conversation_read` | как в названии |
| `group_created`, `group_member_added`, `group_member_removed`, `group_role_changed`, `group_updated`, `group_deleted` | изменения групп |
| `message_pinned`, `message_unpinned`, `pins_cleared` | закрепы |
| `new_thread_reply` | новый ответ в треде — свой `thread_reply` (сокет) или REST-тред из таблицы выше; это трансляция в саму беседу, не персональная, как `new_message`, — приходит только если вы сделали `join` в эту беседу |
| `conversation_state` | хозяин связки поменял в приложении Taler ID черновик, архив или закреп этого чата в списке — не ваше действие, но видно и вам, если беседа личная или группа |
| `error` `{message}` | отказ — код в `message`, список ниже |

Коды `error.message`: `not_available_for_partner` — событие не из восьми перечисленных выше либо беседа/сообщение не личный чат и не группа; `not_a_participant` — `join` в беседу, где вас нет; на `message` в личный чат — `blocked` (получатель заблокировал отправителя) или `not_a_contact` (вы больше не контакты); `internal_error` — с любого из восьми событий, внутренняя ошибка на стороне Taler ID, подробности только в её логе.

Вместе с `conversation_read` иногда приходит такой же по смыслу легаси-дубль `messages_read` (без `messageIds`) — можно игнорировать.

## Вебхуки

Taler ID шлёт `message.created`, когда у получателя с вашей связкой не открыт этот чат (нет `join` в эту беседу), чат не на «без звука» (упоминание пробивает) и отправитель не пометил сообщение «тихим». Только личные чаты и группы.

«Чат открыт» для сервера — это `join` в беседу с любого сокета человека: вашего или приложения Taler ID. Покинуть комнату без отключения нельзя, поэтому:
- делайте `join` только в чат, который на экране, а не во все чаты сразу — иначе вебхуки по ним не придут вообще;
- уходя в фон, отключайте сокет, иначе чат так и останется «открытым», и пуша человек не получит;
- если человек открывал этот чат в приложении Taler ID в текущем подключении (приложение держит открытыми все чаты, куда заходило, пока не порвётся связь), вебхука тоже не будет: он и так получает сообщения там; то же — если чат открыт через сокет другого партнёра.

```json
{
  "id": "evt_<messageId>_<talerUserId>",
  "type": "message.created",
  "createdAt": "2026-10-01T10:00:00.000Z",
  "recipient":    { "externalId": "cm1abc", "talerUserId": "…" },
  "conversation": { "id": "…", "type": "GROUP", "title": "Толока" },
  "message": {
    "id": "…", "senderTalerUserId": "…", "senderExternalId": "cm1xyz",
    "senderName": "Іван Петренко", "preview": "Збираємося в суботу",
    "kind": "text", "mentionsRecipient": false, "createdAt": "…"
  }
}
```

- `title` — имя группы, для личного чата `null`.
- `senderExternalId` — `null`, если пишет человек не из вашего продукта.
- `kind`: `text`, `image`, `video`, `audio`, `file` или `system`. Для файлов `preview` уже готов: «🖼 Фото», «📎 Файл».
- `preview` — до 200 символов.

Заголовки: `X-TalerID-Event`, `X-TalerID-Delivery` (равен `id`), `X-TalerID-Signature: t=<unix-время>,v1=<hex>`.

**Подпись проверять обязательно и по сырому телу:**

```ts
import { createHmac, timingSafeEqual } from 'crypto';

export function verifyTalerIdWebhook(rawBody: string, header: string | null, secret: string): boolean {
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header ?? '');
  if (!m) return false;
  const t = Number(m[1]);
  if (Math.abs(Date.now() / 1000 - t) > 300) return false; // старше 5 минут — повтор
  const expected = createHmac('sha256', secret).update(`${t}.${rawBody}`).digest();
  const got = Buffer.from(m[2], 'hex');
  return got.length === expected.length && timingSafeEqual(got, expected);
}
```

Next.js (App Router):

```ts
export async function POST(req: Request) {
  const raw = await req.text(); // именно текст: подпись считается по сырому телу
  if (!verifyTalerIdWebhook(raw, req.headers.get('x-talerid-signature'), process.env.TALERID_WEBHOOK_SECRET!)) {
    return new Response(null, { status: 401 });
  }
  const event = JSON.parse(raw);
  // 1) отбросить повтор по event.id; 2) ответить быстро; 3) пуш — после ответа
  return new Response(null, { status: 204 });
}
```

- Ответ `2xx` за 5 секунд — доставлено. Иначе повторы: 10 с → 30 с → 1 мин → 5 мин → 15 мин → 1 ч, потом событие выбрасывается.
- Порядок не гарантирован; повторы отбрасывайте по `id`.
- `POST /partner/v1/webhooks/test` шлёт `ping` и сразу возвращает `{ delivered, status, error?, durationMs }`.
- `GET /partner/v1/webhooks/deliveries?limit=50` — последние попытки: `{ eventId, type, attempt, delivered, status, error, durationMs, at }`.

Адрес вебхука и его секрет заводит Taler ID по вашей просьбе, отдельно для DEV и для PROD.

## Лимиты

- Партнёрский API: 600 выдач токена и 120 прочих запросов в минуту на партнёра; ответ сверх лимита — `429` с `retryAfter` и заголовком `Retry-After`.
- Отказы по ключу (`401`/`403` из раздела «Ключ партнёра»): после 30 за минуту с одного адреса — `429 too_many_auth_failures`. Верный ключ этот счётчик не блокирует.
- Код из письма (раздел «У вас уже есть аккаунт Taler ID»): отправка — не чаще раза в минуту и 5 раз в час на человека; на партнёра в целом — 1000 отправок и 3000 проверок кода в сутки. Тот же `Retry-After`.
- `GET /webhooks/deliveries`: `limit` — от 1 до 200, по умолчанию 50; значение вне диапазона тихо подрезается, а не отвечает ошибкой.
- Мессенджер по токену человека — как у приложения Taler ID: считается по IP устройства.
- `GET /messenger/link-preview`: 60 запросов в минуту на человека (считается по тому, чей токен, не по партнёру); сверх лимита — `400` с обычным текстом `"Too many link previews, slow down"` — это не машинный код и не `429`.
- Файл — до 100 МБ одним запросом, больше — загрузкой по частям.

## Частые вопросы

**Как сопоставить участников бесед с вашими людьми?** Храните пару `externalId ↔ talerUserId` из ответов `POST /users` и `link-code/verify`. В `message.created` есть оба id.

**В беседе человек без `externalId`.** Это пользователь самого Taler ID (приложение Taler ID). Если он в контактах человека, переписка с ним идёт так же.

**Почему в списке только личные чаты и группы?** Партнёрскому токену открыты только они: канал новостей Taler ID, «Избранное» и чаты AI в ваш интерфейс не попадают.

**Будет ли два пуша?** Если у человека установлено ещё и приложение Taler ID — да, уведомят оба приложения.

**Отказ при отправке сообщения или при `POST /messenger/conversations`.** Частая причина обоих — контакт снят: `not_a_contact` (дружбу сняли, или собеседники пока не контакты вовсе) или `blocked` (получатель заблокировал отправителя). Коды — в таблицах выше.

## Для политики конфиденциальности

Предлагаемый текст: «Переписка в Nadi работает на мессенджере Taler ID. Для этого при первом входе мы создаём вам аккаунт Taler ID на вашу почту или, с вашего подтверждения, подключаем существующий. Taler ID хранит ваши сообщения и файлы переписки; мы получаем уведомления о новых сообщениях, чтобы присылать вам пуши.»
