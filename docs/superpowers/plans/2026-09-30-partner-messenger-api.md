# Партнёрский API мессенджера (первый партнёр — nadi) — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Внешний продукт (первым — nadi) автоматически заводит своих людей в TalerID и даёт им переписываться в своём интерфейсе через мессенджер TalerID.

**Architecture:** Два новых модуля. `src/partner-core/` — без HTTP: реестр партнёров, один OAuth-грант со scope `messenger` на каждую связку «партнёр + externalId ↔ пользователь», выпуск/опознание/отзыв токенов, вебхуки через BullMQ. `src/partner-api/` — ручки `/partner/v1/*` под ключом партнёра. Мессенджер получает `MessengerAuthGuard`: собственный токен входа TalerID работает как прежде, партнёрский пускается только в обработчики с `@PartnerAllowed()` и только к личным чатам и группам; в сокете то же делает фильтр пакетов `socket-gate.ts`.

**Tech Stack:** NestJS 11, Prisma 5 (PostgreSQL), oidc-provider 9.6 (Redis-адаптер), BullMQ 5, Socket.IO 4 + Redis-адаптер, Jest 30 + ts-jest; e2e — ts-node-набор в `~/Downloads/taler_id_tests` (axios, socket.io-client).

**Спека:** `docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md`

**Правила для исполнителя:**
- Каждый коммит — с двумя `-m`: сообщение и `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.
- В репозитории есть давно сломанные тесты. Базу снимает Task 0; дальше критерий — «новых падений нет», а не «всё зелёное».
- `tsconfig`: `noImplicitAny` и `strictNullChecks` включены. ts-jest здесь только транспилирует (`isolatedModules`), поэтому ошибки типов в спеках тесты не ловят — типы кода проверяет `npm run build`, и он обязателен в каждой задаче, где меняется `src`. Параметры колбэков в тестах всё равно типизировать явно (`(args: any) => …`), чтобы спеки не расходились со стилем кода.
- С `isolatedModules` + `emitDecoratorMetadata` тип из другого файла в сигнатуре с декоратором параметра (`@Req() req: X`) импортировать через `import type`.
- Ключи и секреты партнёров в вывод не печатать: скрипт администратора пишет их в файл с правами 600 (`--out`), дальше файл передаётся конвейером, минуя экран.
- Выкатка строго DEV → TEST → PROD, каждая — отдельным шагом. PROD и пуш в общие ветки `dev`/`main` — только после явного «да» пользователя.

---

## Отклонения от спеки, найденные при подготовке плана

1. В мессенджере нет REST-ручки «список контактов». Для партнёра открываются `contacts/check/:userId` и ручки блокировки; список друзей nadi знает сам.
2. Звонки и прочие события сокета закрываются не правкой каждого обработчика, а одним фильтром входящих пакетов (`socket-gate.ts`) со списком разрешённых событий. Как и в REST, новое событие для партнёра закрыто, пока его явно не откроют.
3. Код из письма e2e-набор читает через почтовый мост TalerID (`GET /mail/messages` тестового пользователя), а не прямым IMAP: мост сам ходит по IMAP, а набору не нужен пароль ящика.
4. Блокировки, сделанные до выкатки, получат `hadContact=false`, и при их снятии контакт не восстановится. Для старых блокировок неизвестно, были ли люди контактами; безопасный выбор — не выдумывать контакт.
5. Ветка берётся от `origin/main`, а на DEV попадает мёржем в `dev`. Ветки `dev` и `main` на 2026-09-30 отличаются двумя коммитами (переводчик, KYC), наших файлов они не касаются.

### Правки по ревью, уже внесённые в код (задачи 1–4, коммит `d92bcd3`)

Код задач 1–4 отличается от блоков ниже, источник правды — файлы в ветке:
- у `PartnerLink.status` нет умолчания: `ACTIVE` открывает партнёру чаты, статус всегда задаётся явно;
- удаление `Partner` — `Restrict`, а не каскад (удаления партнёров не бывает, выключатель — `enabled=false`);
- у `PartnerContact` есть индекс `(userAId, userBId)`;
- миграция начинается с `SET lock_timeout = '5s'`, а `ALTER` таблицы `BlockedUser` стоит последним;
- `PARTNER_CONVERSATION_TYPES` типизирован через `satisfies readonly ConvType[]`;
- добавлены тесты: неверный мастер-ключ, разные шифртексты одного секрета, границы длины slug, `allowedScopes` у DCR-клиента.

Задачи 6, 8, 16, 20 и шаги выкатки в этом плане уже переписаны по тому же ревью: реальный срок токена, отпечаток ключа секретов в логе, атомарное списание попытки кода, скрипт не трогает чужой OAuth-клиент.

### Правки по ревью ядра (задачи 5–7) — код отличается от блоков ниже

Ревью прогнало ядро на настоящей oidc-provider и нашло, что отзыв связки не всегда гасил её токены (параллельная выдача, смена гранта, гонка с отзывом, сбой Redis), а кэш партнёров рос без предела на неавторизованных запросах. Исправлено, источник правды — файлы в ветке:
- `verify()` принимает токен, только пока жив его грант того же пользователя и клиента, только с `gty` партнёрского API и только формата 43 символа (прочие токены не ходят в Redis);
- грант в связке меняется через compare-and-swap; токен не переживает свой грант; отзыв сначала уничтожает грант, а `grantId` в связке обнуляется только после этого — недоделанный отзыв (REVOKED с грантом) доделывают `revokeAllForUser`, `DELETE` связки и повторная привязка;
- комната сокетов — по связке (`partnerLinkRoom(partnerId, userId)`), а не по гранту;
- реестр партнёров — снимок всей таблицы раз в 30 с;
- `scripts/verify-partner-tokens.cjs` проверяет отзыв на настоящей библиотеке.

Задачи 14, 15, 19, 28, 40 и 44 в этом плане уже приведены в соответствие.

Не взяты, отдельными задачами на потом: allow-list вместо deny-list для scope в DCR и `scopes_supported` в discovery (сейчас `messenger` там виден, но получить его через DCR нельзя); проверка связок партнёра в слиянии дубликатов Linkeon.

### Правки по ревью задач 9–13 — код отличается от блоков ниже

Источник правды для задач 9–13 — файлы в ветке:
- счётчики лимитов — `partner-counter.util.ts`: `INCR`+`EXPIRE` одной транзакцией и ожидание Redis не дольше 250 мс (без этого мёртвый Redis вешал каждый запрос партнёра на ~10 с и отдавал 500). Лимит партнёра без Redis пропускает запрос с предупреждением в лог — так же, как лимит регистрации клиентов в `main.ts`;
- `PartnerKeyGuard` считает свои отказы по IP клиента: после 30 за минуту — `429 too_many_auth_failures`. Глобальные лимиты по IP с этих ручек сняты, а фильтр ошибок пишет строку в лог на каждый 401/403 (на 429 — нет);
- у обоих 429 есть заголовок `Retry-After`; лимит без `req.partner` падает с 500, а не пропускает молча;
- декоратор `@PartnerApi()` (`partner-api.decorator.ts`) задаёт порядок guard'ов и снимает именованные глобальные лимиты — контроллеры ставят его вместо пары `@SkipThrottle`/`@UseGuards`;
- `externalId` из одних точек отклоняется: по URL до него не достучаться;
- поля `partner`/`externalId` в `meta` аудита вызывающий не перетрёт; действия типизированы `PartnerAuditAction`;
- у каждого валидатора DTO — код ошибки. Английской фразой остаётся только лишнее поле (`property X should not exist`): эту ошибку выдаёт глобальный `ValidationPipe`.

Код из письма остался в теме письма, как у `sendOtp`: угроза «код продиктуют злоумышленнику» от места кода в письме не зависит, а e2e читает его оттуда.

### Правки по финальному ревью ветки и ревью безопасности (Task 40)

- Безопасность: привязка существующего аккаунта — только при подтверждённой почте (`409 email_unverified`), в `findOwner`, `link-code` и условной активации.
- Первый пароль на аккаунте, заведённом партнёром, отзывает его связки (защита от «захвата до регистрации»).
- Суточный потолок на создание аккаунтов партнёром (`PARTNER_ACCOUNTS_PER_DAY`, по умолчанию 5000); тестовый партнёр `e2e` на PROD навсегда ограничен адресом бот-сервера, короткий прогон на PROD — оттуда (Task 43).
- `/mcp` не принимает партнёрский токен; блокировка администратором отзывает связки; пересылка с не-массивом — 400; контакты пишутся транзакцией; скрипт требует `--out` для секретов; рассылка не ждёт планирования вебхуков и не читает тип беседы при выключенном API; `link-code` возвращает окна при сбое ключа секретов.
- Повторное ревью: чужой управляемый аккаунт без пароля — тоже `409 email_unverified`; отзыв связок при первом пароле — в той же транзакции, что и пароль, плюс блокировка строки пользователя при управляемой перепривязке; потолок создания не держит слоты отказов; `verify` при битом ключе — 503 с возвратом попытки.
- Найдено, но вне ветки (важно, отдельной задачей): коды подтверждения почты и сброса пароля в `auth.service.ts` не считают попытки и делаются `Math.random()` — перебор ботнетом посилен, а привязка партнёра опирается на эти коды.
- Отложено отдельными задачами: смена почты управляемого аккаунта через партнёрский API; индекс по `lower(email)` (`CREATE INDEX CONCURRENTLY` отдельной миграцией); метрики очереди вебхуков; не подписывать управляемые аккаунты на системный канал.

### Правки по ревью задач 29–35 (вебхуки) — код отличается от блоков ниже

Ревью проверило рассылку и доставку вживую на двух нодах с настоящим BullMQ и https-приёмником: условия «кому и когда» совпали с решением о пуше во всех случаях, подпись сходится, повторы идут по расписанию, выключатели останавливают очередь. Исправлено, источник правды — файлы в ветке:
- `planFanOut` получает тип беседы от шлюза, читает беседу только ради названия группы; `enqueue` не бросает; для «тихих» сообщений план не строится;
- превью режется по графемам без разрыва длинных эмодзи;
- доставка: общий таймаут 5 с (`AbortSignal`), ответ до 64 КБ, без редиректов, свой User-Agent; нерасшифровываемый секрет — запись `secret_unreadable` в журнал и повтор, а не 500; отозванной связке события не доставляются; финальная неудача — строка `warn` для мониторинга;
- задачи удаляются из Redis сразу после завершения (BullMQ 5 чистит по возрасту только при следующем завершении — обещание «час/сутки» не выполнялось);
- тестовый приёмник проверяет подпись по сырому телу и ограничивает размер.

### Правки при подготовке ревью задач 27–28 — код отличается от блоков ниже

В спеке был пробел: партнёрский сокет входил в личную комнату `user:<id>`, куда сервер шлёт всё пользовательское (сообщения «Избранного» и AI, потоковые ответы аналитика, звонки, биллинг) — nadi получал бы скрытые беседы в реальном времени. Исправлено, источник правды — файлы в ветке: партнёрский сокет сидит в `puser:<id>` (`partnerUserRoom`), туда дублирует `emitToUserInConversation` только события личных чатов и групп (новые сообщения и доставка, реакции, прочтения, `conversation_state`, события групп); выселение из комнаты беседы касается обеих комнат; доставка учитывает сокеты обеих комнат. Задача 34 (вебхуки в рассылке) встраивается в тот же `fanOutToParticipants`, где тип беседы теперь уже известен.

### Правки по ревью задач 27–28 (живая проверка на двух нодах)

- Critical: таймер истечения лежал в `socket.data`; Redis-адаптер сериализует `data` в JSON по запросу соседней ноды (`fetchSockets` на каждое сообщение), и циклический `Timeout` ронял процесс — на PROD (две ноды) одно сообщение человеку с открытым nadi клало ноду. Таймер теперь в замыкании с очисткой по `disconnect`, кэш проверенных бесед фильтра — в `WeakMap`. На DEV/TEST (одна нода) это не воспроизводится — поэтому в Task 43 обязателен прогон `test:partner:talerid` и наблюдение за рестартами pm2 на обеих нодах.
- Порядок входа: `plink` → повторная проверка токена → `puser`.
- Фильтр сокета закрыт по умолчанию (id не строкой, несуществующие беседы и сообщения — отказ); «удалено у меня» дублируется в `puser:`; один `emit` на две комнаты.
- Выключение партнёра не рвёт открытые сокеты до истечения токена (≤15 мин) — принято, описано в спеке.

### Правки по ревью задач 24–26 — код отличается от блоков ниже

Ревью безопасности на живом стенде нашло три обхода: партнёрский токен читал «Избранное», чаты AI и системный канал. Причина — `@PartnerAllowed` проверял только id из параметров маршрута. Исправлено, источник правды — файлы в ветке:
- пересылка проверяет тип беседы каждого исходного сообщения (`PartnerConversationScope.assertMessages`);
- `sync` и `searchMessages` принимают типы бесед и фильтруют в самом запросе: курсор синхронизации больше не проходит по скрытым беседам (он отдавал их id и точное время), лимит поиска считается по видимым;
- тред и закреп сообщения проверяют тип и по беседе из маршрута, и по самому сообщению (`getThreadReplies` берёт беседу из родителя, а не из URL).
Разблокировка через токен оставлена открытой — это действие самого человека; формулировка в спеке уточнена.

### Правки по ревью задач 21–23 — код отличается от блоков ниже

Ревью проверило правки на настоящем Postgres и мобильном клиенте: для обычных пользователей регрессий нет, задачи 21–22 закрывают две дыры согласия, открытые сейчас на всех окружениях. Исправлено, источник правды — файлы в ветке:
- время первого отзыва связки пишется вместе со статусом одной транзакцией до обращения к Redis (правка ядра, сделанная перед задачами 21–23, писала его последним — оборванный отзыв терял исходное время, а сбой последней записи оставлял `revokedAt = NULL` навсегда); стенд `verify-partner-tokens.cjs` теперь это проверяет;
- дружба, которую партнёр снял, сбрасывает `hadContact` у блокировок пары;
- список участников канала — только `OWNER`/`ADMIN`; запрос в контакты управляемому аккаунту — нейтральный `403`;
- разблокировка атомарна и при встречной блокировке не восстанавливает контакт, а передаёт память о нём оставшейся блокировке.

### Правки по ревью задач 18–20 — код отличается от блоков ниже

Ревью подняло собранное приложение на временных Postgres, Redis и SMTP и прогнало 131 живую проверку ручек `/partner/v1` и скрипта. Исправлено, источник правды — файлы в ветке:
- удаление аккаунта человеком (задача 19) отзывает связку сразу, но `/token` по-прежнему отвечает `410 account_deleted`, если партнёр был допущен к аккаунту и не отвязал его сам раньше; иначе `404`. GET — `revoked` по тем же правилам. Без этого nadi на `404` молча заводила бы новый аккаунт человеку, который только что удалил свой;
- скрипт открывает файл секрета (600) до изменения базы, отвергает пустой `--out`, `--var` без `--out` и неправильное имя переменной: раньше ошибка пути оставляла партнёра без ключа, а пустой `--out` печатал ключ на экран. IPv6 в белом списке хранится в каноническом виде. `create`/`rotate-key` предупреждают про окно в 30 с;
- `deleteAccount` — DTO `true|false`, иначе `400 invalid_delete_account` (было: `?deleteAccount=1` — тихий `204` без удаления);
- `Retry-After` ставит глобальный фильтр ошибок для любого `429` с `retryAfter` (у `link-code` его не было); при сбое письма возвращается и часовой слот человека;
- в Task 40 добавлен prettier по всем файлам ветки.

Для эксплуатации: выбор `410`/`404` сравнивает `revokedAt` и `deletedAt`; ручная блокировка SQL-ом на сервере не в UTC (`now()` в местном времени) его ломает — блокировать через admin API или писать `now() at time zone 'utc'`. Отзыв не должен переписывать `revokedAt` уже отозванной связки (доделка оборванного отзыва) — правка в партнёрском ядре вместе с задачами 21–23.

Принято без правки: гонка в `revokeAllForUser` (строку связки успели переиспользовать под другой аккаунт — отзывается свежая связка; безопасная сторона, лечится повторным `POST /users`), действия скрипта не пишутся в `AuditLog`.

### Правки по ревью задач 16–17 — код отличается от блоков ниже

Ревью проверило код привязки и контакты на настоящих Redis и Postgres. Ядро кода привязки подтверждено: 20 параллельных проверок дали ровно 5 сравнений. Исправлено, источник правды — файлы в ветке:
- `DELETE /contacts` — только для двух `ACTIVE`-связок: с `PENDING`-связками ответ `{contact}` раскрывал, дружат ли два произвольных аккаунта;
- `createdContact` сверяется на каждом `PUT` (upsert): иначе партнёр не мог снять собственный контакт, заведённый повторно, а гонка двух `PUT` записывала `false`; остаточная неточность описана в спеке;
- суточный потолок партнёра: 1000 выданных кодов и 3000 сравнений — на одну жертву перебор безнадёжен, но утёкший ключ перебирал бы тысячи аккаунтов параллельно (~0,17 взлома в сутки без потолка, с потолком — порядка одного за год, и всё в журнале). Отклонённые запросы и проверки без сравнения потолок не расходуют (иначе цикл повторов клиента выключал привязку всему партнёру на сутки), первое превышение — ошибка в логе;
- окна кода на связку считаются по человеку (`partnerId:userId`): перепривязка под новым `externalId` их не обнуляет;
- флаг контакта при уже существующем контакте пишется `createMany … skipDuplicates` (атомарный `ON CONFLICT DO NOTHING`): эмулированный upsert с пустым `update` давал 500 во второй гонке;
- неудачные и сжёгшие код попытки пишутся в журнал (`PARTNER_LINK_CODE_FAILED`);
- `countInWindow` возвращает срок ключу, оставшемуся без него, вместо вечной блокировки.

### Правки по ревью задач 14–15 — код и схема отличаются от блоков ниже

Ревью прогнало сервис на настоящем Postgres. Источник правды для задач 14–15 и для схемы — файлы в ветке:
- владелец почты ищется `$queryRaw` с `lower(email) = lower($1)`: фильтр Prisma `mode: 'insensitive'` становится `ILIKE`, и `_`/`%` в адресе работали как шаблон (`ivan_petrenko@` находил `ivan.petrenko@`, через отозванную связку — вплоть до захвата без кода);
- аккаунт и связка — одной транзакцией; строка связки переиспользуется и удаляется только в том полностью отозванном виде, в каком прочитана; гонка — до трёх попыток, потом `503 link_busy`;
- «аккаунт завёл партнёр» — `User.createdByPartnerId` вместо `PartnerLink.createdAccount` (строку связки переиспользуют под другой аккаунт, и отметка терялась). Миграция задачи 1 поправлена на месте — она ещё нигде не накатывалась;
- почта заблокированного администратором аккаунта — `409 email_unavailable`, а не 500 на каждый запрос;
- повторный `DELETE ?deleteAccount=true` — снова `204`, без второго удаления; `PATCH` с `null` стирает поле; пустой `PATCH` и повторный отзыв не пишут журнал;
- `PENDING` удалённого аккаунта — `404` (о судьбе чужого аккаунта не сообщаем), `ACTIVE` удалённого — `revoked` в статусе и `410` на токен;
- сбой Redis при отзыве — `503 revocation_unavailable`.

Под это переписаны задачи 23 (фильтр поиска по `createdByPartnerId`), 37 (формулировка `managed`) и 39 (гонки проверяются e2e-набором на настоящей базе: `2g`, `2h`).

Код «письмо не ушло» у `link-code` (задача 16) — `503 email_send_failed`, чтобы не путать с `409 email_unavailable` у `POST /users`. Миграция поправлена на месте, поэтому перед выкаткой на каждое окружение `npx prisma migrate status` должен показывать её как ещё не применённую — иначе Prisma откажется («migration was modified after it was applied»).

При подготовке задачи 17 (контакты) исправлено: одновременные одинаковые PUT не падают на уникальном индексе `ContactRequest`, принимаются все запросы пары, повторный DELETE не падает.

Под это переписаны задачи 16 (лимиты письма с кодом — `countInWindow`: без Redis отказ 503, окно не продлевается отказами), 18 (`@PartnerApi()`), 20 (скрипт отвергает неизвестные флаги и проверяет адреса, `set-ips` требует `--ips` или `--clear`), 37 (ошибки и заголовки в документации), 41–43 (проверка `TRUST_PROXY` и подделки `X-Forwarded-For`).

Замечено попутно, вне этой ветки: guard Linkeon (`src/partner/partner-secret.guard.ts`) берёт первый адрес из `X-Forwarded-For`, который задаёт сам клиент, — его белый список IP подделывается; в `email.service.ts` имя организации, имя пригласившего и причина отказа KYC попадают в HTML без экранирования.

## Структура файлов

**Создать — `src/partner-core/`** (без HTTP; им пользуются мессенджер, профиль и партнёрский API):
- `partner.constants.ts` — scope `messenger`, типы бесед партнёра, имя очереди, комната гранта, `PartnerPrincipal`.
- `partner-key.util.ts` — формат, хэш и сверка ключа партнёра.
- `partner-secrets.util.ts` — мастер-ключ `PARTNER_SECRETS_KEY`, шифр секрета вебхука, HMAC кода привязки.
- `partner-registry.service.ts` — партнёры из БД с кэшем на 30 секунд.
- `partner-tokens.service.ts` — грант на связку; выпуск, отзыв и опознание токенов.
- `partner-realtime.service.ts` — «порвать сокеты гранта»; шлюз регистрирует себя при старте.
- `partner-link-revoker.service.ts` — отзыв связки и всех связок пользователя.
- `partner-webhook-events.ts` — формат событий, подпись, расписание повторов.
- `partner-webhooks.service.ts` — план рассылки, очередь, доставка, журнал.
- `partner-webhooks.processor.ts` — воркер BullMQ.
- `partner-core.module.ts`.

**Создать — `src/partner-api/`** (ручки `/partner/v1/*`):
- `partner-key.guard.ts`, `partner-rate-limit.guard.ts` — ключ и лимиты.
- `partner-audit.service.ts` — записи в `AuditLog`.
- `external-id.util.ts`, `dto/provision-user.dto.ts`, `dto/patch-user.dto.ts`, `dto/verify-link-code.dto.ts`.
- `partner-users.service.ts` — создание и привязка, токен, статус, имя, отзыв, удаление.
- `partner-link-code.service.ts` — код из письма.
- `partner-contacts.service.ts` — контакты по дружбе.
- `partner-webhook-sink.store.ts` — тестовый приёмник вебхуков (только DEV/TEST).
- `partner-api.controller.ts`, `partner-webhook-sink.controller.ts`, `partner-api.module.ts`.

**Создать — мессенджер:**
- `src/messenger/partner-allowed.decorator.ts` — какие обработчики открыты партнёру.
- `src/messenger/partner-conversation-scope.service.ts` — только личные чаты и группы; правило групп.
- `src/messenger/messenger-auth.guard.ts` — два вида токена.
- `src/messenger/socket-gate.ts` — фильтр пакетов сокета.
- `src/messenger/push-text.util.ts` — текст уведомления, общий для пуша и вебхука.

**Изменить:**
- `prisma/schema.prisma` и новая миграция `prisma/migrations/20260930120000_partner_api/migration.sql`.
- `src/oidc/oidc-provider.factory.ts`, `src/oidc/adapters/prisma-client-adapter.ts` — scope `messenger`.
- `src/email/email.service.ts` — письмо с кодом привязки.
- `src/messenger/messenger.service.ts` — два исправления контактов, скрытие из поиска.
- `src/messenger/messenger.controller.ts` — новый guard, allowlist, фильтры списков, правило групп.
- `src/messenger/messenger.gateway.ts` — вход по партнёрскому токену, фильтр пакетов, отключение по сроку, вебхуки в рассылке.
- `src/messenger/messenger.module.ts`, `src/profile/profile.service.ts`, `src/profile/profile.module.ts`, `src/app.module.ts`, `.env.example`.
- Спеки, которые собирают шлюз или `ProfileService`: `src/messenger/messenger.gateway.deliver.spec.ts`, `src/messenger/messenger.gateway.analyst.spec.ts`, `src/profile/profile.service.spec.ts`, `src/profile/profile.service.delete-account.spec.ts`.

**Создать — прочее:**
- `scripts/partner-admin.ts` — выпуск партнёров, ключей, секретов вебхука.
- `docs/partner-messenger-api.md` и `docs/partner-messenger-api/example-client.ts` — для разработчиков nadi.
- `~/Downloads/taler_id_tests/partner_messenger_test.ts` и скрипты `test:partner*` в его `package.json`.

---

## Task 0: Рабочее дерево и база тестов

**Files:** кода не меняет.

- [ ] **Step 1: Создать рабочее дерево от свежего `main`**

```bash
cd /Users/dmitry/taler-id
git fetch origin
git check-ignore -q .worktrees && echo "worktrees ignored: ok"
git worktree add .worktrees/partner-messenger-api -b feat/partner-messenger-api origin/main
cd .worktrees/partner-messenger-api
npm ci
```

Expected: `worktrees ignored: ok`, рабочее дерево создано, `npm ci` без ошибок.

- [ ] **Step 2: Перенести спеку и план в ветку и убрать их из основного клона**

Сейчас оба файла лежат в основном клоне неотслеживаемыми. Если их там оставить, следующий `git pull` в основном клоне после мёржа упадёт на «untracked working tree files would be overwritten».

```bash
cd /Users/dmitry/taler-id/.worktrees/partner-messenger-api
cp /Users/dmitry/taler-id/docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md docs/superpowers/specs/
cp /Users/dmitry/taler-id/docs/superpowers/plans/2026-09-30-partner-messenger-api.md docs/superpowers/plans/
git add docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md docs/superpowers/plans/2026-09-30-partner-messenger-api.md
git commit -m "docs: спека и план партнёрского API мессенджера (nadi)" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
rm /Users/dmitry/taler-id/docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md \
   /Users/dmitry/taler-id/docs/superpowers/plans/2026-09-30-partner-messenger-api.md
git -C /Users/dmitry/taler-id status --short | grep partner-messenger || echo "main clone clean: ok"
```

Expected: коммит создан, последняя строка — `main clone clean: ok`.

- [ ] **Step 3: Снять базу тестов**

```bash
cd /Users/dmitry/taler-id/.worktrees/partner-messenger-api
npx jest 2>&1 | grep -E "^(FAIL|Tests:|Test Suites:)" | sort -u > ../partner-baseline.txt
cat ../partner-baseline.txt
```

Expected: список уже падающих наборов (`FAIL …`) и итоговые строки. Файл `../partner-baseline.txt` лежит в `.worktrees/`, в git не попадает. Во всех следующих задачах «новых падений нет» значит: `FAIL`-строки вне этого списка не появились.

---

## Task 1: Схема Prisma и миграция

> ⚠️ Блоки кода этой задачи — исторические. Источник правды — `prisma/schema.prisma` и миграция в ветке: после ревью у связки нет `createdAccount`, а у `User` есть `createdByPartnerId` (см. «Правки по ревью задач 14–15» в начале плана).

**Files:**
- Modify: `prisma/schema.prisma` (модели `User`, `BlockedUser`; новые `PartnerLinkStatus`, `Partner`, `PartnerLink`, `PartnerContact` в конце файла)
- Create: `prisma/migrations/20260930120000_partner_api/migration.sql`

- [ ] **Step 1: Связь пользователя со связками**

В `model User` после строки `mailAccount          MailAccount?` добавить:

```prisma
  /// Связки с продуктами-партнёрами (nadi): кто и под каким id завёл или
  /// привязал этого человека. Спека: 2026-09-30-partner-messenger-api-design.md
  partnerLinks         PartnerLink[]
```

- [ ] **Step 2: Флаг «были контактами» у блокировки**

В `model BlockedUser` после строки `createdAt DateTime @default(now())` добавить:

```prisma
  /// Были ли люди контактами в момент блокировки. Разблокировка возвращает
  /// только такой контакт — иначе блок и разблок делали контактами кого угодно.
  hadContact Boolean  @default(false)
```

- [ ] **Step 3: Новые модели в конец `prisma/schema.prisma`**

```prisma
enum PartnerLinkStatus {
  PENDING
  ACTIVE
  REVOKED
}

/// Внешний продукт, который заводит своих людей в TalerID и пускает их в
/// мессенджер (первый — nadi). Ключ хранится только хэшем, секрет вебхука —
/// зашифрованным (PARTNER_SECRETS_KEY).
/// Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
model Partner {
  id               String           @id @default(uuid())
  slug             String           @unique
  /// Так партнёр называется в письмах людям.
  name             String
  keyHash          String
  ipAllowlist      String[]         @default([])
  webhookUrl       String?
  webhookSecretEnc String?
  /// OAuth-клиент `<slug>-partner`, от имени которого выпускаются токены.
  oauthClientId    String           @unique
  enabled          Boolean          @default(true)
  createdAt        DateTime         @default(now())
  updatedAt        DateTime         @updatedAt
  links            PartnerLink[]
  contacts         PartnerContact[]
}

/// «Партнёр + externalId ↔ пользователь TalerID». PENDING — ждёт кода из
/// письма (почта принадлежала чужому аккаунту), ACTIVE — партнёр может
/// выпускать токены, REVOKED — отозвана.
model PartnerLink {
  id             String            @id @default(uuid())
  partnerId      String
  externalId     String
  userId         String
  status         PartnerLinkStatus @default(ACTIVE)
  /// Аккаунт создал сам партнёр (а не привязал существующий).
  createdAccount Boolean           @default(false)
  /// Грант OIDC: по нему отзываются сразу все токены связки.
  grantId        String?
  codeHash       String?
  codeExpiresAt  DateTime?
  codeAttempts   Int               @default(0)
  activatedAt    DateTime?
  revokedAt      DateTime?
  createdAt      DateTime          @default(now())
  updatedAt      DateTime          @updatedAt
  partner        Partner           @relation(fields: [partnerId], references: [id], onDelete: Cascade)
  user           User              @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([partnerId, externalId])
  @@unique([partnerId, userId])
  @@index([userId, status])
}

/// Контакт, который завёл партнёр по своей «дружбе». createdContact=false —
/// люди были контактами в TalerID ещё до партнёра, и снимать такой контакт
/// партнёр не вправе. userAId < userBId.
model PartnerContact {
  id             String   @id @default(uuid())
  partnerId      String
  userAId        String
  userBId        String
  createdContact Boolean
  createdAt      DateTime @default(now())
  partner        Partner  @relation(fields: [partnerId], references: [id], onDelete: Cascade)

  @@unique([partnerId, userAId, userBId])
}
```

- [ ] **Step 4: Миграция**

Создать `prisma/migrations/20260930120000_partner_api/migration.sql`:

```sql
-- Партнёрский API мессенджера (первый партнёр — nadi).
-- Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
--
-- Всё аддитивно: новые таблицы и колонка с дефолтом. Старый код продолжает
-- работать поверх этой схемы, поэтому миграцию можно накатить до рестарта нод.

-- CreateEnum
CREATE TYPE "PartnerLinkStatus" AS ENUM ('PENDING', 'ACTIVE', 'REVOKED');

-- CreateTable
CREATE TABLE "Partner" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "ipAllowlist" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "webhookUrl" TEXT,
    "webhookSecretEnc" TEXT,
    "oauthClientId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Partner_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PartnerLink" (
    "id" TEXT NOT NULL,
    "partnerId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" "PartnerLinkStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAccount" BOOLEAN NOT NULL DEFAULT false,
    "grantId" TEXT,
    "codeHash" TEXT,
    "codeExpiresAt" TIMESTAMP(3),
    "codeAttempts" INTEGER NOT NULL DEFAULT 0,
    "activatedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PartnerLink_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PartnerContact" (
    "id" TEXT NOT NULL,
    "partnerId" TEXT NOT NULL,
    "userAId" TEXT NOT NULL,
    "userBId" TEXT NOT NULL,
    "createdContact" BOOLEAN NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PartnerContact_pkey" PRIMARY KEY ("id")
);

-- Блокировки, сделанные до этой миграции, получают false: неизвестно, были ли
-- люди контактами, и безопаснее не восстанавливать контакт при разблокировке.
ALTER TABLE "BlockedUser" ADD COLUMN "hadContact" BOOLEAN NOT NULL DEFAULT false;

-- CreateIndex
CREATE UNIQUE INDEX "Partner_slug_key" ON "Partner"("slug");
CREATE UNIQUE INDEX "Partner_oauthClientId_key" ON "Partner"("oauthClientId");
CREATE UNIQUE INDEX "PartnerLink_partnerId_externalId_key" ON "PartnerLink"("partnerId", "externalId");
CREATE UNIQUE INDEX "PartnerLink_partnerId_userId_key" ON "PartnerLink"("partnerId", "userId");
CREATE INDEX "PartnerLink_userId_status_idx" ON "PartnerLink"("userId", "status");
CREATE UNIQUE INDEX "PartnerContact_partnerId_userAId_userBId_key" ON "PartnerContact"("partnerId", "userAId", "userBId");

-- AddForeignKey
ALTER TABLE "PartnerLink" ADD CONSTRAINT "PartnerLink_partnerId_fkey" FOREIGN KEY ("partnerId") REFERENCES "Partner"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PartnerLink" ADD CONSTRAINT "PartnerLink_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "PartnerContact" ADD CONSTRAINT "PartnerContact_partnerId_fkey" FOREIGN KEY ("partnerId") REFERENCES "Partner"("id") ON DELETE CASCADE ON UPDATE CASCADE;
```

- [ ] **Step 5: Проверить схему и сгенерировать клиент**

```bash
DATABASE_URL=postgresql://u:p@localhost:5432/x npx prisma validate
npx prisma generate
npm run build
```

Expected: `The schema at prisma/schema.prisma is valid`, `Generated Prisma Client`, сборка без ошибок. Локальной БД нет — переменная в `validate` нужна только, чтобы Prisma не споткнулся о `env("DATABASE_URL")`. Саму миграцию проверит DEV в Task 41 (`prisma migrate status` → `deploy`).

- [ ] **Step 6: Commit**

```bash
git add prisma/schema.prisma prisma/migrations/20260930120000_partner_api/migration.sql
git commit -m "feat(partner): схема связок партнёров, их контактов и флаг hadContact у блокировки" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Константы и ключ партнёра

**Files:**
- Create: `src/partner-core/partner.constants.ts`
- Create: `src/partner-core/partner-key.util.ts`
- Test: `src/partner-core/partner-key.util.spec.ts`

- [ ] **Step 1: Константы**

Создать `src/partner-core/partner.constants.ts`:

```ts
/**
 * Партнёрский API мессенджера: общие константы.
 * Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 */

/** Scope токенов партнёра. Мессенджер принимает его вместо токена входа TalerID. */
export const MESSENGER_SCOPE = 'messenger';

/** Какие беседы видит и может трогать партнёрский токен. */
export const PARTNER_CONVERSATION_TYPES = ['DIRECT', 'GROUP'] as const;

export function isPartnerConversationType(type: string | null | undefined): boolean {
  return (PARTNER_CONVERSATION_TYPES as readonly string[]).includes(type ?? '');
}

/** Совпадает с ttl.AccessToken в oidc-provider.factory.ts. */
export const PARTNER_ACCESS_TOKEN_TTL_SECONDS = 900;

export const PARTNER_WEBHOOK_QUEUE = 'partner-webhooks';

/** Текст отказа, когда партнёрский токен пришёл туда, куда ему нельзя. */
export const PARTNER_FORBIDDEN = 'not_available_for_partner';

/** Комната Socket.IO со всеми сокетами одного гранта: так отзыв рвёт их разом. */
export function partnerGrantRoom(grantId: string): string {
  return `pgrant:${grantId}`;
}

/** Кто стоит за партнёрским токеном. */
export interface PartnerPrincipal {
  userId: string;
  partnerId: string;
  partnerSlug: string;
  grantId: string;
  /** Когда токен истекает, unix-секунды. */
  expiresAt: number;
}

/** Пришёл ли запрос мессенджера по партнёрскому токену (см. MessengerAuthGuard). */
export function isPartnerCaller(user: unknown): user is { sub: string; partner: PartnerPrincipal } {
  return !!(user as { partner?: unknown } | null | undefined)?.partner;
}
```

- [ ] **Step 2: Написать падающий тест ключа**

Создать `src/partner-core/partner-key.util.spec.ts`:

```ts
import {
  generatePartnerKey,
  hashPartnerKey,
  parsePartnerKey,
  partnerKeyMatches,
} from './partner-key.util';

describe('partner key', () => {
  it('generates tidp_<slug>_<secret> and parses the slug back', () => {
    const key = generatePartnerKey('nadi');
    expect(key).toMatch(/^tidp_nadi_[A-Za-z0-9_-]{43}$/);
    expect(parsePartnerKey(key)).toEqual({ slug: 'nadi' });
  });

  it('takes the slug up to the first underscore even if the secret has underscores', () => {
    expect(parsePartnerKey('tidp_nadi_abc_def_ghi_jkl_mno_pqr_stu_vwx_yz0123')).toEqual({ slug: 'nadi' });
  });

  it.each(['', 'nadi_x', 'tidp_', 'tidp__secret', `tidp_NADI_${'a'.repeat(43)}`, 'tidp_nadi_short'])(
    'rejects malformed key %p',
    (key: string) => {
      expect(parsePartnerKey(key)).toBeNull();
    },
  );

  it('matches only the exact key', () => {
    const key = generatePartnerKey('nadi');
    const hash = hashPartnerKey(key);
    expect(partnerKeyMatches(key, hash)).toBe(true);
    expect(partnerKeyMatches(`${key}x`, hash)).toBe(false);
    expect(partnerKeyMatches(key, 'not-hex')).toBe(false);
  });

  it('refuses to generate a key for an invalid slug', () => {
    expect(() => generatePartnerKey('Bad_Slug')).toThrow('invalid partner slug');
  });
});
```

- [ ] **Step 3: Убедиться, что тест падает**

Run: `npx jest src/partner-core/partner-key.util.spec.ts`
Expected: FAIL — `Cannot find module './partner-key.util'`.

- [ ] **Step 4: Реализация**

Создать `src/partner-core/partner-key.util.ts`:

```ts
import { createHash, randomBytes, timingSafeEqual } from 'crypto';

const KEY_PREFIX = 'tidp_';
const SLUG_RE = /^[a-z0-9-]{2,32}$/;
/** 32 случайных байта в base64url — 43 символа; меньше 32 точно не наш ключ. */
const MIN_SECRET_LENGTH = 32;

export function isValidPartnerSlug(slug: string): boolean {
  return SLUG_RE.test(slug);
}

/**
 * Новый ключ партнёра: `tidp_<slug>_<256 бит в base64url>`. Показывается один
 * раз при выпуске, в БД остаётся только хэш. В slug нет подчёркиваний, поэтому
 * первое подчёркивание после префикса однозначно отделяет его от секрета.
 */
export function generatePartnerKey(slug: string): string {
  if (!isValidPartnerSlug(slug)) throw new Error(`invalid partner slug: ${slug}`);
  return `${KEY_PREFIX}${slug}_${randomBytes(32).toString('base64url')}`;
}

/** Достаёт slug из ключа. null — ключ не нашего формата. */
export function parsePartnerKey(key: string): { slug: string } | null {
  if (typeof key !== 'string' || !key.startsWith(KEY_PREFIX)) return null;
  const rest = key.slice(KEY_PREFIX.length);
  const sep = rest.indexOf('_');
  if (sep <= 0) return null;
  const slug = rest.slice(0, sep);
  const secret = rest.slice(sep + 1);
  if (!isValidPartnerSlug(slug) || secret.length < MIN_SECRET_LENGTH) return null;
  return { slug };
}

export function hashPartnerKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

/** Сверка за постоянное время: хэши одной длины по построению. */
export function partnerKeyMatches(key: string, storedHash: string): boolean {
  const a = Buffer.from(hashPartnerKey(key), 'hex');
  const b = Buffer.from(storedHash ?? '', 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
```

- [ ] **Step 5: Тест проходит**

Run: `npx jest src/partner-core/partner-key.util.spec.ts`
Expected: PASS, 10 тестов.

- [ ] **Step 6: Commit**

```bash
git add src/partner-core/partner.constants.ts src/partner-core/partner-key.util.ts src/partner-core/partner-key.util.spec.ts
git commit -m "feat(partner): константы и ключ партнёра" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Секреты партнёров

**Files:**
- Create: `src/partner-core/partner-secrets.util.ts`
- Test: `src/partner-core/partner-secrets.util.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-core/partner-secrets.util.spec.ts`:

```ts
import {
  decryptWebhookSecret,
  encryptWebhookSecret,
  generateWebhookSecret,
  hashLinkCode,
  linkCodeMatches,
} from './partner-secrets.util';

const saved = process.env.PARTNER_SECRETS_KEY;

describe('partner secrets', () => {
  beforeEach(() => {
    process.env.PARTNER_SECRETS_KEY = 'a'.repeat(64);
  });
  afterAll(() => {
    if (saved === undefined) delete process.env.PARTNER_SECRETS_KEY;
    else process.env.PARTNER_SECRETS_KEY = saved;
  });

  it('encrypts and decrypts the webhook secret', () => {
    const secret = generateWebhookSecret();
    expect(secret).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    const enc = encryptWebhookSecret(secret);
    expect(enc).not.toContain(secret);
    expect(decryptWebhookSecret(enc)).toBe(secret);
  });

  it('binds the link-code hash to the link', () => {
    const hash = hashLinkCode('link-1', '123456');
    expect(linkCodeMatches('link-1', '123456', hash)).toBe(true);
    expect(linkCodeMatches('link-2', '123456', hash)).toBe(false);
    expect(linkCodeMatches('link-1', '654321', hash)).toBe(false);
    expect(linkCodeMatches('link-1', '123456', '')).toBe(false);
  });

  it('fails closed without a proper master key', () => {
    process.env.PARTNER_SECRETS_KEY = 'short';
    expect(() => hashLinkCode('l', '1')).toThrow('PARTNER_SECRETS_KEY');
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-core/partner-secrets.util.spec.ts`
Expected: FAIL — `Cannot find module './partner-secrets.util'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-core/partner-secrets.util.ts`:

```ts
import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { decryptSecret, encryptSecret } from '../mail/mail-crypto';

/**
 * Мастер-ключ партнёрских секретов: 64 hex-символа (`openssl rand -hex 32`).
 * На всех нодах окружения он обязан совпадать — секрет вебхука, зашифрованный
 * на одной ноде, расшифровывает воркер очереди на любой другой.
 */
function masterKey(): Buffer {
  const hex = process.env.PARTNER_SECRETS_KEY ?? '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('PARTNER_SECRETS_KEY must be 64 hex chars (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
}

/** Отдельный подключ на каждое назначение: один ключ не служит и шифром, и HMAC. */
function derive(label: string): Buffer {
  return createHmac('sha256', masterKey()).update(label).digest();
}

export function generateWebhookSecret(): string {
  return `whsec_${randomBytes(32).toString('base64url')}`;
}

export function encryptWebhookSecret(secret: string): string {
  return encryptSecret(secret, derive('webhook-secret').toString('hex'));
}

export function decryptWebhookSecret(payload: string): string {
  return decryptSecret(payload, derive('webhook-secret').toString('hex'));
}

/** Код привязки храним только как HMAC, привязанный к конкретной связке. */
export function hashLinkCode(linkId: string, code: string): string {
  return createHmac('sha256', derive('link-code')).update(`${linkId}:${code}`).digest('hex');
}

export function linkCodeMatches(linkId: string, code: string, storedHash: string): boolean {
  const a = Buffer.from(hashLinkCode(linkId, code), 'hex');
  const b = Buffer.from(storedHash ?? '', 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-core/partner-secrets.util.spec.ts`
Expected: PASS, 3 теста.

- [ ] **Step 5: Commit**

```bash
git add src/partner-core/partner-secrets.util.ts src/partner-core/partner-secrets.util.spec.ts
git commit -m "feat(partner): шифр секрета вебхука и HMAC кода привязки" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Scope `messenger` в OIDC

**Files:**
- Modify: `src/oidc/oidc-provider.factory.ts` (импорты; массив `scopes`)
- Modify: `src/oidc/adapters/prisma-client-adapter.ts` (метод `upsert`, фильтр scope)
- Test: `src/oidc/adapters/prisma-client-adapter.spec.ts`

- [ ] **Step 1: Написать падающий тест**

В `src/oidc/adapters/prisma-client-adapter.spec.ts` внутри `describe('PrismaClientAdapter DCR', …)` после теста `'upsert stores dynamic client and strips offline_access from scope'` добавить:

```ts
  it('upsert strips the partner-only messenger scope from dynamic clients', async () => {
    // Токен со scope messenger пускает в чужие переписки. Выдавать его может
    // только партнёрский API, а не любой, кто зарегистрировался через DCR.
    prisma.oAuthClient.findUnique.mockResolvedValue(null);
    await adapter.upsert('dyn-client-2', {
      client_name: 'Someone',
      redirect_uris: ['https://example.com/cb'],
      token_endpoint_auth_method: 'none',
      scope: 'openid messenger mcp:calendar',
    }, 0);
    const createCall = prisma.oAuthClient.create.mock.calls[0][0];
    expect(createCall.data.dcrMetadata.scope).toBe('openid mcp:calendar');
  });
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/oidc/adapters/prisma-client-adapter.spec.ts`
Expected: FAIL — `Expected: "openid mcp:calendar"`, `Received: "openid messenger mcp:calendar"`.

- [ ] **Step 3: Отрезать scope в DCR**

В `src/oidc/adapters/prisma-client-adapter.ts`:
- после строки `import type { PrismaService } from '../../prisma/prisma.service';` добавить `import { MESSENGER_SCOPE } from '../../partner-core/partner.constants';`;
- в `upsert` заменить `.filter((s) => s && s !== 'offline_access')` на:

```ts
      // offline_access — только для проверенных партнёров, messenger — только
      // для партнёрского API: через открытую регистрацию их не получить.
      .filter((s) => s && s !== 'offline_access' && s !== MESSENGER_SCOPE)
```

- [ ] **Step 4: Объявить scope провайдеру**

В `src/oidc/oidc-provider.factory.ts` после `import { MCP_SCOPES } from '../mcp/mcp.constants';` добавить:

```ts
import { MESSENGER_SCOPE } from '../partner-core/partner.constants';
```

В массиве `scopes: [ … ]` после `...MCP_SCOPES,` добавить:

```ts
      // Токены партнёров (nadi): выпускаются только партнёрским API на сервере,
      // через consent-экран и DCR не выдаются (см. prisma-client-adapter).
      MESSENGER_SCOPE,
```

- [ ] **Step 5: Тесты и сборка**

Run: `npx jest src/oidc && npm run build`
Expected: PASS, сборка без ошибок.

- [ ] **Step 6: Commit**

```bash
git add src/oidc/oidc-provider.factory.ts src/oidc/adapters/prisma-client-adapter.ts src/oidc/adapters/prisma-client-adapter.spec.ts
git commit -m "feat(oidc): scope messenger для партнёров, закрытый для DCR" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Реестр партнёров

**Files:**
- Create: `src/partner-core/partner-registry.service.ts`
- Test: `src/partner-core/partner-registry.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-core/partner-registry.service.spec.ts`:

```ts
import { PartnerRegistryService } from './partner-registry.service';

const partner = {
  id: 'p1',
  slug: 'nadi',
  name: 'Nadi',
  keyHash: 'h',
  ipAllowlist: [],
  webhookUrl: null,
  webhookSecretEnc: null,
  oauthClientId: 'nadi-partner',
  enabled: true,
};

describe('PartnerRegistryService', () => {
  let prisma: any;
  let registry: PartnerRegistryService;

  beforeEach(() => {
    jest.useFakeTimers({ now: new Date('2026-10-01T10:00:00Z') });
    prisma = { partner: { findUnique: jest.fn().mockResolvedValue(partner) } };
    registry = new PartnerRegistryService(prisma);
  });
  afterEach(() => jest.useRealTimers());

  it('caches lookups by slug for 30 seconds', async () => {
    await registry.findBySlug('nadi');
    await registry.findBySlug('nadi');
    expect(prisma.partner.findUnique).toHaveBeenCalledTimes(1);
    jest.setSystemTime(new Date('2026-10-01T10:00:31Z'));
    await registry.findBySlug('nadi');
    expect(prisma.partner.findUnique).toHaveBeenCalledTimes(2);
  });

  it('looks partners up by OAuth client id', async () => {
    await expect(registry.findByClientId('nadi-partner')).resolves.toEqual(partner);
    expect(prisma.partner.findUnique).toHaveBeenCalledWith({ where: { oauthClientId: 'nadi-partner' } });
  });

  it('caches misses too', async () => {
    prisma.partner.findUnique.mockResolvedValue(null);
    await registry.findBySlug('ghost');
    await registry.findBySlug('ghost');
    expect(prisma.partner.findUnique).toHaveBeenCalledTimes(1);
  });

  it('reads by id straight from the database', async () => {
    await registry.findById('p1');
    await registry.findById('p1');
    expect(prisma.partner.findUnique).toHaveBeenCalledTimes(2);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-core/partner-registry.service.spec.ts`
Expected: FAIL — `Cannot find module './partner-registry.service'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-core/partner-registry.service.ts`:

```ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface PartnerRecord {
  id: string;
  slug: string;
  name: string;
  keyHash: string;
  ipAllowlist: string[];
  webhookUrl: string | null;
  webhookSecretEnc: string | null;
  oauthClientId: string;
  enabled: boolean;
}

const CACHE_TTL_MS = 30_000;

type Cache = Map<string, { at: number; value: PartnerRecord | null }>;

/**
 * Партнёры читаются на каждый запрос партнёрского API и на каждый запрос
 * мессенджера по партнёрскому токену, а меняются раз в месяцы. Поэтому кэш на
 * 30 секунд: выключение партнёра или смена ключа доходят за это время.
 */
@Injectable()
export class PartnerRegistryService {
  private readonly bySlug: Cache = new Map();
  private readonly byClient: Cache = new Map();

  constructor(private readonly prisma: PrismaService) {}

  findBySlug(slug: string): Promise<PartnerRecord | null> {
    return this.cached(this.bySlug, slug, () => this.prisma.partner.findUnique({ where: { slug } }));
  }

  findByClientId(clientId: string): Promise<PartnerRecord | null> {
    return this.cached(this.byClient, clientId, () =>
      this.prisma.partner.findUnique({ where: { oauthClientId: clientId } }),
    );
  }

  /** Без кэша: воркер вебхуков должен видеть свежий адрес и секрет. */
  findById(id: string): Promise<PartnerRecord | null> {
    return this.prisma.partner.findUnique({ where: { id } });
  }

  private async cached(
    cache: Cache,
    key: string,
    load: () => Promise<PartnerRecord | null>,
  ): Promise<PartnerRecord | null> {
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;
    const value = (await load()) ?? null;
    cache.set(key, { at: Date.now(), value });
    return value;
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-core/partner-registry.service.spec.ts`
Expected: PASS, 4 теста.

- [ ] **Step 5: Commit**

```bash
git add src/partner-core/partner-registry.service.ts src/partner-core/partner-registry.service.spec.ts
git commit -m "feat(partner): реестр партнёров с кэшем на 30 секунд" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Токены партнёра

**Files:**
- Create: `src/partner-core/partner-tokens.service.ts`
- Test: `src/partner-core/partner-tokens.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-core/partner-tokens.service.spec.ts`:

```ts
import { ServiceUnavailableException } from '@nestjs/common';
import { PartnerTokensService } from './partner-tokens.service';

function makeProvider() {
  const grants: any[] = [];
  const Grant: any = jest.fn().mockImplementation((args: any) => {
    const grant = { args, addOIDCScope: jest.fn(), save: jest.fn().mockResolvedValue('grant-new') };
    grants.push(grant);
    return grant;
  });
  Grant.find = jest.fn();
  const AccessToken: any = jest.fn().mockImplementation((args: any) => ({
    args,
    save: jest.fn().mockResolvedValue('at-opaque'),
  }));
  AccessToken.find = jest.fn();
  AccessToken.adapter = { revokeByGrantId: jest.fn().mockResolvedValue(undefined) };
  const Client = { find: jest.fn().mockResolvedValue({ clientId: 'nadi-partner' }) };
  return { provider: { Grant, AccessToken, Client } as any, grants };
}

const partner: any = { id: 'p1', slug: 'nadi', oauthClientId: 'nadi-partner', enabled: true };
const saved = process.env.PARTNER_API_ENABLED;

describe('PartnerTokensService', () => {
  let provider: any;
  let grants: any[];
  let prisma: any;
  let registry: any;
  let service: PartnerTokensService;

  beforeEach(() => {
    process.env.PARTNER_API_ENABLED = 'true';
    ({ provider, grants } = makeProvider());
    prisma = { partnerLink: { update: jest.fn().mockResolvedValue({}) } };
    registry = { findByClientId: jest.fn().mockResolvedValue(partner) };
    service = new PartnerTokensService(provider, prisma, registry);
  });
  afterAll(() => {
    if (saved === undefined) delete process.env.PARTNER_API_ENABLED;
    else process.env.PARTNER_API_ENABLED = saved;
  });

  describe('issueAccessToken', () => {
    it('reuses a live grant', async () => {
      provider.Grant.find.mockResolvedValue({ jti: 'grant-1' });
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(res).toEqual({ accessToken: 'at-opaque', expiresIn: 900, grantId: 'grant-1' });
      expect(provider.Grant).not.toHaveBeenCalled();
      expect(provider.AccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ accountId: 'u1', grantId: 'grant-1', scope: 'messenger' }),
      );
      expect(prisma.partnerLink.update).not.toHaveBeenCalled();
    });

    it('creates and stores a new grant when the old one expired', async () => {
      provider.Grant.find.mockResolvedValue(undefined);
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-old' }, partner);
      expect(res.grantId).toBe('grant-new');
      expect(grants[0].args).toEqual({ accountId: 'u1', clientId: 'nadi-partner' });
      expect(grants[0].addOIDCScope).toHaveBeenCalledWith('messenger');
      expect(prisma.partnerLink.update).toHaveBeenCalledWith({ where: { id: 'l1' }, data: { grantId: 'grant-new' } });
    });

    it('creates a grant for a link that never had one', async () => {
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: null }, partner);
      expect(provider.Grant.find).not.toHaveBeenCalled();
      expect(res.grantId).toBe('grant-new');
    });

    it('reports the TTL the provider actually gave the token', async () => {
      provider.Grant.find.mockResolvedValue({ jti: 'grant-1' });
      provider.AccessToken.mockImplementationOnce((args: any) => ({
        args,
        expiration: 600,
        save: jest.fn().mockResolvedValue('at-short'),
      }));
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(res).toEqual({ accessToken: 'at-short', expiresIn: 600, grantId: 'grant-1' });
    });
  });

  describe('revokeGrant', () => {
    it('revokes the tokens and destroys the grant', async () => {
      const destroy = jest.fn();
      provider.Grant.find.mockResolvedValue({ destroy });
      await service.revokeGrant('grant-1');
      expect(provider.AccessToken.adapter.revokeByGrantId).toHaveBeenCalledWith('grant-1');
      expect(destroy).toHaveBeenCalled();
    });
  });

  describe('verify', () => {
    const token = {
      accountId: 'u1',
      clientId: 'nadi-partner',
      grantId: 'grant-1',
      scope: 'messenger',
      exp: 1_900_000_000,
      isExpired: false,
    };

    it('returns the principal for a live messenger token of an enabled partner', async () => {
      provider.AccessToken.find.mockResolvedValue(token);
      await expect(service.verify('opaque')).resolves.toEqual({
        userId: 'u1',
        partnerId: 'p1',
        partnerSlug: 'nadi',
        grantId: 'grant-1',
        expiresAt: 1_900_000_000,
      });
    });

    it.each([
      ['an unknown token', undefined],
      ['an expired token', { ...token, isExpired: true }],
      ['a token without the messenger scope', { ...token, scope: 'openid mcp:calendar' }],
      ['a token without a grant', { ...token, grantId: undefined }],
    ])('returns null for %s', async (_name: string, found: any) => {
      provider.AccessToken.find.mockResolvedValue(found);
      await expect(service.verify('opaque')).resolves.toBeNull();
    });

    it('returns null when the client is not a partner or the partner is off', async () => {
      provider.AccessToken.find.mockResolvedValue(token);
      registry.findByClientId.mockResolvedValueOnce(null);
      await expect(service.verify('opaque')).resolves.toBeNull();
      registry.findByClientId.mockResolvedValueOnce({ ...partner, enabled: false });
      await expect(service.verify('opaque')).resolves.toBeNull();
    });

    it('is off entirely while PARTNER_API_ENABLED is not true', async () => {
      process.env.PARTNER_API_ENABLED = 'false';
      await expect(service.verify('opaque')).resolves.toBeNull();
      expect(provider.AccessToken.find).not.toHaveBeenCalled();
    });

    it('maps a token store failure to 503, not to "invalid token"', async () => {
      provider.AccessToken.find.mockRejectedValue(new Error('redis down'));
      await expect(service.verify('opaque')).rejects.toThrow(ServiceUnavailableException);
    });
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-core/partner-tokens.service.spec.ts`
Expected: FAIL — `Cannot find module './partner-tokens.service'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-core/partner-tokens.service.ts`:

```ts
import {
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { OIDC_PROVIDER } from '../oidc/oidc.service';
import { PrismaService } from '../prisma/prisma.service';
import { PartnerRecord, PartnerRegistryService } from './partner-registry.service';
import {
  MESSENGER_SCOPE,
  PARTNER_ACCESS_TOKEN_TTL_SECONDS,
  PartnerPrincipal,
} from './partner.constants';

/**
 * Токены партнёра — обычные опаковые access-токены oidc-provider со scope
 * `messenger`, выпущенные на сервере (как у Linkeon в PartnerService.mintTokens).
 * Refresh-токенов нет: бэкенд партнёра просто просит новый access-токен.
 */
@Injectable()
export class PartnerTokensService {
  private readonly logger = new Logger(PartnerTokensService.name);

  constructor(
    @Inject(OIDC_PROVIDER) private readonly provider: any,
    private readonly prisma: PrismaService,
    private readonly registry: PartnerRegistryService,
  ) {}

  /**
   * Токен мессенджера для действующей связки. Грант один на связку: по нему
   * отзываются сразу все токены, когда связку снимают. Гранты в Redis живут
   * 30 дней, поэтому истёкший грант пересоздаётся здесь же.
   */
  async issueAccessToken(
    link: { id: string; userId: string; grantId: string | null },
    partner: PartnerRecord,
  ): Promise<{ accessToken: string; expiresIn: number; grantId: string }> {
    const client = await this.provider.Client.find(partner.oauthClientId);
    if (!client) throw new InternalServerErrorException('partner oauth client not configured');

    let grantId = link.grantId;
    const live = grantId ? await this.provider.Grant.find(grantId) : undefined;
    if (!live) {
      const grant = new this.provider.Grant({ accountId: link.userId, clientId: partner.oauthClientId });
      grant.addOIDCScope(MESSENGER_SCOPE);
      grantId = (await grant.save()) as string;
      await this.prisma.partnerLink.update({ where: { id: link.id }, data: { grantId } });
    }

    const at = new this.provider.AccessToken({
      accountId: link.userId,
      client,
      grantId,
      scope: MESSENGER_SCOPE,
      gty: 'authorization_code',
    });
    const accessToken: string = await at.save();
    // Срок — из настроек провайдера (ttl.AccessToken), а не из своей копии:
    // поменяют TTL глобально — партнёр получит правду, а не старые 900 секунд.
    const expiresIn =
      typeof at.expiration === 'number' ? at.expiration : PARTNER_ACCESS_TOKEN_TTL_SECONDS;
    return { accessToken, expiresIn, grantId: grantId as string };
  }

  /** Гасит все токены гранта и сам грант. Повторный вызов безопасен. */
  async revokeGrant(grantId: string): Promise<void> {
    await this.provider.AccessToken.adapter.revokeByGrantId(grantId);
    const grant = await this.provider.Grant.find(grantId);
    if (grant) await grant.destroy();
  }

  /**
   * Опознаёт партнёрский токен мессенджера. null — это не он: не наш формат,
   * истёк, без scope, партнёр выключен или весь API выключен. Сбой хранилища
   * токенов — 503, а не «неверный токен» (как в McpAuthGuard).
   */
  async verify(token: string): Promise<PartnerPrincipal | null> {
    if (process.env.PARTNER_API_ENABLED !== 'true' || !token) return null;
    let at: any;
    try {
      at = await this.provider.AccessToken.find(token);
    } catch (err) {
      this.logger.warn(`partner token lookup failed: ${(err as Error).message}`);
      throw new ServiceUnavailableException('Token validation unavailable');
    }
    if (!at?.accountId || at.isExpired || !at.grantId) return null;
    const scopes = String(at.scope ?? '').split(' ');
    if (!scopes.includes(MESSENGER_SCOPE)) return null;
    const partner = await this.registry.findByClientId(at.clientId);
    if (!partner?.enabled) return null;
    return {
      userId: at.accountId,
      partnerId: partner.id,
      partnerSlug: partner.slug,
      grantId: at.grantId,
      expiresAt: at.exp,
    };
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-core/partner-tokens.service.spec.ts`
Expected: PASS, 13 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/partner-core/partner-tokens.service.ts src/partner-core/partner-tokens.service.spec.ts
git commit -m "feat(partner): выпуск, отзыв и опознание токенов мессенджера" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Отзыв связки и разрыв сокетов

**Files:**
- Create: `src/partner-core/partner-realtime.service.ts`
- Create: `src/partner-core/partner-link-revoker.service.ts`
- Test: `src/partner-core/partner-link-revoker.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-core/partner-link-revoker.service.spec.ts`:

```ts
import { PartnerLinkRevokerService } from './partner-link-revoker.service';
import { PartnerRealtimeService } from './partner-realtime.service';

describe('PartnerRealtimeService', () => {
  it('does nothing until the gateway registers', async () => {
    await expect(new PartnerRealtimeService().disconnectGrant('g1')).resolves.toBeUndefined();
  });

  it('calls the registered disconnector and swallows its errors', async () => {
    const realtime = new PartnerRealtimeService();
    const fn = jest.fn().mockRejectedValue(new Error('boom'));
    realtime.registerDisconnector(fn);
    await expect(realtime.disconnectGrant('g1')).resolves.toBeUndefined();
    expect(fn).toHaveBeenCalledWith('g1');
  });
});

describe('PartnerLinkRevokerService', () => {
  let prisma: any;
  let tokens: any;
  let realtime: any;
  let revoker: PartnerLinkRevokerService;

  beforeEach(() => {
    prisma = { partnerLink: { update: jest.fn().mockResolvedValue({}), findMany: jest.fn() } };
    tokens = { revokeGrant: jest.fn().mockResolvedValue(undefined) };
    realtime = { disconnectGrant: jest.fn().mockResolvedValue(undefined) };
    revoker = new PartnerLinkRevokerService(prisma, tokens, realtime);
  });

  it('revokes the link, its tokens and its sockets', async () => {
    await revoker.revokeLink({ id: 'l1', grantId: 'g1' });
    expect(prisma.partnerLink.update).toHaveBeenCalledWith({
      where: { id: 'l1' },
      data: expect.objectContaining({ status: 'REVOKED', grantId: null, codeHash: null }),
    });
    expect(tokens.revokeGrant).toHaveBeenCalledWith('g1');
    expect(realtime.disconnectGrant).toHaveBeenCalledWith('g1');
  });

  it('skips tokens and sockets for a link that never had a grant', async () => {
    await revoker.revokeLink({ id: 'l1', grantId: null });
    expect(tokens.revokeGrant).not.toHaveBeenCalled();
    expect(realtime.disconnectGrant).not.toHaveBeenCalled();
  });

  it('revokes every live link of a user', async () => {
    prisma.partnerLink.findMany.mockResolvedValue([
      { id: 'l1', grantId: 'g1' },
      { id: 'l2', grantId: null },
    ]);
    await expect(revoker.revokeAllForUser('u1')).resolves.toBe(2);
    expect(prisma.partnerLink.findMany).toHaveBeenCalledWith({
      where: { userId: 'u1', status: { not: 'REVOKED' } },
      select: { id: true, grantId: true },
    });
    expect(prisma.partnerLink.update).toHaveBeenCalledTimes(2);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-core/partner-link-revoker.service.spec.ts`
Expected: FAIL — `Cannot find module './partner-link-revoker.service'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-core/partner-realtime.service.ts`:

```ts
import { Injectable, Logger } from '@nestjs/common';

type Disconnector = (grantId: string) => Promise<void> | void;

/**
 * Мостик к шлюзу мессенджера: шлюз при старте регистрирует функцию «порвать
 * сокеты гранта» (как AiTwinService.registerEmitters), и отзыв связки рвёт их
 * на всех нодах через Redis-адаптер Socket.IO, не завися от MessengerModule.
 */
@Injectable()
export class PartnerRealtimeService {
  private readonly logger = new Logger(PartnerRealtimeService.name);
  private disconnector: Disconnector | null = null;

  registerDisconnector(fn: Disconnector): void {
    this.disconnector = fn;
  }

  /** Ошибка разрыва не должна мешать отзыву: токены к этому моменту уже погашены. */
  async disconnectGrant(grantId: string): Promise<void> {
    if (!this.disconnector) return;
    try {
      await this.disconnector(grantId);
    } catch (e) {
      this.logger.warn(`disconnect grant ${grantId} failed: ${(e as Error).message}`);
    }
  }
}
```

Создать `src/partner-core/partner-link-revoker.service.ts`:

```ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { PartnerRealtimeService } from './partner-realtime.service';
import { PartnerTokensService } from './partner-tokens.service';

@Injectable()
export class PartnerLinkRevokerService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: PartnerTokensService,
    private readonly realtime: PartnerRealtimeService,
  ) {}

  /** Снимает связку: статус, все её токены, открытые сокеты. Аккаунт TalerID не трогает. */
  async revokeLink(link: { id: string; grantId: string | null }): Promise<void> {
    await this.prisma.partnerLink.update({
      where: { id: link.id },
      data: {
        status: 'REVOKED',
        revokedAt: new Date(),
        grantId: null,
        codeHash: null,
        codeExpiresAt: null,
        codeAttempts: 0,
      },
    });
    if (link.grantId) {
      await this.tokens.revokeGrant(link.grantId);
      await this.realtime.disconnectGrant(link.grantId);
    }
  }

  /** Все живые связки пользователя — когда он удаляет аккаунт в самом TalerID. */
  async revokeAllForUser(userId: string): Promise<number> {
    const links = await this.prisma.partnerLink.findMany({
      where: { userId, status: { not: 'REVOKED' } },
      select: { id: true, grantId: true },
    });
    for (const link of links) await this.revokeLink(link);
    return links.length;
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-core/partner-link-revoker.service.spec.ts`
Expected: PASS, 5 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/partner-core/partner-realtime.service.ts src/partner-core/partner-link-revoker.service.ts src/partner-core/partner-link-revoker.service.spec.ts
git commit -m "feat(partner): отзыв связки гасит токены и рвёт сокеты" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Модуль `PartnerCoreModule` (без вебхуков) и отпечаток ключа секретов

**Files:**
- Modify: `src/partner-core/partner-secrets.util.ts` (функции `partnerSecretsKeyFingerprint`, `reportPartnerSecretsKey`)
- Create: `src/partner-core/partner-core.module.ts`
- Test: `src/partner-core/partner-secrets.util.spec.ts`

Зачем отпечаток: на PROD две ноды с `.env`, правленными руками. Разный `PARTNER_SECRETS_KEY` на них не виден ни по одной ошибке — код, отправленный с одной ноды, другая молча отвергнет как неверный и спишет попытку, а вебхуки начнут падать через раз. Отпечаток в логе при старте позволяет сравнить ключи, не показывая их.

- [ ] **Step 1: Написать падающие тесты**

В `src/partner-core/partner-secrets.util.spec.ts` добавить в импорт `partnerSecretsKeyFingerprint, reportPartnerSecretsKey`, под сохранённым `saved` добавить `const savedEnabled = process.env.PARTNER_API_ENABLED;`, в `afterAll` — такое же восстановление `PARTNER_API_ENABLED`, и в конец `describe` добавить:

```ts
  it('gives a short non-secret fingerprint that changes with the key', () => {
    const first = partnerSecretsKeyFingerprint();
    expect(first).toMatch(/^[0-9a-f]{8}$/);
    process.env.PARTNER_SECRETS_KEY = 'b'.repeat(64);
    expect(partnerSecretsKeyFingerprint()).not.toBe(first);
  });

  it('logs the fingerprint at startup, or shouts when the key is bad, without throwing', () => {
    const logger = { log: jest.fn(), error: jest.fn() };
    process.env.PARTNER_API_ENABLED = 'true';
    reportPartnerSecretsKey(logger);
    expect(logger.log).toHaveBeenCalledWith(`partner secrets key fingerprint: ${partnerSecretsKeyFingerprint()}`);
    process.env.PARTNER_SECRETS_KEY = 'short';
    expect(() => reportPartnerSecretsKey(logger)).not.toThrow();
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('PARTNER_SECRETS_KEY'));
  });

  it('stays silent at startup while the partner API is off', () => {
    const logger = { log: jest.fn(), error: jest.fn() };
    process.env.PARTNER_API_ENABLED = 'false';
    reportPartnerSecretsKey(logger);
    expect(logger.log).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `npx jest src/partner-core/partner-secrets.util.spec.ts`
Expected: FAIL — `partnerSecretsKeyFingerprint is not a function`.

- [ ] **Step 3: Отпечаток и проверка при старте**

В конец `src/partner-core/partner-secrets.util.ts` добавить:

```ts
/** Короткий отпечаток мастер-ключа: не секрет, его сравнивают глазами в логах нод. */
export function partnerSecretsKeyFingerprint(): string {
  return derive('key-fingerprint').subarray(0, 4).toString('hex');
}

/**
 * Проверка при старте: при включённом партнёрском API пишет в лог отпечаток
 * ключа (на обеих нодах PROD он обязан совпадать) или громко ругается, если
 * ключа нет. Бэкенд при этом не падает: вход и чаты не должны страдать из-за
 * настроек партнёров.
 */
export function reportPartnerSecretsKey(logger: {
  log(message: string): void;
  error(message: string): void;
}): void {
  if (process.env.PARTNER_API_ENABLED !== 'true') return;
  try {
    logger.log(`partner secrets key fingerprint: ${partnerSecretsKeyFingerprint()}`);
  } catch (e) {
    logger.error(
      `PARTNER_API_ENABLED=true, но ${(e as Error).message} — коды привязки и вебхуки работать не будут`,
    );
  }
}
```

Run: `npx jest src/partner-core/partner-secrets.util.spec.ts`
Expected: PASS.

- [ ] **Step 4: Модуль**

Создать `src/partner-core/partner-core.module.ts`:

```ts
import { Logger, Module, OnModuleInit } from '@nestjs/common';
import { OidcModule } from '../oidc/oidc.module';
import { PartnerLinkRevokerService } from './partner-link-revoker.service';
import { PartnerRealtimeService } from './partner-realtime.service';
import { PartnerRegistryService } from './partner-registry.service';
import { reportPartnerSecretsKey } from './partner-secrets.util';
import { PartnerTokensService } from './partner-tokens.service';

/**
 * Ядро партнёрского API без HTTP. Импортируют мессенджер (опознание токенов,
 * вебхуки), профиль (отзыв связок при удалении аккаунта) и партнёрский API.
 * Сам ничего из них не импортирует — так нет циклов между модулями.
 * PrismaModule и RedisModule глобальные.
 */
@Module({
  imports: [OidcModule],
  providers: [
    PartnerRegistryService,
    PartnerTokensService,
    PartnerRealtimeService,
    PartnerLinkRevokerService,
  ],
  exports: [
    PartnerRegistryService,
    PartnerTokensService,
    PartnerRealtimeService,
    PartnerLinkRevokerService,
  ],
})
export class PartnerCoreModule implements OnModuleInit {
  private readonly logger = new Logger('PartnerCore');

  onModuleInit(): void {
    reportPartnerSecretsKey(this.logger);
  }
}
```

- [ ] **Step 5: Тесты ядра и сборка**

Run: `npx jest src/partner-core && npm run build`
Expected: PASS; сборка без ошибок. Сам модуль в Jest не импортировать: он тянет `OidcModule` с ESM-пакетом `oidc-provider`. Поэтому проверка при старте вынесена в функцию и тестируется отдельно.

- [ ] **Step 6: Commit**

```bash
git add src/partner-core/partner-core.module.ts src/partner-core/partner-secrets.util.ts src/partner-core/partner-secrets.util.spec.ts
git commit -m "feat(partner): модуль ядра партнёрского API и отпечаток ключа секретов в логе" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Проверка ключа партнёра

**Files:**
- Create: `src/partner-api/partner-key.guard.ts`
- Test: `src/partner-api/partner-key.guard.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-api/partner-key.guard.spec.ts`:

```ts
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { generatePartnerKey, hashPartnerKey } from '../partner-core/partner-key.util';
import { PartnerKeyGuard } from './partner-key.guard';

function ctx(req: any) {
  return { switchToHttp: () => ({ getRequest: () => req }) } as any;
}

const saved = process.env.PARTNER_API_ENABLED;

describe('PartnerKeyGuard', () => {
  const key = generatePartnerKey('nadi');
  const partner = { id: 'p1', slug: 'nadi', keyHash: hashPartnerKey(key), enabled: true, ipAllowlist: [] as string[] };
  const request = (over: any = {}) => ({ headers: { authorization: `Bearer ${key}` }, ip: '1.2.3.4', ...over });
  let registry: any;
  let guard: PartnerKeyGuard;

  beforeEach(() => {
    process.env.PARTNER_API_ENABLED = 'true';
    registry = { findBySlug: jest.fn().mockResolvedValue(partner) };
    guard = new PartnerKeyGuard(registry);
  });
  afterAll(() => {
    if (saved === undefined) delete process.env.PARTNER_API_ENABLED;
    else process.env.PARTNER_API_ENABLED = saved;
  });

  it('attaches the partner for a valid key', async () => {
    const req: any = request();
    await expect(guard.canActivate(ctx(req))).resolves.toBe(true);
    expect(req.partner).toBe(partner);
    expect(registry.findBySlug).toHaveBeenCalledWith('nadi');
  });

  it('403 while the partner API is switched off, before looking at the key', async () => {
    process.env.PARTNER_API_ENABLED = 'false';
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow(ForbiddenException);
    expect(registry.findBySlug).not.toHaveBeenCalled();
  });

  it.each([undefined, 'Bearer', `Basic ${key}`, `Bearer tidp_nadi_${'x'.repeat(43)}`])(
    '401 for authorization %p',
    async (authorization: string | undefined) => {
      await expect(guard.canActivate(ctx(request({ headers: { authorization } })))).rejects.toThrow(
        UnauthorizedException,
      );
    },
  );

  it('401 for an unknown partner', async () => {
    registry.findBySlug.mockResolvedValue(null);
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow(UnauthorizedException);
  });

  it('403 for a disabled partner with a valid key', async () => {
    registry.findBySlug.mockResolvedValue({ ...partner, enabled: false });
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow(ForbiddenException);
  });

  it('checks the IP allowlist, ignoring the ::ffff: prefix', async () => {
    registry.findBySlug.mockResolvedValue({ ...partner, ipAllowlist: ['165.227.141.149'] });
    await expect(guard.canActivate(ctx(request({ ip: '::ffff:165.227.141.149' })))).resolves.toBe(true);
    await expect(guard.canActivate(ctx(request({ ip: '8.8.8.8' })))).rejects.toThrow(UnauthorizedException);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-api/partner-key.guard.spec.ts`
Expected: FAIL — `Cannot find module './partner-key.guard'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-api/partner-key.guard.ts`:

```ts
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { parsePartnerKey, partnerKeyMatches } from '../partner-core/partner-key.util';
import { PartnerRegistryService } from '../partner-core/partner-registry.service';

/** Адрес клиента, как его видит Express за нашим nginx, без префикса IPv4-in-IPv6. */
export function clientIp(req: { ip?: string }): string {
  return String(req.ip ?? '').replace(/^::ffff:/, '');
}

/**
 * Пускает в /partner/v1/* только сервер партнёра:
 *   1. партнёрский API выключен на окружении → 403 (по умолчанию выключен);
 *   2. ключа нет, формат чужой, ключ не подходит → 401;
 *   3. партнёр выключен → 403;
 *   4. IP не из белого списка партнёра (если список задан) → 401.
 * req.ip берётся с доверием только к loopback (main.ts, trust proxy), поэтому
 * подделать его заголовком X-Forwarded-For снаружи нельзя.
 */
@Injectable()
export class PartnerKeyGuard implements CanActivate {
  constructor(private readonly registry: PartnerRegistryService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (process.env.PARTNER_API_ENABLED !== 'true') {
      throw new ForbiddenException('partner_api_disabled');
    }
    const req = context.switchToHttp().getRequest();
    const match = /^Bearer\s+(\S+)$/i.exec(String(req.headers?.authorization ?? ''));
    const key = match?.[1] ?? '';
    const parsed = parsePartnerKey(key);
    const partner = parsed ? await this.registry.findBySlug(parsed.slug) : null;
    if (!partner || !partnerKeyMatches(key, partner.keyHash)) {
      throw new UnauthorizedException('invalid_partner_key');
    }
    if (!partner.enabled) throw new ForbiddenException('partner_disabled');
    if (partner.ipAllowlist.length > 0 && !partner.ipAllowlist.includes(clientIp(req))) {
      throw new UnauthorizedException('ip_not_allowed');
    }
    req.partner = partner;
    return true;
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-api/partner-key.guard.spec.ts`
Expected: PASS, 9 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/partner-api/partner-key.guard.ts src/partner-api/partner-key.guard.spec.ts
git commit -m "feat(partner): проверка ключа партнёра, выключатель и белый список IP" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Лимиты запросов партнёра

**Files:**
- Create: `src/partner-api/partner-rate-limit.guard.ts`
- Test: `src/partner-api/partner-rate-limit.guard.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-api/partner-rate-limit.guard.spec.ts`:

```ts
import { PartnerRateLimitGuard } from './partner-rate-limit.guard';

function ctx(req: any) {
  return {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as any;
}

describe('PartnerRateLimitGuard', () => {
  const now = new Date('2026-10-01T10:00:15Z');
  const minute = Math.floor(now.getTime() / 60_000);
  let redis: any;
  let reflector: any;
  let guard: PartnerRateLimitGuard;

  beforeEach(() => {
    jest.useFakeTimers({ now });
    redis = { incr: jest.fn().mockResolvedValue(1), expire: jest.fn().mockResolvedValue(undefined) };
    reflector = { getAllAndOverride: jest.fn().mockReturnValue(undefined) };
    guard = new PartnerRateLimitGuard(reflector, redis);
  });
  afterEach(() => jest.useRealTimers());

  it('counts per partner, bucket and minute', async () => {
    await expect(guard.canActivate(ctx({ partner: { id: 'p1' } }))).resolves.toBe(true);
    expect(redis.incr).toHaveBeenCalledWith(`partner:rl:p1:default:${minute}`);
    expect(redis.expire).toHaveBeenCalledWith(`partner:rl:p1:default:${minute}`, 120);
  });

  it('lets the token bucket through up to 600 a minute', async () => {
    reflector.getAllAndOverride.mockReturnValue('token');
    redis.incr.mockResolvedValue(600);
    await expect(guard.canActivate(ctx({ partner: { id: 'p1' } }))).resolves.toBe(true);
    expect(redis.incr).toHaveBeenCalledWith(`partner:rl:p1:token:${minute}`);
    redis.incr.mockResolvedValue(601);
    const err = await guard.canActivate(ctx({ partner: { id: 'p1' } })).catch((e) => e);
    expect(err.getStatus()).toBe(429);
  });

  it('answers 429 with retryAfter above 120 a minute on ordinary routes', async () => {
    redis.incr.mockResolvedValue(121);
    const err = await guard.canActivate(ctx({ partner: { id: 'p1' } })).catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({ message: 'rate_limited', retryAfter: 45 });
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-api/partner-rate-limit.guard.spec.ts`
Expected: FAIL — `Cannot find module './partner-rate-limit.guard'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-api/partner-rate-limit.guard.ts`:

```ts
import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RedisService } from '../redis/redis.service';

export type PartnerRateBucketName = 'token' | 'default';

/** Запросов в минуту на партнёра. Токен просят чаще всего: каждые 15 минут на человека. */
export const PARTNER_RATE_LIMITS: Record<PartnerRateBucketName, number> = {
  token: 600,
  default: 120,
};

export const PARTNER_RATE_BUCKET = 'partnerRateBucket';
export const PartnerRateBucket = (bucket: PartnerRateBucketName) =>
  SetMetadata(PARTNER_RATE_BUCKET, bucket);

/**
 * Лимит по партнёру, а не по IP: весь партнёр ходит с одного сервера, и
 * глобальные лимиты по IP (1000 в час на эндпоинт) упёрлись бы в него на
 * первых же сотнях активных людей. Счётчик — в Redis, общий для всех нод.
 * Ставится после PartnerKeyGuard: без req.partner считать нечего.
 */
@Injectable()
export class PartnerRateLimitGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly redis: RedisService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const partner = req.partner as { id: string } | undefined;
    if (!partner) return true;
    const bucket =
      this.reflector.getAllAndOverride<PartnerRateBucketName>(PARTNER_RATE_BUCKET, [
        context.getHandler(),
        context.getClass(),
      ]) ?? 'default';
    const nowSec = Math.floor(Date.now() / 1000);
    const key = `partner:rl:${partner.id}:${bucket}:${Math.floor(nowSec / 60)}`;
    const count = await this.redis.incr(key);
    if (count === 1) await this.redis.expire(key, 120);
    if (count > PARTNER_RATE_LIMITS[bucket]) {
      throw new HttpException(
        { message: 'rate_limited', retryAfter: 60 - (nowSec % 60) },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    return true;
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-api/partner-rate-limit.guard.spec.ts`
Expected: PASS, 3 теста.

- [ ] **Step 5: Commit**

```bash
git add src/partner-api/partner-rate-limit.guard.ts src/partner-api/partner-rate-limit.guard.spec.ts
git commit -m "feat(partner): лимиты запросов по партнёру, а не по IP" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Журнал действий партнёра

**Files:**
- Create: `src/partner-api/partner-audit.service.ts`
- Test: `src/partner-api/partner-audit.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-api/partner-audit.service.spec.ts`:

```ts
import { PartnerAuditService } from './partner-audit.service';

describe('PartnerAuditService', () => {
  it('writes a PARTNER_* audit row with the partner and externalId', async () => {
    const prisma: any = { auditLog: { create: jest.fn().mockResolvedValue({}) } };
    await new PartnerAuditService(prisma).log({ id: 'p1', slug: 'nadi' }, 'USER_CREATED', {
      externalId: 'm-1',
      userId: 'u1',
      ip: '1.2.3.4',
      meta: { otherUserId: 'u2' },
    });
    expect(prisma.auditLog.create).toHaveBeenCalledWith({
      data: {
        userId: 'u1',
        action: 'PARTNER_USER_CREATED',
        ipAddress: '1.2.3.4',
        meta: { partner: 'nadi', externalId: 'm-1', otherUserId: 'u2' },
      },
    });
  });

  it('never fails the request because of the audit log', async () => {
    const prisma: any = { auditLog: { create: jest.fn().mockRejectedValue(new Error('db down')) } };
    await expect(
      new PartnerAuditService(prisma).log({ id: 'p1', slug: 'nadi' }, 'LINK_REVOKED', {}),
    ).resolves.toBeUndefined();
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-api/partner-audit.service.spec.ts`
Expected: FAIL — `Cannot find module './partner-audit.service'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-api/partner-audit.service.ts`:

```ts
import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface PartnerAuditEntry {
  externalId?: string;
  userId?: string | null;
  ip?: string;
  meta?: Record<string, string | number | boolean | null>;
}

/**
 * Изменяющие действия партнёра — в AuditLog с префиксом PARTNER_. Глобальный
 * AuditLogInterceptor пишет только /auth, /profile и /kyc, поэтому здесь явно.
 */
@Injectable()
export class PartnerAuditService {
  private readonly logger = new Logger('PartnerApi');

  constructor(private readonly prisma: PrismaService) {}

  async log(partner: { id: string; slug: string }, action: string, entry: PartnerAuditEntry): Promise<void> {
    this.logger.log(`[${partner.slug}] ${action} externalId=${entry.externalId ?? '-'} user=${entry.userId ?? '-'}`);
    try {
      await this.prisma.auditLog.create({
        data: {
          userId: entry.userId ?? null,
          action: `PARTNER_${action}`,
          ipAddress: entry.ip ?? null,
          meta: { partner: partner.slug, externalId: entry.externalId ?? null, ...(entry.meta ?? {}) },
        },
      });
    } catch (e) {
      this.logger.warn(`audit write failed: ${(e as Error).message}`);
    }
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-api/partner-audit.service.spec.ts`
Expected: PASS, 2 теста.

- [ ] **Step 5: Commit**

```bash
git add src/partner-api/partner-audit.service.ts src/partner-api/partner-audit.service.spec.ts
git commit -m "feat(partner): журнал действий партнёра в AuditLog" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 12: Письмо с кодом привязки

**Files:**
- Modify: `src/email/email.service.ts` (новый метод после `sendOtp`, функция `escapeHtml` в конце файла)
- Test: `src/email/email.service.spec.ts` (новый файл)

- [ ] **Step 1: Написать падающий тест**

Создать `src/email/email.service.spec.ts`:

```ts
import { EmailService } from './email.service';

function make() {
  const values: Record<string, unknown> = {
    'email.smtp.host': 'smtp.test',
    'email.smtp.port': 587,
    'email.smtp.user': 'noreply@talerid.io',
    'email.smtp.pass': 'x',
  };
  const config: any = { get: jest.fn((key: string) => values[key]) };
  const service = new EmailService(config);
  const sendMail = jest.fn().mockResolvedValue({});
  (service as any).transporter = { sendMail };
  return { service, sendMail };
}

describe('EmailService.sendPartnerLinkCode', () => {
  it('sends a Russian letter to ru accounts with the code in the subject', async () => {
    const { service, sendMail } = make();
    await service.sendPartnerLinkCode('ivan@example.com', '123456', 'Nadi', 'ru');
    const mail = sendMail.mock.calls[0][0];
    expect(mail.to).toBe('ivan@example.com');
    expect(mail.subject).toBe('Код для подключения Nadi к Taler ID: 123456');
    expect(mail.html).toContain('123456');
    expect(mail.html).toContain('проигнорируйте');
  });

  it('writes in English to everyone else', async () => {
    const { service, sendMail } = make();
    await service.sendPartnerLinkCode('ivan@example.com', '123456', 'Nadi', 'uk');
    expect(sendMail.mock.calls[0][0].subject).toBe('Code to connect Nadi to Taler ID: 123456');
  });

  it('escapes the partner name in HTML', async () => {
    const { service, sendMail } = make();
    await service.sendPartnerLinkCode('ivan@example.com', '123456', '<b>X</b>', 'en');
    const html = sendMail.mock.calls[0][0].html as string;
    expect(html).not.toContain('<b>X</b>');
    expect(html).toContain('&lt;b&gt;X&lt;/b&gt;');
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/email/email.service.spec.ts`
Expected: FAIL — `TypeError: service.sendPartnerLinkCode is not a function`.

- [ ] **Step 3: Реализация**

В `src/email/email.service.ts` после метода `sendOtp` добавить:

```ts
  /**
   * Код, которым человек подтверждает, что сам подключает приложение-партнёра
   * (nadi) к своему существующему аккаунту. Без кода партнёр не получает
   * доступ к его чатам. Язык — из профиля TalerID: ru или en.
   */
  async sendPartnerLinkCode(
    to: string,
    code: string,
    partnerName: string,
    language: string,
  ): Promise<void> {
    const name = escapeHtml(partnerName);
    const ru = language === 'ru';
    await this.transporter.sendMail({
      from: `"Taler ID" <${this.config.get('email.smtp.user')}>`,
      to,
      subject: ru
        ? `Код для подключения ${partnerName} к Taler ID: ${code}`
        : `Code to connect ${partnerName} to Taler ID: ${code}`,
      html: ru
        ? `<h2>Подключение ${name} к вашему аккаунту Taler ID</h2>
<p>Приложение <strong>${name}</strong> просит доступ к вашим чатам Taler ID: оно сможет показывать ваши личные чаты и группы и писать в них от вашего имени.</p>
<p>Если это вы — введите код в приложении ${name}:</p>
<p style="font-size:32px;letter-spacing:8px;font-weight:bold;">${code}</p>
<p style="color:#888;font-size:12px;">Код действителен 10 минут. Если вы ничего не подключали — просто проигнорируйте письмо: без кода доступ не откроется.</p>`
        : `<h2>Connecting ${name} to your Taler ID account</h2>
<p>The <strong>${name}</strong> app asks for access to your Taler ID chats: it will be able to show your direct chats and groups and write to them on your behalf.</p>
<p>If this is you, enter the code in the ${name} app:</p>
<p style="font-size:32px;letter-spacing:8px;font-weight:bold;">${code}</p>
<p style="color:#888;font-size:12px;">The code is valid for 10 minutes. If you did not connect anything, just ignore this email: without the code no access is granted.</p>`,
    });
    this.logger.log(`Partner link code sent to ${to} for ${partnerName}`);
  }
```

В конец файла (после закрывающей скобки класса) добавить:

```ts
function escapeHtml(value: string): string {
  const map: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return value.replace(/[&<>"']/g, (ch) => map[ch]);
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/email/email.service.spec.ts`
Expected: PASS, 3 теста.

- [ ] **Step 5: Commit**

```bash
git add src/email/email.service.ts src/email/email.service.spec.ts
git commit -m "feat(email): письмо с кодом подключения приложения-партнёра" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 13: `externalId` и DTO партнёрского API

**Files:**
- Create: `src/partner-api/external-id.util.ts`
- Create: `src/partner-api/dto/provision-user.dto.ts`, `src/partner-api/dto/patch-user.dto.ts`, `src/partner-api/dto/verify-link-code.dto.ts`
- Test: `src/partner-api/external-id.util.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-api/external-id.util.spec.ts`:

```ts
import { BadRequestException } from '@nestjs/common';
import { assertExternalId } from './external-id.util';

describe('assertExternalId', () => {
  it.each(['cm1abc', 'e2e-a-lx9', 'org:42', 'a.b_c'])('accepts %p', (value: string) => {
    expect(assertExternalId(value)).toBe(value);
  });

  it.each(['', 'has space', 'x'.repeat(129), 'кирилиця', 'a/b'])('rejects %p', (value: string) => {
    expect(() => assertExternalId(value)).toThrow(BadRequestException);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-api/external-id.util.spec.ts`
Expected: FAIL — `Cannot find module './external-id.util'`.

- [ ] **Step 3: Реализация и DTO**

Создать `src/partner-api/external-id.util.ts`:

```ts
import { BadRequestException } from '@nestjs/common';

/** Стабильный id человека у партнёра (у nadi — id участника). */
export const EXTERNAL_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

export function assertExternalId(value: string): string {
  if (typeof value !== 'string' || !EXTERNAL_ID_RE.test(value)) {
    throw new BadRequestException('invalid_external_id');
  }
  return value;
}
```

Создать `src/partner-api/dto/provision-user.dto.ts`:

```ts
import { IsEmail, IsOptional, IsString, Matches, MaxLength } from 'class-validator';
import { EXTERNAL_ID_RE } from '../external-id.util';

export class ProvisionUserDto {
  @IsString()
  @Matches(EXTERNAL_ID_RE, { message: 'invalid_external_id' })
  externalId!: string;

  /** Партнёр обязан проверить её сам до вызова (у nadi — вход по коду из письма). */
  @IsEmail({}, { message: 'invalid_email' })
  @MaxLength(254)
  email!: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  firstName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  lastName?: string;

  /** Язык человека у партнёра. Профиль TalerID знает ru и en, остальное станет en. */
  @IsOptional()
  @IsString()
  @MaxLength(10)
  locale?: string;
}
```

Создать `src/partner-api/dto/patch-user.dto.ts`:

```ts
import { IsOptional, IsString, MaxLength } from 'class-validator';

export class PatchUserDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  firstName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  lastName?: string;
}
```

Создать `src/partner-api/dto/verify-link-code.dto.ts`:

```ts
import { IsString, Matches } from 'class-validator';

export class VerifyLinkCodeDto {
  @IsString()
  @Matches(/^\d{6}$/, { message: 'invalid_code' })
  code!: string;
}
```

- [ ] **Step 4: Тест проходит и всё собирается**

Run: `npx jest src/partner-api/external-id.util.spec.ts && npm run build`
Expected: PASS, 9 тестов; сборка без ошибок.

- [ ] **Step 5: Commit**

```bash
git add src/partner-api/external-id.util.ts src/partner-api/external-id.util.spec.ts src/partner-api/dto
git commit -m "feat(partner): externalId и DTO партнёрского API" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 14: Завести или привязать человека

> ⚠️ Блоки кода этой задачи — исторические, повторять их нельзя: в них поиск почты через `mode: 'insensitive'` (ILIKE с шаблонами) и неатомарная запись. Источник правды — `src/partner-api/partner-users.service.ts` и его spec в ветке (см. «Правки по ревью задач 14–15»).

**Files:**
- Create: `src/partner-api/partner-users.service.ts`
- Test: `src/partner-api/partner-users.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-api/partner-users.service.spec.ts`:

```ts
import { ConflictException } from '@nestjs/common';
import { PartnerUsersService, profileLanguage } from './partner-users.service';

const partner: any = { id: 'p1', slug: 'nadi', name: 'Nadi' };
const dto: any = {
  externalId: 'm-1',
  email: ' Ivan@Example.COM ',
  firstName: 'Іван',
  lastName: 'Петренко',
  locale: 'uk',
};
const liveUser = { id: 'u1', deletedAt: null, passwordHash: null };

function make() {
  const prisma: any = {
    partnerLink: {
      findUnique: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({}),
      update: jest.fn().mockResolvedValue({}),
      delete: jest.fn().mockResolvedValue({}),
    },
    user: {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({ id: 'u-new' }),
    },
    profile: { upsert: jest.fn().mockResolvedValue({}) },
    conversationParticipant: { deleteMany: jest.fn().mockResolvedValue({ count: 1 }) },
  };
  const tokens: any = { issueAccessToken: jest.fn(), revokeGrant: jest.fn() };
  const revoker: any = { revokeLink: jest.fn().mockResolvedValue(undefined) };
  const systemChannel: any = { subscribeUser: jest.fn().mockResolvedValue(undefined) };
  const profiles: any = { deleteAccount: jest.fn().mockResolvedValue({ success: true }) };
  const audit: any = { log: jest.fn().mockResolvedValue(undefined) };
  const service = new PartnerUsersService(prisma, tokens, revoker, systemChannel, profiles, audit);
  return { service, prisma, tokens, revoker, systemChannel, profiles, audit };
}

/** findUnique отвечает по форме where: связка по externalId или по пользователю. */
function links(prisma: any, byExternal: any, byUser: any = null) {
  prisma.partnerLink.findUnique.mockImplementation(({ where }: any) =>
    Promise.resolve(where.partnerId_externalId ? byExternal : where.partnerId_userId ? byUser : null),
  );
}

describe('PartnerUsersService.provision', () => {
  it('creates an account for a new email and links it as ACTIVE', async () => {
    const { service, prisma, systemChannel, audit } = make();
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u-new',
      created: true,
    });
    expect(prisma.user.findFirst).toHaveBeenCalledWith({
      where: { email: { equals: 'ivan@example.com', mode: 'insensitive' }, deletedAt: null },
      select: { id: true, passwordHash: true },
    });
    expect(prisma.user.create).toHaveBeenCalledWith({
      data: {
        email: 'ivan@example.com',
        emailVerified: true,
        profile: { create: { firstName: 'Іван', lastName: 'Петренко', language: 'en' } },
        kycRecord: { create: {} },
      },
      select: { id: true },
    });
    expect(systemChannel.subscribeUser).toHaveBeenCalledWith('u-new');
    expect(prisma.partnerLink.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        partnerId: 'p1',
        externalId: 'm-1',
        userId: 'u-new',
        status: 'ACTIVE',
        createdAccount: true,
      }),
    });
    expect(audit.log).toHaveBeenCalledWith(
      partner,
      'USER_CREATED',
      expect.objectContaining({ externalId: 'm-1', userId: 'u-new' }),
    );
  });

  it('is idempotent for an ACTIVE link', async () => {
    const { service, prisma } = make();
    links(prisma, { id: 'l1', userId: 'u1', status: 'ACTIVE', createdAccount: true, user: liveUser });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'active', talerUserId: 'u1', created: false });
    expect(prisma.user.findFirst).not.toHaveBeenCalled();
  });

  it('keeps a PENDING link pending', async () => {
    const { service, prisma } = make();
    links(prisma, { id: 'l1', userId: 'u1', status: 'PENDING', createdAccount: false, user: liveUser });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'confirmation_required', talerUserId: null });
  });

  it('asks for confirmation when the email already belongs to someone', async () => {
    const { service, prisma } = make();
    prisma.user.findFirst.mockResolvedValue({ id: 'u-existing', passwordHash: 'hash' });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'confirmation_required', talerUserId: null });
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.partnerLink.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ userId: 'u-existing', status: 'PENDING', createdAccount: false }),
    });
  });

  it('refuses when that account is linked under another externalId', async () => {
    const { service, prisma } = make();
    prisma.user.findFirst.mockResolvedValue({ id: 'u-existing', passwordHash: null });
    links(prisma, null, { id: 'l-other', userId: 'u-existing', externalId: 'm-0', status: 'ACTIVE', createdAccount: true });
    await expect(service.provision(partner, dto)).rejects.toThrow(ConflictException);
  });

  it('replaces a revoked link held under another externalId', async () => {
    const { service, prisma } = make();
    prisma.user.findFirst.mockResolvedValue({ id: 'u-existing', passwordHash: null });
    links(prisma, null, { id: 'l-other', userId: 'u-existing', externalId: 'm-0', status: 'REVOKED', createdAccount: true });
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u-existing',
      created: false,
    });
    expect(prisma.partnerLink.delete).toHaveBeenCalledWith({ where: { id: 'l-other' } });
  });

  it('reactivates its own managed account without a code', async () => {
    const { service, prisma } = make();
    const revoked = { id: 'l1', userId: 'u1', externalId: 'm-1', status: 'REVOKED', createdAccount: true, grantId: null, user: liveUser };
    links(prisma, revoked, revoked);
    prisma.user.findFirst.mockResolvedValue({ id: 'u1', passwordHash: null });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'active', talerUserId: 'u1', created: false });
    expect(prisma.partnerLink.update).toHaveBeenCalledWith({
      where: { id: 'l1' },
      data: expect.objectContaining({ status: 'ACTIVE', revokedAt: null }),
    });
  });

  it('asks for a code again once the person has set a TalerID password', async () => {
    const { service, prisma } = make();
    const revoked = {
      id: 'l1', userId: 'u1', externalId: 'm-1', status: 'REVOKED', createdAccount: true, grantId: null,
      user: { ...liveUser, passwordHash: 'set' },
    };
    links(prisma, revoked, revoked);
    prisma.user.findFirst.mockResolvedValue({ id: 'u1', passwordHash: 'set' });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'confirmation_required', talerUserId: null });
  });

  it('revokes a link whose account was deleted and starts over', async () => {
    const { service, prisma, revoker } = make();
    const stale = {
      id: 'l1', userId: 'u-dead', externalId: 'm-1', status: 'ACTIVE', createdAccount: true, grantId: 'g1',
      user: { id: 'u-dead', deletedAt: new Date(), passwordHash: null },
    };
    links(prisma, stale);
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'active', talerUserId: 'u-new', created: true });
    expect(revoker.revokeLink).toHaveBeenCalledWith(stale);
    expect(prisma.partnerLink.update).toHaveBeenCalledWith({
      where: { id: 'l1' },
      data: expect.objectContaining({ userId: 'u-new', status: 'ACTIVE' }),
    });
  });

  it('finishes an unfinished revocation before reusing the link row', async () => {
    const { service, prisma, revoker } = make();
    const unfinished = { id: 'l1', userId: 'u1', externalId: 'm-1', status: 'REVOKED', createdAccount: true, grantId: 'g-old', user: liveUser };
    links(prisma, unfinished, unfinished);
    prisma.user.findFirst.mockResolvedValue({ id: 'u1', passwordHash: null });
    await service.provision(partner, dto);
    expect(revoker.revokeLink).toHaveBeenCalledWith(unfinished);
  });

  it('finishes the revocation of a stale link under another externalId before deleting it', async () => {
    const { service, prisma, revoker } = make();
    prisma.user.findFirst.mockResolvedValue({ id: 'u-existing', passwordHash: null });
    const other = { id: 'l-other', userId: 'u-existing', externalId: 'm-0', status: 'REVOKED', createdAccount: true, grantId: 'g-old' };
    links(prisma, null, other);
    await service.provision(partner, dto);
    expect(revoker.revokeLink).toHaveBeenCalledWith(other);
    expect(prisma.partnerLink.delete).toHaveBeenCalledWith({ where: { id: 'l-other' } });
  });

  it('retries once on a unique-constraint race', async () => {
    const { service, prisma } = make();
    prisma.user.create.mockRejectedValueOnce(Object.assign(new Error('dup'), { code: 'P2002' }));
    prisma.user.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce({ id: 'u-raced', passwordHash: 'x' });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'confirmation_required', talerUserId: null });
  });
});

describe('profileLanguage', () => {
  it.each([
    ['ru', 'ru'],
    ['ru-UA', 'ru'],
    ['en', 'en'],
    ['uk', 'en'],
    [undefined, 'en'],
  ])('%p → %p', (input: string | undefined, out: string) => {
    expect(profileLanguage(input)).toBe(out);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-api/partner-users.service.spec.ts`
Expected: FAIL — `Cannot find module './partner-users.service'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-api/partner-users.service.ts`:

```ts
import {
  ConflictException,
  GoneException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ProfileService } from '../profile/profile.service';
import { SystemChannelService } from '../system-channel/system-channel.service';
import { PartnerLinkRevokerService } from '../partner-core/partner-link-revoker.service';
import { PartnerRecord } from '../partner-core/partner-registry.service';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { PartnerAuditService } from './partner-audit.service';
import { PatchUserDto } from './dto/patch-user.dto';
import { ProvisionUserDto } from './dto/provision-user.dto';

export type ProvisionResult =
  | { status: 'active'; talerUserId: string; created: boolean }
  | { status: 'confirmation_required'; talerUserId: null };

type LinkStatus = 'PENDING' | 'ACTIVE' | 'REVOKED';

interface LinkWithUser {
  id: string;
  userId: string;
  status: LinkStatus;
  createdAccount: boolean;
  grantId: string | null;
  activatedAt: Date | null;
  user: { id: string; deletedAt: Date | null; passwordHash: string | null };
}

/** Профиль TalerID знает ru и en; всё остальное (uk и т.д.) — en. */
export function profileLanguage(locale?: string): 'ru' | 'en' {
  return locale?.toLowerCase().startsWith('ru') ? 'ru' : 'en';
}

/**
 * Аккаунт, которым партнёр вправе распоряжаться (переименовать, удалить):
 * он его создал, и человек ни разу не задавал пароль TalerID.
 */
export function isManaged(link: LinkWithUser): boolean {
  return link.createdAccount && link.user.passwordHash === null && link.user.deletedAt === null;
}

/**
 * Люди партнёра в TalerID. Спека, раздел «Партнёрский API»:
 * docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 */
@Injectable()
export class PartnerUsersService {
  private readonly logger = new Logger(PartnerUsersService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: PartnerTokensService,
    private readonly revoker: PartnerLinkRevokerService,
    private readonly systemChannel: SystemChannelService,
    private readonly profiles: ProfileService,
    private readonly audit: PartnerAuditService,
  ) {}

  async provision(
    partner: PartnerRecord,
    dto: ProvisionUserDto,
    ip?: string,
    retried = false,
  ): Promise<ProvisionResult> {
    const email = dto.email.trim().toLowerCase();
    try {
      return await this.provisionOnce(partner, dto.externalId, email, dto, ip);
    } catch (e: any) {
      // Два одновременных запроса про одного человека: второй упирается в
      // уникальный индекс. Состояние к этому моменту уже записано — перечитываем.
      if (e?.code === 'P2002' && !retried) return this.provision(partner, dto, ip, true);
      throw e;
    }
  }

  private async provisionOnce(
    partner: PartnerRecord,
    externalId: string,
    email: string,
    dto: ProvisionUserDto,
    ip?: string,
  ): Promise<ProvisionResult> {
    const link = await this.findLink(partner.id, externalId);
    if (link && !link.user.deletedAt) {
      if (link.status === 'ACTIVE') return { status: 'active', talerUserId: link.userId, created: false };
      if (link.status === 'PENDING') return { status: 'confirmation_required', talerUserId: null };
    }
    if (link && (link.status !== 'REVOKED' || link.grantId)) {
      // Строку связки сейчас переиспользуем (аккаунт удалён или связка
      // отозвана). Сначала гасим всё, что за ней числится: действующий доступ
      // удалённого аккаунта или недоделанный прошлый отзыв (REVOKED с грантом).
      await this.revoker.revokeLink(link);
    }

    // Уникальный индекс почты в БД регистрозависим: Ivan@ и ivan@ иначе стали
    // бы двумя аккаунтами.
    const owner = await this.prisma.user.findFirst({
      where: { email: { equals: email, mode: 'insensitive' }, deletedAt: null },
      select: { id: true, passwordHash: true },
    });

    if (!owner) {
      const userId = await this.createAccount(email, dto);
      await this.saveLink(partner.id, externalId, link?.id ?? null, {
        userId,
        status: 'ACTIVE',
        createdAccount: true,
      });
      await this.audit.log(partner, 'USER_CREATED', { externalId, userId, ip });
      return { status: 'active', talerUserId: userId, created: true };
    }

    const other = await this.prisma.partnerLink.findUnique({
      where: { partnerId_userId: { partnerId: partner.id, userId: owner.id } },
    });
    if (other && other.externalId !== externalId) {
      if (other.status !== 'REVOKED') throw new ConflictException('user_linked_to_other_external_id');
      // Отозванная связка того же человека под старым id больше ничего не
      // значит, а уникальный индекс (partnerId, userId) не даст завести новую.
      // Если её отзыв не доделан (остался грант) — доделываем до удаления строки.
      if (other.grantId) await this.revoker.revokeLink(other);
      await this.prisma.partnerLink.delete({ where: { id: other.id } });
    }

    const createdByPartner = [link, other].some(
      (l) => !!l && l.userId === owner.id && l.createdAccount,
    );
    const managed = createdByPartner && owner.passwordHash === null;
    await this.saveLink(partner.id, externalId, link?.id ?? null, {
      userId: owner.id,
      status: managed ? 'ACTIVE' : 'PENDING',
      createdAccount: createdByPartner,
    });
    await this.audit.log(partner, managed ? 'USER_RELINKED' : 'LINK_PENDING', {
      externalId,
      userId: owner.id,
      ip,
    });
    return managed
      ? { status: 'active', talerUserId: owner.id, created: false }
      : { status: 'confirmation_required', talerUserId: null };
  }

  /** Тот же набор, что при обычной регистрации, только без пароля. */
  private async createAccount(email: string, dto: ProvisionUserDto): Promise<string> {
    const user = await this.prisma.user.create({
      data: {
        email,
        // Партнёр проверил почту своим кодом до вызова — это его обязанность.
        emailVerified: true,
        profile: {
          create: {
            firstName: dto.firstName?.trim() || null,
            lastName: dto.lastName?.trim() || null,
            language: profileLanguage(dto.locale),
          },
        },
        kycRecord: { create: {} },
      },
      select: { id: true },
    });
    // Как у всех: ensureSeeded() всё равно подписал бы при следующем рестарте.
    // Партнёрский токен каналов не видит (PartnerConversationScope).
    try {
      await this.systemChannel.subscribeUser(user.id);
    } catch (e) {
      this.logger.warn(`system-channel subscribe failed for ${user.id}: ${(e as Error).message}`);
    }
    return user.id;
  }

  private async saveLink(
    partnerId: string,
    externalId: string,
    existingId: string | null,
    data: { userId: string; status: 'ACTIVE' | 'PENDING'; createdAccount: boolean },
  ): Promise<void> {
    const fields = {
      userId: data.userId,
      status: data.status,
      createdAccount: data.createdAccount,
      activatedAt: data.status === 'ACTIVE' ? new Date() : null,
      revokedAt: null,
      grantId: null,
      codeHash: null,
      codeExpiresAt: null,
      codeAttempts: 0,
    };
    if (existingId) {
      await this.prisma.partnerLink.update({ where: { id: existingId }, data: fields });
    } else {
      await this.prisma.partnerLink.create({ data: { partnerId, externalId, ...fields } });
    }
  }

  private findLink(partnerId: string, externalId: string): Promise<LinkWithUser | null> {
    return this.prisma.partnerLink.findUnique({
      where: { partnerId_externalId: { partnerId, externalId } },
      include: { user: { select: { id: true, deletedAt: true, passwordHash: true } } },
    });
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-api/partner-users.service.spec.ts`
Expected: PASS, 17 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/partner-api/partner-users.service.ts src/partner-api/partner-users.service.spec.ts
git commit -m "feat(partner): заведение и привязка людей партнёра" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 15: Токен, статус, имя, отзыв и удаление

> ⚠️ Блоки кода этой задачи — исторические. Источник правды — `src/partner-api/partner-users.service.ts` и его spec в ветке (см. «Правки по ревью задач 14–15»).

**Files:**
- Modify: `src/partner-api/partner-users.service.ts` (методы `issueToken`, `getUser`, `patchUser`, `deleteUser`)
- Test: `src/partner-api/partner-users.service.spec.ts` (новый `describe` в конце)

- [ ] **Step 1: Написать падающие тесты**

В конец `src/partner-api/partner-users.service.spec.ts` добавить:

```ts
describe('PartnerUsersService token and lifecycle', () => {
  const active = {
    id: 'l1',
    userId: 'u1',
    status: 'ACTIVE',
    createdAccount: true,
    grantId: 'g1',
    activatedAt: new Date('2026-10-01T10:00:00Z'),
    user: liveUser,
  };

  it('issues a messenger token for an ACTIVE link', async () => {
    const { service, prisma, tokens } = make();
    links(prisma, active);
    tokens.issueAccessToken.mockResolvedValue({ accessToken: 'at', expiresIn: 900, grantId: 'g1' });
    await expect(service.issueToken(partner, 'm-1')).resolves.toEqual({
      accessToken: 'at',
      tokenType: 'Bearer',
      expiresIn: 900,
      talerUserId: 'u1',
    });
    expect(tokens.issueAccessToken).toHaveBeenCalledWith(active, partner);
  });

  it.each([
    [null, 'not_linked'],
    [{ ...active, status: 'REVOKED' }, 'not_linked'],
    [{ ...active, status: 'PENDING' }, 'confirmation_required'],
  ])('refuses a token for link %#', async (link: any, message: string) => {
    const { service, prisma } = make();
    links(prisma, link);
    await expect(service.issueToken(partner, 'm-1')).rejects.toThrow(message);
  });

  it('revokes the link and answers 410 when the account was deleted in TalerID', async () => {
    const { service, prisma, revoker } = make();
    const dead = { ...active, user: { ...liveUser, deletedAt: new Date() } };
    links(prisma, dead);
    const err = await service.issueToken(partner, 'm-1').catch((e) => e);
    expect(err.getStatus()).toBe(410);
    expect(revoker.revokeLink).toHaveBeenCalledWith(dead);
  });

  it('reports the status without leaking the id of a pending account', async () => {
    const { service, prisma } = make();
    links(prisma, { ...active, status: 'PENDING', createdAccount: false, activatedAt: null });
    await expect(service.getUser(partner, 'm-1')).resolves.toEqual({
      status: 'confirmation_required',
      talerUserId: null,
      managed: false,
      linkedAt: null,
    });
    links(prisma, active);
    await expect(service.getUser(partner, 'm-1')).resolves.toEqual({
      status: 'active',
      talerUserId: 'u1',
      managed: true,
      linkedAt: '2026-10-01T10:00:00.000Z',
    });
  });

  it('renames only managed accounts', async () => {
    const { service, prisma } = make();
    links(prisma, active);
    await expect(service.patchUser(partner, 'm-1', { firstName: ' Олена ' })).resolves.toEqual({ ok: true });
    expect(prisma.profile.upsert).toHaveBeenCalledWith({
      where: { userId: 'u1' },
      update: { firstName: 'Олена' },
      create: { userId: 'u1', firstName: 'Олена' },
    });
    links(prisma, { ...active, createdAccount: false });
    await expect(service.patchUser(partner, 'm-1', { firstName: 'X' })).rejects.toThrow('profile_not_managed');
  });

  it('revokes the link and keeps the account by default', async () => {
    const { service, prisma, revoker, profiles } = make();
    links(prisma, active);
    await service.deleteUser(partner, 'm-1', false);
    expect(revoker.revokeLink).toHaveBeenCalledWith(active);
    expect(profiles.deleteAccount).not.toHaveBeenCalled();
  });

  it('deletes a managed account and its channel subscriptions on request', async () => {
    const { service, prisma, profiles } = make();
    links(prisma, active);
    await service.deleteUser(partner, 'm-1', true);
    expect(profiles.deleteAccount).toHaveBeenCalledWith('u1');
    expect(prisma.conversationParticipant.deleteMany).toHaveBeenCalledWith({
      where: { userId: 'u1', conversation: { type: 'CHANNEL' } },
    });
  });

  it('refuses to delete an account it does not manage, and changes nothing', async () => {
    const { service, prisma, revoker, profiles } = make();
    links(prisma, { ...active, createdAccount: false });
    await expect(service.deleteUser(partner, 'm-1', true)).rejects.toThrow('account_not_managed');
    expect(revoker.revokeLink).not.toHaveBeenCalled();
    expect(profiles.deleteAccount).not.toHaveBeenCalled();
  });

  it('is idempotent for an already revoked link', async () => {
    const { service, prisma, revoker } = make();
    links(prisma, { ...active, status: 'REVOKED', grantId: null });
    await service.deleteUser(partner, 'm-1', false);
    expect(revoker.revokeLink).not.toHaveBeenCalled();
  });

  it('finishes a revocation that was interrupted (REVOKED with a grant left)', async () => {
    const { service, prisma, revoker } = make();
    const unfinished = { ...active, status: 'REVOKED' };
    links(prisma, unfinished);
    await service.deleteUser(partner, 'm-1', false);
    expect(revoker.revokeLink).toHaveBeenCalledWith(unfinished);
  });
});
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `npx jest src/partner-api/partner-users.service.spec.ts`
Expected: FAIL — `TypeError: service.issueToken is not a function` (и так же для `getUser`, `patchUser`, `deleteUser`).

- [ ] **Step 3: Реализация**

В `src/partner-api/partner-users.service.ts` в класс `PartnerUsersService` после метода `provision` добавить:

```ts
  async issueToken(
    partner: PartnerRecord,
    externalId: string,
  ): Promise<{ accessToken: string; tokenType: 'Bearer'; expiresIn: number; talerUserId: string }> {
    const link = await this.findLink(partner.id, externalId);
    if (!link || link.status === 'REVOKED') throw new NotFoundException('not_linked');
    if (link.status === 'PENDING') throw new ConflictException('confirmation_required');
    if (link.user.deletedAt) {
      await this.revoker.revokeLink(link);
      throw new GoneException('account_deleted');
    }
    const { accessToken, expiresIn } = await this.tokens.issueAccessToken(link, partner);
    return { accessToken, tokenType: 'Bearer', expiresIn, talerUserId: link.userId };
  }

  async getUser(partner: PartnerRecord, externalId: string) {
    const link = await this.findLink(partner.id, externalId);
    if (!link) throw new NotFoundException('not_linked');
    const status =
      link.status === 'ACTIVE' ? 'active' : link.status === 'PENDING' ? 'confirmation_required' : 'revoked';
    return {
      status,
      // Пока человек не подтвердил привязку кодом, id его аккаунта партнёру не положен.
      talerUserId: link.status === 'ACTIVE' ? link.userId : null,
      managed: isManaged(link),
      linkedAt: link.activatedAt ? link.activatedAt.toISOString() : null,
    };
  }

  async patchUser(partner: PartnerRecord, externalId: string, dto: PatchUserDto, ip?: string) {
    const link = await this.findLink(partner.id, externalId);
    if (!link || link.status !== 'ACTIVE') throw new NotFoundException('not_linked');
    if (!isManaged(link)) throw new ConflictException('profile_not_managed');
    const data: { firstName?: string | null; lastName?: string | null } = {};
    if (dto.firstName !== undefined) data.firstName = dto.firstName.trim() || null;
    if (dto.lastName !== undefined) data.lastName = dto.lastName.trim() || null;
    await this.prisma.profile.upsert({
      where: { userId: link.userId },
      update: data,
      create: { userId: link.userId, ...data },
    });
    await this.audit.log(partner, 'PROFILE_UPDATED', { externalId, userId: link.userId, ip });
    return { ok: true };
  }

  /**
   * Снимает связку. С deleteAccount — ещё и удаляет аккаунт штатной процедурой
   * TalerID, но только управляемый: человек удалился у партнёра и просит
   * стереть данные. Неуправляемый аккаунт — 409, и ничего не меняется.
   */
  async deleteUser(partner: PartnerRecord, externalId: string, deleteAccount: boolean, ip?: string): Promise<void> {
    const link = await this.findLink(partner.id, externalId);
    if (!link) throw new NotFoundException('not_linked');
    if (deleteAccount && !isManaged(link)) throw new ConflictException('account_not_managed');
    // REVOKED с грантом — прошлый отзыв не доделан (сбой Redis): доделываем.
    if (link.status !== 'REVOKED' || link.grantId) await this.revoker.revokeLink(link);
    if (deleteAccount) {
      await this.profiles.deleteAccount(link.userId);
      // Подписки на каналы удалённому ни к чему, а тестовые прогоны иначе
      // копили бы их в системном канале.
      await this.prisma.conversationParticipant.deleteMany({
        where: { userId: link.userId, conversation: { type: 'CHANNEL' } },
      });
    }
    await this.audit.log(partner, deleteAccount ? 'ACCOUNT_DELETED' : 'LINK_REVOKED', {
      externalId,
      userId: link.userId,
      ip,
    });
  }
```

- [ ] **Step 4: Тесты проходят**

Run: `npx jest src/partner-api/partner-users.service.spec.ts`
Expected: PASS, 29 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/partner-api/partner-users.service.ts src/partner-api/partner-users.service.spec.ts
git commit -m "feat(partner): токен мессенджера, статус, имя, отзыв и удаление управляемого аккаунта" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 16: Код привязки из письма

> ⚠️ Блоки кода задач 16–17 — исторические: после ревью добавлены суточные потолки партнёра, аудит неудачных кодов, самолечение ключа без срока в `countInWindow`, а у контактов — только активные связки и сверка `createdContact`. Источник правды — файлы в ветке (см. «Правки по ревью задач 16–17»).

**Files:**
- Create: `src/partner-api/partner-link-code.service.ts`
- Modify: `src/partner-api/partner-counter.util.ts` (общий потолок ожидания `bounded`, счётчик в окне `countInWindow`)
- Test: `src/partner-api/partner-link-code.service.spec.ts`, `src/partner-api/partner-counter.util.spec.ts`

Лимиты отправки письма берегут почтовый ящик человека. Поэтому, в отличие от лимита запросов партнёра, без Redis они отказывают (`503 rate_limiter_unavailable`), а не пропускают. Окно открывает первое письмо: ключ создаётся сразу со сроком (`SET NX EX`), `INCR` срок не трогает. Потерять срок между командами нельзя, отказы внутри окна его не продлевают, `retryAfter` — точный остаток окна. Ждать Redis дольше 250 мс не будем, как и в лимитах задач 9–13.

- [ ] **Step 1: Написать падающие тесты**

В конец `src/partner-api/partner-counter.util.spec.ts` добавить (и `countInWindow` — в импорт из `./partner-counter.util`):

```ts
describe('countInWindow', () => {
  /** multi().set().incr().ttl().exec() с управляемым результатом exec(). */
  function fakeWindowRedis(exec: () => Promise<any>) {
    const chain: any = {};
    chain.set = jest.fn(() => chain);
    chain.incr = jest.fn(() => chain);
    chain.ttl = jest.fn(() => chain);
    chain.exec = exec;
    return { redis: { getClient: () => ({ multi: () => chain }) } as any, chain };
  }

  it('opens the window with SET NX EX, counts with INCR and reports the time left', async () => {
    const { redis, chain } = fakeWindowRedis(() =>
      Promise.resolve([
        [null, null], // окно уже открыто — SET NX ничего не сделал
        [null, 3],
        [null, 1795],
      ]),
    );
    await expect(countInWindow(redis, 'w', 3600)).resolves.toEqual({ count: 3, retryAfter: 1795 });
    expect(chain.set).toHaveBeenCalledWith('w', '0', 'EX', 3600, 'NX');
    expect(chain.incr).toHaveBeenCalledWith('w');
    expect(chain.ttl).toHaveBeenCalledWith('w');
  });

  it('returns null when a queued command failed, exec() rejected or Redis did not answer', async () => {
    const failed = fakeWindowRedis(() =>
      Promise.resolve([
        [null, 'OK'],
        [new Error('ERR value is not an integer or out of range'), null],
        [null, 60],
      ]),
    );
    await expect(countInWindow(failed.redis, 'w', 60)).resolves.toBeNull();
    const rejected = fakeWindowRedis(() =>
      Promise.reject(new Error('EXECABORT Transaction discarded because of previous errors.')),
    );
    await expect(countInWindow(rejected.redis, 'w', 60)).resolves.toBeNull();
    const hung = fakeWindowRedis(() => new Promise(() => {}));
    await expect(countInWindow(hung.redis, 'w', 60, 5)).resolves.toBeNull();
  });
});
```

Создать `src/partner-api/partner-link-code.service.spec.ts`:

```ts
import { hashLinkCode } from '../partner-core/partner-secrets.util';
import { countInWindow } from './partner-counter.util';
import { PartnerLinkCodeService } from './partner-link-code.service';

jest.mock('./partner-counter.util', () => ({
  ...jest.requireActual('./partner-counter.util'),
  countInWindow: jest.fn(),
}));
const windowCount = countInWindow as jest.Mock;

beforeEach(() => {
  windowCount.mockReset();
  // Оба окна свободны: первое письмо за минуту и за час.
  windowCount.mockResolvedValue({ count: 1, retryAfter: 60 });
});

// До описания тестов: withCode() ниже зовёт hashLinkCode, которому нужен ключ.
const savedKey = process.env.PARTNER_SECRETS_KEY;
process.env.PARTNER_SECRETS_KEY = 'b'.repeat(64);
afterAll(() => {
  if (savedKey === undefined) delete process.env.PARTNER_SECRETS_KEY;
  else process.env.PARTNER_SECRETS_KEY = savedKey;
});

const partner: any = { id: 'p1', slug: 'nadi', name: 'Nadi' };
const pending = {
  id: 'l1',
  userId: 'u1',
  status: 'PENDING',
  codeHash: null as string | null,
  codeExpiresAt: null as Date | null,
  codeAttempts: 0,
  user: { email: 'ivan@example.com', deletedAt: null, profile: { language: 'ru' } },
};
const withCode = (over: any = {}) => ({
  ...pending,
  codeHash: hashLinkCode('l1', '123456'),
  codeExpiresAt: new Date(Date.now() + 60_000),
  codeAttempts: 0,
  ...over,
});

function make(link: any) {
  const prisma: any = {
    partnerLink: {
      findUnique: jest.fn().mockResolvedValue(link),
      // Попытку списывает сама БД: условия «не истёк, не сожжён» — в where.
      // Здесь попытка по умолчанию списалась; тест на истёкший код задаёт count: 0.
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      findUniqueOrThrow: jest.fn().mockResolvedValue({ codeAttempts: (link?.codeAttempts ?? 0) + 1 }),
      update: jest.fn().mockResolvedValue({}),
    },
  };
  // Окна считает countInWindow (замокан выше); сервис сам зовёт только del.
  const redis: any = { del: jest.fn().mockResolvedValue(undefined) };
  const email: any = { sendPartnerLinkCode: jest.fn().mockResolvedValue(undefined) };
  const audit: any = { log: jest.fn().mockResolvedValue(undefined) };
  return { service: new PartnerLinkCodeService(prisma, redis, email, audit), prisma, redis, email };
}

describe('PartnerLinkCodeService.send', () => {
  it("stores only a hash and mails the code in the person's language", async () => {
    const { service, prisma, redis, email } = make(pending);
    await expect(service.send(partner, 'm-1')).resolves.toEqual({ sent: true, expiresIn: 600 });
    expect(windowCount).toHaveBeenNthCalledWith(1, redis, 'partner:linkcode:cd:l1', 60);
    expect(windowCount).toHaveBeenNthCalledWith(2, redis, 'partner:linkcode:h:l1', 3600);
    const [to, code, name, lang] = email.sendPartnerLinkCode.mock.calls[0];
    expect([to, name, lang]).toEqual(['ivan@example.com', 'Nadi', 'ru']);
    expect(code).toMatch(/^\d{6}$/);
    const data = prisma.partnerLink.update.mock.calls[0][0].data;
    expect(data.codeHash).toBe(hashLinkCode('l1', code));
    expect(data.codeAttempts).toBe(0);
    expect(data.codeExpiresAt.getTime()).toBeGreaterThan(Date.now() + 590_000);
  });

  it('answers 429 with retryAfter inside the one-minute cooldown', async () => {
    const { service, email } = make(pending);
    windowCount.mockResolvedValueOnce({ count: 2, retryAfter: 42 });
    const err = await service.send(partner, 'm-1').catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({ message: 'too_many_requests', retryAfter: 42 });
    expect(windowCount).toHaveBeenCalledTimes(1);
    expect(email.sendPartnerLinkCode).not.toHaveBeenCalled();
  });

  it('answers 429 after five letters in an hour', async () => {
    const { service, email } = make(pending);
    windowCount
      .mockResolvedValueOnce({ count: 1, retryAfter: 60 })
      .mockResolvedValueOnce({ count: 6, retryAfter: 1800 });
    const err = await service.send(partner, 'm-1').catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({ message: 'too_many_requests', retryAfter: 1800 });
    expect(email.sendPartnerLinkCode).not.toHaveBeenCalled();
  });

  it.each([0, 1])(
    'refuses with 503 when Redis cannot count window #%i: the limits protect the inbox',
    async (failing: number) => {
      const { service, email } = make(pending);
      if (failing === 1) windowCount.mockResolvedValueOnce({ count: 1, retryAfter: 60 });
      windowCount.mockResolvedValueOnce(null);
      const err = await service.send(partner, 'm-1').catch((e) => e);
      expect(err.getStatus()).toBe(503);
      expect(err.message).toBe('rate_limiter_unavailable');
      expect(email.sendPartnerLinkCode).not.toHaveBeenCalled();
    },
  );

  it('409 for a link that is not waiting for a code', async () => {
    const { service } = make({ ...pending, status: 'ACTIVE' });
    await expect(service.send(partner, 'm-1')).rejects.toThrow('not_pending');
  });

  it('404 for an unknown link', async () => {
    const { service } = make(null);
    await expect(service.send(partner, 'm-1')).rejects.toThrow('not_linked');
  });

  it('frees the cooldown and answers 503 when mail fails', async () => {
    const { service, redis, email } = make(pending);
    email.sendPartnerLinkCode.mockRejectedValue(new Error('smtp down'));
    const err = await service.send(partner, 'm-1').catch((e) => e);
    expect(err.getStatus()).toBe(503);
    expect(redis.del).toHaveBeenCalledWith('partner:linkcode:cd:l1');
  });
});

describe('PartnerLinkCodeService.verify', () => {
  it('spends an attempt on this very code before comparing, then activates on the right code', async () => {
    const link = withCode();
    const { service, prisma } = make(link);
    await expect(service.verify(partner, 'm-1', '123456')).resolves.toEqual({ status: 'active', talerUserId: 'u1' });
    expect(prisma.partnerLink.updateMany).toHaveBeenNthCalledWith(1, {
      where: {
        id: 'l1',
        status: 'PENDING',
        codeHash: link.codeHash,
        codeExpiresAt: { gt: expect.any(Date) },
        codeAttempts: { lt: 5 },
      },
      data: { codeAttempts: { increment: 1 } },
    });
    expect(prisma.partnerLink.updateMany).toHaveBeenLastCalledWith({
      where: { id: 'l1', status: 'PENDING', codeHash: link.codeHash },
      data: expect.objectContaining({ status: 'ACTIVE', codeHash: null, codeAttempts: 0 }),
    });
  });

  it('does not spend an attempt when no code was ever sent', async () => {
    const { service, prisma } = make(pending);
    const err = await service.verify(partner, 'm-1', '123456').catch((e) => e);
    expect(err.getStatus()).toBe(410);
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
  });

  it('does not revive the link when its code changed meanwhile', async () => {
    const { service, prisma } = make(withCode());
    prisma.partnerLink.updateMany.mockResolvedValueOnce({ count: 1 }).mockResolvedValueOnce({ count: 0 });
    const err = await service.verify(partner, 'm-1', '123456').catch((e) => e);
    expect(err.getStatus()).toBe(410);
  });

  it('answers 400 with attemptsLeft on a wrong code', async () => {
    const { service } = make(withCode());
    const err = await service.verify(partner, 'm-1', '000000').catch((e) => e);
    expect(err.getStatus()).toBe(400);
    expect(err.getResponse()).toEqual({ message: 'invalid_code', attemptsLeft: 4 });
  });

  it('burns the code on the fifth wrong attempt', async () => {
    const link = withCode({ codeAttempts: 4 });
    const { service, prisma } = make(link);
    const err = await service.verify(partner, 'm-1', '000000').catch((e) => e);
    expect(err.getStatus()).toBe(410);
    expect(prisma.partnerLink.updateMany).toHaveBeenLastCalledWith({
      where: { id: 'l1', status: 'PENDING', codeHash: link.codeHash },
      data: { codeHash: null, codeExpiresAt: null },
    });
  });

  it('answers 410 without comparing when no attempt can be spent (expired or burned)', async () => {
    const { service, prisma } = make(withCode());
    prisma.partnerLink.updateMany.mockResolvedValue({ count: 0 });
    // Верный код: если бы сравнение всё же случилось, связка ожила бы.
    const err = await service.verify(partner, 'm-1', '123456').catch((e) => e);
    expect(err.getStatus()).toBe(410);
    expect(prisma.partnerLink.updateMany).toHaveBeenCalledTimes(1);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-api/partner-link-code.service.spec.ts src/partner-api/partner-counter.util.spec.ts`
Expected: FAIL — `Cannot find module './partner-link-code.service'` и `countInWindow is not a function`.

- [ ] **Step 3: Реализация**

В `src/partner-api/partner-counter.util.ts` перед `incrementCounter` добавить общий потолок ожидания:

```ts
/**
 * Запрос к Redis с потолком ожидания. Никогда не бросает: таймаут, отказ
 * Redis и синхронная ошибка клиента — это null, а что делать без ответа,
 * решает вызывающий.
 */
async function bounded<T>(run: () => Promise<T | null>, timeoutMs: number): Promise<T | null> {
  let timer!: ReturnType<typeof setTimeout>;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs);
  });
  try {
    return await Promise.race([run().catch((): null => null), timeout]);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
```

Тело `incrementCounter` (JSDoc над ним оставить как есть) заменить на:

```ts
export function incrementCounter(
  redis: RedisService,
  key: string,
  ttlSeconds: number,
  timeoutMs: number = PARTNER_COUNTER_TIMEOUT_MS,
): Promise<number | null> {
  return bounded(async () => {
    const results = await redis.getClient().multi().incr(key).expire(key, ttlSeconds).exec();
    if (!results) return null;
    const [err, value] = results[0];
    return err ? null : Number(value);
  }, timeoutMs);
}
```

и после него добавить:

```ts
/**
 * Счётчик в окне, которое открывает первый запрос: SET NX EX создаёт ключ
 * сразу со сроком, INCR срок не трогает. Одна транзакция — срок не потеряется
 * между командами, а отказы внутри окна его не продлевают. retryAfter —
 * сколько окну осталось жить. null — Redis не ответил за timeoutMs.
 */
export function countInWindow(
  redis: RedisService,
  key: string,
  windowSeconds: number,
  timeoutMs: number = PARTNER_COUNTER_TIMEOUT_MS,
): Promise<{ count: number; retryAfter: number } | null> {
  return bounded(async () => {
    const results = await redis
      .getClient()
      .multi()
      .set(key, '0', 'EX', windowSeconds, 'NX')
      .incr(key)
      .ttl(key)
      .exec();
    if (!results || results.some(([err]) => err)) return null;
    return { count: Number(results[1][1]), retryAfter: Math.max(1, Number(results[2][1])) };
  }, timeoutMs);
}
```

Создать `src/partner-api/partner-link-code.service.ts`:

```ts
import {
  BadRequestException,
  ConflictException,
  GoneException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { randomInt } from 'crypto';
import { EmailService } from '../email/email.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { PartnerRecord } from '../partner-core/partner-registry.service';
import { hashLinkCode, linkCodeMatches } from '../partner-core/partner-secrets.util';
import { PartnerAuditService } from './partner-audit.service';
import { countInWindow } from './partner-counter.util';

const CODE_TTL_SECONDS = 600;
const CODE_MAX_ATTEMPTS = 5;
const SEND_COOLDOWN_SECONDS = 60;
const SENDS_PER_HOUR = 5;

/**
 * Привязка существующего аккаунта TalerID к партнёру — только кодом, который
 * TalerID сам шлёт на почту аккаунта. Иначе утёкший ключ партнёра открывал бы
 * чаты любого пользователя по одной почте.
 */
@Injectable()
export class PartnerLinkCodeService {
  private readonly logger = new Logger(PartnerLinkCodeService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly email: EmailService,
    private readonly audit: PartnerAuditService,
  ) {}

  async send(partner: PartnerRecord, externalId: string, ip?: string): Promise<{ sent: true; expiresIn: number }> {
    const link = await this.pendingLink(partner.id, externalId);
    const to = link.user.email;
    if (!to) throw new NotFoundException('not_linked');

    // Оба окна берегут почтовый ящик человека: без Redis — отказ (503), а не
    // пропуск, как у лимита запросов партнёра.
    const cooldownKey = `partner:linkcode:cd:${link.id}`;
    const cooldown = await countInWindow(this.redis, cooldownKey, SEND_COOLDOWN_SECONDS);
    if (!cooldown) throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (cooldown.count > 1) throw tooManyRequests(cooldown.retryAfter);
    const hour = await countInWindow(this.redis, `partner:linkcode:h:${link.id}`, 3600);
    if (!hour) throw new ServiceUnavailableException('rate_limiter_unavailable');
    if (hour.count > SENDS_PER_HOUR) throw tooManyRequests(hour.retryAfter);

    const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
    await this.prisma.partnerLink.update({
      where: { id: link.id },
      data: {
        codeHash: hashLinkCode(link.id, code),
        codeExpiresAt: new Date(Date.now() + CODE_TTL_SECONDS * 1000),
        codeAttempts: 0,
      },
    });
    try {
      await this.email.sendPartnerLinkCode(to, code, partner.name, link.user.profile?.language ?? 'en');
    } catch (e) {
      // Письмо не ушло — человек не должен ждать минуту до следующей попытки.
      // Ответ про почту не держим ради Redis: del — без ожидания.
      this.redis.del(cooldownKey).catch(() => undefined);
      this.logger.error(`link code mail failed for ${link.id}: ${(e as Error).message}`);
      throw new ServiceUnavailableException('email_send_failed');
    }
    await this.audit.log(partner, 'LINK_CODE_SENT', { externalId, userId: link.userId, ip });
    return { sent: true, expiresIn: CODE_TTL_SECONDS };
  }

  async verify(
    partner: PartnerRecord,
    externalId: string,
    code: string,
    ip?: string,
  ): Promise<{ status: 'active'; talerUserId: string }> {
    const link = await this.pendingLink(partner.id, externalId);
    // Кода не отправляли — и попытку тратить не на что.
    if (!link.codeHash) throw new GoneException('code_expired');
    const codeHash = link.codeHash;
    // Попытку списываем ДО сравнения и одним условным UPDATE, привязанным к
    // этому самому коду. Иначе параллельные запросы успевали бы сравнить
    // десятки кодов, пока счётчик ещё не вырос, — а подбирать код может как
    // раз партнёр, от которого этот код защищает чужой аккаунт.
    const spent = await this.prisma.partnerLink.updateMany({
      where: {
        id: link.id,
        status: 'PENDING',
        codeHash,
        codeExpiresAt: { gt: new Date() },
        codeAttempts: { lt: CODE_MAX_ATTEMPTS },
      },
      data: { codeAttempts: { increment: 1 } },
    });
    if (spent.count === 0) throw new GoneException('code_expired');
    // Дальше пишем только пока код тот же: гонка с повторной отправкой не
    // сотрёт свежий код, а гонка с отзывом не оживит отозванную связку.
    const sameCode = { id: link.id, status: 'PENDING' as const, codeHash };
    if (!linkCodeMatches(link.id, code, codeHash)) {
      const { codeAttempts } = await this.prisma.partnerLink.findUniqueOrThrow({
        where: { id: link.id },
        select: { codeAttempts: true },
      });
      if (codeAttempts >= CODE_MAX_ATTEMPTS) {
        await this.prisma.partnerLink.updateMany({
          where: sameCode,
          data: { codeHash: null, codeExpiresAt: null },
        });
        throw new GoneException('code_expired');
      }
      throw new BadRequestException({ message: 'invalid_code', attemptsLeft: CODE_MAX_ATTEMPTS - codeAttempts });
    }
    const activated = await this.prisma.partnerLink.updateMany({
      where: sameCode,
      data: { status: 'ACTIVE', activatedAt: new Date(), codeHash: null, codeExpiresAt: null, codeAttempts: 0 },
    });
    if (activated.count === 0) throw new GoneException('code_expired');
    await this.audit.log(partner, 'LINK_CONFIRMED', { externalId, userId: link.userId, ip });
    return { status: 'active', talerUserId: link.userId };
  }

  private async pendingLink(partnerId: string, externalId: string) {
    const link = await this.prisma.partnerLink.findUnique({
      where: { partnerId_externalId: { partnerId, externalId } },
      include: {
        user: { select: { email: true, deletedAt: true, profile: { select: { language: true } } } },
      },
    });
    if (!link || link.status === 'REVOKED' || link.user.deletedAt) throw new NotFoundException('not_linked');
    if (link.status !== 'PENDING') throw new ConflictException('not_pending');
    return link;
  }
}

function tooManyRequests(retryAfter: number): HttpException {
  return new HttpException({ message: 'too_many_requests', retryAfter }, HttpStatus.TOO_MANY_REQUESTS);
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-api/partner-link-code.service.spec.ts src/partner-api/partner-counter.util.spec.ts`
Expected: PASS — 14 тестов кода привязки, 11 тестов счётчиков (прежние 9 без изменений: `incrementCounter` перешёл на `bounded`, поведение то же).

- [ ] **Step 5: Commit**

```bash
git add src/partner-api/partner-link-code.service.ts src/partner-api/partner-link-code.service.spec.ts src/partner-api/partner-counter.util.ts src/partner-api/partner-counter.util.spec.ts
git commit -m "feat(partner): привязка существующего аккаунта кодом из письма" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 17: Контакты по дружбе партнёра

> ⚠️ Блоки кода этой задачи — исторические (см. «Правки по ревью задач 16–17»); источник правды — файлы в ветке.

**Files:**
- Create: `src/partner-api/partner-contacts.service.ts`
- Test: `src/partner-api/partner-contacts.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-api/partner-contacts.service.spec.ts`:

```ts
import { PartnerContactsService } from './partner-contacts.service';

const partner: any = { id: 'p1', slug: 'nadi' };

function make() {
  const prisma: any = {
    // Внешние id нарочно «перевёрнуты» относительно userId: пара хранится
    // упорядоченной по userId, а не по порядку аргументов.
    partnerLink: {
      findMany: jest.fn().mockResolvedValue([
        { externalId: 'a', userId: 'u-b' },
        { externalId: 'b', userId: 'u-a' },
      ]),
    },
    blockedUser: { findFirst: jest.fn().mockResolvedValue(null) },
    partnerContact: {
      findUnique: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({}),
      deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
      count: jest.fn().mockResolvedValue(0),
    },
    contactRequest: {
      findMany: jest.fn().mockResolvedValue([]),
      create: jest.fn().mockResolvedValue({}),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
  };
  const audit: any = { log: jest.fn().mockResolvedValue(undefined) };
  return { service: new PartnerContactsService(prisma, audit), prisma };
}

describe('PartnerContactsService.put', () => {
  it('creates an accepted contact and remembers that the partner created it', async () => {
    const { service, prisma } = make();
    await expect(service.put(partner, 'a', 'b')).resolves.toEqual({ contact: true, created: true });
    expect(prisma.contactRequest.create).toHaveBeenCalledWith({
      data: { senderId: 'u-a', receiverId: 'u-b', status: 'ACCEPTED' },
    });
    expect(prisma.partnerContact.create).toHaveBeenCalledWith({
      data: { partnerId: 'p1', userAId: 'u-a', userBId: 'u-b', createdContact: true },
    });
  });

  it('records a contact that existed before the partner as not its own', async () => {
    const { service, prisma } = make();
    prisma.contactRequest.findMany.mockResolvedValue([{ id: 'c1', status: 'ACCEPTED' }]);
    await expect(service.put(partner, 'a', 'b')).resolves.toEqual({ contact: true, created: false });
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
    expect(prisma.contactRequest.updateMany).not.toHaveBeenCalled();
    expect(prisma.partnerContact.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ createdContact: false }),
    });
  });

  it('upgrades every request of the pair instead of creating another row', async () => {
    const { service, prisma } = make();
    // Отклонённый запрос в одну сторону и висящий встречный: оба становятся
    // принятыми, иначе у человека остался бы «входящий запрос» от контакта.
    prisma.contactRequest.findMany.mockResolvedValue([
      { id: 'c1', status: 'REJECTED' },
      { id: 'c2', status: 'PENDING' },
    ]);
    await service.put(partner, 'a', 'b');
    expect(prisma.contactRequest.updateMany).toHaveBeenCalledWith({
      where: { id: { in: ['c1', 'c2'] } },
      data: { status: 'ACCEPTED' },
    });
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
  });

  it('answers the same PUT sent twice at once instead of failing on the unique index', async () => {
    const { service, prisma } = make();
    prisma.contactRequest.create.mockRejectedValueOnce(Object.assign(new Error('dup'), { code: 'P2002' }));
    // К повтору параллельный запрос уже всё записал.
    prisma.contactRequest.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ id: 'c1', status: 'ACCEPTED' }]);
    // Первая попытка до PartnerContact не дошла, а параллельный запрос его уже завёл.
    prisma.partnerContact.findUnique.mockResolvedValue({ id: 'pc1' });
    await expect(service.put(partner, 'a', 'b')).resolves.toEqual({ contact: true, created: false });
    expect(prisma.partnerContact.create).not.toHaveBeenCalled();
  });

  it('never overrides a block', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.findFirst.mockResolvedValue({ blockerId: 'u-b', blockedId: 'u-a' });
    await expect(service.put(partner, 'a', 'b')).rejects.toThrow('blocked');
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
  });

  it('needs both links to be active', async () => {
    const { service, prisma } = make();
    prisma.partnerLink.findMany.mockResolvedValue([{ externalId: 'a', userId: 'u-b' }]);
    await expect(service.put(partner, 'a', 'b')).rejects.toThrow('link_not_active');
  });

  it('refuses a contact with oneself', async () => {
    const { service } = make();
    await expect(service.put(partner, 'a', 'a')).rejects.toThrow('same_user');
  });
});

describe('PartnerContactsService.remove', () => {
  it('removes a contact the partner created when nobody else holds it', async () => {
    const { service, prisma } = make();
    prisma.partnerContact.findUnique.mockResolvedValue({ id: 'pc1', createdContact: true });
    await expect(service.remove(partner, 'a', 'b')).resolves.toEqual({ contact: false });
    expect(prisma.partnerContact.deleteMany).toHaveBeenCalledWith({ where: { id: 'pc1' } });
    expect(prisma.contactRequest.deleteMany).toHaveBeenCalled();
  });

  it('keeps a contact that existed before the partner', async () => {
    const { service, prisma } = make();
    prisma.partnerContact.findUnique.mockResolvedValue({ id: 'pc1', createdContact: false });
    prisma.contactRequest.findMany.mockResolvedValue([{ id: 'c1', status: 'ACCEPTED' }]);
    await expect(service.remove(partner, 'a', 'b')).resolves.toEqual({ contact: true });
    expect(prisma.contactRequest.deleteMany).not.toHaveBeenCalled();
  });

  it('keeps a contact another partner still holds', async () => {
    const { service, prisma } = make();
    prisma.partnerContact.findUnique.mockResolvedValue({ id: 'pc1', createdContact: true });
    prisma.partnerContact.count.mockResolvedValue(1);
    await service.remove(partner, 'a', 'b');
    expect(prisma.contactRequest.deleteMany).not.toHaveBeenCalled();
  });

  it('does nothing but report when the partner never made them contacts', async () => {
    const { service, prisma } = make();
    await expect(service.remove(partner, 'a', 'b')).resolves.toEqual({ contact: false });
    expect(prisma.partnerContact.deleteMany).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-api/partner-contacts.service.spec.ts`
Expected: FAIL — `Cannot find module './partner-contacts.service'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-api/partner-contacts.service.ts`:

```ts
import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { PartnerRecord } from '../partner-core/partner-registry.service';
import { assertExternalId } from './external-id.util';
import { PartnerAuditService } from './partner-audit.service';

/**
 * «Друзья партнёра = контакты TalerID». Личный чат в TalerID возможен только
 * между контактами, и это правило проверяет сервер мессенджера; партнёр лишь
 * говорит, кто с кем дружит. Блокировок партнёр не снимает.
 */
@Injectable()
export class PartnerContactsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: PartnerAuditService,
  ) {}

  async put(
    partner: PartnerRecord,
    extA: string,
    extB: string,
    ip?: string,
    retried = false,
  ): Promise<{ contact: true; created: boolean }> {
    try {
      return await this.putOnce(partner, extA, extB, ip);
    } catch (e: any) {
      // Тот же PUT пришёл дважды одновременно (оба друга подтвердили дружбу):
      // второй упирается в уникальный индекс. Первый уже всё записал — перечитываем.
      if (e?.code === 'P2002' && !retried) return this.put(partner, extA, extB, ip, true);
      throw e;
    }
  }

  private async putOnce(
    partner: PartnerRecord,
    extA: string,
    extB: string,
    ip?: string,
  ): Promise<{ contact: true; created: boolean }> {
    const [userAId, userBId] = await this.pair(partner, extA, extB, true);
    const blocked = await this.prisma.blockedUser.findFirst({
      where: {
        OR: [
          { blockerId: userAId, blockedId: userBId },
          { blockerId: userBId, blockedId: userAId },
        ],
      },
    });
    if (blocked) throw new ConflictException('blocked');

    const rows = await this.pairRows(userAId, userBId);
    const wasContact = rows.some((r) => r.status === 'ACCEPTED');
    if (!wasContact) {
      if (rows.length > 0) {
        // Все запросы пары, а не первый: висящий встречный запрос иначе
        // остался бы «входящим» от человека, который уже в контактах.
        await this.prisma.contactRequest.updateMany({
          where: { id: { in: rows.map((r) => r.id) } },
          data: { status: 'ACCEPTED' },
        });
      } else {
        await this.prisma.contactRequest.create({
          data: { senderId: userAId, receiverId: userBId, status: 'ACCEPTED' },
        });
      }
    }
    const record = await this.prisma.partnerContact.findUnique({
      where: { partnerId_userAId_userBId: { partnerId: partner.id, userAId, userBId } },
    });
    if (!record) {
      await this.prisma.partnerContact.create({
        data: { partnerId: partner.id, userAId, userBId, createdContact: !wasContact },
      });
    }
    if (!wasContact) {
      await this.audit.log(partner, 'CONTACT_CREATED', {
        externalId: `${extA},${extB}`,
        userId: userAId,
        ip,
        meta: { otherUserId: userBId },
      });
    }
    return { contact: true, created: !wasContact };
  }

  async remove(partner: PartnerRecord, extA: string, extB: string, ip?: string): Promise<{ contact: boolean }> {
    const [userAId, userBId] = await this.pair(partner, extA, extB, false);
    const record = await this.prisma.partnerContact.findUnique({
      where: { partnerId_userAId_userBId: { partnerId: partner.id, userAId, userBId } },
    });
    if (record) {
      // deleteMany: повторный или параллельный DELETE не падает на уже удалённой строке.
      await this.prisma.partnerContact.deleteMany({ where: { id: record.id } });
      // Снимаем только контакт, который завёл сам партнёр, и только если его
      // не держит другой партнёр. Дружба, бывшая в TalerID раньше, остаётся.
      const heldByOthers = await this.prisma.partnerContact.count({ where: { userAId, userBId } });
      if (record.createdContact && heldByOthers === 0) {
        await this.prisma.contactRequest.deleteMany({
          where: {
            OR: [
              { senderId: userAId, receiverId: userBId },
              { senderId: userBId, receiverId: userAId },
            ],
          },
        });
      }
      await this.audit.log(partner, 'CONTACT_REMOVED', {
        externalId: `${extA},${extB}`,
        userId: userAId,
        ip,
        meta: { otherUserId: userBId },
      });
    }
    const rows = await this.pairRows(userAId, userBId);
    return { contact: rows.some((r) => r.status === 'ACCEPTED') };
  }

  /** userId обоих, упорядоченные: так пара хранится в PartnerContact. */
  private async pair(partner: PartnerRecord, extA: string, extB: string, activeOnly: boolean): Promise<[string, string]> {
    assertExternalId(extA);
    assertExternalId(extB);
    if (extA === extB) throw new BadRequestException('same_user');
    const links = await this.prisma.partnerLink.findMany({
      where: {
        partnerId: partner.id,
        externalId: { in: [extA, extB] },
        ...(activeOnly ? { status: 'ACTIVE' as const, user: { deletedAt: null } } : {}),
      },
      select: { externalId: true, userId: true },
    });
    const a = links.find((l) => l.externalId === extA);
    const b = links.find((l) => l.externalId === extB);
    if (!a || !b) {
      if (activeOnly) throw new ConflictException('link_not_active');
      throw new NotFoundException('not_linked');
    }
    return [a.userId, b.userId].sort() as [string, string];
  }

  private pairRows(userAId: string, userBId: string) {
    return this.prisma.contactRequest.findMany({
      where: {
        OR: [
          { senderId: userAId, receiverId: userBId },
          { senderId: userBId, receiverId: userAId },
        ],
      },
      select: { id: true, status: true },
    });
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-api/partner-contacts.service.spec.ts`
Expected: PASS, 11 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/partner-api/partner-contacts.service.ts src/partner-api/partner-contacts.service.spec.ts
git commit -m "feat(partner): контакты TalerID по дружбе партнёра" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 18: Контроллер и модуль партнёрского API

> ⚠️ Блоки кода задачи — исторические в части `deleteUser` (теперь `DeleteUserQueryDto`) и спеки контроллера; источник правды — файлы в ветке (см. «Правки по ревью задач 18–20»).

**Files:**
- Create: `src/partner-api/partner-api.controller.ts`
- Create: `src/partner-api/partner-api.module.ts`
- Modify: `src/app.module.ts` (импорт и строка в `imports`)
- Test: `src/partner-api/partner-api.controller.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-api/partner-api.controller.spec.ts`:

```ts
import { BadRequestException } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { PartnerApiController } from './partner-api.controller';
import { PartnerKeyGuard } from './partner-key.guard';
import { PartnerRateLimitGuard } from './partner-rate-limit.guard';

describe('PartnerApiController', () => {
  const partner: any = { id: 'p1', slug: 'nadi' };
  const req: any = { partner, ip: '1.2.3.4' };
  let users: any;
  let codes: any;
  let contacts: any;
  let controller: PartnerApiController;

  beforeEach(() => {
    users = { provision: jest.fn(), getUser: jest.fn(), patchUser: jest.fn(), deleteUser: jest.fn(), issueToken: jest.fn() };
    codes = { send: jest.fn(), verify: jest.fn() };
    contacts = { put: jest.fn(), remove: jest.fn() };
    controller = new PartnerApiController(users, codes, contacts);
  });

  it('passes deleteAccount=true through and validates the externalId', async () => {
    await controller.deleteUser(req, 'm-1', 'true');
    expect(users.deleteUser).toHaveBeenCalledWith(partner, 'm-1', true, '1.2.3.4');
    await controller.deleteUser(req, 'm-1', undefined);
    expect(users.deleteUser).toHaveBeenLastCalledWith(partner, 'm-1', false, '1.2.3.4');
    expect(() => controller.getUser(req, 'bad id')).toThrow(BadRequestException);
  });

  it('hands the six-digit code to the code service', () => {
    controller.verifyLinkCode(req, 'm-1', { code: '123456' });
    expect(codes.verify).toHaveBeenCalledWith(partner, 'm-1', '123456', '1.2.3.4');
  });

  it('is guarded by the partner key and limit instead of the global per-IP throttler', () => {
    expect(Reflect.getMetadata(GUARDS_METADATA, PartnerApiController)).toEqual([
      PartnerKeyGuard,
      PartnerRateLimitGuard,
    ]);
    for (const name of ['short', 'medium', 'long']) {
      expect(Reflect.getMetadata(`THROTTLER:SKIP${name}`, PartnerApiController)).toBe(true);
    }
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-api/partner-api.controller.spec.ts`
Expected: FAIL — `Cannot find module './partner-api.controller'`.

- [ ] **Step 3: Контроллер**

Создать `src/partner-api/partner-api.controller.ts`:

```ts
import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Patch,
  Post,
  Put,
  Query,
  Req,
} from '@nestjs/common';
import type { PartnerRecord } from '../partner-core/partner-registry.service';
import { PatchUserDto } from './dto/patch-user.dto';
import { ProvisionUserDto } from './dto/provision-user.dto';
import { VerifyLinkCodeDto } from './dto/verify-link-code.dto';
import { assertExternalId } from './external-id.util';
import { PartnerApi } from './partner-api.decorator';
import { PartnerContactsService } from './partner-contacts.service';
import { PartnerLinkCodeService } from './partner-link-code.service';
import { PartnerRateBucket } from './partner-rate-limit.guard';
import { PartnerUsersService } from './partner-users.service';

interface PartnerRequest {
  partner: PartnerRecord;
  ip?: string;
}

/**
 * Партнёрский API мессенджера. Зовёт только сервер партнёра с ключом.
 * @PartnerApi(): проверка ключа, лимит по партнёру вместо глобальных лимитов
 * по IP (весь партнёр ходит с одного адреса) — см. partner-api.decorator.ts.
 * Документация для партнёров: docs/partner-messenger-api.md
 */
@Controller('partner/v1')
@PartnerApi()
export class PartnerApiController {
  constructor(
    private readonly users: PartnerUsersService,
    private readonly codes: PartnerLinkCodeService,
    private readonly contacts: PartnerContactsService,
  ) {}

  @Post('users')
  @HttpCode(200)
  provision(@Req() req: PartnerRequest, @Body() dto: ProvisionUserDto) {
    return this.users.provision(req.partner, dto, req.ip);
  }

  @Get('users/:externalId')
  getUser(@Req() req: PartnerRequest, @Param('externalId') externalId: string) {
    return this.users.getUser(req.partner, assertExternalId(externalId));
  }

  @Patch('users/:externalId')
  patchUser(
    @Req() req: PartnerRequest,
    @Param('externalId') externalId: string,
    @Body() dto: PatchUserDto,
  ) {
    return this.users.patchUser(req.partner, assertExternalId(externalId), dto, req.ip);
  }

  @Delete('users/:externalId')
  @HttpCode(204)
  async deleteUser(
    @Req() req: PartnerRequest,
    @Param('externalId') externalId: string,
    @Query('deleteAccount') deleteAccount?: string,
  ): Promise<void> {
    await this.users.deleteUser(req.partner, assertExternalId(externalId), deleteAccount === 'true', req.ip);
  }

  @Post('users/:externalId/link-code')
  @HttpCode(200)
  sendLinkCode(@Req() req: PartnerRequest, @Param('externalId') externalId: string) {
    return this.codes.send(req.partner, assertExternalId(externalId), req.ip);
  }

  @Post('users/:externalId/link-code/verify')
  @HttpCode(200)
  verifyLinkCode(
    @Req() req: PartnerRequest,
    @Param('externalId') externalId: string,
    @Body() dto: VerifyLinkCodeDto,
  ) {
    return this.codes.verify(req.partner, assertExternalId(externalId), dto.code, req.ip);
  }

  @Post('users/:externalId/token')
  @HttpCode(200)
  @PartnerRateBucket('token')
  token(@Req() req: PartnerRequest, @Param('externalId') externalId: string) {
    return this.users.issueToken(req.partner, assertExternalId(externalId));
  }

  @Put('contacts/:a/:b')
  putContact(@Req() req: PartnerRequest, @Param('a') a: string, @Param('b') b: string) {
    return this.contacts.put(req.partner, a, b, req.ip);
  }

  @Delete('contacts/:a/:b')
  removeContact(@Req() req: PartnerRequest, @Param('a') a: string, @Param('b') b: string) {
    return this.contacts.remove(req.partner, a, b, req.ip);
  }
}
```

- [ ] **Step 4: Модуль и подключение**

Создать `src/partner-api/partner-api.module.ts`:

```ts
import { Module } from '@nestjs/common';
import { PartnerCoreModule } from '../partner-core/partner-core.module';
import { ProfileModule } from '../profile/profile.module';
import { SystemChannelModule } from '../system-channel/system-channel.module';
import { PartnerApiController } from './partner-api.controller';
import { PartnerAuditService } from './partner-audit.service';
import { PartnerContactsService } from './partner-contacts.service';
import { PartnerKeyGuard } from './partner-key.guard';
import { PartnerLinkCodeService } from './partner-link-code.service';
import { PartnerRateLimitGuard } from './partner-rate-limit.guard';
import { PartnerUsersService } from './partner-users.service';

// PrismaModule, RedisModule и EmailModule глобальные.
@Module({
  imports: [PartnerCoreModule, SystemChannelModule, ProfileModule],
  controllers: [PartnerApiController],
  providers: [
    PartnerKeyGuard,
    PartnerRateLimitGuard,
    PartnerAuditService,
    PartnerUsersService,
    PartnerLinkCodeService,
    PartnerContactsService,
  ],
})
export class PartnerApiModule {}
```

В `src/app.module.ts` после `import { PartnerModule } from './partner/partner.module';` добавить:

```ts
import { PartnerApiModule } from './partner-api/partner-api.module';
```

и в массиве `imports` после строки `PartnerModule,` добавить `PartnerApiModule,`.

- [ ] **Step 5: Тесты и сборка**

Run: `npx jest src/partner-api && npm run build`
Expected: PASS (все наборы `src/partner-api`), сборка без ошибок.

- [ ] **Step 6: Commit**

```bash
git add src/partner-api/partner-api.controller.ts src/partner-api/partner-api.controller.spec.ts src/partner-api/partner-api.module.ts src/app.module.ts
git commit -m "feat(partner): ручки /partner/v1 и модуль партнёрского API" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 19: Удаление аккаунта отзывает партнёрские связки

**Files:**
- Modify: `src/profile/profile.service.ts` (конструктор, `deleteAccount`)
- Modify: `src/profile/profile.module.ts`
- Modify: `src/profile/profile.service.spec.ts`, `src/profile/profile.service.delete-account.spec.ts`

- [ ] **Step 1: Написать падающий тест**

В `src/profile/profile.service.delete-account.spec.ts`:
- после импорта `FileStorageService` добавить `import { PartnerLinkRevokerService } from '../partner-core/partner-link-revoker.service';`;
- после объявления `mockFileStorage` добавить `const mockPartnerLinks = { revokeAllForUser: jest.fn().mockResolvedValue(0) };`;
- в `providers` тестового модуля добавить `{ provide: PartnerLinkRevokerService, useValue: mockPartnerLinks },`;
- в конец `describe('ProfileService.deleteAccount', …)` добавить тест:

```ts
  it('revokes partner links so partners lose access at once', async () => {
    mockPrisma.profile.findUnique.mockResolvedValue({ id: 'profile-1', userId: 'user-1' });
    await service.deleteAccount('user-1');
    expect(mockPartnerLinks.revokeAllForUser).toHaveBeenCalledWith('user-1');
  });

  it('still deletes the account when partner revocation fails', async () => {
    mockPrisma.profile.findUnique.mockResolvedValue({ id: 'profile-1', userId: 'user-1' });
    mockPartnerLinks.revokeAllForUser.mockRejectedValueOnce(new Error('redis down'));
    await expect(service.deleteAccount('user-1')).resolves.toEqual({ success: true });
  });
```

В `src/profile/profile.service.spec.ts` добавить такой же импорт и в `providers` строку:

```ts
        { provide: PartnerLinkRevokerService, useValue: { revokeAllForUser: jest.fn().mockResolvedValue(0) } },
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/profile`
Expected: FAIL — новый тест: `expect(jest.fn()).toHaveBeenCalledWith(...)`, вызовов 0.

- [ ] **Step 3: Реализация**

В `src/profile/profile.service.ts`:
- добавить импорт `import { PartnerLinkRevokerService } from '../partner-core/partner-link-revoker.service';`;
- конструктор:

```ts
  constructor(
    private prisma: PrismaService,
    private fileStorage: FileStorageService,
    private partnerLinks: PartnerLinkRevokerService,
  ) {}
```

- в `deleteAccount` между закрывающей `]);` транзакции и `return { success: true };` вставить:

```ts
    // Партнёры (nadi) теряют доступ сразу, а не когда истекут выданные токены:
    // человек удалил аккаунт — его чатов не должен видеть никто. Сбой отзыва
    // не отменяет удаления: новых токенов партнёр уже не получит (аккаунт
    // удалён), выданные доживут не дольше 15 минут, а недоделанный отзыв
    // добьёт следующий DELETE связки партнёром.
    try {
      await this.partnerLinks.revokeAllForUser(userId);
    } catch (e) {
      this.logger.error(`partner links not fully revoked for ${userId}: ${(e as Error).message}`);
    }
```

и в класс — поле `private readonly logger = new Logger(ProfileService.name);` (добавить `Logger` в импорт из `@nestjs/common`, если его там нет).

В `src/profile/profile.module.ts` добавить импорт `import { PartnerCoreModule } from '../partner-core/partner-core.module';` и в декоратор `@Module({ … })` строку `imports: [PartnerCoreModule],`.

- [ ] **Step 4: Тесты и сборка**

Run: `npx jest src/profile && npm run build`
Expected: новые и прежние тесты профиля — как в базе плюс новый зелёный; сборка без ошибок.

- [ ] **Step 5: Commit**

```bash
git add src/profile/profile.service.ts src/profile/profile.module.ts src/profile/profile.service.spec.ts src/profile/profile.service.delete-account.spec.ts
git commit -m "feat(profile): удаление аккаунта отзывает партнёрские связки" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 20: Скрипт администратора партнёров

> ⚠️ Блоки кода задачи — исторические в части вывода секретов и нормализации IPv6; источник правды — `scripts/partner-admin.ts` в ветке (см. «Правки по ревью задач 18–20»).

**Files:**
- Create: `scripts/partner-admin.ts`

- [ ] **Step 1: Скрипт**

Создать `scripts/partner-admin.ts`:

```ts
/**
 * Партнёры партнёрского API мессенджера (первый — nadi): выпуск, ключи, вебхук.
 * Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 *
 * Запуск на сервере окружения из каталога бэкенда:
 *   npx ts-node -r dotenv/config scripts/partner-admin.ts <команда> [флаги]
 *
 * Ключ и секрет вебхука показываются один раз. С --out <файл> [--var ИМЯ] они
 * не печатаются, а дописываются в файл строкой ИМЯ=значение с правами 600 —
 * так секрет не оседает в истории терминала и в логах сессий.
 * Бэкенд кэширует партнёров 30 секунд — изменения доходят за это время.
 */
import { PrismaClient } from '@prisma/client';
import { randomBytes } from 'crypto';
import * as fs from 'fs';
import { isIP } from 'net';
import { generatePartnerKey, hashPartnerKey, isValidPartnerSlug } from '../src/partner-core/partner-key.util';
import { encryptWebhookSecret, generateWebhookSecret } from '../src/partner-core/partner-secrets.util';
import { MESSENGER_SCOPE } from '../src/partner-core/partner.constants';

const prisma = new PrismaClient();

type Flags = Record<string, string>;

const USAGE = `Использование: npx ts-node -r dotenv/config scripts/partner-admin.ts <команда> [флаги]
  create        --slug <slug> --name <имя> [--ips a,b] [--out файл [--var ИМЯ]]
  rotate-key    --slug <slug> [--out файл [--var ИМЯ]]
  set-webhook   --slug <slug> --url https://… [--out файл [--var ИМЯ]]
  clear-webhook --slug <slug>
  set-ips       --slug <slug> --ips a,b | --clear   (точные адреса, без CIDR; --clear — без ограничения)
  enable | disable --slug <slug>
  show          --slug <slug>`;

/**
 * Флаги команды. Незнакомый флаг — ошибка: опечатка `--ip` вместо `--ips`
 * иначе молча сняла бы белый список партнёра на PROD.
 */
function parseFlags(argv: string[], allowed: readonly string[]): Flags {
  const flags: Flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) throw new Error(`непонятный аргумент: ${arg}`);
    const name = arg.slice(2);
    if (!allowed.includes(name)) throw new Error(`флаг --${name} этой команде неизвестен`);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags[name] = next;
      i++;
    } else {
      flags[name] = '';
    }
  }
  return flags;
}

function slugOf(flags: Flags): string {
  const slug = flags.slug ?? '';
  if (!isValidPartnerSlug(slug)) throw new Error('--slug обязателен: a-z, 0-9 и дефис, 2–32 символа');
  return slug;
}

/**
 * Белый список — только точные адреса, как их видит бэкенд (IPv4 без ::ffff:).
 * Маски guard не понимает: запись с CIDR никогда бы не совпала.
 */
function ipsOf(value: string): string[] {
  const ips = value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (ips.length === 0) throw new Error('--ips без адресов; снять ограничение — set-ips --clear');
  for (const ip of ips) {
    if (isIP(ip) === 0 || /^::ffff:/i.test(ip)) {
      throw new Error(`не IP-адрес: ${ip} (нужен точный IPv4 или IPv6, без маски и без ::ffff:)`);
    }
  }
  return ips;
}

/** Секрет — в файл с правами 600, либо на экран, если файл не указан. */
function reveal(flags: Flags, defaultVar: string, value: string, what: string): void {
  if (flags.out) {
    const name = flags.var || defaultVar;
    fs.appendFileSync(flags.out, `${name}=${value}\n`, { mode: 0o600 });
    fs.chmodSync(flags.out, 0o600);
    console.log(`${what} записан в ${flags.out} как ${name}`);
  } else {
    console.log(`${what} (показывается один раз, передавать вне чатов):\n${value}`);
  }
}

async function partnerOrFail(slug: string) {
  const partner = await prisma.partner.findUnique({ where: { slug } });
  if (!partner) throw new Error(`партнёра ${slug} нет — сначала create`);
  return partner;
}

async function create(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  const name = flags.name;
  if (!name) throw new Error('--name обязателен: так партнёр называется в письмах людям');
  const ips = flags.ips === undefined ? [] : ipsOf(flags.ips);
  if (await prisma.partner.findUnique({ where: { slug } })) {
    throw new Error(`партнёр ${slug} уже есть — для нового ключа rotate-key`);
  }
  const clientId = `${slug}-partner`;
  const clientName = `${name} (partner messenger)`;
  // Чужой клиент не трогаем: `--slug linkeon` иначе переписал бы живой клиент
  // linkeon-partner и сломал бы Linkeon на PROD.
  if (await prisma.oAuthClient.findUnique({ where: { clientId } })) {
    throw new Error(`OAuth-клиент ${clientId} уже существует — это не наш клиент, выберите другой slug`);
  }
  const key = generatePartnerKey(slug);
  // Токены выпускает сам бэкенд; в /oauth/token с этим клиентом никто не ходит,
  // поэтому секрет клиента случайный и нигде, кроме БД, не нужен. Клиент и
  // партнёр — одной транзакцией: сбой не оставит клиента без партнёра.
  await prisma.$transaction([
    prisma.oAuthClient.create({
      data: {
        clientId,
        clientSecret: randomBytes(32).toString('hex'),
        name: clientName,
        redirectUris: [],
        allowedScopes: [MESSENGER_SCOPE],
        verifiedPartner: true,
        isDynamic: false,
      },
    }),
    prisma.partner.create({
      data: { slug, name, keyHash: hashPartnerKey(key), ipAllowlist: ips, oauthClientId: clientId },
    }),
  ]);
  console.log(`Партнёр ${slug} создан (OAuth-клиент ${clientId}).`);
  reveal(flags, 'TALERID_PARTNER_KEY', key, 'Ключ партнёра');
}

async function rotateKey(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  await partnerOrFail(slug);
  const key = generatePartnerKey(slug);
  await prisma.partner.update({ where: { slug }, data: { keyHash: hashPartnerKey(key) } });
  reveal(flags, 'TALERID_PARTNER_KEY', key, 'Новый ключ партнёра');
}

async function setWebhook(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  await partnerOrFail(slug);
  let url: URL;
  try {
    url = new URL(flags.url ?? '');
  } catch {
    throw new Error('--url должен быть полным адресом https://…');
  }
  if (url.protocol !== 'https:') throw new Error('вебхук только по https');
  const secret = generateWebhookSecret();
  await prisma.partner.update({
    where: { slug },
    data: { webhookUrl: url.toString(), webhookSecretEnc: encryptWebhookSecret(secret) },
  });
  console.log(`Вебхук ${slug} → ${url.toString()}`);
  reveal(flags, 'TALERID_WEBHOOK_SECRET', secret, 'Секрет вебхука');
}

async function clearWebhook(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  await partnerOrFail(slug);
  await prisma.partner.update({ where: { slug }, data: { webhookUrl: null, webhookSecretEnc: null } });
  console.log(`Вебхук ${slug} снят.`);
}

async function setIps(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  // Снять ограничение — только явно: пустой список пускает партнёра с любого адреса.
  if ((flags.ips === undefined) === (flags.clear === undefined)) {
    throw new Error('нужен ровно один из флагов: --ips a,b или --clear');
  }
  if (flags.clear) throw new Error('--clear пишется без значения');
  const ips = flags.clear !== undefined ? [] : ipsOf(flags.ips);
  await partnerOrFail(slug);
  await prisma.partner.update({ where: { slug }, data: { ipAllowlist: ips } });
  console.log(`IP ${slug}: ${ips.length ? ips.join(', ') : 'без ограничения'}`);
}

async function setEnabled(flags: Flags, enabled: boolean): Promise<void> {
  const slug = slugOf(flags);
  await partnerOrFail(slug);
  await prisma.partner.update({ where: { slug }, data: { enabled } });
  console.log(`Партнёр ${slug} ${enabled ? 'включён' : 'выключен'} (бэкенд увидит за 30 с).`);
}

async function show(flags: Flags): Promise<void> {
  const partner = await partnerOrFail(slugOf(flags));
  const links = await prisma.partnerLink.groupBy({
    by: ['status'],
    where: { partnerId: partner.id },
    _count: { _all: true },
  });
  console.log({
    slug: partner.slug,
    name: partner.name,
    enabled: partner.enabled,
    oauthClientId: partner.oauthClientId,
    ipAllowlist: partner.ipAllowlist,
    webhookUrl: partner.webhookUrl,
    webhookSecret: partner.webhookSecretEnc ? 'задан' : 'нет',
    links: Object.fromEntries(links.map((l) => [l.status, l._count._all])),
  });
}

const OUT = ['out', 'var'];
const COMMANDS: Record<string, { flags: readonly string[]; run: (flags: Flags) => Promise<void> }> = {
  create: { flags: ['slug', 'name', 'ips', ...OUT], run: create },
  'rotate-key': { flags: ['slug', ...OUT], run: rotateKey },
  'set-webhook': { flags: ['slug', 'url', ...OUT], run: setWebhook },
  'clear-webhook': { flags: ['slug'], run: clearWebhook },
  'set-ips': { flags: ['slug', 'ips', 'clear'], run: setIps },
  enable: { flags: ['slug'], run: (flags) => setEnabled(flags, true) },
  disable: { flags: ['slug'], run: (flags) => setEnabled(flags, false) },
  show: { flags: ['slug'], run: show },
};

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const entry =
    command && Object.prototype.hasOwnProperty.call(COMMANDS, command) ? COMMANDS[command] : undefined;
  if (!entry) {
    console.log(USAGE);
    process.exitCode = command && command !== 'help' ? 1 : 0;
    return;
  }
  await entry.run(parseFlags(rest, entry.flags));
}

main()
  .catch((e) => {
    console.error(`Ошибка: ${(e as Error).message}`);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
```

- [ ] **Step 2: Проверить без базы**

```bash
npx ts-node scripts/partner-admin.ts help; echo "exit=$?"
npx ts-node scripts/partner-admin.ts create --name Nadi; echo "exit=$?"
PARTNER_SECRETS_KEY= npx ts-node scripts/partner-admin.ts set-webhook --slug Bad_Slug; echo "exit=$?"
npx ts-node scripts/partner-admin.ts set-ips --slug nadi --ip 1.2.3.4; echo "exit=$?"
npx ts-node scripts/partner-admin.ts set-ips --slug nadi; echo "exit=$?"
npx ts-node scripts/partner-admin.ts create --slug nadi --name Nadi --ips 10.0.0.0/8; echo "exit=$?"
```

Expected: 1) справка и `exit=0`; 2) `Ошибка: --slug обязателен…` и `exit=1`; 3) `Ошибка: --slug обязателен…` и `exit=1`; 4) `Ошибка: флаг --ip этой команде неизвестен` и `exit=1`; 5) `Ошибка: нужен ровно один из флагов…` и `exit=1`; 6) `Ошибка: не IP-адрес: 10.0.0.0/8…` и `exit=1`. До БД ни одна команда не дошла — проверки аргументов идут раньше.

- [ ] **Step 3: Commit**

```bash
git add scripts/partner-admin.ts
git commit -m "feat(partner): скрипт выпуска партнёров, ключей и секретов вебхука" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 21: Исправление — принять запрос в контакты может только получатель

**Files:**
- Modify: `src/messenger/messenger.service.ts` (`acceptContactRequest`)
- Test: `src/messenger/messenger.service.contacts.spec.ts`

- [ ] **Step 1: Написать падающий тест**

В конец `src/messenger/messenger.service.contacts.spec.ts` добавить:

```ts
describe('MessengerService.acceptContactRequest', () => {
  function make(request: any) {
    const prisma: any = {
      contactRequest: {
        findUnique: jest.fn().mockResolvedValue(request),
        update: jest.fn().mockResolvedValue({}),
      },
    };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;
    (service as any).getOrCreateDirectConversation = jest.fn().mockResolvedValue({ id: 'conv-1' });
    return { service, prisma };
  }

  it('refuses the sender accepting their own request', async () => {
    const { service, prisma } = make({ id: 'r1', senderId: 'me', receiverId: 'u2', status: 'PENDING' });
    await expect(service.acceptContactRequest('r1', 'me')).rejects.toThrow('Not your request');
    expect(prisma.contactRequest.update).not.toHaveBeenCalled();
  });

  it('lets the receiver accept', async () => {
    const { service, prisma } = make({ id: 'r1', senderId: 'u2', receiverId: 'me', status: 'PENDING' });
    await expect(service.acceptContactRequest('r1', 'me')).resolves.toEqual({
      senderId: 'u2',
      receiverId: 'me',
      conversationId: 'conv-1',
    });
    expect(prisma.contactRequest.update).toHaveBeenCalledWith({ where: { id: 'r1' }, data: { status: 'ACCEPTED' } });
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/messenger/messenger.service.contacts.spec.ts`
Expected: FAIL — `refuses the sender accepting their own request`: промис разрешился вместо отказа.

- [ ] **Step 3: Исправление**

В `src/messenger/messenger.service.ts`, метод `acceptContactRequest`, заменить

```ts
    if (request.receiverId !== userId && request.senderId !== userId) {
      throw new ForbiddenException('Not your request');
    }
```

на

```ts
    // Принять запрос может только тот, кому он адресован. Раньше его мог
    // «принять» и сам отправитель — и стать контактом без согласия второго.
    if (request.receiverId !== userId) {
      throw new ForbiddenException('Not your request');
    }
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/messenger/messenger.service.contacts.spec.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/messenger/messenger.service.ts src/messenger/messenger.service.contacts.spec.ts
git commit -m "fix(контакты): принять запрос может только получатель, а не отправитель" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 22: Исправление — разблокировка возвращает только бывший контакт

> ⚠️ `unblockUser` в блоке ниже — исторический: после ревью он атомарный и учитывает встречную блокировку (см. «Правки по ревью задач 21–23»).

**Files:**
- Modify: `src/messenger/messenger.service.ts` (`blockUser`, `unblockUser`)
- Test: `src/messenger/messenger.service.block.spec.ts` (новый)

- [ ] **Step 1: Написать падающий тест**

Создать `src/messenger/messenger.service.block.spec.ts`:

```ts
import { MessengerService } from './messenger.service';

function make() {
  const prisma: any = {
    contactRequest: {
      findFirst: jest.fn().mockResolvedValue(null),
      deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
      create: jest.fn().mockResolvedValue({}),
      update: jest.fn().mockResolvedValue({}),
    },
    blockedUser: {
      create: jest.fn().mockResolvedValue({}),
      findFirst: jest.fn().mockResolvedValue(null),
      deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
  };
  const service = Object.create(MessengerService.prototype) as MessengerService;
  (service as any).prisma = prisma;
  return { service, prisma };
}

describe('MessengerService block and unblock', () => {
  it('remembers that they were contacts when blocking', async () => {
    const { service, prisma } = make();
    prisma.contactRequest.findFirst.mockResolvedValue({ id: 'c1', status: 'ACCEPTED' });
    await service.blockUser('me', 'u2');
    expect(prisma.contactRequest.deleteMany).toHaveBeenCalled();
    expect(prisma.blockedUser.create).toHaveBeenCalledWith({
      data: { blockerId: 'me', blockedId: 'u2', hadContact: true },
    });
  });

  it('records hadContact=false when they were not contacts', async () => {
    const { service, prisma } = make();
    await service.blockUser('me', 'u2');
    expect(prisma.blockedUser.create).toHaveBeenCalledWith({
      data: { blockerId: 'me', blockedId: 'u2', hadContact: false },
    });
  });

  it('does not invent a contact on unblock', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.findFirst.mockResolvedValue({ hadContact: false });
    await service.unblockUser('me', 'u2');
    expect(prisma.blockedUser.deleteMany).toHaveBeenCalledWith({ where: { blockerId: 'me', blockedId: 'u2' } });
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
    expect(prisma.contactRequest.update).not.toHaveBeenCalled();
  });

  it('restores the contact that existed before the block', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.findFirst.mockResolvedValue({ hadContact: true });
    await service.unblockUser('me', 'u2');
    expect(prisma.contactRequest.create).toHaveBeenCalledWith({
      data: { senderId: 'me', receiverId: 'u2', status: 'ACCEPTED' },
    });
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/messenger/messenger.service.block.spec.ts`
Expected: FAIL — в `create` нет `hadContact`; `does not invent a contact on unblock` — `contactRequest.create` вызван.

- [ ] **Step 3: Исправление**

В `src/messenger/messenger.service.ts` заменить методы `blockUser` и `unblockUser` целиком:

```ts
  async blockUser(myId: string, targetId: string) {
    // Запоминаем, были ли контактами: разблокировка вернёт только такой
    // контакт. Раньше она создавала его всегда, и блок с разблоком делали
    // контактами людей, которые ими не были.
    const hadContact = await this.hasContactWith(myId, targetId);
    // Delete contact relationship first
    await this.deleteContact(myId, targetId);
    // Create block record
    try {
      await this.prisma.blockedUser.create({
        data: { blockerId: myId, blockedId: targetId, hadContact },
      });
    } catch (_) {}
    return { ok: true };
  }

  async unblockUser(myId: string, targetId: string) {
    const block = await this.prisma.blockedUser.findFirst({
      where: { blockerId: myId, blockedId: targetId },
    });
    await this.prisma.blockedUser.deleteMany({
      where: { blockerId: myId, blockedId: targetId },
    });
    if (!block?.hadContact) return { ok: true };
    // Restore contact relationship so they don't need to re-add each other
    const existing = await this.prisma.contactRequest.findFirst({
      where: {
        OR: [
          { senderId: myId, receiverId: targetId },
          { senderId: targetId, receiverId: myId },
        ],
      },
    });
    if (!existing) {
      await this.prisma.contactRequest.create({
        data: { senderId: myId, receiverId: targetId, status: 'ACCEPTED' },
      });
    } else if (existing.status !== 'ACCEPTED') {
      await this.prisma.contactRequest.update({
        where: { id: existing.id },
        data: { status: 'ACCEPTED' },
      });
    }
    return { ok: true };
  }
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/messenger/messenger.service.block.spec.ts`
Expected: PASS, 4 теста.

- [ ] **Step 5: Commit**

```bash
git add src/messenger/messenger.service.ts src/messenger/messenger.service.block.spec.ts
git commit -m "fix(контакты): разблокировка возвращает только контакт, бывший до блокировки" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 23: Управляемые аккаунты не видны в глобальном поиске

**Files:**
- Modify: `src/messenger/messenger.service.ts` (`searchUsers`)
- Test: `src/messenger/messenger.service.search.spec.ts` (новый)

- [ ] **Step 1: Написать падающий тест**

Создать `src/messenger/messenger.service.search.spec.ts`:

```ts
import { MessengerService } from './messenger.service';

describe('MessengerService.searchUsers', () => {
  it('hides partner-managed accounts, both by name and by phone', async () => {
    const prisma: any = { user: { findMany: jest.fn().mockResolvedValue([]) } };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;
    await service.searchUsers('ivan', 'me');
    await service.searchUsers('+380501234567', 'me');
    expect(prisma.user.findMany).toHaveBeenCalledTimes(2);
    for (const [args] of prisma.user.findMany.mock.calls) {
      expect(args.where.NOT).toEqual({
        passwordHash: null,
        createdByPartnerId: { not: null },
      });
    }
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/messenger/messenger.service.search.spec.ts`
Expected: FAIL — `args.where.NOT` равен `undefined`.

- [ ] **Step 3: Реализация**

В `src/messenger/messenger.service.ts`, метод `searchUsers`, в объект `where` после строки `deletedAt: null,` добавить:

```ts
        // Аккаунты, которые завёл партнёр (nadi) и в которые человек сам не
        // входил: он не регистрировался в TalerID и не соглашался показывать
        // почту незнакомым. Задал пароль, чтобы войти в TalerID, — стал виден.
        NOT: { passwordHash: null, createdByPartnerId: { not: null } },
```

- [ ] **Step 4: Тест проходит, сборка**

Run: `npx jest src/messenger/messenger.service.search.spec.ts && npm run build`
Expected: PASS; сборка без ошибок (поле `User.createdByPartnerId` появилось в правках по ревью задач 14–15).

- [ ] **Step 5: Commit**

```bash
git add src/messenger/messenger.service.ts src/messenger/messenger.service.search.spec.ts
git commit -m "feat(messenger): аккаунты, заведённые партнёром, не видны в глобальном поиске" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 24: Область бесед партнёрского токена

**Files:**
- Create: `src/messenger/partner-conversation-scope.service.ts`
- Test: `src/messenger/partner-conversation-scope.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/messenger/partner-conversation-scope.service.spec.ts`:

```ts
import { ForbiddenException } from '@nestjs/common';
import { PartnerConversationScope } from './partner-conversation-scope.service';

describe('PartnerConversationScope', () => {
  let prisma: any;
  let scope: PartnerConversationScope;

  beforeEach(() => {
    prisma = {
      conversation: { findUnique: jest.fn() },
      message: { findUnique: jest.fn() },
      conversationParticipant: { findMany: jest.fn() },
      contactRequest: { findMany: jest.fn() },
    };
    scope = new PartnerConversationScope(prisma);
  });

  it.each(['DIRECT', 'GROUP'])('allows %s conversations', async (type: string) => {
    prisma.conversation.findUnique.mockResolvedValue({ type });
    await expect(scope.assertConversation('c1')).resolves.toBeUndefined();
  });

  it.each(['CHANNEL', 'SAVED', 'AI_ANALYST', 'AI_ASSISTANT'])('refuses %s conversations', async (type: string) => {
    prisma.conversation.findUnique.mockResolvedValue({ type });
    await expect(scope.assertConversation('c1')).rejects.toThrow(ForbiddenException);
  });

  it('leaves unknown ids and missing params to the handler', async () => {
    prisma.conversation.findUnique.mockResolvedValue(null);
    await expect(scope.assertConversation('ghost')).resolves.toBeUndefined();
    await expect(scope.assertConversation(undefined)).resolves.toBeUndefined();
    expect(prisma.conversation.findUnique).toHaveBeenCalledTimes(1);
  });

  it('checks the conversation of a message', async () => {
    prisma.message.findUnique.mockResolvedValue({ conversation: { type: 'SAVED' } });
    await expect(scope.assertMessage('m1')).rejects.toThrow(ForbiddenException);
    prisma.message.findUnique.mockResolvedValue({ conversation: { type: 'GROUP' } });
    await expect(scope.assertMessage('m2')).resolves.toBeUndefined();
  });

  it('lists only direct chats and groups as visible', async () => {
    prisma.conversationParticipant.findMany.mockResolvedValue([{ conversationId: 'c1' }, { conversationId: 'c3' }]);
    await expect(scope.visibleConversationIds('u1')).resolves.toEqual(new Set(['c1', 'c3']));
    expect(prisma.conversationParticipant.findMany).toHaveBeenCalledWith({
      where: { userId: 'u1', conversation: { type: { in: ['DIRECT', 'GROUP'] } } },
      select: { conversationId: true },
    });
  });

  it('names the people who are not contacts', async () => {
    prisma.contactRequest.findMany.mockResolvedValue([
      { senderId: 'u1', receiverId: 'u2' },
      { senderId: 'u3', receiverId: 'u1' },
    ]);
    await expect(scope.assertAllContacts('u1', ['u2', 'u3'])).resolves.toBeUndefined();
    prisma.contactRequest.findMany.mockResolvedValue([{ senderId: 'u1', receiverId: 'u2' }]);
    const err = await scope.assertAllContacts('u1', ['u2', 'u4', 'u1']).catch((e) => e);
    expect(err).toBeInstanceOf(ForbiddenException);
    expect(err.getResponse()).toEqual({ message: 'not_a_contact', userIds: ['u4'] });
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/messenger/partner-conversation-scope.service.spec.ts`
Expected: FAIL — `Cannot find module './partner-conversation-scope.service'`.

- [ ] **Step 3: Реализация**

Создать `src/messenger/partner-conversation-scope.service.ts`:

```ts
import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  isPartnerConversationType,
  PARTNER_CONVERSATION_TYPES,
  PARTNER_FORBIDDEN,
} from '../partner-core/partner.constants';

/**
 * Что можно партнёрскому токену в мессенджере сверх обычных прав участника:
 * только личные чаты и группы (канал новостей TalerID, «Избранное» и чаты
 * AI-ассистентов в интерфейс партнёра не попадают) и группы только из своих
 * контактов. Спека: 2026-09-30-partner-messenger-api-design.md
 */
@Injectable()
export class PartnerConversationScope {
  constructor(private readonly prisma: PrismaService) {}

  /** Беседа другого типа — 403. Несуществующая — пропускаем: ответит обработчик. */
  async assertConversation(conversationId: string | undefined): Promise<void> {
    if (!conversationId) return;
    const conv = await this.prisma.conversation.findUnique({
      where: { id: conversationId },
      select: { type: true },
    });
    if (conv && !isPartnerConversationType(conv.type)) throw new ForbiddenException(PARTNER_FORBIDDEN);
  }

  async assertMessage(messageId: string | undefined): Promise<void> {
    if (!messageId) return;
    const msg = await this.prisma.message.findUnique({
      where: { id: messageId },
      select: { conversation: { select: { type: true } } },
    });
    if (msg && !isPartnerConversationType(msg.conversation.type)) {
      throw new ForbiddenException(PARTNER_FORBIDDEN);
    }
  }

  /** Беседы пользователя, видимые партнёрскому токену, — для фильтрации списков. */
  async visibleConversationIds(userId: string): Promise<Set<string>> {
    const rows = await this.prisma.conversationParticipant.findMany({
      where: { userId, conversation: { type: { in: [...PARTNER_CONVERSATION_TYPES] } } },
      select: { conversationId: true },
    });
    return new Set(rows.map((r) => r.conversationId));
  }

  /** В группу — только свои контакты (у партнёра это его «друзья»). */
  async assertAllContacts(userId: string, targetIds: string[]): Promise<void> {
    const others = [...new Set(targetIds ?? [])].filter((id) => id !== userId);
    if (others.length === 0) return;
    const rows = await this.prisma.contactRequest.findMany({
      where: {
        status: 'ACCEPTED',
        OR: [
          { senderId: userId, receiverId: { in: others } },
          { receiverId: userId, senderId: { in: others } },
        ],
      },
      select: { senderId: true, receiverId: true },
    });
    const contacts = new Set(rows.map((r) => (r.senderId === userId ? r.receiverId : r.senderId)));
    const missing = others.filter((id) => !contacts.has(id));
    if (missing.length > 0) throw new ForbiddenException({ message: 'not_a_contact', userIds: missing });
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/messenger/partner-conversation-scope.service.spec.ts`
Expected: PASS, 10 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/messenger/partner-conversation-scope.service.ts src/messenger/partner-conversation-scope.service.spec.ts
git commit -m "feat(messenger): партнёрскому токену — только личные чаты и группы из контактов" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 25: `@PartnerAllowed` и `MessengerAuthGuard`

**Files:**
- Create: `src/messenger/partner-allowed.decorator.ts`
- Create: `src/messenger/messenger-auth.guard.ts`
- Modify: `src/messenger/messenger.module.ts` (импорт `PartnerCoreModule`, провайдер `PartnerConversationScope`)
- Test: `src/messenger/messenger-auth.guard.spec.ts`

- [ ] **Step 1: Декоратор**

Создать `src/messenger/partner-allowed.decorator.ts`:

```ts
import { SetMetadata } from '@nestjs/common';

export const PARTNER_ALLOWED_KEY = 'partnerAllowed';

export interface PartnerAllowedOptions {
  /** Параметр маршрута с id беседы: беседа не того типа закрыта для партнёра. */
  conversationParam?: string;
  /** Параметр маршрута с id сообщения: то же по беседе этого сообщения. */
  messageParam?: string;
}

/**
 * Открывает обработчик мессенджера для партнёрского токена. Без декоратора
 * партнёр получает 403 — новые ручки закрыты для партнёров, пока их не откроют.
 */
export const PartnerAllowed = (options: PartnerAllowedOptions = {}) =>
  SetMetadata(PARTNER_ALLOWED_KEY, options);
```

- [ ] **Step 2: Написать падающий тест guard'а**

Создать `src/messenger/messenger-auth.guard.spec.ts`:

```ts
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { generateKeyPairSync } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as jwt from 'jsonwebtoken';
import { Public } from '../common/decorators/public.decorator';
import { MessengerAuthGuard } from './messenger-auth.guard';
import { PartnerAllowed } from './partner-allowed.decorator';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const keyPath = path.join(os.tmpdir(), `messenger-auth-guard-${process.pid}.pem`);
fs.writeFileSync(keyPath, publicKey);

class Handlers {
  @PartnerAllowed({ conversationParam: 'id' })
  allowed() {}

  @PartnerAllowed({ messageParam: 'id' })
  byMessage() {}

  notForPartners() {}

  @Public()
  open() {}
}

function ctx(handler: keyof Handlers, req: any) {
  return {
    getHandler: () => Handlers.prototype[handler],
    getClass: () => Handlers,
    switchToHttp: () => ({ getRequest: () => req }),
  } as any;
}

const principal = { userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1', expiresAt: 1_900_000_000 };

describe('MessengerAuthGuard', () => {
  let tokens: any;
  let scope: any;
  let guard: MessengerAuthGuard;

  beforeEach(() => {
    tokens = { verify: jest.fn().mockResolvedValue(null) };
    scope = {
      assertConversation: jest.fn().mockResolvedValue(undefined),
      assertMessage: jest.fn().mockResolvedValue(undefined),
    };
    const config: any = { get: (key: string) => (key === 'jwt.publicKeyPath' ? keyPath : undefined) };
    guard = new MessengerAuthGuard(new Reflector(), tokens, scope, config);
  });
  afterAll(() => fs.unlinkSync(keyPath));

  it('lets public routes through without a token', async () => {
    await expect(guard.canActivate(ctx('open', { headers: {} }))).resolves.toBe(true);
  });

  it('accepts the TalerID access token exactly as before, on any handler', async () => {
    const token = jwt.sign({ sub: 'u1', typ: 'access' }, privateKey, { algorithm: 'RS256', expiresIn: 60 });
    const req: any = { headers: { authorization: `Bearer ${token}` }, params: {} };
    await expect(guard.canActivate(ctx('notForPartners', req))).resolves.toBe(true);
    expect(req.user).toMatchObject({ sub: 'u1', typ: 'access' });
    expect(tokens.verify).not.toHaveBeenCalled();
  });

  it('does not take an OIDC id_token signed with the same key for an access token', async () => {
    const idToken = jwt.sign({ sub: 'u1', aud: 'client', iss: 'https://x/oauth' }, privateKey, {
      algorithm: 'RS256',
      expiresIn: 60,
    });
    const req = { headers: { authorization: `Bearer ${idToken}` }, params: {} };
    await expect(guard.canActivate(ctx('allowed', req))).rejects.toThrow(UnauthorizedException);
  });

  it('lets a partner token into an allowed handler and checks the conversation type', async () => {
    tokens.verify.mockResolvedValue(principal);
    const req: any = { headers: { authorization: 'Bearer opaque' }, params: { id: 'conv-1' } };
    await expect(guard.canActivate(ctx('allowed', req))).resolves.toBe(true);
    expect(req.user).toEqual({ sub: 'u1', partner: principal });
    expect(scope.assertConversation).toHaveBeenCalledWith('conv-1');
  });

  it('checks the conversation of the message on message routes', async () => {
    tokens.verify.mockResolvedValue(principal);
    await guard.canActivate(ctx('byMessage', { headers: { authorization: 'Bearer opaque' }, params: { id: 'msg-1' } }));
    expect(scope.assertMessage).toHaveBeenCalledWith('msg-1');
  });

  it('403 for a partner token on a handler not opened to partners', async () => {
    tokens.verify.mockResolvedValue(principal);
    const req = { headers: { authorization: 'Bearer opaque' }, params: {} };
    await expect(guard.canActivate(ctx('notForPartners', req))).rejects.toThrow(ForbiddenException);
  });

  it('passes on the 403 for a conversation of another type', async () => {
    tokens.verify.mockResolvedValue(principal);
    scope.assertConversation.mockRejectedValue(new ForbiddenException('not_available_for_partner'));
    const req = { headers: { authorization: 'Bearer opaque' }, params: { id: 'channel-1' } };
    await expect(guard.canActivate(ctx('allowed', req))).rejects.toThrow(ForbiddenException);
  });

  it.each([undefined, 'Basic abc', 'Bearer'])('401 for authorization header %p', async (header: string | undefined) => {
    const req = { headers: { authorization: header }, params: {} };
    await expect(guard.canActivate(ctx('allowed', req))).rejects.toThrow(UnauthorizedException);
  });

  it('401 for an unknown token', async () => {
    const req = { headers: { authorization: 'Bearer nope' }, params: {} };
    await expect(guard.canActivate(ctx('allowed', req))).rejects.toThrow(UnauthorizedException);
  });
});
```

- [ ] **Step 3: Убедиться, что тест падает**

Run: `npx jest src/messenger/messenger-auth.guard.spec.ts`
Expected: FAIL — `Cannot find module './messenger-auth.guard'`.

- [ ] **Step 4: Реализация guard'а**

Создать `src/messenger/messenger-auth.guard.ts`:

```ts
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import * as fs from 'fs';
import * as jwt from 'jsonwebtoken';
import { IS_PUBLIC_KEY } from '../common/decorators/public.decorator';
import { isApiAccessToken } from '../common/utils/access-token.util';
import { PARTNER_FORBIDDEN } from '../partner-core/partner.constants';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { PARTNER_ALLOWED_KEY, PartnerAllowedOptions } from './partner-allowed.decorator';
import { PartnerConversationScope } from './partner-conversation-scope.service';

/**
 * Вход в REST мессенджера по двум видам токена:
 *  - собственный токен входа TalerID — ровно как JwtAuthGuard до этого;
 *  - OAuth-токен партнёра со scope `messenger` — только в обработчики с
 *    @PartnerAllowed() и только к личным чатам и группам.
 * Партнёрский токен опаковый и не проходит jwt.verify, поэтому остальные
 * guard'ы TalerID (профиль, KYC, админка, голосовой прокси) его не пускают
 * без всяких правок.
 * Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 */
@Injectable()
export class MessengerAuthGuard implements CanActivate {
  private readonly publicKey: string;

  constructor(
    private readonly reflector: Reflector,
    private readonly partnerTokens: PartnerTokensService,
    private readonly scope: PartnerConversationScope,
    config: ConfigService,
  ) {
    const keyPath = config.get<string>('jwt.publicKeyPath') ?? '';
    this.publicKey = keyPath ? fs.readFileSync(keyPath, 'utf8') : '';
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets)) return true;

    const req = context.switchToHttp().getRequest();
    const match = /^Bearer\s+(\S+)$/i.exec(String(req.headers?.authorization ?? ''));
    const token = match?.[1];
    if (!token) throw new UnauthorizedException('Invalid or expired token');

    const native = this.verifyNative(token);
    if (native) {
      req.user = native;
      return true;
    }

    const principal = await this.partnerTokens.verify(token);
    if (!principal) throw new UnauthorizedException('Invalid or expired token');

    const allowed = this.reflector.getAllAndOverride<PartnerAllowedOptions>(PARTNER_ALLOWED_KEY, targets);
    if (!allowed) throw new ForbiddenException(PARTNER_FORBIDDEN);
    req.user = { sub: principal.userId, partner: principal };
    if (allowed.conversationParam) await this.scope.assertConversation(req.params?.[allowed.conversationParam]);
    if (allowed.messageParam) await this.scope.assertMessage(req.params?.[allowed.messageParam]);
    return true;
  }

  private verifyNative(token: string): Record<string, unknown> | null {
    if (!this.publicKey) return null;
    try {
      const payload = jwt.verify(token, this.publicKey, { algorithms: ['RS256'] });
      // ID-токены OIDC подписаны тем же ключом — пропускаем только access.
      return isApiAccessToken(payload) ? (payload as Record<string, unknown>) : null;
    } catch {
      return null;
    }
  }
}
```

- [ ] **Step 5: Подключить к модулю мессенджера**

В `src/messenger/messenger.module.ts`:
- добавить импорты:

```ts
import { PartnerCoreModule } from '../partner-core/partner-core.module';
import { PartnerConversationScope } from './partner-conversation-scope.service';
```

- в `imports` после `RedisModule,` добавить `PartnerCoreModule,`;
- в `providers` после `VideoTranscodeService,` добавить `PartnerConversationScope,`.

- [ ] **Step 6: Тесты и сборка**

Run: `npx jest src/messenger/messenger-auth.guard.spec.ts && npm run build`
Expected: PASS, 11 тестов; сборка без ошибок.

- [ ] **Step 7: Commit**

```bash
git add src/messenger/partner-allowed.decorator.ts src/messenger/messenger-auth.guard.ts src/messenger/messenger-auth.guard.spec.ts src/messenger/messenger.module.ts
git commit -m "feat(messenger): вход по партнёрскому токену только в открытые обработчики" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 26: Контроллер мессенджера — guard, allowlist, фильтры, правило групп

> ⚠️ Блоки кода задачи — исторические в части `sync`, `searchMessages`, `forwardMessages`, тредов и закрепа (см. «Правки по ревью задач 24–26»).

**Files:**
- Modify: `src/messenger/messenger.controller.ts`
- Test: `src/messenger/messenger.controller.partner.spec.ts` (новый)

- [ ] **Step 1: Написать падающий тест**

Создать `src/messenger/messenger.controller.partner.spec.ts`:

```ts
import { MessengerAuthGuard } from './messenger-auth.guard';
import { MessengerController } from './messenger.controller';
import { PARTNER_ALLOWED_KEY, PartnerAllowedOptions } from './partner-allowed.decorator';

/** Ровно этот набор обработчиков открыт партнёрам — спека, раздел «Что открыто». */
const EXPECTED: Record<string, PartnerAllowedOptions> = {
  create: {},
  list: {},
  sync: {},
  readState: {},
  conversationReadState: { conversationParam: 'id' },
  messages: { conversationParam: 'id' },
  readers: { messageParam: 'id' },
  sharedMedia: { conversationParam: 'id' },
  createGroup: {},
  getMembers: { conversationParam: 'id' },
  addMembers: { conversationParam: 'id' },
  removeMember: { conversationParam: 'id' },
  changeRole: { conversationParam: 'id' },
  updateGroup: { conversationParam: 'id' },
  muteConversation: { conversationParam: 'id' },
  unmuteConversation: { conversationParam: 'id' },
  leaveGroup: { conversationParam: 'id' },
  deleteGroup: { conversationParam: 'id' },
  getContactStatus: {},
  blockUser: {},
  unblockUser: {},
  isBlocked: {},
  searchMessages: {},
  uploadFile: {},
  getFileUrl: {},
  initChunkedUpload: {},
  uploadChunk: {},
  completeChunkedUpload: {},
  abortChunkedUpload: {},
  linkPreview: {},
  forwardMessages: { conversationParam: 'id' },
  pinMessage: { conversationParam: 'id' },
  unpinMessage: { conversationParam: 'id' },
  listPinned: { conversationParam: 'id' },
  unpinAll: { conversationParam: 'id' },
  dismissPins: { conversationParam: 'id' },
  getThread: { conversationParam: 'convId' },
  sendThreadReply: { conversationParam: 'convId' },
};

function partnerAllowlist(): Record<string, PartnerAllowedOptions> {
  const proto = MessengerController.prototype as any;
  const out: Record<string, PartnerAllowedOptions> = {};
  for (const name of Object.getOwnPropertyNames(proto)) {
    if (name === 'constructor') continue;
    const meta = Reflect.getMetadata(PARTNER_ALLOWED_KEY, proto[name]);
    if (meta) out[name] = meta;
  }
  return out;
}

describe('MessengerController for partner tokens', () => {
  it('opens exactly the agreed handlers to partners', () => {
    expect(partnerAllowlist()).toEqual(EXPECTED);
  });

  it('guards the whole controller with MessengerAuthGuard', () => {
    expect(Reflect.getMetadata('__guards__', MessengerController)).toEqual([MessengerAuthGuard]);
  });

  describe('lists and groups', () => {
    const partnerUser = { sub: 'u1', partner: { partnerId: 'p1' } };
    const nativeUser = { sub: 'u1' };
    let service: any;
    let scope: any;
    let controller: MessengerController;

    beforeEach(() => {
      service = {
        getConversations: jest.fn().mockResolvedValue([
          { id: 'c1', type: 'DIRECT' },
          { id: 'c2', type: 'CHANNEL' },
          { id: 'c3', type: 'GROUP' },
          { id: 'c4', type: 'SAVED' },
        ]),
        sync: jest.fn().mockResolvedValue({
          messages: [{ id: 'm1', conversationId: 'c1' }, { id: 'm2', conversationId: 'c2' }],
          nextCursor: 'x',
          hasMore: false,
        }),
        readStateForUser: jest.fn().mockResolvedValue({ conversations: [{ conversationId: 'c1' }, { conversationId: 'c2' }] }),
        searchMessages: jest.fn().mockResolvedValue([{ id: 'm1', conversationId: 'c1' }, { id: 'm2', conversationId: 'c4' }]),
        createGroupConversation: jest.fn().mockResolvedValue({ id: 'g1', participantIds: ['u1', 'u2'] }),
        addGroupMembers: jest.fn().mockResolvedValue([]),
      };
      scope = {
        visibleConversationIds: jest.fn().mockResolvedValue(new Set(['c1', 'c3'])),
        assertAllContacts: jest.fn().mockResolvedValue(undefined),
      };
      const gateway: any = { emitToUser: jest.fn(), emitToConversationParticipants: jest.fn() };
      const unused: any = {};
      controller = new MessengerController(
        service, gateway, unused, unused, unused, unused, unused,
        unused, unused, unused, unused, unused, unused, scope,
      );
    });

    it('shows partners only direct chats and groups', async () => {
      await expect(controller.list(partnerUser)).resolves.toEqual([
        { id: 'c1', type: 'DIRECT' },
        { id: 'c3', type: 'GROUP' },
      ]);
      await expect(controller.list(nativeUser)).resolves.toHaveLength(4);
    });

    it('filters sync, read state and message search by visible conversations', async () => {
      await expect(controller.sync(undefined, undefined, partnerUser)).resolves.toEqual({
        messages: [{ id: 'm1', conversationId: 'c1' }],
        nextCursor: 'x',
        hasMore: false,
      });
      await expect(controller.readState(partnerUser)).resolves.toEqual({ conversations: [{ conversationId: 'c1' }] });
      await expect(controller.searchMessages('hi', partnerUser)).resolves.toEqual([{ id: 'm1', conversationId: 'c1' }]);
      const nativeSync: any = await controller.sync(undefined, undefined, nativeUser);
      expect(nativeSync.messages).toHaveLength(2);
      expect(scope.visibleConversationIds).toHaveBeenCalledTimes(3);
    });

    it('lets partners put only their contacts into groups', async () => {
      await controller.createGroup({ name: 'G', participantIds: ['u2'] } as any, partnerUser);
      expect(scope.assertAllContacts).toHaveBeenCalledWith('u1', ['u2']);
      await controller.addMembers('g1', { userIds: ['u3'] } as any, partnerUser);
      expect(scope.assertAllContacts).toHaveBeenCalledWith('u1', ['u3']);
      scope.assertAllContacts.mockClear();
      await controller.createGroup({ name: 'G', participantIds: ['u9'] } as any, nativeUser);
      expect(scope.assertAllContacts).not.toHaveBeenCalled();
    });
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/messenger/messenger.controller.partner.spec.ts`
Expected: FAIL — `partnerAllowlist()` возвращает `{}`, guard'ы — `[JwtAuthGuard]`.

- [ ] **Step 3: Импорты, guard и конструктор**

В `src/messenger/messenger.controller.ts`:
- заменить строку `import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';` на:

```ts
import { MessengerAuthGuard } from './messenger-auth.guard';
import { PartnerAllowed } from './partner-allowed.decorator';
import { PartnerConversationScope } from './partner-conversation-scope.service';
import { isPartnerCaller, isPartnerConversationType } from '../partner-core/partner.constants';
```

- над классом заменить `@UseGuards(JwtAuthGuard)` на `@UseGuards(MessengerAuthGuard)`;
- в конструкторе после `private readonly scheduled: ScheduledMessageService,` добавить `private readonly partnerScope: PartnerConversationScope,`.

- [ ] **Step 4: Открыть обработчики партнёрам**

Над каждым обработчиком из таблицы, сразу под его декоратором маршрута, добавить указанную строку. Остальные обработчики не трогать — партнёр получит на них 403.

| Декоратор маршрута | Обработчик | Добавить |
|---|---|---|
| `@Post('conversations')` | `create` | `@PartnerAllowed()` |
| `@Get('conversations')` | `list` | `@PartnerAllowed()` |
| `@Get('sync')` | `sync` | `@PartnerAllowed()` |
| `@Get('read-state')` | `readState` | `@PartnerAllowed()` |
| `@Get('conversations/:id/read-state')` | `conversationReadState` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Get('conversations/:id/messages')` | `messages` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Get('messages/:id/readers')` | `readers` | `@PartnerAllowed({ messageParam: 'id' })` |
| `@Get('conversations/:id/media')` | `sharedMedia` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Post('conversations/group')` | `createGroup` | `@PartnerAllowed()` |
| `@Get('conversations/:id/members')` | `getMembers` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Post('conversations/:id/members')` | `addMembers` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Delete('conversations/:id/members/:uid')` | `removeMember` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Patch('conversations/:id/members/:uid/role')` | `changeRole` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Patch('conversations/:id')` | `updateGroup` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Post('conversations/:id/mute')` | `muteConversation` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Post('conversations/:id/unmute')` | `unmuteConversation` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Post('conversations/:id/leave')` | `leaveGroup` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Delete('conversations/:id')` | `deleteGroup` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Get('contacts/check/:userId')` | `getContactStatus` | `@PartnerAllowed()` |
| `@Post('contacts/:userId/block')` | `blockUser` | `@PartnerAllowed()` |
| `@Delete('contacts/:userId/block')` | `unblockUser` | `@PartnerAllowed()` |
| `@Get('contacts/:userId/block')` | `isBlocked` | `@PartnerAllowed()` |
| `@Get('messages/search')` | `searchMessages` | `@PartnerAllowed()` |
| `@Post('files')` | `uploadFile` | `@PartnerAllowed()` |
| `@Get('files/url')` | `getFileUrl` | `@PartnerAllowed()` |
| `@Post('files/init')` | `initChunkedUpload` | `@PartnerAllowed()` |
| `@Post('files/chunk')` | `uploadChunk` | `@PartnerAllowed()` |
| `@Post('files/complete')` | `completeChunkedUpload` | `@PartnerAllowed()` |
| `@Delete('files/:uploadId')` | `abortChunkedUpload` | `@PartnerAllowed()` |
| `@Get('link-preview')` | `linkPreview` | `@PartnerAllowed()` |
| `@Post('conversations/:id/forward')` | `forwardMessages` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Post('conversations/:id/messages/:msgId/pin')` | `pinMessage` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Delete('conversations/:id/messages/:msgId/pin')` | `unpinMessage` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Get('conversations/:id/pinned')` | `listPinned` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Delete('conversations/:id/pinned')` | `unpinAll` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Post('conversations/:id/pinned/dismiss')` | `dismissPins` | `@PartnerAllowed({ conversationParam: 'id' })` |
| `@Get('conversations/:convId/messages/:msgId/thread')` | `getThread` | `@PartnerAllowed({ conversationParam: 'convId' })` |
| `@Post('conversations/:convId/messages/:msgId/thread')` | `sendThreadReply` | `@PartnerAllowed({ conversationParam: 'convId' })` |

Пример — как это выглядит в файле:

```ts
  @Get('conversations/:id/members')
  @PartnerAllowed({ conversationParam: 'id' })
  getMembers(@Param('id') id: string, @CurrentUser() user: any) {
```

- [ ] **Step 5: Фильтры списков и правило групп**

Заменить обработчики `list`, `sync`, `readState` целиком:

```ts
  @Get('conversations')
  @PartnerAllowed()
  async list(@CurrentUser() user: any) {
    const conversations = await this.service.getConversations(user.sub);
    if (!isPartnerCaller(user)) return conversations;
    // Партнёру — только личные чаты и группы: канал новостей TalerID,
    // «Избранное» и чаты AI в его интерфейс не попадают.
    return conversations.filter((c) => isPartnerConversationType(c.type));
  }

  @Get('sync')
  @PartnerAllowed()
  async sync(
    @Query('cursor') cursor: string | undefined,
    @Query('limit') limit: string | undefined,
    @CurrentUser() user: any,
  ) {
    const parsedLimit = limit ? Math.min(Math.max(parseInt(limit, 10) || 200, 1), 500) : 200;
    const page = await this.service.sync(user.sub, cursor || undefined, parsedLimit);
    if (!isPartnerCaller(user)) return page;
    // Курсор остаётся от полной страницы: отфильтрованные сообщения просто не
    // отдаются, следующая страница начнётся там же, где и без фильтра.
    const visible = await this.partnerScope.visibleConversationIds(user.sub);
    return { ...page, messages: page.messages.filter((m) => visible.has(m.conversationId)) };
  }

  @Get('read-state')
  @PartnerAllowed()
  async readState(@CurrentUser() user: any) {
    const state = await this.service.readStateForUser(user.sub);
    if (!isPartnerCaller(user)) return state;
    const visible = await this.partnerScope.visibleConversationIds(user.sub);
    return { conversations: state.conversations.filter((c) => visible.has(c.conversationId)) };
  }
```

Заменить обработчик `searchMessages` целиком:

```ts
  @Get('messages/search')
  @PartnerAllowed()
  async searchMessages(@Query('q') q: string, @CurrentUser() user: any) {
    const found = await this.service.searchMessages(q, user.sub);
    if (!isPartnerCaller(user)) return found;
    const visible = await this.partnerScope.visibleConversationIds(user.sub);
    return found.filter((m: any) => visible.has(m.conversationId));
  }
```

В начало тела `createGroup` (перед `const conv = await this.service.createGroupConversation(`) вставить:

```ts
    // Партнёр кладёт в группу только свои контакты (у nadi — друзей).
    if (isPartnerCaller(user)) {
      await this.partnerScope.assertAllContacts(user.sub, dto.participantIds);
    }
```

В начало тела `addMembers` (перед `const newIds = await this.service.addGroupMembers(`) вставить:

```ts
    if (isPartnerCaller(user)) {
      await this.partnerScope.assertAllContacts(user.sub, dto.userIds);
    }
```

- [ ] **Step 6: Тесты проходят, прежние не сломаны**

Run: `npx jest src/messenger/messenger.controller && npm run build`
Expected: PASS — и новый набор, и `messenger.controller.pins.spec.ts`; сборка без ошибок.

- [ ] **Step 7: Commit**

```bash
git add src/messenger/messenger.controller.ts src/messenger/messenger.controller.partner.spec.ts
git commit -m "feat(messenger): партнёрам открыты только чаты, группы, файлы и прочтения" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 27: Фильтр пакетов сокета

**Files:**
- Create: `src/messenger/socket-gate.ts`
- Test: `src/messenger/socket-gate.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/messenger/socket-gate.spec.ts`:

```ts
import { ForbiddenException } from '@nestjs/common';
import { installSocketGate } from './socket-gate';

function fakeSocket(data: any = {}) {
  let middleware: (packet: any[], next: (err?: Error) => void) => void = () => undefined;
  const socket: any = {
    data,
    emit: jest.fn(),
    use: jest.fn((fn: any) => {
      middleware = fn;
    }),
  };
  const send = async (packet: any[]) => {
    const next = jest.fn();
    middleware(packet, next);
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    return next;
  };
  return { socket, send };
}

describe('installSocketGate', () => {
  let scope: any;
  beforeEach(() => {
    scope = {
      assertConversation: jest.fn().mockResolvedValue(undefined),
      assertMessage: jest.fn().mockResolvedValue(undefined),
    };
  });

  it('lets every event of a TalerID socket through', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1' });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['call_invite', {}])).toHaveBeenCalled();
    expect(scope.assertConversation).not.toHaveBeenCalled();
  });

  it('drops packets of a socket that failed authentication', async () => {
    const { socket, send } = fakeSocket();
    installSocketGate(socket, Promise.resolve(false), scope);
    expect(await send(['message', { conversationId: 'c1' }])).not.toHaveBeenCalled();
    expect(socket.emit).not.toHaveBeenCalled();
  });

  it('holds packets until authentication finishes instead of losing them', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1' });
    let finish: (ok: boolean) => void = () => undefined;
    installSocketGate(socket, new Promise<boolean>((r) => (finish = r)), scope);
    const pending = send(['join', { conversationId: 'c1' }]);
    finish(true);
    expect(await pending).toHaveBeenCalled();
  });

  it('refuses call events on a partner socket', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['call_invite', { conversationId: 'c1' }])).not.toHaveBeenCalled();
    expect(socket.emit).toHaveBeenCalledWith('error', { message: 'not_available_for_partner', event: 'call_invite' });
  });

  it('lets a partner message into a chat and checks each chat only once', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['message', { conversationId: 'c1', content: 'hi' }])).toHaveBeenCalled();
    expect(await send(['typing', { conversationId: 'c1', isTyping: true }])).toHaveBeenCalled();
    expect(scope.assertConversation).toHaveBeenCalledTimes(1);
  });

  it('refuses a partner packet aimed at a channel', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    scope.assertConversation.mockRejectedValue(new ForbiddenException('not_available_for_partner'));
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['message', { conversationId: 'channel-1' }])).not.toHaveBeenCalled();
    expect(socket.emit).toHaveBeenCalledWith('error', { message: 'not_available_for_partner', event: 'message' });
  });

  it('checks the message of edit, delete, react and thread replies', async () => {
    const { socket, send } = fakeSocket({ userId: 'u1', partner: { partnerId: 'p1' } });
    scope.assertMessage.mockRejectedValue(new ForbiddenException('not_available_for_partner'));
    installSocketGate(socket, Promise.resolve(true), scope);
    expect(await send(['react_message', { conversationId: 'c1', messageId: 'saved-msg', emoji: '👍' }])).not.toHaveBeenCalled();
    expect(await send(['thread_reply', { conversationId: 'c1', threadParentId: 'saved-msg', content: 'x' }])).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/messenger/socket-gate.spec.ts`
Expected: FAIL — `Cannot find module './socket-gate'`.

- [ ] **Step 3: Реализация**

Создать `src/messenger/socket-gate.ts`:

```ts
import type { Socket } from 'socket.io';
import { PARTNER_FORBIDDEN } from '../partner-core/partner.constants';
import type { PartnerConversationScope } from './partner-conversation-scope.service';

/** События, которые принимает сокет с партнёрским токеном. Всё остальное — отказ. */
export const PARTNER_SOCKET_EVENTS: ReadonlySet<string> = new Set([
  'join',
  'message',
  'edit_message',
  'delete_message',
  'typing',
  'react_message',
  'mark_read',
  'thread_reply',
]);

/** Поля пакета, где лежит id сообщения чужой беседы, если клиент хитрит. */
const MESSAGE_ID_FIELDS = ['messageId', 'threadParentId'] as const;

/**
 * Фильтр входящих пакетов сокета мессенджера:
 *  - пока проверяется токен, пакеты ждут — не теряются и не обгоняют друг друга;
 *  - проверка не прошла — пакеты выбрасываются (сокет к этому моменту отключён);
 *  - партнёрский сокет пропускает только PARTNER_SOCKET_EVENTS и только к
 *    личным чатам и группам. Новое событие закрыто для партнёров, пока его не
 *    добавят в список, — так же, как @PartnerAllowed в REST.
 */
export function installSocketGate(
  client: Socket,
  ready: Promise<boolean>,
  scope: PartnerConversationScope,
): void {
  client.use((packet, next) => {
    void ready.then(async (ok) => {
      if (!ok) return;
      if (!client.data.partner) return next();
      const [event, payload] = packet as unknown as [string, any];
      if (PARTNER_SOCKET_EVENTS.has(event) && (await partnerPayloadAllowed(client, payload, scope))) {
        return next();
      }
      client.emit('error', { message: PARTNER_FORBIDDEN, event });
    });
  });
}

async function partnerPayloadAllowed(
  client: Socket,
  payload: any,
  scope: PartnerConversationScope,
): Promise<boolean> {
  try {
    const seen: Set<string> = (client.data.partnerConversations ??= new Set<string>());
    const conversationId = typeof payload?.conversationId === 'string' ? payload.conversationId : undefined;
    // Тип беседы не меняется: проверенную один раз больше не спрашиваем
    // («печатает…» шлётся часто).
    if (conversationId && !seen.has(conversationId)) {
      await scope.assertConversation(conversationId);
      seen.add(conversationId);
    }
    for (const field of MESSAGE_ID_FIELDS) {
      const messageId = typeof payload?.[field] === 'string' ? payload[field] : undefined;
      if (messageId) await scope.assertMessage(messageId);
    }
    return true;
  } catch {
    return false;
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/messenger/socket-gate.spec.ts`
Expected: PASS, 7 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/messenger/socket-gate.ts src/messenger/socket-gate.spec.ts
git commit -m "feat(messenger): фильтр пакетов сокета — партнёру только чаты и группы, без звонков" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 28: Шлюз — вход по партнёрскому токену и отключение по сроку

> ⚠️ Блоки кода задачи — исторические в части комнат: партнёрский сокет входит в `puser:<id>`, а не в `user:<id>` (см. «Правки при подготовке ревью задач 27–28»).

**Files:**
- Modify: `src/messenger/messenger.gateway.ts` (импорты, конструктор, `onModuleInit`, `handleConnection`, `handleDisconnect`)
- Modify: `src/messenger/messenger.gateway.deliver.spec.ts`, `src/messenger/messenger.gateway.analyst.spec.ts` (провайдеры)
- Test: `src/messenger/messenger.gateway.partner.spec.ts` (новый)

- [ ] **Step 1: Написать падающий тест**

Создать `src/messenger/messenger.gateway.partner.spec.ts`:

```ts
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { generateKeyPairSync } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as jwt from 'jsonwebtoken';
import { AiAnalystService } from '../ai-analyst/ai-analyst.service';
import { AssistantChatService } from '../assistant/assistant-chat.service';
import { ApnsService } from '../common/apns.service';
import { FcmService } from '../common/fcm.service';
import { PartnerRealtimeService } from '../partner-core/partner-realtime.service';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { AiTwinService } from './ai-twin.service';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';
import { PartnerConversationScope } from './partner-conversation-scope.service';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const keyPath = path.join(os.tmpdir(), `messenger-gateway-partner-${process.pid}.pem`);
fs.writeFileSync(keyPath, publicKey);

function fakeClient(token?: string) {
  return {
    handshake: { auth: token ? { token } : {} },
    data: {} as any,
    join: jest.fn(),
    disconnect: jest.fn(),
    emit: jest.fn(),
    use: jest.fn(),
  };
}

describe('MessengerGateway connections', () => {
  let gateway: MessengerGateway;
  let partnerTokens: any;
  let realtime: any;

  beforeEach(async () => {
    partnerTokens = { verify: jest.fn().mockResolvedValue(null) };
    realtime = { registerDisconnector: jest.fn() };
    const mod = await Test.createTestingModule({
      providers: [
        MessengerGateway,
        { provide: MessengerService, useValue: {} },
        { provide: PrismaService, useValue: { user: { update: jest.fn().mockResolvedValue({}) } } },
        { provide: RedisService, useValue: {} },
        { provide: AiTwinService, useValue: { registerEmitters: jest.fn() } },
        { provide: AiAnalystService, useValue: {} },
        { provide: AssistantChatService, useValue: {} },
        { provide: FcmService, useValue: {} },
        { provide: ApnsService, useValue: {} },
        {
          provide: ConfigService,
          useValue: { get: (key: string) => (key === 'jwt.publicKeyPath' ? keyPath : undefined) },
        },
        { provide: PartnerTokensService, useValue: partnerTokens },
        { provide: PartnerRealtimeService, useValue: realtime },
        {
          provide: PartnerConversationScope,
          useValue: { assertConversation: jest.fn(), assertMessage: jest.fn() },
        },
      ],
    }).compile();
    gateway = mod.get(MessengerGateway);
  });
  afterEach(() => jest.useRealTimers());
  afterAll(() => fs.unlinkSync(keyPath));

  it('joins the personal room for a TalerID access token without asking the partner store', async () => {
    const token = jwt.sign({ sub: 'u1', typ: 'access' }, privateKey, { algorithm: 'RS256', expiresIn: 60 });
    const client = fakeClient(token);
    await gateway.handleConnection(client as any);
    expect(client.data.userId).toBe('u1');
    expect(client.data.partner).toBeUndefined();
    expect(client.join).toHaveBeenCalledWith('user:u1');
    expect(client.use).toHaveBeenCalledTimes(1);
    expect(partnerTokens.verify).not.toHaveBeenCalled();
  });

  it('accepts a partner token, joins the link room and drops the socket when the token expires', async () => {
    jest.useFakeTimers({ now: new Date('2026-10-01T10:00:00Z') });
    const expiresAt = Math.floor(Date.parse('2026-10-01T10:15:00Z') / 1000);
    partnerTokens.verify.mockResolvedValue({ userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1', expiresAt });
    const client = fakeClient('opaque');
    await gateway.handleConnection(client as any);
    expect(client.data.partner).toMatchObject({ partnerId: 'p1', grantId: 'g1' });
    expect(client.join).toHaveBeenCalledWith('user:u1');
    expect(client.join).toHaveBeenCalledWith('plink:p1:u1');
    jest.advanceTimersByTime(15 * 60 * 1000 - 1);
    expect(client.disconnect).not.toHaveBeenCalled();
    jest.advanceTimersByTime(1);
    expect(client.disconnect).toHaveBeenCalledWith(true);
  });

  it('disconnects an unknown token', async () => {
    const client = fakeClient('garbage');
    await gateway.handleConnection(client as any);
    expect(client.disconnect).toHaveBeenCalled();
    expect(client.join).not.toHaveBeenCalled();
  });

  it('drops a partner socket whose link was revoked while it was connecting', async () => {
    const principal = { userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1', expiresAt: Math.floor(Date.now() / 1000) + 900 };
    partnerTokens.verify.mockResolvedValueOnce(principal).mockResolvedValueOnce(null);
    const client = fakeClient('opaque');
    await gateway.handleConnection(client as any);
    expect(client.join).toHaveBeenCalledWith('plink:p1:u1');
    expect(client.disconnect).toHaveBeenCalled();
  });

  it('clears the expiry timer when the socket goes away first', async () => {
    jest.useFakeTimers({ now: new Date('2026-10-01T10:00:00Z') });
    partnerTokens.verify.mockResolvedValue({
      userId: 'u1', partnerId: 'p1', partnerSlug: 'nadi', grantId: 'g1',
      expiresAt: Math.floor(Date.now() / 1000) + 60,
    });
    const client = fakeClient('opaque');
    await gateway.handleConnection(client as any);
    gateway.handleDisconnect(client as any);
    jest.advanceTimersByTime(120_000);
    expect(client.disconnect).not.toHaveBeenCalled();
  });

  it('registers a disconnector that drops every socket of a link', () => {
    const disconnectSockets = jest.fn();
    const server = { in: jest.fn().mockReturnValue({ disconnectSockets }), to: jest.fn() };
    (gateway as any).server = server;
    gateway.onModuleInit();
    const [disconnector] = realtime.registerDisconnector.mock.calls[0];
    disconnector('p1', 'u1');
    expect(server.in).toHaveBeenCalledWith('plink:p1:u1');
    expect(disconnectSockets).toHaveBeenCalledWith(true);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/messenger/messenger.gateway.partner.spec.ts`
Expected: FAIL — партнёрский токен приводит к `disconnect`, `client.use` не вызывается, `registerDisconnector` не зовётся.

- [ ] **Step 3: Импорты и конструктор**

В `src/messenger/messenger.gateway.ts` после строки `import { RedisService } from '../redis/redis.service';` добавить:

```ts
import { PartnerRealtimeService } from '../partner-core/partner-realtime.service';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { partnerLinkRoom } from '../partner-core/partner.constants';
import { PartnerConversationScope } from './partner-conversation-scope.service';
import { installSocketGate } from './socket-gate';
```

В конструкторе перед строкой `@Optional() private readonly informerBot?: InformerBotService,` вставить (необязательный параметр должен остаться последним):

```ts
    private readonly partnerTokens: PartnerTokensService,
    private readonly partnerRealtime: PartnerRealtimeService,
    private readonly partnerScope: PartnerConversationScope,
```

- [ ] **Step 4: Регистрация разрыва сокетов**

В конец метода `onModuleInit` (после вызова `this.aiTwin.registerEmitters(…);`) добавить:

```ts
    // Отзыв партнёрской связки рвёт её сокеты на всех нодах (Redis-адаптер).
    this.partnerRealtime.registerDisconnector((partnerId, userId) => {
      this.server.in(partnerLinkRoom(partnerId, userId)).disconnectSockets(true);
    });
```

- [ ] **Step 5: Вход по двум видам токена**

Заменить метод `handleConnection` целиком на:

```ts
  async handleConnection(client: Socket) {
    const ready = this.authenticateSocket(client);
    installSocketGate(client, ready, this.partnerScope);
    await ready;
  }

  /**
   * Опознаёт сокет: сначала собственный токен входа TalerID (синхронно, как
   * раньше), потом партнёрский OAuth-токен со scope `messenger`. Не опознали —
   * отключаем. Партнёрский сокет живёт не дольше своего токена.
   */
  private async authenticateSocket(client: Socket): Promise<boolean> {
    try {
      const token = (client.handshake.auth?.token as string)?.replace('Bearer ', '');
      if (!token) throw new Error('No token');
      const nativeUserId = this.nativeUserId(token);
      if (nativeUserId) {
        client.data.userId = nativeUserId;
        client.data.connectedAt = Date.now();
        client.join(`user:${nativeUserId}`);
        return true;
      }
      const principal = await this.partnerTokens.verify(token);
      if (!principal) throw new Error('Not an access token');
      client.data.userId = principal.userId;
      client.data.connectedAt = Date.now();
      client.data.partner = principal;
      client.join(`user:${principal.userId}`);
      client.join(partnerLinkRoom(principal.partnerId, principal.userId));
      // Отзыв мог прийти, пока шла проверка: тогда команда «порвать сокеты
      // связки» разошлась раньше, чем этот сокет вошёл в комнату. Проверяем
      // токен ещё раз уже из комнаты — всё, что отзовут дальше, его достанет.
      if (!(await this.partnerTokens.verify(token))) throw new Error('Revoked while connecting');
      // Дальше клиент переподключается со свежим токеном, а отозванная связка
      // не держит открытым старое соединение.
      const timer = setTimeout(
        () => client.disconnect(true),
        Math.max(0, principal.expiresAt * 1000 - Date.now()),
      );
      timer.unref?.();
      client.data.partnerExpiryTimer = timer;
      return true;
    } catch {
      client.disconnect();
      return false;
    }
  }

  private nativeUserId(token: string): string | null {
    try {
      const payload = jwt.verify(token, this.publicKey, { algorithms: ['RS256'] }) as any;
      // OIDC ID tokens are signed with the same key — reject them here too.
      return isApiAccessToken(payload) ? payload.sub : null;
    } catch {
      return null;
    }
  }
```

В начало тела `handleDisconnect` добавить:

```ts
    if (client.data.partnerExpiryTimer) clearTimeout(client.data.partnerExpiryTimer);
```

- [ ] **Step 6: Провайдеры в прежних спеках шлюза**

В `src/messenger/messenger.gateway.deliver.spec.ts` и `src/messenger/messenger.gateway.analyst.spec.ts` добавить импорты

```ts
import { PartnerRealtimeService } from '../partner-core/partner-realtime.service';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { PartnerConversationScope } from './partner-conversation-scope.service';
```

и в массив `providers` тестового модуля — строки:

```ts
        { provide: PartnerTokensService, useValue: { verify: jest.fn().mockResolvedValue(null) } },
        { provide: PartnerRealtimeService, useValue: { registerDisconnector: jest.fn() } },
        { provide: PartnerConversationScope, useValue: { assertConversation: jest.fn(), assertMessage: jest.fn() } },
```

- [ ] **Step 7: Тесты мессенджера и сборка**

Run: `npx jest src/messenger && npm run build`
Expected: новый набор PASS (6 тестов), прежние наборы — как в базе; сборка без ошибок.

- [ ] **Step 8: Commit**

```bash
git add src/messenger/messenger.gateway.ts src/messenger/messenger.gateway.partner.spec.ts src/messenger/messenger.gateway.deliver.spec.ts src/messenger/messenger.gateway.analyst.spec.ts
git commit -m "feat(messenger): сокет по партнёрскому токену — комната гранта и отключение по сроку" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 29: Текст уведомления — общий хелпер

**Files:**
- Create: `src/messenger/push-text.util.ts`
- Modify: `src/messenger/messenger.gateway.ts` (`fanOutToParticipants`: вычисление `pushText`)
- Test: `src/messenger/push-text.util.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/messenger/push-text.util.spec.ts`:

```ts
import { buildPushText, messageKind } from './push-text.util';

describe('push text', () => {
  it.each([
    [{ content: 'hello' }, 'hello', 'text'],
    [{ content: '[CONTACT]{"id":"x"}' }, '📇 Контакт', 'text'],
    [{ content: '[POLL]{"q":"?"}' }, '📊 Опрос', 'text'],
    [{ content: '', fileUrl: 'u', fileType: 'image' }, '🖼 Фото', 'image'],
    [{ content: '', fileUrl: 'u', fileType: 'video' }, '🎥 Видео', 'video'],
    [{ content: '', fileUrl: 'u', fileType: 'audio' }, '🎵 Аудио', 'audio'],
    [{ content: '', fileUrl: 'u', fileType: 'pdf' }, '📎 Файл', 'file'],
  ])('%j → %p / %p', (msg: any, text: string, kind: string) => {
    expect(buildPushText(msg)).toBe(text);
    expect(messageKind(msg)).toBe(kind);
  });

  it('decodes system messages instead of showing JSON', () => {
    const msg = {
      isSystem: true,
      content: JSON.stringify({ action: 'message_pinned', actor: 'Alice', preview: 'Встреча' }),
    };
    expect(buildPushText(msg)).not.toContain('{');
    expect(messageKind(msg)).toBe('system');
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/messenger/push-text.util.spec.ts`
Expected: FAIL — `Cannot find module './push-text.util'`.

- [ ] **Step 3: Хелпер**

Создать `src/messenger/push-text.util.ts` (логика перенесена из тела `fanOutToParticipants` без изменений):

```ts
import { systemMessagePushText } from './system-message-text.util';

/** Текст уведомления о сообщении: общий для пуша TalerID и вебхука партнёра. */
export function buildPushText(msg: any): string {
  const c = (msg?.content as string | null) ?? '';
  // У служебных сообщений в content лежит JSON, который расшифровывает клиент
  // при отрисовке ленты. В пуше расшифровывать некому — без этой ветки в
  // шторку прилетало «{"action":"member_added",…}».
  if (msg?.isSystem) return systemMessagePushText(c);
  if (c.startsWith('[CONTACT]')) return '📇 Контакт';
  if (c.startsWith('[POLL]')) return '📊 Опрос';
  if (msg?.fileUrl) {
    const ft = (msg?.fileType as string | null) ?? '';
    if (ft === 'image') return '🖼 Фото';
    if (ft === 'video') return '🎥 Видео';
    if (ft === 'audio') return '🎵 Аудио';
    return '📎 Файл';
  }
  return c;
}

export type MessageKind = 'text' | 'image' | 'video' | 'audio' | 'file' | 'system';

/** Вид сообщения для вебхука партнёра: по нему партнёр подбирает иконку пуша. */
export function messageKind(msg: any): MessageKind {
  if (msg?.isSystem) return 'system';
  if (msg?.fileUrl) {
    const ft = (msg?.fileType as string | null) ?? '';
    return ft === 'image' || ft === 'video' || ft === 'audio' ? ft : 'file';
  }
  return 'text';
}
```

- [ ] **Step 4: Шлюз берёт текст из хелпера**

В `src/messenger/messenger.gateway.ts`:
- добавить импорт `import { buildPushText } from './push-text.util';`;
- в `fanOutToParticipants` сразу перед строкой `for (const p of participants) {` вставить:

```ts
    const pushText = buildPushText(enrichedMsg);
```

- в том же методе внутри `if (fcmTokens.length) {` удалить целиком блок `const pushText = (() => { … })();` — он заменён строкой выше;
- проверить, остался ли `systemMessagePushText` нужен шлюзу:

```bash
grep -n "systemMessagePushText" src/messenger/messenger.gateway.ts
```

Если осталась только строка импорта — удалить импорт.

- [ ] **Step 5: Тесты — хелпер и прежняя доставка**

Run: `npx jest src/messenger/push-text.util.spec.ts src/messenger/messenger.gateway.deliver.spec.ts`
Expected: PASS — в том числе прежний `pushes readable text for a system message, never the raw JSON`.

- [ ] **Step 6: Commit**

```bash
git add src/messenger/push-text.util.ts src/messenger/push-text.util.spec.ts src/messenger/messenger.gateway.ts
git commit -m "refactor(messenger): текст уведомления вынесен в общий хелпер" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 30: События вебхука, подпись и расписание повторов

**Files:**
- Create: `src/partner-core/partner-webhook-events.ts`
- Test: `src/partner-core/partner-webhook-events.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-core/partner-webhook-events.spec.ts`:

```ts
import { createHmac } from 'crypto';
import {
  buildMessageCreatedEvent,
  partnerWebhookBackoff,
  pingEvent,
  signWebhook,
  WEBHOOK_RETRY_DELAYS_MS,
} from './partner-webhook-events';

describe('partner webhook events', () => {
  const input = {
    message: { id: 'm1', senderId: 'u-a', sentAt: new Date('2026-10-01T10:00:00Z') },
    senderName: 'Іван',
    preview: 'x'.repeat(250),
    kind: 'text',
    mentionsRecipient: true,
  };

  it('builds message.created with a deterministic id and a 200-char preview', () => {
    const event = buildMessageCreatedEvent({
      recipient: { userId: 'u-b', externalId: 'm-b' },
      senderExternalId: 'm-a',
      conversation: { id: 'c1', type: 'GROUP', title: 'Громада' },
      input,
    });
    expect(event).toEqual({
      id: 'evt_m1_u-b',
      type: 'message.created',
      createdAt: expect.any(String),
      recipient: { externalId: 'm-b', talerUserId: 'u-b' },
      conversation: { id: 'c1', type: 'GROUP', title: 'Громада' },
      message: {
        id: 'm1',
        senderTalerUserId: 'u-a',
        senderExternalId: 'm-a',
        senderName: 'Іван',
        preview: 'x'.repeat(200),
        kind: 'text',
        mentionsRecipient: true,
        createdAt: '2026-10-01T10:00:00.000Z',
      },
    });
  });

  it('does not split an emoji when cutting the preview', () => {
    const event = buildMessageCreatedEvent({
      recipient: { userId: 'u-b', externalId: 'm-b' },
      senderExternalId: null,
      conversation: { id: 'c1', type: 'DIRECT', title: null },
      input: { ...input, preview: '😀'.repeat(201) },
    });
    expect((event.message as any).preview).toBe('😀'.repeat(200));
  });

  it('signs "t.body" with HMAC-SHA256', () => {
    const expected = createHmac('sha256', 'whsec_test').update('1700000000.{"a":1}').digest('hex');
    expect(signWebhook('whsec_test', 1_700_000_000, '{"a":1}')).toBe(`t=1700000000,v1=${expected}`);
  });

  it('gives every ping its own id without a colon', () => {
    const a = pingEvent();
    const b = pingEvent();
    expect(a.type).toBe('ping');
    expect(a.id).not.toBe(b.id);
    expect(a.id).not.toContain(':');
  });

  it('backs off 10 s → 30 s → 1 min → 5 min → 15 min → 1 h', () => {
    expect(WEBHOOK_RETRY_DELAYS_MS).toEqual([10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000]);
    expect([1, 2, 3, 4, 5, 6].map(partnerWebhookBackoff)).toEqual(WEBHOOK_RETRY_DELAYS_MS);
    expect(partnerWebhookBackoff(9)).toBe(3_600_000);
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-core/partner-webhook-events.spec.ts`
Expected: FAIL — `Cannot find module './partner-webhook-events'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-core/partner-webhook-events.ts`:

```ts
import { createHmac, randomUUID } from 'crypto';

/** Паузы перед повторами доставки. Дальше событие выбрасывается: пуш через час бессмыслен. */
export const WEBHOOK_RETRY_DELAYS_MS = [10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000];
export const WEBHOOK_MAX_ATTEMPTS = 1 + WEBHOOK_RETRY_DELAYS_MS.length;
const PREVIEW_MAX = 200;

export interface WebhookEvent {
  id: string;
  type: 'message.created' | 'ping';
  createdAt: string;
  [key: string]: unknown;
}

export interface MessageCreatedInput {
  message: { id: string; senderId: string; sentAt?: Date | string | null };
  senderName: string;
  preview: string;
  kind: string;
  mentionsRecipient: boolean;
}

export interface WebhookConversation {
  id: string;
  type: string;
  title: string | null;
}

export function buildMessageCreatedEvent(args: {
  recipient: { userId: string; externalId: string };
  senderExternalId: string | null;
  conversation: WebhookConversation;
  input: MessageCreatedInput;
}): WebhookEvent {
  const { recipient, senderExternalId, conversation, input } = args;
  const sentAt = input.message.sentAt ? new Date(input.message.sentAt) : new Date();
  return {
    // Одно сообщение одному получателю — одно событие: по id партнёр
    // отбрасывает повторные доставки.
    id: `evt_${input.message.id}_${recipient.userId}`,
    type: 'message.created',
    createdAt: new Date().toISOString(),
    recipient: { externalId: recipient.externalId, talerUserId: recipient.userId },
    conversation,
    message: {
      id: input.message.id,
      senderTalerUserId: input.message.senderId,
      senderExternalId,
      senderName: input.senderName,
      // По символам, а не по UTF-16: эмодзи на границе не разрезается пополам.
      preview: Array.from(input.preview ?? '').slice(0, PREVIEW_MAX).join(''),
      kind: input.kind,
      mentionsRecipient: input.mentionsRecipient,
      createdAt: sentAt.toISOString(),
    },
  };
}

export function pingEvent(): WebhookEvent {
  return { id: `evt_ping_${randomUUID()}`, type: 'ping', createdAt: new Date().toISOString() };
}

/** Заголовок X-TalerID-Signature: t=<unix-время>,v1=<hex HMAC-SHA256(секрет, "t.тело")>. */
export function signWebhook(secret: string, timestamp: number, body: string): string {
  const mac = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  return `t=${timestamp},v1=${mac}`;
}

/** Пауза перед повтором № attemptsMade (BullMQ считает с 1). */
export function partnerWebhookBackoff(attemptsMade: number): number {
  const index = Math.min(Math.max(attemptsMade, 1), WEBHOOK_RETRY_DELAYS_MS.length) - 1;
  return WEBHOOK_RETRY_DELAYS_MS[index];
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-core/partner-webhook-events.spec.ts`
Expected: PASS, 5 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/partner-core/partner-webhook-events.ts src/partner-core/partner-webhook-events.spec.ts
git commit -m "feat(partner): событие message.created, подпись и расписание повторов" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 31: План рассылки вебхуков

> ⚠️ Блоки кода задачи — исторические (см. «Правки по ревью задач 29–35»); источник правды — файлы в ветке.

**Files:**
- Create: `src/partner-core/partner-webhooks.service.ts`
- Test: `src/partner-core/partner-webhooks.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-core/partner-webhooks.service.spec.ts`:

```ts
import { PartnerWebhooksService } from './partner-webhooks.service';

const savedEnabled = process.env.PARTNER_API_ENABLED;
afterAll(() => {
  if (savedEnabled === undefined) delete process.env.PARTNER_API_ENABLED;
  else process.env.PARTNER_API_ENABLED = savedEnabled;
});

function make() {
  const prisma: any = {
    conversation: { findUnique: jest.fn().mockResolvedValue({ type: 'DIRECT', name: null }) },
    partnerLink: { findMany: jest.fn().mockResolvedValue([]) },
  };
  const registry: any = { findById: jest.fn() };
  const list: string[] = [];
  const client: any = {
    lpush: jest.fn(async (_key: string, value: string) => list.unshift(value)),
    ltrim: jest.fn().mockResolvedValue('OK'),
    lrange: jest.fn(async (_key: string, start: number, stop: number) => list.slice(start, stop + 1)),
  };
  const redis: any = { getClient: () => client };
  const queue: any = { add: jest.fn().mockResolvedValue({}) };
  const service = new PartnerWebhooksService(prisma, registry, redis, queue);
  return { service, prisma, registry, client, queue };
}

const flush = () => new Promise((r) => setImmediate(r));

describe('PartnerWebhooksService.planFanOut', () => {
  const args = { conversationId: 'c1', participantIds: ['u-a', 'u-b', 'u-c'], senderId: 'u-a', systemPost: false };
  const input = {
    message: { id: 'm1', senderId: 'u-a', sentAt: new Date('2026-10-01T10:00:00Z') },
    senderName: 'A',
    preview: 'hi',
    kind: 'text',
    mentionsRecipient: false,
  };

  beforeEach(() => {
    process.env.PARTNER_API_ENABLED = 'true';
  });

  it('does nothing while the partner API is off', async () => {
    process.env.PARTNER_API_ENABLED = 'false';
    const { service, prisma } = make();
    await expect(service.planFanOut(args)).resolves.toBeNull();
    expect(prisma.conversation.findUnique).not.toHaveBeenCalled();
  });

  it('skips system posts and conversations other than chats and groups', async () => {
    const { service, prisma } = make();
    await expect(service.planFanOut({ ...args, systemPost: true })).resolves.toBeNull();
    prisma.conversation.findUnique.mockResolvedValue({ type: 'CHANNEL', name: 'News' });
    await expect(service.planFanOut(args)).resolves.toBeNull();
    expect(prisma.partnerLink.findMany).not.toHaveBeenCalled();
  });

  it('loads the links of all participants in one query and returns null when there are none', async () => {
    const { service, prisma } = make();
    await expect(service.planFanOut(args)).resolves.toBeNull();
    expect(prisma.partnerLink.findMany).toHaveBeenCalledTimes(1);
    expect(prisma.partnerLink.findMany).toHaveBeenCalledWith({
      where: {
        userId: { in: ['u-a', 'u-b', 'u-c'] },
        status: 'ACTIVE',
        partner: { enabled: true, webhookUrl: { not: null } },
      },
      select: { userId: true, externalId: true, partnerId: true },
    });
  });

  it("queues one event per linked recipient, with the sender's externalId from the same partner", async () => {
    const { service, prisma, queue } = make();
    prisma.conversation.findUnique.mockResolvedValue({ type: 'GROUP', name: 'Громада' });
    prisma.partnerLink.findMany.mockResolvedValue([
      { userId: 'u-a', externalId: 'm-a', partnerId: 'p1' },
      { userId: 'u-b', externalId: 'm-b', partnerId: 'p1' },
    ]);
    const plan = await service.planFanOut(args);
    plan!.enqueue('u-b', input);
    plan!.enqueue('u-c', input);
    plan!.enqueue('u-a', input);
    await flush();
    expect(queue.add).toHaveBeenCalledTimes(1);
    const [name, data, opts] = queue.add.mock.calls[0];
    expect(name).toBe('deliver');
    expect(data.partnerId).toBe('p1');
    expect(data.event).toMatchObject({
      id: 'evt_m1_u-b',
      recipient: { externalId: 'm-b' },
      conversation: { id: 'c1', type: 'GROUP', title: 'Громада' },
      message: { senderExternalId: 'm-a', preview: 'hi' },
    });
    expect(opts).toEqual({
      jobId: 'p1_evt_m1_u-b',
      attempts: 7,
      backoff: { type: 'custom' },
      removeOnComplete: 1000,
      removeOnFail: 1000,
    });
  });

  it('never breaks message delivery on a database error', async () => {
    const { service, prisma } = make();
    prisma.conversation.findUnique.mockRejectedValue(new Error('db down'));
    await expect(service.planFanOut(args)).resolves.toBeNull();
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-core/partner-webhooks.service.spec.ts`
Expected: FAIL — `Cannot find module './partner-webhooks.service'`.

- [ ] **Step 3: Реализация плана и очереди**

Создать `src/partner-core/partner-webhooks.service.ts`:

```ts
import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { Queue } from 'bullmq';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { PartnerRegistryService } from './partner-registry.service';
import {
  buildMessageCreatedEvent,
  MessageCreatedInput,
  WEBHOOK_MAX_ATTEMPTS,
  WebhookEvent,
} from './partner-webhook-events';
import { isPartnerConversationType, PARTNER_WEBHOOK_QUEUE } from './partner.constants';

/** Что шлюз мессенджера делает с планом: ставит событие получателю, если нужно. */
export interface PartnerFanOut {
  /** Никогда не бросает и не ждёт: доставка сообщения от вебхука не зависит. */
  enqueue(recipientUserId: string, input: MessageCreatedInput): void;
}

@Injectable()
export class PartnerWebhooksService {
  private readonly logger = new Logger(PartnerWebhooksService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly registry: PartnerRegistryService,
    private readonly redis: RedisService,
    @InjectQueue(PARTNER_WEBHOOK_QUEUE) private readonly queue: Queue,
  ) {}

  /**
   * Готовит рассылку по одному сообщению. null — вебхуки здесь не нужны:
   * API выключен, системный пост, не личный чат и не группа, или среди
   * участников нет никого с действующей связкой у партнёра с вебхуком.
   * Связки всех участников — одним запросом: пошаговые запросы по участникам
   * уже роняли рассылку по системному каналу на PROD (2026-07-24).
   */
  async planFanOut(args: {
    conversationId: string;
    participantIds: string[];
    senderId: string;
    systemPost: boolean;
  }): Promise<PartnerFanOut | null> {
    if (process.env.PARTNER_API_ENABLED !== 'true' || args.systemPost) return null;
    try {
      const conv = await this.prisma.conversation.findUnique({
        where: { id: args.conversationId },
        select: { type: true, name: true },
      });
      if (!conv || !isPartnerConversationType(conv.type)) return null;
      const links = await this.prisma.partnerLink.findMany({
        where: {
          userId: { in: args.participantIds },
          status: 'ACTIVE',
          partner: { enabled: true, webhookUrl: { not: null } },
        },
        select: { userId: true, externalId: true, partnerId: true },
      });
      if (links.length === 0) return null;
      const conversation = {
        id: args.conversationId,
        type: conv.type,
        title: conv.type === 'GROUP' ? (conv.name ?? null) : null,
      };
      return {
        enqueue: (recipientUserId, input) => {
          if (recipientUserId === args.senderId) return;
          for (const link of links) {
            if (link.userId !== recipientUserId) continue;
            const senderLink = links.find((l) => l.userId === args.senderId && l.partnerId === link.partnerId);
            const event = buildMessageCreatedEvent({
              recipient: link,
              senderExternalId: senderLink?.externalId ?? null,
              conversation,
              input,
            });
            this.enqueueEvent(link.partnerId, event).catch((e) =>
              this.logger.warn(`enqueue ${event.id} failed: ${(e as Error).message}`),
            );
          }
        },
      };
    } catch (e) {
      this.logger.warn(`planFanOut failed for ${args.conversationId}: ${(e as Error).message}`);
      return null;
    }
  }

  async enqueueEvent(partnerId: string, event: WebhookEvent): Promise<void> {
    await this.queue.add(
      'deliver',
      { partnerId, event },
      {
        // BullMQ не принимает «:» в своих id. Один и тот же id не встанет в
        // очередь дважды, пока задача хранится.
        jobId: `${partnerId}_${event.id}`,
        attempts: WEBHOOK_MAX_ATTEMPTS,
        backoff: { type: 'custom' },
        removeOnComplete: 1000,
        removeOnFail: 1000,
      },
    );
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-core/partner-webhooks.service.spec.ts`
Expected: PASS, 5 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/partner-core/partner-webhooks.service.ts src/partner-core/partner-webhooks.service.spec.ts
git commit -m "feat(partner): план рассылки вебхуков одним запросом на сообщение" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 32: Доставка вебхука и журнал

> ⚠️ Блоки кода задачи — исторические (см. «Правки по ревью задач 29–35»); источник правды — файлы в ветке.

**Files:**
- Modify: `src/partner-core/partner-webhooks.service.ts` (методы `deliver`, `recentDeliveries`, `record`)
- Test: `src/partner-core/partner-webhooks.service.spec.ts`

- [ ] **Step 1: Написать падающие тесты**

В начало `src/partner-core/partner-webhooks.service.spec.ts` (до остальных импортов) добавить:

```ts
jest.mock('axios');
import axios from 'axios';
import { encryptWebhookSecret } from './partner-secrets.util';
import { signWebhook } from './partner-webhook-events';

const savedSecretsKey = process.env.PARTNER_SECRETS_KEY;
process.env.PARTNER_SECRETS_KEY = 'c'.repeat(64);
afterAll(() => {
  if (savedSecretsKey === undefined) delete process.env.PARTNER_SECRETS_KEY;
  else process.env.PARTNER_SECRETS_KEY = savedSecretsKey;
});
```

В конец файла добавить:

```ts
describe('PartnerWebhooksService.deliver', () => {
  const event: any = { id: 'evt_1', type: 'ping', createdAt: '2026-10-01T10:00:00.000Z' };
  let partner: any;

  beforeEach(() => {
    (axios.post as jest.Mock).mockReset();
    partner = {
      id: 'p1',
      slug: 'nadi',
      enabled: true,
      webhookUrl: 'https://nadi.example/hook',
      webhookSecretEnc: encryptWebhookSecret('whsec_test'),
    };
  });

  it('posts the signed body and records a 2xx as delivered', async () => {
    const { service, registry, client } = make();
    registry.findById.mockResolvedValue(partner);
    (axios.post as jest.Mock).mockResolvedValue({ status: 204 });
    const res = await service.deliver('p1', event, 2);
    expect(res).toMatchObject({ eventId: 'evt_1', type: 'ping', attempt: 2, delivered: true, status: 204, error: null });
    const [url, body, config] = (axios.post as jest.Mock).mock.calls[0];
    expect(url).toBe('https://nadi.example/hook');
    expect(body).toBe(JSON.stringify(event));
    const t = Number(/t=(\d+)/.exec(config.headers['X-TalerID-Signature'])![1]);
    expect(config.headers['X-TalerID-Signature']).toBe(signWebhook('whsec_test', t, body));
    expect(config.headers).toMatchObject({
      'Content-Type': 'application/json',
      'X-TalerID-Event': 'ping',
      'X-TalerID-Delivery': 'evt_1',
    });
    expect(config).toMatchObject({ timeout: 5000, maxRedirects: 0 });
    expect(client.lpush).toHaveBeenCalledWith('partner:webhook:log:p1', expect.any(String));
    expect(client.ltrim).toHaveBeenCalledWith('partner:webhook:log:p1', 0, 999);
  });

  it('records non-2xx answers and network errors as failures', async () => {
    const { service, registry } = make();
    registry.findById.mockResolvedValue(partner);
    (axios.post as jest.Mock).mockResolvedValueOnce({ status: 500 });
    await expect(service.deliver('p1', event)).resolves.toMatchObject({ delivered: false, status: 500, error: 'http_500' });
    (axios.post as jest.Mock).mockRejectedValueOnce(new Error('ECONNREFUSED'));
    await expect(service.deliver('p1', event)).resolves.toMatchObject({ delivered: false, status: null, error: 'ECONNREFUSED' });
  });

  it('calls nobody when the webhook is not configured', async () => {
    const { service, registry } = make();
    registry.findById.mockResolvedValue({ ...partner, webhookUrl: null });
    await expect(service.deliver('p1', event)).resolves.toMatchObject({ delivered: false, error: 'webhook_not_configured' });
    expect(axios.post).not.toHaveBeenCalled();
  });

  it('returns the newest deliveries first, clamped to 200', async () => {
    const { service, registry, client } = make();
    registry.findById.mockResolvedValue(partner);
    (axios.post as jest.Mock).mockResolvedValue({ status: 200 });
    await service.deliver('p1', { ...event, id: 'evt_a' });
    await service.deliver('p1', { ...event, id: 'evt_b' });
    const rows = await service.recentDeliveries('p1', 500);
    expect(rows.map((r) => r.eventId)).toEqual(['evt_b', 'evt_a']);
    expect(client.lrange).toHaveBeenLastCalledWith('partner:webhook:log:p1', 0, 199);
  });
});
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `npx jest src/partner-core/partner-webhooks.service.spec.ts`
Expected: FAIL — `TypeError: service.deliver is not a function`.

- [ ] **Step 3: Реализация**

В `src/partner-core/partner-webhooks.service.ts`:
- добавить импорты:

```ts
import axios from 'axios';
import { decryptWebhookSecret } from './partner-secrets.util';
import { signWebhook } from './partner-webhook-events';
```

- после интерфейса `PartnerFanOut` добавить:

```ts
export interface DeliveryResult {
  eventId: string;
  type: string;
  attempt: number;
  delivered: boolean;
  status: number | null;
  error: string | null;
  durationMs: number;
  at: string;
}

const DELIVERY_TIMEOUT_MS = 5_000;
const DELIVERY_LOG_MAX = 1_000;
const logKey = (partnerId: string) => `partner:webhook:log:${partnerId}`;
```

- в класс после `enqueueEvent` добавить:

```ts
  /**
   * Одна попытка: подписать, отправить, записать в журнал. Не бросает —
   * решение о повторе принимает воркер очереди по полю delivered.
   */
  async deliver(partnerId: string, event: WebhookEvent, attempt = 1): Promise<DeliveryResult> {
    const partner = await this.registry.findById(partnerId);
    if (!partner?.enabled || !partner.webhookUrl || !partner.webhookSecretEnc) {
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered: false, status: null, error: 'webhook_not_configured', durationMs: 0,
      });
    }
    const body = JSON.stringify(event);
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signWebhook(decryptWebhookSecret(partner.webhookSecretEnc), timestamp, body);
    const started = Date.now();
    try {
      const res = await axios.post(partner.webhookUrl, body, {
        headers: {
          'Content-Type': 'application/json',
          'X-TalerID-Event': event.type,
          'X-TalerID-Delivery': event.id,
          'X-TalerID-Signature': signature,
        },
        timeout: DELIVERY_TIMEOUT_MS,
        maxRedirects: 0,
        validateStatus: () => true,
      });
      const delivered = res.status >= 200 && res.status < 300;
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered, status: res.status, error: delivered ? null : `http_${res.status}`,
        durationMs: Date.now() - started,
      });
    } catch (e) {
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered: false, status: null, error: (e as Error).message.slice(0, 200),
        durationMs: Date.now() - started,
      });
    }
  }

  /** Последние попытки доставки, новые сначала. */
  async recentDeliveries(partnerId: string, limit: number): Promise<DeliveryResult[]> {
    const count = Math.min(Math.max(Math.floor(limit) || 50, 1), 200);
    const rows = await this.redis.getClient().lrange(logKey(partnerId), 0, count - 1);
    return rows.map((row) => JSON.parse(row) as DeliveryResult);
  }

  private async record(partnerId: string, result: Omit<DeliveryResult, 'at'>): Promise<DeliveryResult> {
    const entry: DeliveryResult = { ...result, at: new Date().toISOString() };
    try {
      const client = this.redis.getClient();
      await client.lpush(logKey(partnerId), JSON.stringify(entry));
      await client.ltrim(logKey(partnerId), 0, DELIVERY_LOG_MAX - 1);
    } catch (e) {
      this.logger.warn(`webhook log write failed for ${partnerId}: ${(e as Error).message}`);
    }
    return entry;
  }
```

- [ ] **Step 4: Тесты проходят**

Run: `npx jest src/partner-core/partner-webhooks.service.spec.ts`
Expected: PASS, 9 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/partner-core/partner-webhooks.service.ts src/partner-core/partner-webhooks.service.spec.ts
git commit -m "feat(partner): доставка вебхука с подписью и журнал попыток" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 33: Воркер очереди вебхуков

**Files:**
- Create: `src/partner-core/partner-webhooks.processor.ts`
- Test: `src/partner-core/partner-webhooks.processor.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/partner-core/partner-webhooks.processor.spec.ts`:

```ts
import { PartnerWebhooksProcessor } from './partner-webhooks.processor';

describe('PartnerWebhooksProcessor', () => {
  const job: any = {
    name: 'deliver',
    attemptsMade: 2,
    data: { partnerId: 'p1', event: { id: 'evt_1', type: 'ping', createdAt: 'x' } },
  };

  it('passes the attempt number and throws on failure so BullMQ retries', async () => {
    const webhooks: any = { deliver: jest.fn().mockResolvedValue({ delivered: false, error: 'http_500' }) };
    await expect(new PartnerWebhooksProcessor(webhooks).process(job)).rejects.toThrow('http_500');
    expect(webhooks.deliver).toHaveBeenCalledWith('p1', job.data.event, 3);
  });

  it('finishes quietly on success and when the webhook is not configured', async () => {
    const ok: any = { deliver: jest.fn().mockResolvedValue({ delivered: true }) };
    await expect(new PartnerWebhooksProcessor(ok).process(job)).resolves.toBeUndefined();
    const off: any = { deliver: jest.fn().mockResolvedValue({ delivered: false, error: 'webhook_not_configured' }) };
    await expect(new PartnerWebhooksProcessor(off).process(job)).resolves.toBeUndefined();
  });

  it('ignores unknown job names', async () => {
    const webhooks: any = { deliver: jest.fn() };
    await new PartnerWebhooksProcessor(webhooks).process({ ...job, name: 'other' });
    expect(webhooks.deliver).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `npx jest src/partner-core/partner-webhooks.processor.spec.ts`
Expected: FAIL — `Cannot find module './partner-webhooks.processor'`.

- [ ] **Step 3: Реализация**

Создать `src/partner-core/partner-webhooks.processor.ts`:

```ts
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { partnerWebhookBackoff, WebhookEvent } from './partner-webhook-events';
import { PARTNER_WEBHOOK_QUEUE } from './partner.constants';
import { PartnerWebhooksService } from './partner-webhooks.service';

/**
 * Воркер `partner-webhooks`. Работает на каждой ноде, очередь общая в Redis.
 * Неудача → исключение → BullMQ повторяет по partnerWebhookBackoff; после
 * последней попытки событие остаётся в журнале доставок и больше не шлётся.
 */
@Processor(PARTNER_WEBHOOK_QUEUE, {
  concurrency: 10,
  settings: { backoffStrategy: (attemptsMade: number) => partnerWebhookBackoff(attemptsMade) },
})
export class PartnerWebhooksProcessor extends WorkerHost {
  private readonly logger = new Logger(PartnerWebhooksProcessor.name);

  constructor(private readonly webhooks: PartnerWebhooksService) {
    super();
  }

  async process(job: Job<{ partnerId: string; event: WebhookEvent }>): Promise<void> {
    if (job.name !== 'deliver') {
      this.logger.warn(`Unknown job name '${job.name}' on ${PARTNER_WEBHOOK_QUEUE}`);
      return;
    }
    const result = await this.webhooks.deliver(job.data.partnerId, job.data.event, job.attemptsMade + 1);
    // Партнёр снял вебхук — повторять некуда.
    if (!result.delivered && result.error !== 'webhook_not_configured') {
      throw new Error(`webhook ${job.data.event.id} to ${job.data.partnerId}: ${result.error}`);
    }
  }
}
```

- [ ] **Step 4: Тест проходит**

Run: `npx jest src/partner-core/partner-webhooks.processor.spec.ts`
Expected: PASS, 3 теста.

- [ ] **Step 5: Commit**

```bash
git add src/partner-core/partner-webhooks.processor.ts src/partner-core/partner-webhooks.processor.spec.ts
git commit -m "feat(partner): воркер очереди вебхуков с повторами" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 34: Вебхуки в рассылке сообщений

> ⚠️ Блоки кода задачи — исторические (см. «Правки по ревью задач 29–35»); источник правды — файлы в ветке.

**Files:**
- Modify: `src/partner-core/partner-core.module.ts` (очередь, сервис, воркер)
- Modify: `src/messenger/messenger.gateway.ts` (конструктор, `fanOutToParticipants`)
- Modify: `src/messenger/messenger.gateway.deliver.spec.ts`, `src/messenger/messenger.gateway.analyst.spec.ts`, `src/messenger/messenger.gateway.partner.spec.ts` (провайдер; новые тесты в deliver)

- [ ] **Step 1: Написать падающие тесты**

В `src/messenger/messenger.gateway.deliver.spec.ts`:
- добавить импорт `import { PartnerWebhooksService } from '../partner-core/partner-webhooks.service';`;
- к объявлениям `let` в начале `describe` добавить `let mockWebhooks: PartnerWebhooksService;`;
- в `providers` добавить `{ provide: PartnerWebhooksService, useValue: { planFanOut: jest.fn().mockResolvedValue(null) } },`;
- после `mockFcm = mod.get(FcmService);` добавить `mockWebhooks = mod.get(PartnerWebhooksService);`;
- в конец главного `describe` добавить:

```ts
  describe('partner webhooks', () => {
    let enqueue: jest.Mock;

    beforeEach(() => {
      enqueue = jest.fn();
      (mockWebhooks.planFanOut as jest.Mock).mockResolvedValue({ enqueue });
    });

    it('queues a webhook for a recipient who does not have the chat open', async () => {
      await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
      expect(mockWebhooks.planFanOut).toHaveBeenCalledWith({
        conversationId: 'conv-1',
        participantIds: ['sender', 'recipient'],
        senderId: 'sender',
        systemPost: false,
      });
      expect(enqueue).toHaveBeenCalledWith('recipient', {
        message: { id: 'msg-1', senderId: 'sender', sentAt: baseMsg.sentAt },
        senderName: 'Alice',
        preview: 'hello',
        kind: 'text',
        mentionsRecipient: false,
      });
    });

    it('does not queue for a recipient who has the chat open', async () => {
      socketsInConv = [{ data: { userId: 'recipient' } }];
      await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
      expect(enqueue).not.toHaveBeenCalled();
    });

    it('does not queue for a muted chat or a silent message', async () => {
      (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
      await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
      (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(false);
      await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1', { silent: true });
      expect(enqueue).not.toHaveBeenCalled();
    });
  });
```

В `src/messenger/messenger.gateway.analyst.spec.ts` и `src/messenger/messenger.gateway.partner.spec.ts` добавить тот же импорт и в `providers` строку `{ provide: PartnerWebhooksService, useValue: { planFanOut: jest.fn().mockResolvedValue(null) } },`.

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `npx jest src/messenger/messenger.gateway.deliver.spec.ts`
Expected: FAIL — `planFanOut` не вызывается, `enqueue` не вызывается.

- [ ] **Step 3: Модуль ядра: очередь, сервис, воркер**

`src/partner-core/partner-core.module.ts` заменить целиком:

```ts
import { BullModule } from '@nestjs/bullmq';
import { Logger, Module, OnModuleInit } from '@nestjs/common';
import { OidcModule } from '../oidc/oidc.module';
import { PartnerLinkRevokerService } from './partner-link-revoker.service';
import { PartnerRealtimeService } from './partner-realtime.service';
import { PartnerRegistryService } from './partner-registry.service';
import { reportPartnerSecretsKey } from './partner-secrets.util';
import { PartnerTokensService } from './partner-tokens.service';
import { PartnerWebhooksProcessor } from './partner-webhooks.processor';
import { PartnerWebhooksService } from './partner-webhooks.service';
import { PARTNER_WEBHOOK_QUEUE } from './partner.constants';

/**
 * Ядро партнёрского API без HTTP. Импортируют мессенджер (опознание токенов,
 * вебхуки), профиль (отзыв связок при удалении аккаунта) и партнёрский API.
 * Сам ничего из них не импортирует — так нет циклов между модулями.
 * PrismaModule и RedisModule глобальные, подключение BullMQ — в AppModule.
 */
@Module({
  imports: [OidcModule, BullModule.registerQueue({ name: PARTNER_WEBHOOK_QUEUE })],
  providers: [
    PartnerRegistryService,
    PartnerTokensService,
    PartnerRealtimeService,
    PartnerLinkRevokerService,
    PartnerWebhooksService,
    PartnerWebhooksProcessor,
  ],
  exports: [
    PartnerRegistryService,
    PartnerTokensService,
    PartnerRealtimeService,
    PartnerLinkRevokerService,
    PartnerWebhooksService,
  ],
})
export class PartnerCoreModule implements OnModuleInit {
  private readonly logger = new Logger('PartnerCore');

  onModuleInit(): void {
    reportPartnerSecretsKey(this.logger);
  }
}
```

- [ ] **Step 4: Шлюз ставит вебхук там же, где решает про пуш**

В `src/messenger/messenger.gateway.ts`:
- импорты: `import { PartnerWebhooksService } from '../partner-core/partner-webhooks.service';`, а в строке импорта из `./push-text.util` добавить `messageKind`: `import { buildPushText, messageKind } from './push-text.util';`;
- конструктор: после `private readonly partnerScope: PartnerConversationScope,` добавить `private readonly partnerWebhooks: PartnerWebhooksService,`;
- в `fanOutToParticipants` строку `const pushText = buildPushText(enrichedMsg);` (Task 29) заменить на:

```ts
    // Партнёрам (nadi) — вебхук тем же, кому шлём пуш: приложения TalerID у их
    // людей нет, пуш отправит сам партнёр своими ключами.
    const partnerFanOut = await this.partnerWebhooks.planFanOut({
      conversationId,
      participantIds: participants.map((p) => p.userId),
      senderId,
      systemPost: opts.systemPost === true,
    });
    const pushText = buildPushText(enrichedMsg);
    const kind = messageKind(enrichedMsg);
```

- в том же методе заменить

```ts
        } else {
          const fcmTokens = await this.service.getFcmTokens(p.userId);
```

на

```ts
        } else {
          partnerFanOut?.enqueue(p.userId, {
            message: { id: enrichedMsg.id, senderId, sentAt: enrichedMsg.sentAt },
            senderName,
            preview: pushText,
            kind,
            mentionsRecipient: mentionsMe,
          });
          const fcmTokens = await this.service.getFcmTokens(p.userId);
```

- [ ] **Step 5: Тесты мессенджера и ядра, сборка**

Run: `npx jest src/messenger src/partner-core && npm run build`
Expected: новые тесты PASS, прежние — как в базе; сборка без ошибок.

- [ ] **Step 6: Commit**

```bash
git add src/partner-core/partner-core.module.ts src/messenger/messenger.gateway.ts src/messenger/messenger.gateway.deliver.spec.ts src/messenger/messenger.gateway.analyst.spec.ts src/messenger/messenger.gateway.partner.spec.ts
git commit -m "feat(messenger): вебхук партнёру тем же получателям, кому шлётся пуш" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 35: Ручки вебхуков и тестовый приёмник

> ⚠️ Блоки кода задачи — исторические (см. «Правки по ревью задач 29–35»); источник правды — файлы в ветке.

**Files:**
- Create: `src/partner-api/partner-webhook-sink.store.ts`
- Create: `src/partner-api/partner-webhook-sink.controller.ts`
- Modify: `src/partner-api/partner-api.controller.ts` (конструктор, три ручки)
- Modify: `src/partner-api/partner-api.module.ts`
- Test: `src/partner-api/partner-webhook-sink.controller.spec.ts` (новый), `src/partner-api/partner-api.controller.spec.ts`

- [ ] **Step 1: Написать падающие тесты**

Создать `src/partner-api/partner-webhook-sink.controller.spec.ts`:

```ts
import { NotFoundException } from '@nestjs/common';
import { PartnerWebhookSinkController } from './partner-webhook-sink.controller';
import { PartnerWebhookSinkStore } from './partner-webhook-sink.store';

const saved = process.env.PARTNER_WEBHOOK_SINK;

function make(partner: any = { slug: 'e2e' }) {
  const client: any = {
    lpush: jest.fn().mockResolvedValue(1),
    ltrim: jest.fn().mockResolvedValue('OK'),
    expire: jest.fn().mockResolvedValue(1),
    lrange: jest.fn().mockResolvedValue([]),
  };
  const store = new PartnerWebhookSinkStore({ getClient: () => client } as any);
  const registry: any = { findBySlug: jest.fn().mockResolvedValue(partner) };
  return { controller: new PartnerWebhookSinkController(registry, store), client };
}

describe('PartnerWebhookSinkController', () => {
  afterEach(() => {
    if (saved === undefined) delete process.env.PARTNER_WEBHOOK_SINK;
    else process.env.PARTNER_WEBHOOK_SINK = saved;
  });

  it('is 404 unless PARTNER_WEBHOOK_SINK=true', async () => {
    delete process.env.PARTNER_WEBHOOK_SINK;
    const { controller, client } = make();
    await expect(controller.receive('e2e', {}, { a: 1 })).rejects.toThrow(NotFoundException);
    expect(client.lpush).not.toHaveBeenCalled();
  });

  it('stores the event with its signature headers for that partner', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller, client } = make();
    const headers = { 'x-talerid-event': 'ping', 'x-talerid-delivery': 'evt_1', 'x-talerid-signature': 't=1,v1=ab' };
    await expect(controller.receive('e2e', headers, { id: 'evt_1' })).resolves.toEqual({ ok: true });
    expect(client.lpush.mock.calls[0][0]).toBe('partner:sink:e2e');
    expect(JSON.parse(client.lpush.mock.calls[0][1])).toMatchObject({
      event: 'ping',
      delivery: 'evt_1',
      signature: 't=1,v1=ab',
      body: '{"id":"evt_1"}',
    });
    expect(client.ltrim).toHaveBeenCalledWith('partner:sink:e2e', 0, 99);
    expect(client.expire).toHaveBeenCalledWith('partner:sink:e2e', 3600);
  });

  it('404 for an unknown partner', async () => {
    process.env.PARTNER_WEBHOOK_SINK = 'true';
    const { controller } = make(null);
    await expect(controller.receive('ghost', {}, {})).rejects.toThrow(NotFoundException);
  });
});
```

В `src/partner-api/partner-api.controller.spec.ts`:
- в `beforeEach` добавить `webhooks = { deliver: jest.fn(), recentDeliveries: jest.fn() }; sink = { list: jest.fn() };` (и объявления `let webhooks: any; let sink: any;`), конструктор — `new PartnerApiController(users, codes, contacts, webhooks, sink)`;
- добавить тест:

```ts
  it('sends a ping and reports what the partner answered', async () => {
    webhooks.deliver.mockResolvedValue({
      eventId: 'evt_ping_x', type: 'ping', attempt: 1, delivered: true, status: 204, error: null, durationMs: 12, at: 'x',
    });
    await expect(controller.testWebhook(req)).resolves.toEqual({ delivered: true, status: 204, durationMs: 12 });
    expect(webhooks.deliver).toHaveBeenCalledWith('p1', expect.objectContaining({ type: 'ping' }));
  });
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `npx jest src/partner-api/partner-webhook-sink.controller.spec.ts src/partner-api/partner-api.controller.spec.ts`
Expected: FAIL — нет модулей приёмника; у контроллера нет `testWebhook`.

- [ ] **Step 3: Хранилище и контроллер приёмника**

Создать `src/partner-api/partner-webhook-sink.store.ts`:

```ts
import { Injectable } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';

export interface SinkEntry {
  receivedAt: string;
  event: string | null;
  delivery: string | null;
  signature: string | null;
  body: string;
}

const SINK_MAX = 100;
const SINK_TTL_SECONDS = 3600;
const sinkKey = (slug: string) => `partner:sink:${slug}`;

/** Последние 100 вебхуков партнёра за час — только для e2e на DEV/TEST. */
@Injectable()
export class PartnerWebhookSinkStore {
  constructor(private readonly redis: RedisService) {}

  static enabled(): boolean {
    return process.env.PARTNER_WEBHOOK_SINK === 'true';
  }

  async push(slug: string, entry: SinkEntry): Promise<void> {
    const client = this.redis.getClient();
    await client.lpush(sinkKey(slug), JSON.stringify(entry));
    await client.ltrim(sinkKey(slug), 0, SINK_MAX - 1);
    await client.expire(sinkKey(slug), SINK_TTL_SECONDS);
  }

  async list(slug: string): Promise<SinkEntry[]> {
    const rows = await this.redis.getClient().lrange(sinkKey(slug), 0, SINK_MAX - 1);
    return rows.map((row) => JSON.parse(row) as SinkEntry);
  }
}
```

Создать `src/partner-api/partner-webhook-sink.controller.ts`:

```ts
import { Body, Controller, Headers, HttpCode, NotFoundException, Param, Post } from '@nestjs/common';
import { PartnerRegistryService } from '../partner-core/partner-registry.service';
import { PartnerWebhookSinkStore } from './partner-webhook-sink.store';

/**
 * Тестовый приёмник вебхуков для e2e-набора: вебхук тестового партнёра `e2e`
 * указывает сюда, набор забирает событие через GET /partner/v1/_sink/events и
 * сверяет подпись. Работает только при PARTNER_WEBHOOK_SINK=true (DEV/TEST);
 * на PROD переменная не задаётся, и здесь 404.
 */
@Controller('partner/v1/_sink')
export class PartnerWebhookSinkController {
  constructor(
    private readonly registry: PartnerRegistryService,
    private readonly store: PartnerWebhookSinkStore,
  ) {}

  @Post(':slug')
  @HttpCode(200)
  async receive(
    @Param('slug') slug: string,
    @Headers() headers: Record<string, string>,
    @Body() body: unknown,
  ): Promise<{ ok: true }> {
    if (!PartnerWebhookSinkStore.enabled()) throw new NotFoundException();
    if (!(await this.registry.findBySlug(slug))) throw new NotFoundException();
    await this.store.push(slug, {
      receivedAt: new Date().toISOString(),
      event: headers['x-talerid-event'] ?? null,
      delivery: headers['x-talerid-delivery'] ?? null,
      signature: headers['x-talerid-signature'] ?? null,
      // Тело уже разобрано JSON-парсером Nest. JSON.stringify возвращает ровно
      // ту строку, что подписывалась: отправитель сериализует простой объект.
      body: JSON.stringify(body),
    });
    return { ok: true };
  }
}
```

- [ ] **Step 4: Ручки вебхуков в партнёрском API**

В `src/partner-api/partner-api.controller.ts`:
- в импорт из `@nestjs/common` добавить `NotFoundException`;
- добавить импорты:

```ts
import { pingEvent } from '../partner-core/partner-webhook-events';
import { PartnerWebhooksService } from '../partner-core/partner-webhooks.service';
import { PartnerWebhookSinkStore } from './partner-webhook-sink.store';
```

- в конструктор после `private readonly contacts: PartnerContactsService,` добавить:

```ts
    private readonly webhooks: PartnerWebhooksService,
    private readonly sink: PartnerWebhookSinkStore,
```

- в конец класса добавить:

```ts
  /** Отправить ping на вебхук партнёра и сразу вернуть, что тот ответил. */
  @Post('webhooks/test')
  @HttpCode(200)
  async testWebhook(@Req() req: PartnerRequest) {
    const result = await this.webhooks.deliver(req.partner.id, pingEvent());
    return {
      delivered: result.delivered,
      status: result.status,
      ...(result.error ? { error: result.error } : {}),
      durationMs: result.durationMs,
    };
  }

  @Get('webhooks/deliveries')
  deliveries(@Req() req: PartnerRequest, @Query('limit') limit?: string) {
    return this.webhooks.recentDeliveries(req.partner.id, Number(limit) || 50);
  }

  /** Тестовый приёмник (только DEV/TEST): что пришло на вебхук этого партнёра. */
  @Get('_sink/events')
  sinkEvents(@Req() req: PartnerRequest) {
    if (!PartnerWebhookSinkStore.enabled()) throw new NotFoundException();
    return this.sink.list(req.partner.slug);
  }
```

В `src/partner-api/partner-api.module.ts`:
- добавить импорты `PartnerWebhookSinkController` и `PartnerWebhookSinkStore`;
- `controllers: [PartnerApiController, PartnerWebhookSinkController],`;
- в `providers` добавить `PartnerWebhookSinkStore,`.

- [ ] **Step 5: Тесты и сборка**

Run: `npx jest src/partner-api && npm run build`
Expected: PASS; сборка без ошибок.

- [ ] **Step 6: Commit**

```bash
git add src/partner-api
git commit -m "feat(partner): проверка вебхука, журнал доставок и тестовый приёмник для DEV/TEST" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 36: Переменные окружения в `.env.example`

**Files:**
- Modify: `.env.example` (в конец)

- [ ] **Step 1: Добавить переменные**

В конец `.env.example` добавить:

```
# ── Партнёрский API мессенджера (nadi и др.) — docs/partner-messenger-api.md ──
# Выключатель всего партнёрского API и приёма партнёрских токенов мессенджером.
PARTNER_API_ENABLED=false
# 64 hex-символа (openssl rand -hex 32). Одинаковый на всех нодах окружения:
# им шифруются секреты вебхуков и считается HMAC кодов привязки.
PARTNER_SECRETS_KEY=
# Тестовый приёмник вебхуков /partner/v1/_sink — только DEV/TEST, на PROD не задавать.
PARTNER_WEBHOOK_SINK=false
```

- [ ] **Step 2: Commit**

```bash
git add .env.example
git commit -m "docs(env): переменные партнёрского API" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Task 37: Документация для разработчиков партнёра

**Files:**
- Create: `docs/partner-messenger-api.md`

- [ ] **Step 1: Написать документ**

Создать `docs/partner-messenger-api.md` с таким содержимым (внешняя рамка `~~~~` — только для этого плана, в файл её не переносить):

~~~~markdown
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

У обоих `429` есть заголовок `Retry-After` — столько же секунд, сколько в `retryAfter`.

Формат ошибок общий для Taler ID: машинный код в поле `message`, рядом дополнительные поля (`attemptsLeft`, `retryAfter`, `userIds`). Ошибки проверки тела запроса — `400` с массивом кодов в `message`, например `["invalid_email"]`; коды полей: `invalid_external_id`, `invalid_email`, `invalid_first_name`, `invalid_last_name`, `invalid_locale`, `invalid_code`. Лишних полей в тело не кладите: неизвестное поле — тоже `400`, но в массиве будет фраза `property <имя> should not exist`, а не код.

## Люди

`externalId` — стабильный id человека у вас (у nadi — id участника): 1–128 символов `[A-Za-z0-9._:-]`.

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
   - `409 not_pending` — связка уже подтверждена или кода не ждёт.
   - `503 email_send_failed` — письмо не ушло, можно сразу повторить; `503 rate_limiter_unavailable` — лимит сейчас не проверить, повторите через минуту.
3. Человек вводит 6 цифр: `POST /partner/v1/users/{externalId}/link-code/verify` `{"code":"123456"}` → `{ "status": "active", "talerUserId": "…" }`.
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
| `POST /messenger/conversations` `{participantId}` | открыть или создать личный чат с контактом |
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

Закрыто: запросы в контакты, глобальный поиск людей, звонки, каналы, приглашения по ссылке, опросы, темы, отложенные сообщения, черновики и архив, «Избранное», AI.

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
| `error` `{message}` | отказ |

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
- Мессенджер по токену человека — как у приложения Taler ID: считается по IP устройства.
- Файл — до 100 МБ одним запросом, больше — загрузкой по частям.

## Частые вопросы

**Как сопоставить участников бесед с вашими людьми?** Храните пару `externalId ↔ talerUserId` из ответов `POST /users` и `link-code/verify`. В `message.created` есть оба id.

**В беседе человек без `externalId`.** Это пользователь самого Taler ID (приложение Taler ID). Если он в контактах человека, переписка с ним идёт так же.

**Почему в списке только личные чаты и группы?** Партнёрскому токену открыты только они: канал новостей Taler ID, «Избранное» и чаты AI в ваш интерфейс не попадают.

**Будет ли два пуша?** Если у человека установлено ещё и приложение Taler ID — да, уведомят оба приложения.

**Сокет ответил `error` «Пользователь удалил вас из контактов».** Контакт снят: у вас сняли дружбу, или кто-то из двоих заблокировал другого. Писать в эту личку больше нельзя.

## Для политики конфиденциальности

Предлагаемый текст: «Переписка в Nadi работает на мессенджере Taler ID. Для этого при первом входе мы создаём вам аккаунт Taler ID на вашу почту или, с вашего подтверждения, подключаем существующий. Taler ID хранит ваши сообщения и файлы переписки; мы получаем уведомления о новых сообщениях, чтобы присылать вам пуши.»
~~~~

- [ ] **Step 2: Commit**

```bash
git add docs/partner-messenger-api.md
git commit -m "docs: API мессенджера для продуктов-партнёров" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

Примеры ответов в документе сверяются с живым DEV в Task 41.

---

## Task 38: Тестовый клиент для партнёра

**Files:**
- Create: `docs/partner-messenger-api/example-client.ts`

- [ ] **Step 1: Клиент**

Создать `docs/partner-messenger-api/example-client.ts`:

```ts
/**
 * Пример интеграции с мессенджером Taler ID — для разработчиков партнёра (nadi).
 * Проходит весь путь: двое людей → контакт → токены → сокеты → личка → группа.
 * В конце удаляет созданные аккаунты.
 *
 * Запуск (Node 20+, в пустом каталоге):
 *   npm i axios socket.io-client typescript ts-node
 *   BASE_URL=https://staging.id.taler.tirol TALERID_PARTNER_KEY=tidp_… npx ts-node example-client.ts
 */
import axios from 'axios';
import { io, Socket } from 'socket.io-client';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const KEY = process.env.TALERID_PARTNER_KEY ?? '';

// Ваш бэкенд: ключ партнёра — только здесь.
const partner = axios.create({
  baseURL: `${BASE_URL}/partner/v1`,
  headers: { Authorization: `Bearer ${KEY}` },
});

// Ваше приложение: только короткий токен конкретного человека.
function messenger(token: string) {
  return axios.create({ baseURL: `${BASE_URL}/messenger`, headers: { Authorization: `Bearer ${token}` } });
}

async function connect(token: string): Promise<Socket> {
  const socket = io(`${BASE_URL}/messenger`, { auth: { token }, transports: ['websocket'] });
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => resolve());
    socket.once('connect_error', reject);
    socket.once('disconnect', () => reject(new Error('server rejected the token')));
  });
  return socket;
}

async function main(): Promise<void> {
  if (!KEY) throw new Error('TALERID_PARTNER_KEY is required');
  const run = Date.now().toString(36);
  const people = [
    { externalId: `example-a-${run}`, email: `example-a-${run}@example.com`, firstName: 'Олена' },
    { externalId: `example-b-${run}`, email: `example-b-${run}@example.com`, firstName: 'Петро' },
  ];

  try {
    // 1. Бэкенд заводит людей — у nadi при регистрации или входе.
    for (const person of people) {
      console.log('provision', person.externalId, (await partner.post('/users', person)).data);
    }
    const [a, b] = people;

    // 2. Дружба у вас → контакт в Taler ID.
    console.log('contact', (await partner.put(`/contacts/${a.externalId}/${b.externalId}`)).data);

    // 3. Приложение просит токены у своего бэкенда, бэкенд — у Taler ID.
    const tokenA = (await partner.post(`/users/${a.externalId}/token`)).data;
    const tokenB = (await partner.post(`/users/${b.externalId}/token`)).data;

    // 4. Сокеты. Чтобы получать new_message, join не нужен.
    const socketA = await connect(tokenA.accessToken);
    const socketB = await connect(tokenB.accessToken);
    socketB.on('new_message', (m: any) => console.log('B got:', m.senderName, '—', m.content));
    socketA.on('message_acked', (ack: any) => console.log('A acked:', ack));

    // 5. Личный чат и сообщение.
    const direct = (await messenger(tokenA.accessToken).post('/conversations', { participantId: tokenB.talerUserId })).data;
    socketA.emit('message', { conversationId: direct.id, content: 'Привіт!', clientTempId: `tmp-${run}` });

    // 6. Группа из контактов.
    const group = (
      await messenger(tokenA.accessToken).post('/conversations/group', {
        name: 'Толока',
        participantIds: [tokenB.talerUserId],
      })
    ).data;
    socketA.emit('message', { conversationId: group.id, content: 'Збираємося в суботу' });

    await new Promise((r) => setTimeout(r, 2000));
    socketA.disconnect();
    socketB.disconnect();
  } finally {
    // Аккаунты создали мы, и человек в Taler ID сам не входил — их можно удалить.
    for (const person of people) {
      await partner.delete(`/users/${person.externalId}`, { params: { deleteAccount: 'true' } }).catch(() => undefined);
    }
  }
}

main().catch((e) => {
  console.error(e.response?.data ?? e);
  process.exit(1);
});
```

- [ ] **Step 2: Commit**

```bash
git add docs/partner-messenger-api/example-client.ts
git commit -m "docs: пример клиента партнёрского API" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

Клиент прогоняется против DEV в Task 41.

---

## Task 39: E2E-набор `test:partner`

**Files (репозиторий `~/Downloads/taler_id_tests`):**
- Create: `partner_messenger_test.ts`
- Modify: `package.json` (три скрипта), `.env.example`

- [ ] **Step 1: Синхронизировать репозиторий набора**

```bash
cd ~/Downloads/taler_id_tests && git fetch && git status -sb | head -3 && git pull --ff-only
```

Expected: `Already up to date` или fast-forward. В копии бывают чужие незакоммиченные правки — их не трогать и не добавлять (`git add -A` здесь нельзя).

- [ ] **Step 2: Набор**

Создать `~/Downloads/taler_id_tests/partner_messenger_test.ts`:

```ts
/**
 * Taler ID — партнёрский API мессенджера (nadi), E2E.
 *
 * Проверяет: ключ партнёра → заведение людей и повтор → токены → запреты для
 * партнёрского токена → контакт → личка и группа → доставка по сокету →
 * вебхук с подписью (приёмник PARTNER_WEBHOOK_SINK) → «почта занята» и код из
 * письма → удаление аккаунта в TalerID отзывает связку → отзыв связки гасит
 * токен и рвёт сокет → уборка.
 *
 * Запуск:
 *   npm run test:partner          # DEV
 *   npm run test:partner:prod     # TEST
 *   npm run test:partner:talerid  # PROD, короткий: без приёмника и письма
 *
 * Нужны в .env.*: BASE_URL, PARTNER_E2E_KEY и (кроме PROD) PARTNER_E2E_WEBHOOK_SECRET —
 * ключ и секрет вебхука тестового партнёра `e2e` (scripts/partner-admin.ts в бэкенде).
 */
import axios from 'axios';
import { createHmac } from 'crypto';
import { io, Socket } from 'socket.io-client';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const KEY = process.env.PARTNER_E2E_KEY ?? '';
const WEBHOOK_SECRET = process.env.PARTNER_E2E_WEBHOOK_SECRET ?? '';
const SMOKE = process.env.PARTNER_E2E_SMOKE === '1';
const USER1 = { email: 'integration_test@taler-test.com', password: 'IntegrationTest123!' };
/** Пароль аккаунта «почта занята»: один и тот же, чтобы добить его после упавшего прогона. */
const LINKED_PASSWORD = 'PartnerE2E-Linked-1';

const http = axios.create({ baseURL: BASE_URL, validateStatus: () => true, timeout: 20000 });
const partner = axios.create({
  baseURL: `${BASE_URL}/partner/v1`,
  validateStatus: () => true,
  timeout: 20000,
  headers: { Authorization: `Bearer ${KEY}` },
});

function auth(token: string) {
  return { headers: { Authorization: `Bearer ${token}` } };
}

let failed = 0;
let passed = 0;
function check(name: string, cond: boolean, info?: unknown) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}`, info ?? ''); failed++; }
}

/** Без этого значения дальше проверять нечего — одна внятная строка вместо лавины. */
class PrerequisiteError extends Error {}
function need<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new PrerequisiteError(what);
  return value;
}

async function connectSocket(token: string): Promise<Socket> {
  const socket: Socket = io(`${BASE_URL}/messenger`, { auth: { token }, transports: ['websocket'], timeout: 10000 });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => { socket.disconnect(); reject(new Error('Socket connection timeout (10s)')); }, 10000);
    socket.once('connect', () => { clearTimeout(timer); resolve(); });
    socket.once('connect_error', (err: Error) => { clearTimeout(timer); reject(new Error(`Socket connect_error: ${err.message}`)); });
  });
  return socket;
}

/** Ждёт, пока fn вернёт не undefined, не дольше timeoutMs. Никогда не бросает. */
async function waitFor<T>(fn: () => Promise<T | undefined> | T | undefined, timeoutMs: number, stepMs = 500): Promise<T | undefined> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value !== undefined) return value;
    if (Date.now() >= deadline) return undefined;
    await new Promise((r) => setTimeout(r, stepMs));
  }
}

function signatureValid(header: string | null, body: string, secret: string): boolean {
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header ?? '');
  if (!m) return false;
  return createHmac('sha256', secret).update(`${m[1]}.${body}`).digest('hex') === m[2];
}

function parseBody(entry: any): any {
  try { return JSON.parse(entry.body); } catch { return null; }
}

async function main() {
  console.log(`Partner messenger tests against ${BASE_URL}${SMOKE ? ' (smoke)' : ''}`);
  if (!KEY) throw new PrerequisiteError('PARTNER_E2E_KEY не задан в .env');
  if (!SMOKE && !WEBHOOK_SECRET) throw new PrerequisiteError('PARTNER_E2E_WEBHOOK_SECRET не задан в .env');

  const run = Date.now().toString(36);
  const ext = {
    a: `e2e-a-${run}`, b: `e2e-b-${run}`, c: `e2e-c-${run}`, d: `e2e-d-${run}`,
    r: `e2e-r-${run}`, s1: `e2e-s1-${run}`, s2: `e2e-s2-${run}`,
  };
  const createdExternalIds: string[] = [];
  const sockets: Socket[] = [];
  const mailUidsToDelete: number[] = [];
  let linkedToken: string | null = null;
  let user1Token: string | null = null;

  try {
    console.log('\n1. Ключ партнёра');
    check('1a. без ключа → 401', (await http.post('/partner/v1/users', {})).status === 401);
    check('1b. подделанный ключ → 401', (await http.post('/partner/v1/users', {}, auth(`tidp_e2e_${'x'.repeat(43)}`))).status === 401);

    console.log('\n2. Заведение людей');
    for (const key of ['a', 'b', 'c'] as const) {
      const res = await partner.post('/users', {
        externalId: ext[key],
        email: `partner-e2e-${key}-${run}@taler-test.com`,
        firstName: `E2E ${key.toUpperCase()}`,
      });
      check(`2. ${key}: новая почта → active, created`, res.status === 200 && res.data?.status === 'active' && res.data?.created === true, res.data);
      if (res.data?.status === 'active') createdExternalIds.push(ext[key]);
    }
    const again = await partner.post('/users', { externalId: ext.a, email: `partner-e2e-a-${run}@taler-test.com` });
    check('2d. повтор → created:false', again.data?.status === 'active' && again.data?.created === false, again.data);
    check('2e. неизвестный externalId → 404', (await partner.get(`/users/nobody-${run}`)).status === 404);
    const status = await partner.get(`/users/${ext.a}`);
    check('2f. статус: active, managed', status.data?.status === 'active' && status.data?.managed === true, status.data);

    // Гонки проверяются только здесь, на настоящей базе: юнит-тесты транзакцию
    // и уникальные индексы не видят. Один и тот же запрос дважды разом (повтор
    // по таймауту) — оба 200, аккаунт один.
    const raceEmail = `partner-e2e-r-${run}@taler-test.com`;
    const twin = await Promise.all([0, 1].map(() => partner.post('/users', { externalId: ext.r, email: raceEmail })));
    createdExternalIds.push(ext.r);
    check('2g. одинаковый POST дважды разом → оба active, created ровно у одного',
      twin.every((r) => r.status === 200 && r.data?.status === 'active') &&
        twin.filter((r) => r.data?.created === true).length === 1 &&
        twin[0].data?.talerUserId === twin[1].data?.talerUserId,
      twin.map((r) => [r.status, r.data]));
    // Одна почта под двумя externalId разом — аккаунт один, второму 409.
    const clashEmail = `partner-e2e-s-${run}@taler-test.com`;
    const clash = await Promise.all([ext.s1, ext.s2].map((id) => partner.post('/users', { externalId: id, email: clashEmail })));
    for (const [i, r] of clash.entries()) if (r.data?.status === 'active') createdExternalIds.push([ext.s1, ext.s2][i]);
    check('2h. одна почта под двумя externalId разом → один active, второй 409',
      clash.filter((r) => r.status === 200 && r.data?.status === 'active').length === 1 &&
        clash.filter((r) => r.status === 409 && r.data?.message === 'user_linked_to_other_external_id').length === 1,
      clash.map((r) => [r.status, r.data]));

    console.log('\n3. Токены');
    const tok = {} as Record<'a' | 'b' | 'c', { accessToken: string; talerUserId: string }>;
    for (const key of ['a', 'b', 'c'] as const) {
      const res = await partner.post(`/users/${ext[key]}/token`);
      check(`3. ${key}: токен на 900 с`, res.status === 200 && typeof res.data?.accessToken === 'string' && res.data?.expiresIn === 900, res.data);
      tok[key] = need(res.data?.accessToken ? res.data : null, `токен ${key}`);
    }
    check('3d. /profile по партнёрскому токену → 401', (await http.get('/profile', auth(tok.a.accessToken))).status === 401);
    const socketA = await connectSocket(tok.a.accessToken);
    const socketB = await connectSocket(tok.b.accessToken);
    sockets.push(socketA, socketB);
    const eventsA: any[] = [];
    const eventsB: any[] = [];
    socketA.onAny((event: string, data: any) => eventsA.push({ event, data }));
    socketB.onAny((event: string, data: any) => eventsB.push({ event, data }));
    check('3e. оба сокета подключились', socketA.connected && socketB.connected);

    console.log('\n4. Запреты для партнёрского токена');
    check('4a. глобальный поиск людей → 403', (await http.get('/messenger/users/search?q=test', auth(tok.a.accessToken))).status === 403);
    check('4b. запрос в контакты → 403', (await http.post('/messenger/contacts/request', { receiverId: tok.b.talerUserId }, auth(tok.a.accessToken))).status === 403);
    socketA.emit('call_invite', { conversationId: 'x', roomName: 'x' });
    const callError = await waitFor(() => eventsA.find((e) => e.event === 'error' && e.data?.event === 'call_invite'), 5000, 100);
    check('4c. call_invite → error not_available_for_partner', callError?.data?.message === 'not_available_for_partner', eventsA.slice(-5));
    user1Token = (await http.post('/auth/login', USER1)).data?.accessToken ?? null;
    const t1 = need(user1Token, 'логин integration_test');
    const user1Conversations = (await http.get('/messenger/conversations', auth(t1))).data;
    const channel = Array.isArray(user1Conversations) ? user1Conversations.find((c: any) => c.type === 'CHANNEL') : undefined;
    check('4d. нашёлся канал для проверки', !!channel);
    if (channel) {
      check('4e. сообщения канала по партнёрскому токену → 403', (await http.get(`/messenger/conversations/${channel.id}/messages`, auth(tok.a.accessToken))).status === 403);
    }
    const listA = await http.get('/messenger/conversations', auth(tok.a.accessToken));
    check('4f. в списке бесед партнёра нет каналов', listA.status === 200 && (listA.data as any[]).every((c) => c.type === 'DIRECT' || c.type === 'GROUP'), listA.data);

    console.log('\n5. Контакт и личка');
    check('5a. личка без контакта → 403', (await http.post('/messenger/conversations', { participantId: tok.b.talerUserId }, auth(tok.a.accessToken))).status === 403);
    const put1 = await partner.put(`/contacts/${ext.a}/${ext.b}`);
    check('5b. PUT контакт → created', put1.status === 200 && put1.data?.contact === true && put1.data?.created === true, put1.data);
    const put2 = await partner.put(`/contacts/${ext.b}/${ext.a}`);
    check('5c. повтор в обратном порядке → created:false', put2.data?.created === false, put2.data);
    const direct = await http.post('/messenger/conversations', { participantId: tok.b.talerUserId }, auth(tok.a.accessToken));
    check('5d. личка с контактом создана', direct.status === 201 || direct.status === 200, direct.data);
    const directId: string = need(direct.data?.id, 'id лички');
    const tempId = `tmp-${run}`;
    socketA.emit('message', { conversationId: directId, content: `привет ${run}`, clientTempId: tempId });
    const acked = await waitFor(() => eventsA.find((e) => e.event === 'message_acked' && e.data?.clientTempId === tempId), 5000, 100);
    check('5e. отправителю пришёл message_acked', !!acked, eventsA.slice(-5));
    const got = await waitFor(() => eventsB.find((e) => e.event === 'new_message' && e.data?.content === `привет ${run}`), 5000, 100);
    check('5f. получателю пришёл new_message', !!got, eventsB.slice(-5));
    const messageId: string | undefined = acked?.data?.messageId;

    console.log('\n6. Группы');
    const group = await http.post('/messenger/conversations/group', { name: `E2E ${run}`, participantIds: [tok.b.talerUserId] }, auth(tok.a.accessToken));
    check('6a. группа из контакта создана', group.status === 201 || group.status === 200, group.data);
    const stranger = await http.post('/messenger/conversations/group', { name: `E2E-x ${run}`, participantIds: [tok.c.talerUserId] }, auth(tok.a.accessToken));
    check('6b. группа с не-контактом → 403 not_a_contact', stranger.status === 403 && stranger.data?.message === 'not_a_contact' && (stranger.data?.userIds ?? []).includes(tok.c.talerUserId), stranger.data);
    if (group.data?.id) {
      const add = await http.post(`/messenger/conversations/${group.data.id}/members`, { userIds: [tok.c.talerUserId] }, auth(tok.a.accessToken));
      check('6c. добавить не-контакт → 403', add.status === 403, add.data);
    }

    if (!SMOKE) {
      console.log('\n7. Вебхук');
      const sinkHit = await waitFor(async () => {
        const res = await partner.get('/_sink/events');
        const entries: any[] = Array.isArray(res.data) ? res.data : [];
        return entries.find((e) => {
          const body = parseBody(e);
          return body?.type === 'message.created' && body.recipient?.externalId === ext.b && body.message?.id === messageId;
        });
      }, 20000, 1000);
      check('7a. message.created для B дошёл до приёмника', !!sinkHit);
      if (sinkHit) {
        check('7b. подпись вебхука сходится', signatureValid(sinkHit.signature, sinkHit.body, WEBHOOK_SECRET));
        const body = parseBody(sinkHit);
        check('7c. в событии externalId отправителя и превью', body?.message?.senderExternalId === ext.a && body?.message?.preview === `привет ${run}`, body);
      }
      const ping = await partner.post('/webhooks/test');
      check('7d. тестовый ping доставлен', ping.status === 200 && ping.data?.delivered === true, ping.data);
      const log = await partner.get('/webhooks/deliveries?limit=20');
      check('7e. в журнале есть доставленные', Array.isArray(log.data) && log.data.some((d: any) => d.delivered), log.data);

      // B открыл чат — на следующее сообщение вебхук не нужен.
      socketB.emit('join', { conversationId: directId });
      await new Promise((r) => setTimeout(r, 500));
      const tempId2 = `tmp2-${run}`;
      socketA.emit('message', { conversationId: directId, content: `второе ${run}`, clientTempId: tempId2 });
      const acked2 = await waitFor(() => eventsA.find((e) => e.event === 'message_acked' && e.data?.clientTempId === tempId2), 5000, 100);
      await new Promise((r) => setTimeout(r, 5000));
      const sink2 = await partner.get('/_sink/events');
      const leaked = (Array.isArray(sink2.data) ? sink2.data : []).some((e: any) => parseBody(e)?.message?.id === acked2?.data?.messageId);
      check('7f. при открытом чате вебхука нет', !!acked2 && !leaked);

      console.log('\n8. Почта занята — код из письма');
      let mailbox = await http.get('/mail/account', auth(t1));
      if (mailbox.status !== 200) mailbox = await http.post('/mail/account', { localpart: `itest${run}` }, auth(t1));
      const address: string = need(mailbox.data?.address, 'ящик integration_test на Mailcow');
      // Существующий аккаунт TalerID с почтой-ящиком integration_test: код придёт
      // туда, где набор его прочтёт через почтовый мост.
      const reg = await http.post('/auth/register', { email: address, password: LINKED_PASSWORD, firstName: 'E2E Linked' });
      linkedToken = reg.status < 300
        ? reg.data?.accessToken
        : (await http.post('/auth/login', { email: address, password: LINKED_PASSWORD })).data?.accessToken;
      const linked = need(linkedToken, 'аккаунт на ящик integration_test');
      const linkedId: string = need((await http.get('/profile', auth(linked))).data?.id, 'id этого аккаунта');

      const prov = await partner.post('/users', { externalId: ext.d, email: address.toUpperCase() });
      check('8a. занятая почта (другим регистром) → confirmation_required', prov.data?.status === 'confirmation_required' && prov.data?.talerUserId === null, prov.data);
      check('8b. токен до кода → 409', (await partner.post(`/users/${ext.d}/token`)).status === 409);
      const before = await http.get('/mail/messages', auth(t1));
      const seen = new Set<number>(((before.data?.items ?? []) as any[]).map((m) => m.uid));
      const sent = await partner.post(`/users/${ext.d}/link-code`);
      check('8c. код отправлен', sent.status === 200 && sent.data?.sent === true, sent.data);
      check('8d. повторная отправка сразу → 429', (await partner.post(`/users/${ext.d}/link-code`)).status === 429);
      const wrong = await partner.post(`/users/${ext.d}/link-code/verify`, { code: '000000' });
      check('8e. неверный код → 400, attemptsLeft 4', wrong.status === 400 && wrong.data?.attemptsLeft === 4, wrong.data);
      const letter = await waitFor(async () => {
        const inbox = await http.get('/mail/messages', auth(t1));
        return ((inbox.data?.items ?? []) as any[]).find((m) => !seen.has(m.uid) && /Taler ID: \d{6}$/.test(m.subject ?? ''));
      }, 90000, 3000);
      check('8f. письмо с кодом пришло', !!letter);
      if (letter) {
        mailUidsToDelete.push(letter.uid);
        const code = (/(\d{6})$/.exec(letter.subject) ?? [])[1];
        const ok = await partner.post(`/users/${ext.d}/link-code/verify`, { code });
        check('8g. верный код → active того же аккаунта', ok.data?.status === 'active' && ok.data?.talerUserId === linkedId, ok.data);
        check('8h. переименовать чужой аккаунт → 409', (await partner.patch(`/users/${ext.d}`, { firstName: 'X' })).status === 409);
        check('8i. после кода токен выдаётся', (await partner.post(`/users/${ext.d}/token`)).status === 200);
        const del = await http.delete('/profile', auth(linked));
        check('8j. человек удалил аккаунт в TalerID', del.status < 300, del.data);
        linkedToken = null;
        // Аккаунт привязан кодом, партнёр был допущен — ему положено знать об удалении (410),
        // чтобы не заводить человека заново самому. Повтор — снова 410, GET — revoked без id.
        const gone = await partner.post(`/users/${ext.d}/token`);
        check('8k. после удаления связка отозвана, токен → 410 account_deleted', gone.status === 410 && gone.data?.message === 'account_deleted', gone.data);
        check('8l. повторный запрос токена → снова 410', (await partner.post(`/users/${ext.d}/token`)).status === 410);
        const after = await partner.get(`/users/${ext.d}`);
        check('8m. статус: revoked, id не отдаётся', after.data?.status === 'revoked' && after.data?.talerUserId === null, after.data);
      }
    }

    console.log('\n9. Имя и отзыв связки');
    check('9a. переименовать управляемый аккаунт', (await partner.patch(`/users/${ext.a}`, { firstName: 'Переименован' })).status === 200);
    const dropped = new Promise<boolean>((resolve) => {
      socketA.once('disconnect', () => resolve(true));
      setTimeout(() => resolve(false), 5000);
    });
    check('9b. DELETE связки → 204', (await partner.delete(`/users/${ext.a}`)).status === 204);
    check('9c. сокет отозванной связки разорван', await dropped);
    check('9d. старый токен больше не пускает', (await http.get('/messenger/conversations', auth(tok.a.accessToken))).status === 401);
    check('9e. новый токен не выдаётся → 404', (await partner.post(`/users/${ext.a}/token`)).status === 404);
  } finally {
    for (const s of sockets) s.disconnect();
    for (const id of createdExternalIds) {
      await partner.delete(`/users/${id}`, { params: { deleteAccount: 'true' } }).catch(() => undefined);
    }
    await partner.delete(`/users/${ext.d}`).catch(() => undefined);
    if (linkedToken) await http.delete('/profile', auth(linkedToken)).catch(() => undefined);
    if (user1Token) {
      for (const uid of mailUidsToDelete) await http.delete(`/mail/messages/${uid}`, auth(user1Token)).catch(() => undefined);
    }
  }
}

main()
  .then(() => {
    console.log(`\n${passed} passed, ${failed} failed`);
    process.exit(failed > 0 ? 1 : 0);
  })
  .catch((e) => {
    if (e instanceof PrerequisiteError) console.error(`\n✗ Прерван: ${e.message}`);
    else console.error(e);
    console.log(`\n${passed} passed, ${failed + 1} failed`);
    process.exit(1);
  });
```

- [ ] **Step 3: Скрипты и пример env**

В `~/Downloads/taler_id_tests/package.json` в `scripts` добавить:

```json
    "test:partner": "dotenv -e .env.dev -- npx ts-node partner_messenger_test.ts",
    "test:partner:prod": "dotenv -e .env.prod -- npx ts-node partner_messenger_test.ts",
    "test:partner:talerid": "PARTNER_E2E_SMOKE=1 dotenv -e .env.talerid -- npx ts-node partner_messenger_test.ts",
```

В `~/Downloads/taler_id_tests/.env.example` добавить:

```
# Тестовый партнёр `e2e` (scripts/partner-admin.ts в бэкенде); секрет — не на PROD
PARTNER_E2E_KEY=
PARTNER_E2E_WEBHOOK_SECRET=
```

- [ ] **Step 4: Проверить, что набор собирается и честно падает без ключа**

```bash
cd ~/Downloads/taler_id_tests && npx ts-node partner_messenger_test.ts; echo "exit=$?"
```

Expected: `✗ Прерван: PARTNER_E2E_KEY не задан в .env` и `exit=1`. ts-node проверяет типы файла (в `tsconfig` набора `strict: true`), так что ошибка типов проявится здесь же, до запуска. `tsc -p .` по всему репозиторию не годится: он спотыкается о чужие файлы. Полный прогон — после выкатки на DEV (Task 41).

- [ ] **Step 5: Commit в репозитории набора — только свои файлы**

```bash
cd ~/Downloads/taler_id_tests
git add partner_messenger_test.ts package.json .env.example
git commit -m "test: партнёрский API мессенджера (nadi) — test:partner" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

`git push` — вместе с выкаткой на DEV, после зелёного прогона.

---

## Task 40: Полная проверка ветки и ревью

**Files:** кода не меняет, кроме исправлений по ревью.

- [ ] **Step 1: Все тесты против базы**

```bash
cd /Users/dmitry/taler-id/.worktrees/partner-messenger-api
npx jest 2>&1 | grep -E "^(FAIL|Tests:|Test Suites:)" | sort -u > ../partner-after.txt
diff <(grep '^FAIL' ../partner-baseline.txt) <(grep '^FAIL' ../partner-after.txt) && echo "no new failures"
```

Expected: `no new failures`. Строки с `>` в выводе `diff` — новые падения: чинить до перехода дальше.

- [ ] **Step 1a: Отзыв токенов на настоящей библиотеке**

```bash
node scripts/verify-partner-tokens.cjs
```

Expected: строка `OK` на каждый сценарий (основа, две параллельные выдачи, смена гранта, выдача наперегонки с отзывом, сбой Redis посреди отзыва, замена гранта с остатком меньше минуты), в конце `all … scenarios passed`, код выхода 0. Моки в юнит-тестах такие ошибки не ловят — только этот прогон.

- [ ] **Step 2: Сборка и линтер новых файлов**

```bash
npm run build
git diff --name-only origin/main...HEAD -- 'src/**/*.ts' 'scripts/**/*.ts' | xargs npx prettier --write
git diff --stat
npx eslint "src/partner-core/**/*.ts" "src/partner-api/**/*.ts" src/messenger/messenger-auth.guard.ts src/messenger/socket-gate.ts src/messenger/partner-allowed.decorator.ts src/messenger/partner-conversation-scope.service.ts src/messenger/push-text.util.ts scripts/partner-admin.ts
```

Expected: сборка без ошибок, eslint без ошибок. Код в задачах плана не прогнан через prettier репозитория (ревью задач 18–20 нашло десятки расхождений), поэтому здесь форматируются все файлы ветки одним коммитом `style: prettier для файлов партнёрского API` — после него снова `npx jest src/partner-core src/partner-api src/messenger src/profile` и `npm run build`: форматирование не должно ничего менять по смыслу.

- [ ] **Step 3: Ревью кода**

Вызвать навык `superpowers:requesting-code-review` на `git diff origin/main...HEAD`. Отдельно попросить ревьюера проверить:
- партнёрский токен не проходит ни в одну ручку без `@PartnerAllowed`, ни в одно событие сокета вне `PARTNER_SOCKET_EVENTS`;
- ключи, секреты и коды нигде не пишутся в лог;
- `revokeLink` гасит токены до того, как рвёт сокеты;
- у `fanOutToParticipants` не появилось запросов на каждого участника;
- попытка ввода кода списывается атомарно до сравнения (параллельные запросы не обходят лимит в 5 попыток);
- скрипт администратора не может перезаписать чужой OAuth-клиент.

Замечания по делу чинить через TDD, каждое отдельным коммитом.

- [ ] **Step 4: Ревью безопасности**

Вызвать навык `security-review` на ветку. Критичные находки — чинить до выкатки.

- [ ] **Step 5: Спросить пользователя**

Коротко доложить: сколько тестов, что показало ревью, что исправлено. Спросить разрешения слить ветку в `dev` и выкатить на DEV. Без явного «да» дальше не идти.

---

## Task 41: Выкатка на DEV

**Files:** кода не меняет, кроме правок документации по живым ответам.

- [ ] **Step 1: Слить ветку в `dev`**

```bash
cd /Users/dmitry/taler-id/.worktrees/partner-messenger-api
git fetch origin
git switch -c merge-dev-partner origin/dev
git merge --no-ff feat/partner-messenger-api -m "Merge branch 'feat/partner-messenger-api' into dev" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
npm run build
git push origin HEAD:dev
git switch feat/partner-messenger-api && git branch -D merge-dev-partner
```

Expected: мёрж без конфликтов (ветки `dev` и `main` не трогают наших файлов), сборка прошла, пуш принят.

- [ ] **Step 2: Код и миграция на DEV-сервере**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npx prisma migrate status | tail -4'
```

Expected: не применена одна миграция — `20260930120000_partner_api`. Другие неприменённые миграции — остановиться и разобраться: это чужие изменения.

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && npx prisma migrate deploy && npx prisma generate && npm run build'
```

Expected: `All migrations have been successfully applied`, сборка прошла.

- [ ] **Step 3: Переменные окружения**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && cp .env .env.bak-partner-$(date +%Y%m%d%H%M) && \
  (grep -q "^PARTNER_SECRETS_KEY=" .env || echo "PARTNER_SECRETS_KEY=$(openssl rand -hex 32)" >> .env) && \
  (grep -q "^PARTNER_API_ENABLED=" .env || echo "PARTNER_API_ENABLED=true" >> .env) && \
  (grep -q "^PARTNER_WEBHOOK_SINK=" .env || echo "PARTNER_WEBHOOK_SINK=true" >> .env) && \
  grep -c "^PARTNER_" .env; grep -c "^TRUST_PROXY=" .env || true'
```

Expected: `3`, затем `0`. Значения не печатаются. `TRUST_PROXY` в `.env` быть не должно: Express доверяет только loopback (`main.ts`), а с другим значением белый список IP партнёра обходится заголовком `X-Forwarded-For`. Если строка есть — разобраться до продолжения.

- [ ] **Step 4: Рестарт и проверка старта**

```bash
ssh dvolkov@89.169.55.217 'pm2 restart taler-id-dev --update-env && sleep 10 && pm2 logs taler-id-dev --lines 120 --nostream | grep -E "successfully started|resolve dependencies|key fingerprint|ERROR" | tail -6'
curl -s -o /dev/null -w "health:%{http_code}\n" https://staging.id.taler.tirol/health
curl -s -o /dev/null -w "partner-no-key:%{http_code}\n" -X POST https://staging.id.taler.tirol/partner/v1/users
```

Expected: `Nest application successfully started`; строка `partner secrets key fingerprint: <8 hex>` (а не ругань на `PARTNER_SECRETS_KEY`); ни одного `can't resolve dependencies`; `health:200`; `partner-no-key:401`.

- [ ] **Step 5: Партнёры `e2e` и `nadi`**

```bash
ssh dvolkov@89.169.55.217 'mkdir -p -m 700 ~/partner-keys && cd ~/taler-id && \
  npx ts-node -r dotenv/config scripts/partner-admin.ts create --slug e2e --name E2E --out ~/partner-keys/e2e.env --var PARTNER_E2E_KEY && \
  npx ts-node -r dotenv/config scripts/partner-admin.ts set-webhook --slug e2e --url https://staging.id.taler.tirol/partner/v1/_sink/e2e --out ~/partner-keys/e2e.env --var PARTNER_E2E_WEBHOOK_SECRET && \
  npx ts-node -r dotenv/config scripts/partner-admin.ts create --slug nadi --name Nadi --out ~/partner-keys/nadi-dev.env && \
  npx ts-node -r dotenv/config scripts/partner-admin.ts show --slug e2e'
```

Expected: строки «… записан в … как …» без самих значений; `show` — `enabled: true`, вебхук на `_sink/e2e`, `webhookSecret: 'задан'`.

- [ ] **Step 6: Ключи тестового партнёра — в набор, мимо экрана**

```bash
ssh dvolkov@89.169.55.217 'cat ~/partner-keys/e2e.env' >> ~/Downloads/taler_id_tests/.env.dev
grep -c "^PARTNER_E2E_" ~/Downloads/taler_id_tests/.env.dev
```

Expected: `2`.

- [ ] **Step 7: E2E-набор партнёра**

```bash
cd ~/Downloads/taler_id_tests && npm run test:partner
```

Expected: все проверки ✓, `0 failed`. Падение — чинить в ветке (TDD), снова сливать в `dev` и выкатывать; ничего не «подкручивать» на сервере руками.

- [ ] **Step 8: Обязательные наборы DEV из CLAUDE.md**

Наборы разносить паузой: лимит логинов в nginx даёт 503, которые выглядят как регрессия, но ею не являются.

```bash
cd ~/Downloads/taler_id_tests
for s in test test:voice test:assistant test:files test:channels test:billing test:recording test:voice-session test:translator test:mcp test:system-channel test:device-approval test:pins test:room-chat test:speakers; do
  echo "=== $s"; npm run $s 2>&1 | tail -3; sleep 20
done
```

Expected: как до выкатки. Про `test:speakers` на DEV известно, что он красный и до нас (память «iOS звонки через CallKit»): сравнить с его прошлым результатом. Наборы 1–3 из CLAUDE.md (Flutter, эмуляторы) мобильное приложение не затрагивают, но правило их требует — спросить пользователя, гонять ли их при чисто серверном изменении.

- [ ] **Step 9: Живые примеры для документации**

```bash
cp /Users/dmitry/taler-id/.worktrees/partner-messenger-api/docs/partner-messenger-api/example-client.ts ~/Downloads/taler_id_tests/.example-client.ts
cd ~/Downloads/taler_id_tests && TALERID_PARTNER_KEY="$(grep '^PARTNER_E2E_KEY=' .env.dev | cut -d= -f2-)" BASE_URL=https://staging.id.taler.tirol npx ts-node -T .example-client.ts; rm -f .example-client.ts
```

Expected: `provision … { status: 'active', … created: true }`, `contact …`, `A acked`, `B got: Олена — Привіт!`. Сверить форматы ответов с `docs/partner-messenger-api.md`. Расхождения — поправить документ в ветке, закоммитить (`docs: сверено с DEV`) и слить в `dev` ещё раз.

- [ ] **Step 10: Запушить набор**

```bash
cd ~/Downloads/taler_id_tests && git push
```

---

## Task 42: Выкатка на TEST

**Files:** кода не меняет.

- [ ] **Step 1: Спросить пользователя**

Выкатка на TEST — отдельная команда пользователя. Без неё не начинать.

- [ ] **Step 2: Слить ветку в `main`**

```bash
cd /Users/dmitry/taler-id/.worktrees/partner-messenger-api
git fetch origin
git switch -c merge-main-partner origin/main
git merge --no-ff feat/partner-messenger-api -m "Merge branch 'feat/partner-messenger-api'" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
npm run build
git push origin HEAD:main
git switch feat/partner-messenger-api && git branch -D merge-main-partner
```

- [ ] **Step 3: Код, миграция, сборка на TEST**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && git pull && npx prisma migrate status | tail -4'
ssh dvolkov@138.124.61.221 'cd ~/taler-id && npx prisma migrate deploy && npx prisma generate && npm run build'
```

Expected: как на DEV — одна наша миграция, затем `successfully applied`.

- [ ] **Step 4: Переменные, рестарт, проверка**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && cp .env .env.bak-partner-$(date +%Y%m%d%H%M) && \
  (grep -q "^PARTNER_SECRETS_KEY=" .env || echo "PARTNER_SECRETS_KEY=$(openssl rand -hex 32)" >> .env) && \
  (grep -q "^PARTNER_API_ENABLED=" .env || echo "PARTNER_API_ENABLED=true" >> .env) && \
  (grep -q "^PARTNER_WEBHOOK_SINK=" .env || echo "PARTNER_WEBHOOK_SINK=true" >> .env) && \
  grep -c "^PARTNER_" .env && (grep -c "^TRUST_PROXY=" .env || true) && pm2 restart taler-id --update-env && sleep 10 && \
  pm2 logs taler-id --lines 120 --nostream | grep -E "successfully started|resolve dependencies|key fingerprint" | tail -4'
curl -s -o /dev/null -w "health:%{http_code}\n" https://id.taler.tirol/health
```

Expected: `3`, `0`, `successfully started`, строка `partner secrets key fingerprint: …`, `health:200`. `TRUST_PROXY` в `.env` быть не должно: Express доверяет только loopback (`main.ts`), а с другим значением белый список IP партнёра обходится заголовком `X-Forwarded-For`. Если строка есть — разобраться до продолжения.

- [ ] **Step 5: Только тестовый партнёр**

TEST выводится из обращения — nadi здесь не заводится.

```bash
ssh dvolkov@138.124.61.221 'mkdir -p -m 700 ~/partner-keys && cd ~/taler-id && \
  npx ts-node -r dotenv/config scripts/partner-admin.ts create --slug e2e --name E2E --out ~/partner-keys/e2e.env --var PARTNER_E2E_KEY && \
  npx ts-node -r dotenv/config scripts/partner-admin.ts set-webhook --slug e2e --url https://id.taler.tirol/partner/v1/_sink/e2e --out ~/partner-keys/e2e.env --var PARTNER_E2E_WEBHOOK_SECRET'
ssh dvolkov@138.124.61.221 'cat ~/partner-keys/e2e.env' >> ~/Downloads/taler_id_tests/.env.prod
grep -c "^PARTNER_E2E_" ~/Downloads/taler_id_tests/.env.prod
```

Expected: `2`.

- [ ] **Step 6: Наборы TEST**

```bash
cd ~/Downloads/taler_id_tests && npm run test:partner:prod
for s in test:prod test:voice:prod test:assistant:prod test:files:prod test:channels:prod test:billing:prod test:recording:prod test:voice-session:prod test:translator:prod test:mcp:prod test:system-channel:prod test:device-approval:prod test:pins:prod test:room-chat:prod test:speakers:prod; do
  echo "=== $s"; npm run $s 2>&1 | tail -3; sleep 20
done
```

Expected: `test:partner:prod` — `0 failed`; остальные — как до выкатки.

---

## Task 43: Выкатка на PROD (DigitalOcean)

**Files:** кода не меняет.

- [ ] **Step 1: Только по явной команде пользователя**

PROD — только после слов пользователя вроде «деплой на прод». До этого остановиться и доложить, что DEV и TEST готовы.

- [ ] **Step 2: Код и миграция — одна нода, база общая**

Все команды — с бот-сервера (`ssh dvolkov@77.73.131.137`): до нод DO ходим через его алиасы.

```bash
ssh do-app-1 'cd /opt/taler-id && git fetch && git reset --hard origin/main && npx prisma migrate status | tail -4'
ssh do-app-1 'cd /opt/taler-id && npx prisma migrate deploy'
```

Expected: одна наша миграция, затем `successfully applied`. Миграция аддитивная: обе ноды на старом коде продолжают работать.

- [ ] **Step 3: Одинаковый ключ секретов на обеих нодах**

```bash
KEY=$(openssl rand -hex 32)
for n in do-app-1 do-app-2; do
  ssh $n "cd /opt/taler-id && cp .env .env.bak-partner-\$(date +%Y%m%d%H%M) && \
    (grep -q '^PARTNER_SECRETS_KEY=' .env || echo 'PARTNER_SECRETS_KEY=$KEY' >> .env) && \
    (grep -q '^PARTNER_API_ENABLED=' .env || echo 'PARTNER_API_ENABLED=true' >> .env) && \
    grep -c '^PARTNER_' .env; grep -c '^TRUST_PROXY=' .env || true"
done
unset KEY
for n in do-app-1 do-app-2; do ssh $n "grep '^PARTNER_SECRETS_KEY=' /opt/taler-id/.env | sha256sum"; done
```

Expected: `2` и `0` на каждой ноде; два одинаковых хэша. `PARTNER_WEBHOOK_SINK` на PROD не задаётся. `TRUST_PROXY` в `.env` быть не должно: Express доверяет только loopback (`main.ts`), а с другим значением белый список IP партнёра обходится заголовком `X-Forwarded-For`. Если строка есть — разобраться до продолжения.

- [ ] **Step 4: Поочерёдный рестарт**

```bash
ssh do-app-1 'cd /opt/taler-id && npm ci && npx prisma generate && npm run build && sudo pm2 restart taler-id --update-env && sleep 5 && curl -s -o /dev/null -w "health:%{http_code}\n" http://localhost:3000/health'
```

Дождаться `health:200`, затем:

```bash
ssh do-app-2 'cd /opt/taler-id && git fetch && git reset --hard origin/main && npm ci && npx prisma generate && npm run build && sudo pm2 restart taler-id --update-env && sleep 5 && curl -s -o /dev/null -w "health:%{http_code}\n" http://localhost:3000/health'
```

Expected: `health:200` на обеих. Полный `npm ci`, а не `--omit=dev`: nest CLI живёт в devDependencies.

Ключи секретов на нодах совпадают не только по файлу, но и в работающих процессах:

```bash
for n in do-app-1 do-app-2; do ssh $n "sudo pm2 logs taler-id --lines 400 --nostream | grep 'key fingerprint' | tail -1"; done
```

Expected: одинаковый отпечаток на обеих нодах. Разный — остановиться: коды привязки и вебхуки будут сбоить через раз.

- [ ] **Step 5: Партнёры `e2e` и `nadi`**

```bash
ssh do-app-1 'mkdir -p -m 700 /root/partner-keys && cd /opt/taler-id && \
  npx ts-node -r dotenv/config scripts/partner-admin.ts create --slug e2e --name E2E --ips 77.73.131.137 --out /root/partner-keys/e2e.env --var PARTNER_E2E_KEY && \
  npx ts-node -r dotenv/config scripts/partner-admin.ts create --slug nadi --name Nadi --ips 165.227.141.149 --out /root/partner-keys/nadi-prod.env && \
  npx ts-node -r dotenv/config scripts/partner-admin.ts show --slug nadi'
```

Expected: `show` — `ipAllowlist: ['165.227.141.149']`, вебхука пока нет (его адрес даст команда nadi).

Тестовый партнёр `e2e` на PROD навсегда ограничен адресом бот-сервера: его ключ лежит не только на ноде, и утечка без белого списка позволила бы заводить аккаунты и слать письма с кодом от имени «E2E» кому угодно (финальное ревью ветки). Поэтому короткий прогон на PROD — только с бот-сервера.

- [ ] **Step 6: Короткий прогон и проверки**

На бот-сервере (набор `partner_messenger_test.ts` и скрипты `test:partner*` должны быть в `~/talerid-ws/taler_id_tests`: `git pull`, если коммит набора уже запушен — пушить его только с разрешения пользователя, — иначе скопировать два файла `rsync`-ом с мака):

```bash
ssh do-app-1 'cat /root/partner-keys/e2e.env' >> ~/talerid-ws/taler_id_tests/.env.talerid && chmod 600 ~/talerid-ws/taler_id_tests/.env.talerid
grep -c "^PARTNER_E2E_KEY=" ~/talerid-ws/taler_id_tests/.env.talerid
cd ~/talerid-ws/taler_id_tests && npm run test:partner:talerid && npm run test:talerid
curl -s -o /dev/null -w "sink-on-prod:%{http_code}\n" -X POST https://api.talerid.io/partner/v1/_sink/e2e
```

Expected: `1`; оба набора зелёные; `sink-on-prod:404`.

Две ноды — единственное место, где сокеты партнёра ходят через Redis-адаптер между процессами (ревью задач 27–28 нашло там падение ноды, на одной ноде оно не воспроизводится). На бот-сервере до и после прогона набора:

```bash
for n in do-app-1 do-app-2; do ssh $n "sudo pm2 jlist | jq -r '.[] | select(.name==\"taler-id\") | \"\(.name) restarts=\(.pm2_env.restart_time) uptime_ms=\(.pm2_env.pm_uptime)\"'"; done
for n in do-app-1 do-app-2; do ssh $n "sudo pm2 logs taler-id --lines 400 --nostream | grep -c 'Converting circular structure\|Uncaught'"; done
```

Expected: число рестартов на обеих нодах после прогона то же, что до; второй цикл печатает `0` и `0`.

На бот-сервере — межнодовая доставка сообщений (замена несуществующего гейта из CLAUDE.md):

```bash
cd ~/talerid-ws/taler_id_tests && BASE_URL=https://api.talerid.io npx ts-node multi_message_test.ts
```

Expected: 13 проверок ✓.

- [ ] **Step 7: Белый список IP видит настоящий адрес за балансировщиком**

У nadi на PROD включён белый список. Убедиться, что `req.ip` за цепочкой LB → nginx → Nest — это адрес клиента, а не прокси. Тестовый партнёр уже ограничен адресом бот-сервера (Step 5). На бот-сервере:

```bash
KEY="$(ssh do-app-1 "cut -d= -f2- /root/partner-keys/e2e.env")"
curl -s -o /dev/null -w "from-bot:%{http_code}\n" -H "Authorization: Bearer $KEY" https://api.talerid.io/partner/v1/users/ip-probe
unset KEY
```

С мака:

```bash
K="$(ssh dvolkov@77.73.131.137 "ssh do-app-1 'cut -d= -f2- /root/partner-keys/e2e.env'")"
curl -s -o /dev/null -w "from-mac:%{http_code}\n" -H "Authorization: Bearer $K" https://api.talerid.io/partner/v1/users/ip-probe
```

Expected: `from-bot:404` (ключ и IP приняты, такого `externalId` просто нет), `from-mac:401` (`ip_not_allowed`). Если и с бота 401 — Express видит адрес прокси: разбираться с `TRUST_PROXY` и `real_ip` в nginx до того, как nadi начнёт ходить на PROD.

Там же, с мака — подделка адреса. Заголовок с адресом бота не должен открывать белый список ни через балансировщик, ни через RU-edge (`ru.talerid.io` проксирует на DO с `Host: api.talerid.io`):

```bash
for h in api.talerid.io ru.talerid.io; do
  curl -s -o /dev/null -w "spoof-$h:%{http_code}\n" -H "Authorization: Bearer $K" -H "X-Forwarded-For: 77.73.131.137" "https://$h/partner/v1/users/ip-probe"
done
unset K
```

Expected: `spoof-api.talerid.io:401` и `spoof-ru.talerid.io:401`. `404` хоть на одном — поддельный заголовок дошёл до `req.ip`: nadi на PROD не пускать, пока не исправлен nginx (на edge — `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`, на app-нодах — `real_ip_recursive on` с доверием только LB и edge).

Ограничение тестового партнёра адресом бот-сервера не снимать.
---

## Task 44: CLAUDE.md, память и передача nadi

**Files:**
- Modify: `/Users/dmitry/talerid/CLAUDE.md` (рабочий каталог, не git)
- Create: `/Users/dmitry/.claude/projects/-Users-dmitry-talerid/memory/project_partner_messenger_api.md`, строка в `MEMORY.md`

- [ ] **Step 1: Обязательный набор в CLAUDE.md**

В `/Users/dmitry/talerid/CLAUDE.md`, раздел «🧪 ОБЯЗАТЕЛЬНЫЕ ТЕСТЫ ПЕРЕД ДЕПЛОЕМ», после набора 19 добавить:

~~~~markdown
### 20. Партнёрский API мессенджера (DEV)
E2E: ключ партнёра → заведение людей → токены → запреты для партнёрского токена → контакт → личка и группа → сокет → вебхук с подписью → «почта занята» и код из письма → удаление аккаунта отзывает связку → отзыв гасит токен и рвёт сокет → уборка.
```bash
cd ~/Downloads/taler_id_tests && npm run test:partner          # DEV
cd ~/Downloads/taler_id_tests && npm run test:partner:prod     # TEST
cd ~/Downloads/taler_id_tests && npm run test:partner:talerid  # PROD, короткий
```
- Нужны `PARTNER_E2E_KEY` и (кроме PROD) `PARTNER_E2E_WEBHOOK_SECRET` в `.env.*` набора — ключ тестового партнёра `e2e`.
- Вебхуки проверяет приёмник `/partner/v1/_sink`, включённый `PARTNER_WEBHOOK_SINK=true` только на DEV и TEST.
~~~~

В строку прогона после деплоя на TEST добавить ` && npm run test:partner:prod`, в абзац про PROD-smoke — `npm run test:partner:talerid`.

- [ ] **Step 2: Раздел про партнёрский API в CLAUDE.md**

После раздела «🤖 AI Voice Twin» добавить:

~~~~markdown
## 🤝 Партнёрский API мессенджера (nadi)

Внешний продукт заводит своих людей в TalerID и даёт им переписываться в своём интерфейсе. Спека: `docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md`, документация для партнёров: `docs/partner-messenger-api.md` (в репозитории бэкенда).

- Код: `src/partner-core/` (токены, отзыв, вебхуки), `src/partner-api/` (`/partner/v1/*`), в мессенджере — `MessengerAuthGuard`, `@PartnerAllowed`, `socket-gate.ts`.
- Env: `PARTNER_API_ENABLED` (выключатель), `PARTNER_SECRETS_KEY` (64 hex, **одинаковый на обеих нодах PROD**), `PARTNER_WEBHOOK_SINK=true` — только DEV/TEST.
- Партнёры и ключи — только скриптом: `npx ts-node -r dotenv/config scripts/partner-admin.ts create|rotate-key|set-webhook|set-ips|enable|disable|show`. Секреты — через `--out` в файл 600, не на экран. Каждая нода держит снимок партнёров до 30 с: после `rotate-key` новый ключ заработает, а старый перестанет, в пределах этого окна — партнёру менять ключ с запасом в минуту.
- Где ключи: DEV `~/partner-keys/` на `89.169.55.217`, TEST — там же на `138.124.61.221`, PROD `/root/partner-keys/` на `do-app-1`.
- Партнёры: DEV — `nadi`, `e2e`; TEST — только `e2e`; PROD — `nadi` (IP 165.227.141.149), `e2e`. Вебхук nadi заводится, когда команда nadi даст адрес: `set-webhook --slug nadi --url …`.
- Отключить партнёра: `disable --slug nadi` закрывает REST за ≤30 с, но уже открытые сокеты живут до истечения своего токена (до 15 минут) — токен сокета проверяется только при подключении. Мгновенно всё сразу — `PARTNER_API_ENABLED=false` + рестарт: это гасит и сокеты, и все партнёрские токены мессенджера.
~~~~

- [ ] **Step 3: Память**

Создать `/Users/dmitry/.claude/projects/-Users-dmitry-talerid/memory/project_partner_messenger_api.md`:

```markdown
---
name: project-partner-messenger-api
description: Партнёрский API мессенджера для nadi — где выкачен, где ключи, что ждём от команды nadi
metadata:
  type: project
---

Партнёрский API мессенджера (nadi) выкачен на DEV, TEST и PROD (в эту строку вписать фактические даты из Task 41–43).
Ключи nadi лежат файлами (DEV `~/partner-keys/nadi-dev.env`, PROD `/root/partner-keys/nadi-prod.env` на do-app-1)
и передаются команде nadi вне чатов; вебхук nadi не заведён, пока они не дадут адрес.

**Why:** nadi строит чаты на мессенджере TalerID; сторона nadi (бэкенд selyanska и nadi-app) — их работа
по docs/partner-messenger-api.md.

**How to apply:** новые ручки мессенджера по умолчанию закрыты для партнёров — открывать осознанно
через @PartnerAllowed и тест allowlist в messenger.controller.partner.spec.ts. Связано с [[feedback-aeza-do-naming]].
```

В `/Users/dmitry/.claude/projects/-Users-dmitry-talerid/memory/MEMORY.md` добавить строку:

```markdown
- [Партнёрский API мессенджера (nadi)](project_partner_messenger_api.md) — где выкачен, где ключи, вебхук nadi ждёт их адреса
```

- [ ] **Step 4: Передать nadi**

Доложить пользователю:
- где ключи nadi для DEV и PROD — пути выше, передать вне чатов;
- ссылку на `docs/partner-messenger-api.md`;
- что нужно от команды nadi: адрес вебхука для DEV и PROD (после этого — `set-webhook` и файл с секретом для них) и пункт в политике конфиденциальности nadi.

- [ ] **Step 5: Убрать рабочее дерево**

После того как ветка слита и в `dev`, и в `main`:

```bash
cd /Users/dmitry/taler-id && git worktree remove .worktrees/partner-messenger-api && git branch -d feat/partner-messenger-api
```

---

## Покрытие спеки

| Раздел спеки | Задачи |
|---|---|
| Партнёрский API: ключ, выключатель, IP | 2, 9 |
| Лимиты по партнёру | 10 |
| `POST /users`, статус, имя, отзыв, удаление | 13, 14, 15 |
| Код из письма | 3, 12, 16 |
| Токен мессенджера, грант на связку | 6, 15 |
| Контакты по дружбе | 17 |
| Мессенджер: guard, allowlist, только чаты и группы | 24, 25, 26 |
| Сокет: вход, фильтр пакетов, отключение по сроку | 7, 27, 28 |
| Правило групп, два исправления, скрытие из поиска | 21, 22, 23, 24, 26 |
| Удаление аккаунта отзывает связки | 7, 19 |
| Вебхуки: план, подпись, доставка, повторы, журнал, приёмник | 29–35 |
| Данные | 1 |
| Scope `messenger` и DCR | 4 |
| Скрипт администратора | 20 |
| Окружения и выкатка | 36, 41, 42, 43 |
| Тесты | во всех задачах; e2e — 39 |
| Документация и тестовый клиент | 37, 38 |
| CORS для веб-кабинета nadi | 41–43 при необходимости: добавить `https://nadi.me` в `ALLOWED_ORIGINS` окружения |
