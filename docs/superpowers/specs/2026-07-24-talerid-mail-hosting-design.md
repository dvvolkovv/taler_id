# Taler ID Mail — почта @talerid.io для каждого пользователя

**Дата:** 2026-07-24
**Статус:** дизайн утверждён, ждёт implementation plan

## Цель

Каждый пользователь Taler ID при регистрации получает полноценный почтовый ящик
`<localpart>@talerid.io`: приём и отправка почты, доступ из внешних IMAP/SMTP-клиентов
(Apple Mail, Gmail app, Outlook) по app-паролям и минимальный почтовый клиент внутри
приложения Taler ID (mobile + desktop).

## Ключевые решения (из брейнсторма)

| Вопрос | Решение |
|---|---|
| Объём | Полноценный ящик: IMAP/SMTP для внешних клиентов + in-app клиент |
| Кому | Автоматически каждому при регистрации; существующим ~276 юзерам — экран выбора адреса при следующем логине (пропускаемый) |
| Localpart | Свободный выбор с проверкой занятости и блок-листом системных имён |
| Auth внешних клиентов | Только app-пароли (генерятся в приложении, отзыв per-устройство). Основной пароль аккаунта в почтовые клиенты не вводится |
| Окружения | Один общий Mailcow-стек: домен `talerid.io` (PROD) + `mail-dev.taler.tirol` (DEV и TEST). Отдельных mail-серверов на DEV/TEST нет |
| In-app клиент | Минимальный: inbox + чтение + compose/reply + вложения. Полный клиент и push — позже |
| Стек | **Существующий Mailcow** на дроплете `mail.selyanska.eu` (165.245.254.8, DO FRA1, s-2vcpu-4gb, `/opt/mailcow-dockerized`, SKIP_CLAMD/SKIP_SOLR) — мультидомен, порт 25 уже разблокирован, IP прогрет |

Вариант Stalwart (новый дроплет, JMAP, SQL-directory) рассмотрен и отклонён после того,
как выяснилось наличие готового Mailcow-дроплета: переиспользование снимает блокер
разблокировки порта 25 и стоимость отдельной ноды.

## Архитектура

```
Внешние клиенты ──IMAP:993/SMTP:465/587──┐        Мир ──SMTP:25──┐
                                          ▼                      ▼
                            Mailcow @ 165.245.254.8 (mail.selyanska.eu)
                            домены: selyanska.eu + talerid.io + mail-dev.taler.tirol
                                          ▲                      ▲
                              Mailcow REST API (X-API-Key)   IMAP/SMTP-мост
                                          │                      │
Flutter ──REST+JWT──► NestJS (do-app-1/2 / aeza DEV / aeza TEST) ┘
```

- Письма хранятся только в Mailcow (maildir). В PostgreSQL Taler ID — только
  метаданные аккаунтов и app-паролей.
- Бэкенд — единственный клиент Mailcow API; Flutter ходит только на наш REST под JWT.
- Mailcow admin/API — не публиковать шире необходимого; API-ключ per-environment.

### Ресурсы дроплета

Сейчас ничего не меняем. План роста: (1) block-storage volume под maildir
(`/var/lib/docker/volumes`), (2) CPU/RAM-ресайз дроплета (обратимый), (3) крайний
вариант — миграция Mailcow на отдельный дроплет вместе с maildir.

### Принятые риски

- **Общая судьба с selyanska.eu:** общий IP/репутация/ресурсы. Митигация: Rspamd на
  исходящие, rate-limit отправки, мониторинг блэклистов; при росте — миграция.
- **Две системы истины** (наша PG + Mailcow): лечится идемпотентным провижинингом,
  фоновым ретраем и reconcile-скриптом (сверка списка ящиков домена с `MailAccount`).
- Диск дроплета < суммарной квоты всех ящиков — квоты (1GB) реально лимитируют,
  следить за диском через мониторинг.

## Данные (Prisma, новые модели)

```prisma
model MailAccount {
  id            String   @id @default(uuid())
  userId        String   @unique
  localpart     String   @unique            // citext-семантика: хранить lowercase
  domain        String                       // talerid.io | mail-dev.taler.tirol
  status        MailAccountStatus            // PROVISIONING | ACTIVE | SUSPENDED
  quotaBytes    BigInt   @default(1073741824)
  masterSecret  String                       // AES-GCM(random master password), ключ MAIL_MASTER_KEY
  createdAt     DateTime @default(now())
  appPasswords  MailAppPassword[]
}

model MailAppPassword {
  id            String    @id @default(uuid())
  mailAccountId String
  mailcowId     Int                          // id объекта app-passwd в Mailcow
  label         String                       // "iPhone Apple Mail"
  createdAt     DateTime  @default(now())
  lastUsedAt    DateTime?
  revokedAt     DateTime?
}
```

Хэши app-паролей живут в Mailcow; у нас — только метаданные. Master-пароль ящика
знает только бэкенд (для IMAP/SMTP-моста), юзеру не показывается.

### Валидация localpart

- Regex: `^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$`, без `..`, lowercase.
- Блок-лист: `admin, administrator, postmaster, abuse, noreply, no-reply, support,
  root, security, hostmaster, webmaster, info, billing, sales, help, mail, mailer-daemon,
  taler, talerid` + пополняемый список в конфиге.
- `postmaster@` и `abuse@` — обязательные алиасы на админский ящик (RFC 5321/2142).

## Бэкенд: модуль `src/mail/`

Существующий `src/email/` (nodemailer для OTP/инвайтов через mail.taler.tirol) не
трогаем — это служебная исходящая почта, другой контур.

- **`mail-provision.service.ts`** — Mailcow API: create/suspend/delete mailbox,
  add/delete app-passwd, set quota. Идемпотентно (повторный create того же ящика — ок).
- **`mail-bridge.service.ts`** — IMAP (imapflow) + SMTP (nodemailer) от имени юзера
  через master-пароль. Пул IMAP-соединений с TTL и лимитом, ленивые коннекты.
- **`mail.controller.ts`** — REST (все под JWT):
  - `GET  /mail/availability?localpart=x` — свободен ли адрес
  - `POST /mail/account {localpart}` — создать ящик (регистрация/поздний онбординг)
  - `GET  /mail/account` — мой адрес, статус, квота/занято
  - `POST /mail/app-passwords {label}` → `{password}` (показывается один раз) + инструкция
  - `GET  /mail/app-passwords` / `DELETE /mail/app-passwords/:id`
  - `GET  /mail/messages?folder=INBOX&cursor=` — список (from, subject, date, seen, snippet)
  - `GET  /mail/messages/:uid` — тело (HTML санитизирован на бэкенде, remote-картинки
    блокируются), вложения списком
  - `GET  /mail/messages/:uid/attachments/:part` — стрим вложения
  - `POST /mail/messages {to, subject, text, attachments?}` / `POST /mail/messages/:uid/reply`
  - `POST /mail/messages/:uid/read|unread|delete`
- **Конфиг:** `MAILCOW_API_URL`, `MAILCOW_API_KEY`, `MAIL_DOMAIN`
  (PROD=`talerid.io`; DEV/TEST=`mail-dev.taler.tirol`), `MAIL_MASTER_KEY`.

### Поток регистрации

1. Онбординг: шаг «Выберите ваш email» — live-проверка availability.
2. Создание: запись `MailAccount(status=PROVISIONING)` → Mailcow create → `ACTIVE`.
3. Mailcow недоступен → регистрация **не** падает: ящик остаётся `PROVISIONING`,
   фоновый worker (Redis-очередь, паттерн AiTwinService) ретраит.
4. Существующие юзеры: при логине без `MailAccount` — пропускаемый экран выбора
   адреса; при пропуске — баннер в Настройках.

### Ограничения и абьюз

- Отправка: 50 писем/день на юзера (превышение — 429; платное повышение через
  μTAL-биллинг — вне scope этой фазы).
- Rspamd проверяет и исходящие (защита общей IP-репутации).
- Удаление аккаунта Taler ID → mailbox suspend, через 30 дней — удаление.
- Смена localpart после создания — не поддерживается в фазе 1.

## Flutter: `lib/features/mail/` (Clean Architecture + BLoC)

- **Онбординг:** шаг выбора адреса после регистрации + тот же экран при первом
  логине старых юзеров (кнопка «Позже»).
- **Раздел «Почта»** (вход из Настроек и профиля; bottom nav не трогаем):
  inbox (pull-to-refresh, пагинация), просмотр письма (санитизированный HTML,
  вложения — скачать/открыть), compose (to/subject/body + вложение), reply.
- **Настройки → Почта:** адрес и квота; app-пароли: создать (экран «показывается
  один раз» с копированием + параметры: host `mail.talerid.io`, IMAP 993 SSL,
  SMTP 465 SSL, логин = полный адрес), список, отзыв.
- Локализация ru/en, Dark theme, mobile + desktop layouts.
- Push о новых письмах — **фаза 2** (Dovecot push-notification → бэкенд → FCM).
  В фазе 1 бейдж обновляется при открытии раздела.

## Assistant-first

Новые tools в OpenAI Realtime-сессии (реализация — те же REST-эндпоинты моста):
- `check_mail` — последние N писем кратко
- `read_mail` — прочитать письмо
- `send_mail` — отправить (с голосовым подтверждением перед отправкой)
- `create_mail_app_password` — создать app-пароль (значение показывается на экране, не проговаривается)

## Инфраструктура и DNS

### Mailcow (mail.selyanska.eu, root по ключу dmitry-laptop-talerbot)

1. Добавить домены `talerid.io` и `mail-dev.taler.tirol` (mailbox-домены, DKIM-ключи).
2. Добавить `mail.talerid.io` в `ADDITIONAL_SAN` acme (юзеры настраивают клиенты
   на `mail.talerid.io`, а не selyanska).
3. Выпустить API-ключи (отдельные для PROD и DEV/TEST бэкендов, если Mailcow
   позволяет; иначе один ключ, хранить только в `.env` бэкендов).
4. `postmaster@`/`abuse@` алиасы для обоих доменов.

### DNS

Зона `talerid.io` (DO DNS):
- `A    mail.talerid.io → 165.245.254.8`
- `MX   talerid.io → mail.talerid.io (10)`
- `TXT  talerid.io  "v=spf1 mx -all"`
- `TXT  dkim._domainkey.talerid.io` — из Mailcow
- `TXT  _dmarc.talerid.io  "v=DMARC1; p=quarantine; rua=mailto:postmaster@talerid.io"`
- `CNAME autoconfig/autodiscover → mail.talerid.io` (автонастройка клиентов)

Зона `taler.tirol`: аналогичный набор для `mail-dev.taler.tirol`.

### Мониторинг

Новый бокс `mail` в taler-monitor (`monitor.taler.tirol`): агент на дроплет,
`DOCKER_CONTAINERS` = ключевые контейнеры Mailcow (postfix, dovecot, rspamd, nginx),
HTTP-check Mailcow UI, диск-порог. AUTOFIX_DENY: `postfix*,dovecot*,mysql*`.
Бэкапы: существующий `backup_and_restore.sh` Mailcow → cron на дроплете + выгрузка
в DO Spaces; проверить, что уже настроено для selyanska.eu, и расширить.

## Тестирование

### Новый suite `taler_id_tests` → `npm run test:mail` (DEV, обязателен перед деплоем)

1. Availability: свободный / занятый / блок-лист / невалидный localpart.
2. Создание ящика тестовому юзеру (или использование ранее созданного — идемпотентно).
3. App-пароль: создание → **реальный IMAP-логин** им на mail-сервер → успех.
4. Мост: отправка user1→user2 → письмо появляется в inbox user2 (poll ≤30с) →
   чтение тела → вложение (upload + download, сверка байтов).
5. Отзыв app-пароля → IMAP-логин этим паролем отваливается.
6. Rate-limit: заголовки/429 (без выжигания 50 писем — проверка счётчика).

`npm run test:mail:prod` — тот же suite против TEST после деплоя на TEST;
на PROD — smoke-подмножество в `test:talerid`.

### Deliverability (ручной гейт при запуске PROD)

Отправка на внешний seed-ящик (Gmail): SPF/DKIM/DMARC = pass, не в спаме;
проверка скоринга mail-tester. Проверка IP 165.245.254.8 в основных блэклистах.

### Flutter

Юнит-тесты BLoC'ов фичи mail + шаг «Почта» в `integration_test/app_test.dart`.

## Порядок раскатки

1. Mailcow: домены + DNS + acme + API-ключ + алиасы.
2. Бэкенд-модуль на DEV (`dev` ветка) + `test:mail` зелёный.
3. Flutter в `dev` → dev APK / iOS dev TestFlight, ручная проверка онбординга,
   in-app клиента и подключения Apple Mail по app-паролю.
4. TEST: merge в `main`, деплой aeza-TEST, `test:mail:prod`.
5. PROD (DO, только по явной команде): деплой бэкенда, env, talerid-сборки,
   `/app/version` bump по стандартному чек-листу, deliverability-гейт.

## Вне scope фазы 1 (зафиксировано как будущие фазы)

- Push о новых письмах (Dovecot push-notification → FCM).
- Полный клиент: папки/поиск/threading/черновики/подписи.
- Платное повышение квоты и лимита отправки через μTAL.
- Смена/алиасы localpart, кастомные домены организаций (tenant).
- Миграция Mailcow на выделенный дроплет.
