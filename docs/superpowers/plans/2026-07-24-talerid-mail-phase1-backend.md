# Taler ID Mail — Phase 1 (Mailcow infra + backend + test:mail) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Рабочая почта `@talerid.io` / `@mail-dev.taler.tirol`: провижининг ящиков при регистрации, app-пароли для внешних IMAP/SMTP-клиентов, REST-мост (inbox/чтение/отправка) — всё проверяемо suite'ом `npm run test:mail` без Flutter.

**Architecture:** Переиспользуем Mailcow на `mail.selyanska.eu` (165.245.254.8) — добавляем туда домены и ходим в его REST API из нового NestJS-модуля `src/mail/`. Письма живут только в Mailcow; в PostgreSQL Taler ID — `MailAccount` (localpart, статус, AES-шифрованный master-пароль) и метаданные app-паролей. In-app доступ — через IMAP/SMTP-мост (imapflow + nodemailer) от имени юзера.

**Tech Stack:** NestJS 11, Prisma 5, ioredis (RedisService), axios, imapflow, mailparser, sanitize-html, nodemailer 8; Mailcow API (X-API-Key); тесты: jest (unit, backend) + ts-node smoke suite в `taler_id_tests`.

**Spec:** `docs/superpowers/specs/2026-07-24-talerid-mail-hosting-design.md`

**Репозитории:**
- Backend: `~/Downloads/taler_id` (ветка `dev`)
- Тесты: `~/Downloads/taler_id_tests`
- Mailcow: `root@165.245.254.8` (ключ dmitry-laptop-talerbot), `/opt/mailcow-dockerized`

**Scope Phase 1:** НЕ входят Flutter UI, assistant tools, push — это Phase 2 (отдельный план после фиксации API).

---

### Task 1: Mailcow — домены, acme, API-ключ, алиасы

Ops-задача (без TDD), выполняется по SSH на Mailcow-дроплете + через Mailcow UI/API. Все шаги идемпотентны.

**Files:** нет (инфраструктура). Результаты (API-ключ) — в `.env` бэкендов, НЕ в git.

- [ ] **Step 1: Проверить доступ и версию Mailcow**

```bash
ssh root@165.245.254.8 'cd /opt/mailcow-dockerized && git describe --tags && docker compose ps --format "{{.Name}} {{.Status}}" | head -20'
```
Expected: версия mailcow (например `2026-xx`), контейнеры `postfix-mailcow`, `dovecot-mailcow`, `rspamd-mailcow`, `nginx-mailcow` — `Up`.

- [ ] **Step 2: Выпустить API-ключ (read-write)**

Mailcow UI (`https://mail.selyanska.eu`, admin) → System → Configuration → Access → API: активировать API, добавить в allow-list VPC/публичные IP всех бэкендов Taler ID: `89.169.55.217` (DEV), `138.124.61.221` (TEST), публичные исходящие IP `do-app-1`/`do-app-2` (узнать: `ssh do-app-1 'curl -s ifconfig.me'`). Скопировать ключ.

Verify:
```bash
curl -s -H "X-API-Key: <KEY>" https://mail.selyanska.eu/api/v1/get/domain/all | head -c 300
```
Expected: JSON-массив с доменом `selyanska.eu` (не `401`).

- [ ] **Step 3: Добавить домены**

```bash
curl -s -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
  https://mail.selyanska.eu/api/v1/add/domain \
  -d '{"domain":"talerid.io","active":"1","aliases":"20","mailboxes":"10000","defquota":"1024","maxquota":"2048","quota":"409600","backupmx":"0","relay_all_recipients":"0","restart_sogo":"1"}'

curl -s -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
  https://mail.selyanska.eu/api/v1/add/domain \
  -d '{"domain":"mail-dev.taler.tirol","active":"1","aliases":"20","mailboxes":"1000","defquota":"1024","maxquota":"2048","quota":"51200","backupmx":"0","relay_all_recipients":"0","restart_sogo":"1"}'
```
Expected: `[{"type":"success",...}]` на оба. Квоты в MiB: per-mailbox default 1024 (=1GB из спеки), domain-quota 400G/50G — потолки, подрегулировать под фактический диск (`df -h` на дроплете; если диск меньше — уменьшить).

- [ ] **Step 4: Сгенерировать DKIM-ключи для обоих доменов**

```bash
for d in talerid.io mail-dev.taler.tirol; do
  curl -s -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
    https://mail.selyanska.eu/api/v1/add/dkim -d "{\"domains\":\"$d\",\"dkim_selector\":\"dkim\",\"key_size\":\"2048\"}";
done
curl -s -H "X-API-Key: <KEY>" https://mail.selyanska.eu/api/v1/get/dkim/talerid.io
```
Expected: в ответе `dkim_txt` — публичный ключ (записать, нужен в Task 2).

- [ ] **Step 5: Добавить `mail.talerid.io` в acme-сертификат**

```bash
ssh root@165.245.254.8 'grep ADDITIONAL_SAN /opt/mailcow-dockerized/mailcow.conf'
# дописать (сохранив существующие SAN, через запятую):
ssh root@165.245.254.8 'cd /opt/mailcow-dockerized && sed -i "s/^ADDITIONAL_SAN=.*/&,mail.talerid.io/" mailcow.conf && grep ADDITIONAL_SAN mailcow.conf'
```
⚠️ Перевыпуск сертификата (`docker compose restart acme-mailcow`) — ТОЛЬКО ПОСЛЕ Task 2 (нужна A-запись `mail.talerid.io`, иначе LE-челлендж упадёт). Отметить и вернуться.

- [ ] **Step 6: Админский ящик + обязательные алиасы**

```bash
# служебный ящик, куда падают postmaster/abuse (пароль сгенерить: openssl rand -base64 18)
curl -s -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
  https://mail.selyanska.eu/api/v1/add/mailbox \
  -d '{"local_part":"admin","domain":"talerid.io","name":"TalerID Admin","password":"<GEN>","password2":"<GEN>","quota":"2048","active":"1","force_pw_update":"0"}'

for a in postmaster abuse; do
  curl -s -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
    https://mail.selyanska.eu/api/v1/add/alias \
    -d "{\"address\":\"$a@talerid.io\",\"goto\":\"admin@talerid.io\",\"active\":\"1\"}";
  curl -s -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
    https://mail.selyanska.eu/api/v1/add/alias \
    -d "{\"address\":\"$a@mail-dev.taler.tirol\",\"goto\":\"admin@talerid.io\",\"active\":\"1\"}";
done
```
Expected: success на все. Пароль admin-ящика — в менеджер секретов Дмитрия, не в git.

- [ ] **Step 7: Зафиксировать ключ в env-хранилищах**

Добавить `MAILCOW_API_KEY=<KEY>` в `.env` на DEV (89.169.55.217 `~/taler-id/.env`) — остальные env-переменные добавит Task 4. TEST/PROD — при деплое на них.

---

### Task 2: DNS для talerid.io и mail-dev.taler.tirol

**Files:** нет (DNS-провайдеры). Зона `talerid.io` — в DO DNS (там же, где A-записи talerid.io). Зона `taler.tirol` — у её текущего провайдера (там, где живёт `staging.id.taler.tirol`).

- [ ] **Step 1: Записи в зоне `talerid.io`** (DO DNS UI или `doctl`):

| Тип | Имя | Значение |
|---|---|---|
| A | `mail` | `165.245.254.8` |
| MX | `@` | `10 mail.talerid.io.` |
| TXT | `@` | `v=spf1 mx -all` |
| TXT | `dkim._domainkey` | `<dkim_txt из Task 1 Step 4>` |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:postmaster@talerid.io` |
| CNAME | `autoconfig` | `mail.talerid.io.` |
| CNAME | `autodiscover` | `mail.talerid.io.` |

- [ ] **Step 2: Записи в зоне `taler.tirol`** для сабдомена `mail-dev`:

| Тип | Имя | Значение |
|---|---|---|
| MX | `mail-dev` | `10 mail.talerid.io.` |
| TXT | `mail-dev` | `v=spf1 mx -all` |
| TXT | `dkim._domainkey.mail-dev` | `<dkim_txt для mail-dev.taler.tirol>` |
| TXT | `_dmarc.mail-dev` | `v=DMARC1; p=quarantine; rua=mailto:postmaster@talerid.io` |

- [ ] **Step 3: Проверить резолв (после TTL, обычно ≤5 мин)**

```bash
dig +short A mail.talerid.io        # → 165.245.254.8
dig +short MX talerid.io            # → 10 mail.talerid.io.
dig +short TXT talerid.io           # → "v=spf1 mx -all"
dig +short TXT dkim._domainkey.talerid.io | head -c 60   # → "v=DKIM1; k=rsa; p=..."
dig +short MX mail-dev.taler.tirol  # → 10 mail.talerid.io.
```

- [ ] **Step 4: Перевыпустить acme-сертификат (отложенный шаг из Task 1)**

```bash
ssh root@165.245.254.8 'cd /opt/mailcow-dockerized && docker compose restart acme-mailcow && sleep 60 && docker compose logs --tail 20 acme-mailcow'
echo | openssl s_client -connect mail.talerid.io:993 -servername mail.talerid.io 2>/dev/null | openssl x509 -noout -ext subjectAltName
```
Expected: в SAN есть `mail.talerid.io`; IMAP-порт отвечает валидным сертификатом.

- [ ] **Step 5: rDNS/PTR** — проверить `dig +short -x 165.245.254.8`. Ожидаемо уже `mail.selyanska.eu` — это ОК (PTR один на IP, HELO остаётся selyanska; SPF/DKIM talerid.io всё равно проходят). Ничего не менять.

---

### Task 3: Prisma-модели MailAccount / MailAppPassword

**Files:**
- Modify: `~/Downloads/taler_id/prisma/schema.prisma` (в конец)

- [x] **Step 1: Добавить модели и enum в конец `schema.prisma`**

```prisma
enum MailAccountStatus {
  PROVISIONING
  ACTIVE
  SUSPENDED
}

model MailAccount {
  id           String            @id @default(uuid())
  userId       String            @unique
  user         User              @relation(fields: [userId], references: [id], onDelete: Cascade)
  localpart    String            @unique
  domain       String
  status       MailAccountStatus @default(PROVISIONING)
  quotaBytes   BigInt            @default(1073741824)
  masterSecret String            // AES-256-GCM(random master password), key = MAIL_MASTER_KEY
  createdAt    DateTime          @default(now())
  updatedAt    DateTime          @updatedAt

  appPasswords MailAppPassword[]

  @@index([status])
}

model MailAppPassword {
  id            String      @id @default(uuid())
  mailAccountId String
  mailAccount   MailAccount @relation(fields: [mailAccountId], references: [id], onDelete: Cascade)
  mailcowId     Int
  label         String
  createdAt     DateTime    @default(now())
  revokedAt     DateTime?

  @@index([mailAccountId])
}
```

В модель `User` добавить обратную связь: `mailAccount MailAccount?`

- [x] **Step 2: Сгенерировать миграцию и клиент (локально против dev-БД либо `db:push` на DEV при деплое)**

```bash
cd ~/Downloads/taler_id && npx prisma format && npx prisma validate
npx prisma migrate dev --name mail_accounts --create-only && npx prisma generate
```
Expected: `prisma validate` без ошибок; миграция в `prisma/migrations/*_mail_accounts/`. (Если локальной БД нет — только `format`+`validate`+`generate`, миграция применится на DEV через `prisma migrate deploy` при деплое.)

- [x] **Step 3: Commit**

```bash
git add prisma/ && git commit -m "feat(mail): MailAccount + MailAppPassword prisma models"
```

---

### Task 4: Конфигурация (env + configuration.ts)

**Files:**
- Modify: `~/Downloads/taler_id/src/config/configuration.ts`
- Modify: `~/Downloads/taler_id/.env.example`

- [x] **Step 1: Добавить секцию `mail` в `configuration.ts`** (после секции `email`):

```typescript
mail: {
  mailcowUrl: process.env.MAILCOW_API_URL || 'https://mail.selyanska.eu',
  mailcowApiKey: process.env.MAILCOW_API_KEY || '',
  domain: process.env.MAIL_DOMAIN || 'mail-dev.taler.tirol',
  clientHost: process.env.MAIL_CLIENT_HOST || 'mail.talerid.io', // хост в инструкции для внешних клиентов
  masterKey: process.env.MAIL_MASTER_KEY || '', // 64 hex chars = 32 bytes AES-256
  sendDailyLimit: parseInt(process.env.MAIL_SEND_DAILY_LIMIT ?? '50', 10) || 50,
},
```

- [x] **Step 2: Добавить в `.env.example`:**

```
# Mail hosting (@talerid.io mailboxes via Mailcow)
MAILCOW_API_URL=https://mail.selyanska.eu
MAILCOW_API_KEY=changeme
MAIL_DOMAIN=mail-dev.taler.tirol
MAIL_CLIENT_HOST=mail.talerid.io
MAIL_MASTER_KEY=changeme_64_hex_chars
MAIL_SEND_DAILY_LIMIT=50
```

На PROD (DO) будет `MAIL_DOMAIN=talerid.io`. `MAIL_MASTER_KEY` генерится per-env: `openssl rand -hex 32`.

- [x] **Step 3: Commit**

```bash
git add src/config/configuration.ts .env.example && git commit -m "feat(mail): mailcow + mail env configuration"
```

---

### Task 5: Крипто-хелпер AES-256-GCM (TDD)

**Files:**
- Create: `~/Downloads/taler_id/src/mail/mail-crypto.ts`
- Test: `~/Downloads/taler_id/src/mail/mail-crypto.spec.ts`

- [x] **Step 1: Написать падающий тест `mail-crypto.spec.ts`**

```typescript
import { encryptSecret, decryptSecret } from './mail-crypto';

const KEY = 'a'.repeat(64); // 32 bytes hex

describe('mail-crypto', () => {
  it('roundtrips a secret', () => {
    const enc = encryptSecret('S3cret-Пароль!', KEY);
    expect(enc).not.toContain('S3cret');
    expect(decryptSecret(enc, KEY)).toBe('S3cret-Пароль!');
  });

  it('produces different ciphertext each time (random IV)', () => {
    expect(encryptSecret('x', KEY)).not.toBe(encryptSecret('x', KEY));
  });

  it('fails on wrong key', () => {
    const enc = encryptSecret('x', KEY);
    expect(() => decryptSecret(enc, 'b'.repeat(64))).toThrow();
  });

  it('fails on tampered payload', () => {
    const enc = encryptSecret('x', KEY);
    const buf = Buffer.from(enc, 'base64');
    buf[buf.length - 1] ^= 0xff;
    expect(() => decryptSecret(buf.toString('base64'), KEY)).toThrow();
  });
});
```

- [x] **Step 2: Убедиться, что тест падает**

```bash
cd ~/Downloads/taler_id && npx jest src/mail/mail-crypto.spec.ts
```
Expected: FAIL — `Cannot find module './mail-crypto'`.

- [x] **Step 3: Реализация `mail-crypto.ts`**

```typescript
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

// Формат: base64( iv(12) | authTag(16) | ciphertext )
export function encryptSecret(plain: string, keyHex: string): string {
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) throw new Error('MAIL_MASTER_KEY must be 64 hex chars (32 bytes)');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString('base64');
}

export function decryptSecret(payload: string, keyHex: string): string {
  const key = Buffer.from(keyHex, 'hex');
  const buf = Buffer.from(payload, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}
```

- [x] **Step 4: Тест зелёный**

```bash
npx jest src/mail/mail-crypto.spec.ts
```
Expected: 4 passed.

- [x] **Step 5: Commit**

```bash
git add src/mail/mail-crypto.ts src/mail/mail-crypto.spec.ts && git commit -m "feat(mail): AES-256-GCM secret helper"
```

---

### Task 6: Валидация localpart + блок-лист (TDD)

**Files:**
- Create: `~/Downloads/taler_id/src/mail/localpart.ts`
- Test: `~/Downloads/taler_id/src/mail/localpart.spec.ts`

- [x] **Step 1: Падающий тест `localpart.spec.ts`**

```typescript
import { normalizeLocalpart, validateLocalpart } from './localpart';

describe('localpart', () => {
  it('normalizes to lowercase and trims', () => {
    expect(normalizeLocalpart('  Vasya.Pupkin ')).toBe('vasya.pupkin');
  });

  it.each(['vasya', 'v.p-2026', 'a1b', 'john_doe'])('accepts %s', (lp) => {
    expect(validateLocalpart(lp)).toBeNull();
  });

  it.each([
    ['ab', 'слишком короткий (<3)'],
    ['a'.repeat(65), 'слишком длинный'],
    ['.vasya', 'точка в начале'],
    ['vasya.', 'точка в конце'],
    ['va..sya', 'двойная точка'],
    ['вася', 'не-ASCII'],
    ['va sya', 'пробел'],
    ['va@sya', 'спецсимвол'],
  ])('rejects %s (%s)', (lp) => {
    expect(validateLocalpart(lp)).toBe('INVALID');
  });

  it.each(['admin', 'postmaster', 'abuse', 'noreply', 'root', 'support', 'talerid'])(
    'blocks reserved %s',
    (lp) => {
      expect(validateLocalpart(lp)).toBe('RESERVED');
    },
  );
});
```

- [x] **Step 2: Убедиться, что падает** — `npx jest src/mail/localpart.spec.ts` → FAIL (module not found).

- [x] **Step 3: Реализация `localpart.ts`**

```typescript
const LOCALPART_RE = /^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$/;

const RESERVED = new Set([
  'admin', 'administrator', 'postmaster', 'abuse', 'noreply', 'no-reply',
  'support', 'root', 'security', 'hostmaster', 'webmaster', 'info',
  'billing', 'sales', 'help', 'mail', 'mailer-daemon', 'taler', 'talerid',
  'contact', 'legal', 'privacy', 'team', 'official', 'notifications',
]);

export function normalizeLocalpart(raw: string): string {
  return raw.trim().toLowerCase();
}

/** null = ок; 'INVALID' | 'RESERVED' = причина отказа */
export function validateLocalpart(localpart: string): 'INVALID' | 'RESERVED' | null {
  if (!LOCALPART_RE.test(localpart) || localpart.includes('..')) return 'INVALID';
  if (RESERVED.has(localpart)) return 'RESERVED';
  return null;
}
```

- [x] **Step 4: Тест зелёный** — `npx jest src/mail/localpart.spec.ts` → all passed.

- [x] **Step 5: Commit**

```bash
git add src/mail/localpart.ts src/mail/localpart.spec.ts && git commit -m "feat(mail): localpart validation + reserved blocklist"
```

---

### Task 7: MailcowClient — обёртка над Mailcow API

**Files:**
- Create: `~/Downloads/taler_id/src/mail/mailcow.client.ts`

Тонкая обёртка над HTTP — юнит-тестировать нечего (вся логика — у Mailcow); проверяется e2e-suite'ом Task 12. Endpoint-пути соответствуют Mailcow API v1 (проверить на живом инстансе в Step 2).

- [x] **Step 1: Реализация `mailcow.client.ts`**

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosInstance } from 'axios';

export interface MailcowAppPasswd {
  id: number;
  name: string;
  created: string;
}

@Injectable()
export class MailcowClient {
  private readonly logger = new Logger(MailcowClient.name);
  private readonly http: AxiosInstance;

  constructor(config: ConfigService) {
    this.http = axios.create({
      baseURL: `${config.get<string>('mail.mailcowUrl')}/api/v1`,
      headers: { 'X-API-Key': config.get<string>('mail.mailcowApiKey') ?? '' },
      timeout: 15000,
    });
  }

  /** Mailcow отвечает 200 даже на ошибки — успех определяем по type=success в массиве. */
  private ensureSuccess(op: string, data: unknown): void {
    const arr = Array.isArray(data) ? data : [data];
    const ok = arr.some((r: any) => r?.type === 'success');
    if (!ok) {
      this.logger.error(`mailcow ${op} failed: ${JSON.stringify(data).slice(0, 500)}`);
      throw new Error(`mailcow_${op}_failed`);
    }
  }

  async mailboxExists(username: string): Promise<boolean> {
    const res = await this.http.get(`/get/mailbox/${encodeURIComponent(username)}`);
    return !!res.data && typeof res.data === 'object' && 'username' in res.data;
  }

  async createMailbox(localpart: string, domain: string, password: string, quotaMb: number, name: string): Promise<void> {
    if (await this.mailboxExists(`${localpart}@${domain}`)) return; // идемпотентность
    const res = await this.http.post('/add/mailbox', {
      local_part: localpart,
      domain,
      name,
      password,
      password2: password,
      quota: String(quotaMb),
      active: '1',
      force_pw_update: '0',
      tls_enforce_in: '1',
      tls_enforce_out: '1',
    });
    this.ensureSuccess('add_mailbox', res.data);
  }

  async setMailboxActive(username: string, active: boolean): Promise<void> {
    const res = await this.http.post('/edit/mailbox', {
      items: [username],
      attr: { active: active ? '1' : '0' },
    });
    this.ensureSuccess('edit_mailbox', res.data);
  }

  async deleteMailbox(username: string): Promise<void> {
    const res = await this.http.post('/delete/mailbox', [username]);
    this.ensureSuccess('delete_mailbox', res.data);
  }

  async createAppPassword(username: string, label: string, password: string): Promise<number> {
    const res = await this.http.post('/add/app-passwd', {
      username,
      app_name: label,
      app_passwd: password,
      app_passwd2: password,
      active: '1',
      protocols: ['imap_access', 'smtp_access'],
    });
    this.ensureSuccess('add_app_passwd', res.data);
    // id созданного пароля Mailcow в ответе не отдаёт — перечитываем список
    const list = await this.listAppPasswords(username);
    const created = list.filter((p) => p.name === label).sort((a, b) => b.id - a.id)[0];
    if (!created) throw new Error('mailcow_app_passwd_not_found_after_create');
    return created.id;
  }

  async listAppPasswords(username: string): Promise<MailcowAppPasswd[]> {
    const res = await this.http.get(`/get/app-passwd/all/${encodeURIComponent(username)}`);
    return Array.isArray(res.data) ? res.data : [];
  }

  async deleteAppPassword(id: number): Promise<void> {
    const res = await this.http.post('/delete/app-passwd', [String(id)]);
    this.ensureSuccess('delete_app_passwd', res.data);
  }
}
```

- [x] **Step 2: Ручная проверка endpoint-путей против живого Mailcow** (версии API отличаются):

```bash
curl -s -H "X-API-Key: <KEY>" https://mail.selyanska.eu/api/v1/get/mailbox/admin@talerid.io | head -c 200
curl -s -H "X-API-Key: <KEY>" https://mail.selyanska.eu/api/v1/get/app-passwd/all/admin@talerid.io
```
Expected: JSON-объект mailbox'а; `[]` для app-passwd. Если формат другой — поправить клиент под фактический ответ.

- [x] **Step 3: Компиляция** — `cd ~/Downloads/taler_id && npx tsc --noEmit -p tsconfig.json` → без ошибок (или `npm run build`).

- [x] **Step 4: Commit**

```bash
git add src/mail/mailcow.client.ts && git commit -m "feat(mail): mailcow API client"
```

---

### Task 8: MailAccountService — провижининг + retry-worker + app-пароли

**Files:**
- Create: `~/Downloads/taler_id/src/mail/mail-account.service.ts`

Паттерн retry — Redis sorted-set + poll, как в `src/messenger/ai-twin.service.ts` (`RedisService.getClient()`).

- [x] **Step 1: Реализация `mail-account.service.ts`**

```typescript
import {
  BadRequestException, ConflictException, Injectable, Logger,
  NotFoundException, OnModuleDestroy, OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { MailcowClient } from './mailcow.client';
import { encryptSecret } from './mail-crypto';
import { normalizeLocalpart, validateLocalpart } from './localpart';

const RETRY_ZSET = 'mail:provision:retry';
const RETRY_POLL_MS = 30_000;
const RETRY_DELAY_MS = 60_000;

function generatePassword(bytes = 18): string {
  // base64url без паддинга — 24 символа, безопасен для IMAP/SMTP auth
  return randomBytes(bytes).toString('base64url');
}

@Injectable()
export class MailAccountService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(MailAccountService.name);
  private pollTimer?: NodeJS.Timeout;
  private readonly domain: string;
  private readonly masterKey: string;
  private readonly clientHost: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly mailcow: MailcowClient,
    config: ConfigService,
  ) {
    this.domain = config.get<string>('mail.domain')!;
    this.masterKey = config.get<string>('mail.masterKey')!;
    this.clientHost = config.get<string>('mail.clientHost')!;
  }

  onModuleInit() {
    this.pollTimer = setInterval(
      () => this.retryTick().catch((e) => this.logger.error('retry tick error', e)),
      RETRY_POLL_MS,
    );
  }

  onModuleDestroy() {
    if (this.pollTimer) clearInterval(this.pollTimer);
  }

  address(account: { localpart: string; domain: string }): string {
    return `${account.localpart}@${account.domain}`;
  }

  async checkAvailability(raw: string): Promise<{ localpart: string; available: boolean; reason?: string }> {
    const localpart = normalizeLocalpart(raw ?? '');
    const invalid = validateLocalpart(localpart);
    if (invalid) return { localpart, available: false, reason: invalid };
    const taken = await this.prisma.mailAccount.findUnique({ where: { localpart } });
    return { localpart, available: !taken, reason: taken ? 'TAKEN' : undefined };
  }

  async createAccount(userId: string, rawLocalpart: string) {
    const existing = await this.prisma.mailAccount.findUnique({ where: { userId } });
    if (existing) throw new ConflictException('mail_account_already_exists');

    const { localpart, available, reason } = await this.checkAvailability(rawLocalpart);
    if (!available) throw new BadRequestException(`localpart_${(reason ?? 'invalid').toLowerCase()}`);

    const masterPassword = generatePassword();
    const account = await this.prisma.mailAccount.create({
      data: {
        userId,
        localpart,
        domain: this.domain,
        status: 'PROVISIONING',
        masterSecret: encryptSecret(masterPassword, this.masterKey),
      },
    });

    await this.provision(account.id, localpart, masterPassword);
    return this.getAccount(userId);
  }

  private async provision(accountId: string, localpart: string, masterPassword: string): Promise<void> {
    try {
      await this.mailcow.createMailbox(localpart, this.domain, masterPassword, 1024, localpart);
      await this.prisma.mailAccount.update({ where: { id: accountId }, data: { status: 'ACTIVE' } });
      this.logger.log(`provisioned ${localpart}@${this.domain}`);
    } catch (e) {
      this.logger.warn(`provision failed for ${localpart}, scheduling retry: ${(e as Error).message}`);
      await this.redis.getClient().zadd(RETRY_ZSET, Date.now() + RETRY_DELAY_MS, accountId);
    }
  }

  private async retryTick(): Promise<void> {
    const client = this.redis.getClient();
    const due: string[] = await client.zrangebyscore(RETRY_ZSET, '-inf', String(Date.now()));
    for (const accountId of due) {
      await client.zrem(RETRY_ZSET, accountId);
      const account = await this.prisma.mailAccount.findUnique({ where: { id: accountId } });
      if (!account || account.status !== 'PROVISIONING') continue;
      const { decryptSecret } = await import('./mail-crypto');
      await this.provision(account.id, account.localpart, decryptSecret(account.masterSecret, this.masterKey));
    }
  }

  async getAccount(userId: string) {
    const account = await this.prisma.mailAccount.findUnique({ where: { userId } });
    if (!account) throw new NotFoundException('mail_account_not_found');
    return {
      address: this.address(account),
      localpart: account.localpart,
      domain: account.domain,
      status: account.status,
      quotaBytes: account.quotaBytes.toString(),
      clientSettings: {
        host: this.clientHost,
        imapPort: 993, imapSecurity: 'SSL/TLS',
        smtpPort: 465, smtpSecurity: 'SSL/TLS',
        login: this.address(account),
      },
    };
  }

  /** Внутренний доступ для моста: entity + расшифровка masterSecret */
  async requireActiveAccount(userId: string) {
    const account = await this.prisma.mailAccount.findUnique({ where: { userId } });
    if (!account) throw new NotFoundException('mail_account_not_found');
    if (account.status !== 'ACTIVE') throw new BadRequestException(`mail_account_${account.status.toLowerCase()}`);
    return account;
  }

  // ── App-passwords ──────────────────────────────────────────────

  async createAppPassword(userId: string, label: string) {
    const account = await this.requireActiveAccount(userId);
    const cleanLabel = (label ?? '').trim().slice(0, 64) || 'Mail client';
    const password = generatePassword();
    const mailcowId = await this.mailcow.createAppPassword(this.address(account), cleanLabel, password);
    const rec = await this.prisma.mailAppPassword.create({
      data: { mailAccountId: account.id, mailcowId, label: cleanLabel },
    });
    return {
      id: rec.id,
      label: rec.label,
      password, // показывается ровно один раз
      clientSettings: (await this.getAccount(userId)).clientSettings,
    };
  }

  async listAppPasswords(userId: string) {
    const account = await this.requireActiveAccount(userId);
    const rows = await this.prisma.mailAppPassword.findMany({
      where: { mailAccountId: account.id, revokedAt: null },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => ({ id: r.id, label: r.label, createdAt: r.createdAt }));
  }

  async revokeAppPassword(userId: string, id: string): Promise<void> {
    const account = await this.requireActiveAccount(userId);
    const rec = await this.prisma.mailAppPassword.findFirst({
      where: { id, mailAccountId: account.id, revokedAt: null },
    });
    if (!rec) throw new NotFoundException('app_password_not_found');
    await this.mailcow.deleteAppPassword(rec.mailcowId);
    await this.prisma.mailAppPassword.update({ where: { id }, data: { revokedAt: new Date() } });
  }
}
```

- [x] **Step 2: Компиляция** — `npx tsc --noEmit` → ok. (Проверить фактический путь/имя `RedisService` — `src/redis/redis.service.ts`; если отличается, поправить import.)

- [x] **Step 3: Commit**

```bash
git add src/mail/mail-account.service.ts && git commit -m "feat(mail): account provisioning with retry + app-passwords"
```

---

### Task 9: MailBridgeService — IMAP/SMTP от имени юзера

**Files:**
- Create: `~/Downloads/taler_id/src/mail/mail-bridge.service.ts`

- [x] **Step 1: Установить зависимости**

```bash
cd ~/Downloads/taler_id && npm install imapflow mailparser sanitize-html && npm install -D @types/mailparser @types/sanitize-html
```

- [x] **Step 2: Реализация `mail-bridge.service.ts`**

```typescript
import { BadRequestException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ImapFlow } from 'imapflow';
import { simpleParser, ParsedMail } from 'mailparser';
import * as nodemailer from 'nodemailer';
import * as sanitizeHtml from 'sanitize-html';
import { RedisService } from '../redis/redis.service';
import { MailAccountService } from './mail-account.service';
import { decryptSecret } from './mail-crypto';

export interface MailListItem {
  uid: number;
  from: string;
  fromAddress: string;
  subject: string;
  date: string;
  seen: boolean;
  snippet: string;
  hasAttachments: boolean;
}

@Injectable()
export class MailBridgeService {
  private readonly logger = new Logger(MailBridgeService.name);
  private readonly imapHost: string;
  private readonly masterKey: string;
  private readonly sendDailyLimit: number;

  constructor(
    private readonly accounts: MailAccountService,
    private readonly redis: RedisService,
    config: ConfigService,
  ) {
    // Мост ходит на тот же Mailcow, что и внешние клиенты
    this.imapHost = config.get<string>('mail.clientHost')!;
    this.masterKey = config.get<string>('mail.masterKey')!;
    this.sendDailyLimit = config.get<number>('mail.sendDailyLimit')!;
  }

  private async withImap<T>(userId: string, fn: (client: ImapFlow, address: string) => Promise<T>): Promise<T> {
    const account = await this.accounts.requireActiveAccount(userId);
    const address = this.accounts.address(account);
    const client = new ImapFlow({
      host: this.imapHost,
      port: 993,
      secure: true,
      auth: { user: address, pass: decryptSecret(account.masterSecret, this.masterKey) },
      logger: false,
    });
    await client.connect();
    try {
      return await fn(client, address);
    } finally {
      await client.logout().catch(() => client.close());
    }
  }

  async listMessages(userId: string, folder = 'INBOX', beforeUid?: number, limit = 30): Promise<{ items: MailListItem[]; nextCursor: number | null }> {
    return this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock(folder);
      try {
        const mailbox = client.mailbox;
        if (!mailbox || typeof mailbox === 'boolean' || mailbox.exists === 0) return { items: [], nextCursor: null };
        const range = beforeUid ? `1:${beforeUid - 1}` : '1:*';
        const items: MailListItem[] = [];
        for await (const msg of client.fetch(
          { uid: range },
          { uid: true, envelope: true, flags: true, bodyStructure: true, bodyParts: ['text'] },
          { uid: true },
        )) {
          const text = msg.bodyParts?.get('text')?.toString('utf8') ?? '';
          items.push({
            uid: msg.uid,
            from: msg.envelope?.from?.[0]?.name || msg.envelope?.from?.[0]?.address || '',
            fromAddress: msg.envelope?.from?.[0]?.address || '',
            subject: msg.envelope?.subject || '',
            date: (msg.envelope?.date ?? new Date()).toISOString(),
            seen: msg.flags?.has('\\Seen') ?? false,
            snippet: text.replace(/\s+/g, ' ').trim().slice(0, 120),
            hasAttachments: hasAttachmentParts(msg.bodyStructure),
          });
        }
        items.sort((a, b) => b.uid - a.uid);
        const page = items.slice(0, limit);
        return { items: page, nextCursor: page.length === limit ? page[page.length - 1].uid : null };
      } finally {
        lock.release();
      }
    });
  }

  async getMessage(userId: string, uid: number) {
    return this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock('INBOX');
      try {
        const dl = await client.download(String(uid), undefined, { uid: true });
        if (!dl?.content) throw new NotFoundException('message_not_found');
        const parsed: ParsedMail = await simpleParser(dl.content);
        await client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true });
        return {
          uid,
          from: parsed.from?.text ?? '',
          to: parsed.to ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]).map((t) => t.text).join(', ') : '',
          subject: parsed.subject ?? '',
          date: (parsed.date ?? new Date()).toISOString(),
          messageId: parsed.messageId ?? null,
          html: parsed.html ? sanitize(parsed.html) : null,
          text: parsed.text ?? '',
          attachments: (parsed.attachments ?? []).map((a, i) => ({
            index: i,
            filename: a.filename ?? `attachment-${i}`,
            contentType: a.contentType,
            size: a.size,
          })),
        };
      } finally {
        lock.release();
      }
    });
  }

  async getAttachment(userId: string, uid: number, index: number) {
    return this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock('INBOX');
      try {
        const dl = await client.download(String(uid), undefined, { uid: true });
        if (!dl?.content) throw new NotFoundException('message_not_found');
        const parsed = await simpleParser(dl.content);
        const att = (parsed.attachments ?? [])[index];
        if (!att) throw new NotFoundException('attachment_not_found');
        return { filename: att.filename ?? `attachment-${index}`, contentType: att.contentType, content: att.content };
      } finally {
        lock.release();
      }
    });
  }

  async setSeen(userId: string, uid: number, seen: boolean): Promise<void> {
    await this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock('INBOX');
      try {
        if (seen) await client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true });
        else await client.messageFlagsRemove(String(uid), ['\\Seen'], { uid: true });
      } finally {
        lock.release();
      }
    });
  }

  async deleteMessage(userId: string, uid: number): Promise<void> {
    await this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock('INBOX');
      try {
        await client.messageDelete(String(uid), { uid: true });
      } finally {
        lock.release();
      }
    });
  }

  async sendMessage(
    userId: string,
    input: { to: string; subject: string; text: string; inReplyTo?: string; attachments?: { filename: string; contentBase64: string }[] },
  ): Promise<void> {
    const account = await this.accounts.requireActiveAccount(userId);
    await this.enforceSendLimit(userId);

    const totalSize = (input.attachments ?? []).reduce((s, a) => s + a.contentBase64.length * 0.75, 0);
    if (totalSize > 10 * 1024 * 1024) throw new BadRequestException('attachments_too_large');

    const address = this.accounts.address(account);
    const transport = nodemailer.createTransport({
      host: this.imapHost,
      port: 465,
      secure: true,
      auth: { user: address, pass: decryptSecret(account.masterSecret, this.masterKey) },
    });
    await transport.sendMail({
      from: address,
      to: input.to,
      subject: input.subject,
      text: input.text,
      inReplyTo: input.inReplyTo,
      references: input.inReplyTo,
      attachments: (input.attachments ?? []).map((a) => ({
        filename: a.filename,
        content: Buffer.from(a.contentBase64, 'base64'),
      })),
    });
  }

  private async enforceSendLimit(userId: string): Promise<void> {
    const day = new Date().toISOString().slice(0, 10);
    const key = `mail:send:${userId}:${day}`;
    const client = this.redis.getClient();
    const count = await client.incr(key);
    if (count === 1) await client.expire(key, 86_400);
    if (count > this.sendDailyLimit) throw new BadRequestException('mail_send_daily_limit');
  }
}

function sanitize(html: string): string {
  return sanitizeHtml(html, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'h1', 'h2', 'span']),
    allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, '*': ['style'] },
    // remote-картинки блокируются: разрешаем только data:-URI
    allowedSchemesByTag: { img: ['data'] },
  });
}

function hasAttachmentParts(node: any): boolean {
  if (!node) return false;
  if (node.disposition === 'attachment') return true;
  return (node.childNodes ?? []).some((c: any) => hasAttachmentParts(c));
}
```

- [x] **Step 3: Компиляция** — `npx tsc --noEmit` → ok. (imapflow типы: если `client.fetch` сигнатура ругается — свериться с установленной версией imapflow, у v1 `fetch(range, query, options)`.)

- [x] **Step 4: Commit**

```bash
git add package.json package-lock.json src/mail/mail-bridge.service.ts && git commit -m "feat(mail): IMAP/SMTP bridge service"
```

---

### Task 10: Контроллер, DTO, модуль, регистрация в приложении

**Files:**
- Create: `~/Downloads/taler_id/src/mail/dto/mail.dto.ts`
- Create: `~/Downloads/taler_id/src/mail/mail.controller.ts`
- Create: `~/Downloads/taler_id/src/mail/mail.module.ts`
- Modify: `~/Downloads/taler_id/src/app.module.ts` (imports)

- [x] **Step 1: DTO `dto/mail.dto.ts`**

```typescript
import { IsArray, IsEmail, IsOptional, IsString, MaxLength, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class CreateMailAccountDto {
  @IsString() @MaxLength(64)
  localpart!: string;
}

export class CreateAppPasswordDto {
  @IsString() @MaxLength(64)
  label!: string;
}

export class AttachmentDto {
  @IsString() @MaxLength(255)
  filename!: string;

  @IsString()
  contentBase64!: string;
}

export class SendMessageDto {
  @IsEmail()
  to!: string;

  @IsString() @MaxLength(255)
  subject!: string;

  @IsString() @MaxLength(100_000)
  text!: string;

  @IsOptional() @IsString()
  inReplyTo?: string;

  @IsOptional() @IsArray() @ValidateNested({ each: true }) @Type(() => AttachmentDto)
  attachments?: AttachmentDto[];
}
```

- [x] **Step 2: Контроллер `mail.controller.ts`**

```typescript
import {
  Body, Controller, Delete, Get, Param, ParseIntPipe, Post, Query, Res, UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { Response } from 'express';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { MailAccountService } from './mail-account.service';
import { MailBridgeService } from './mail-bridge.service';
import { CreateAppPasswordDto, CreateMailAccountDto, SendMessageDto } from './dto/mail.dto';

@Controller('mail')
@UseGuards(JwtAuthGuard)
export class MailController {
  constructor(
    private readonly accounts: MailAccountService,
    private readonly bridge: MailBridgeService,
  ) {}

  // ── Аккаунт ────────────────────────────────────────────────

  @Get('availability')
  checkAvailability(@Query('localpart') localpart: string) {
    return this.accounts.checkAvailability(localpart);
  }

  @Post('account')
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  createAccount(@CurrentUser() user: any, @Body() dto: CreateMailAccountDto) {
    return this.accounts.createAccount(user.sub, dto.localpart);
  }

  @Get('account')
  getAccount(@CurrentUser() user: any) {
    return this.accounts.getAccount(user.sub);
  }

  // ── App-пароли ─────────────────────────────────────────────

  @Post('app-passwords')
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  createAppPassword(@CurrentUser() user: any, @Body() dto: CreateAppPasswordDto) {
    return this.accounts.createAppPassword(user.sub, dto.label);
  }

  @Get('app-passwords')
  listAppPasswords(@CurrentUser() user: any) {
    return this.accounts.listAppPasswords(user.sub);
  }

  @Delete('app-passwords/:id')
  async revokeAppPassword(@CurrentUser() user: any, @Param('id') id: string) {
    await this.accounts.revokeAppPassword(user.sub, id);
    return { ok: true };
  }

  // ── Письма ─────────────────────────────────────────────────

  @Get('messages')
  listMessages(
    @CurrentUser() user: any,
    @Query('folder') folder?: string,
    @Query('beforeUid') beforeUid?: string,
  ) {
    return this.bridge.listMessages(user.sub, folder || 'INBOX', beforeUid ? Number(beforeUid) : undefined);
  }

  @Get('messages/:uid')
  getMessage(@CurrentUser() user: any, @Param('uid', ParseIntPipe) uid: number) {
    return this.bridge.getMessage(user.sub, uid);
  }

  @Get('messages/:uid/attachments/:index')
  async getAttachment(
    @CurrentUser() user: any,
    @Param('uid', ParseIntPipe) uid: number,
    @Param('index', ParseIntPipe) index: number,
    @Res() res: Response,
  ) {
    const att = await this.bridge.getAttachment(user.sub, uid, index);
    res.setHeader('Content-Type', att.contentType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(att.filename)}"`);
    res.send(att.content);
  }

  @Post('messages')
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async sendMessage(@CurrentUser() user: any, @Body() dto: SendMessageDto) {
    await this.bridge.sendMessage(user.sub, dto);
    return { ok: true };
  }

  @Post('messages/:uid/read')
  async markRead(@CurrentUser() user: any, @Param('uid', ParseIntPipe) uid: number) {
    await this.bridge.setSeen(user.sub, uid, true);
    return { ok: true };
  }

  @Post('messages/:uid/unread')
  async markUnread(@CurrentUser() user: any, @Param('uid', ParseIntPipe) uid: number) {
    await this.bridge.setSeen(user.sub, uid, false);
    return { ok: true };
  }

  @Delete('messages/:uid')
  async deleteMessage(@CurrentUser() user: any, @Param('uid', ParseIntPipe) uid: number) {
    await this.bridge.deleteMessage(user.sub, uid);
    return { ok: true };
  }
}
```

- [x] **Step 3: Модуль `mail.module.ts`**

```typescript
import { Module } from '@nestjs/common';
import { MailController } from './mail.controller';
import { MailAccountService } from './mail-account.service';
import { MailBridgeService } from './mail-bridge.service';
import { MailcowClient } from './mailcow.client';

@Module({
  controllers: [MailController],
  providers: [MailcowClient, MailAccountService, MailBridgeService],
  exports: [MailAccountService, MailBridgeService], // понадобятся assistant tools в Phase 2
})
export class MailModule {}
```

- [x] **Step 4: Зарегистрировать в `src/app.module.ts`** — добавить `MailModule` в `imports` рядом с `EmailModule` + import-строку:

```typescript
import { MailModule } from './mail/mail.module';
// в imports:
    MailModule,
```

- [x] **Step 5: Полная сборка + существующие unit-тесты**

```bash
cd ~/Downloads/taler_id && npm run build && npx jest src/mail/
```
Expected: build ok; mail-специфичные spec'и зелёные.

- [x] **Step 6: Commit**

```bash
git add src/mail/ src/app.module.ts && git commit -m "feat(mail): REST controller + module wiring"
```

---

### Task 11: Suite `mail_test.ts` в taler_id_tests

**Files:**
- Create: `~/Downloads/taler_id_tests/mail_test.ts`
- Modify: `~/Downloads/taler_id_tests/package.json` (scripts + deps)

Паттерн — `channels_test.ts`: axios + `check()`, счётчики passed/failed, exit code. Реальный IMAP-логин app-паролем — через `imapflow`.

- [x] **Step 1: Установить imapflow в тест-репо**

```bash
cd ~/Downloads/taler_id_tests && npm install imapflow
```

- [x] **Step 2: Добавить scripts в `package.json`**

```json
"test:mail": "npx ts-node mail_test.ts",
"test:mail:prod": "BASE_URL=https://id.taler.tirol npx ts-node mail_test.ts"
```

- [x] **Step 3: Написать `mail_test.ts`**

```typescript
/**
 * Taler ID — Mail hosting E2E Test (Mailcow + src/mail bridge)
 *
 * Проверяет: availability → создание ящика (идемпотентно) → app-пароль →
 * реальный IMAP-логин → отправка user1→user2 через мост → доставка → чтение →
 * flags → отзыв app-пароля → IMAP-логин отваливается.
 *
 * Запуск: npx ts-node mail_test.ts        (DEV)
 *         BASE_URL=https://id.taler.tirol npx ts-node mail_test.ts  (TEST)
 */
import axios from 'axios';
import { ImapFlow } from 'imapflow';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const USER1 = { email: 'integration_test@taler-test.com', password: 'IntegrationTest123!' };
const USER2 = { email: 'integration_test_2@taler-test.com', password: 'IntegrationTest123!' };

const http = axios.create({ baseURL: BASE_URL, validateStatus: () => true, timeout: 30000 });

async function login(creds: { email: string; password: string }): Promise<string> {
  const res = await http.post('/auth/login', creds);
  if (res.status !== 200) throw new Error(`login ${res.status}: ${JSON.stringify(res.data)}`);
  return res.data.accessToken as string;
}
function auth(token: string) { return { headers: { Authorization: `Bearer ${token}` } }; }

let failed = 0; let passed = 0;
function check(name: string, cond: boolean, info?: unknown) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}`, info ?? ''); failed++; }
}

async function tryImapLogin(host: string, user: string, pass: string): Promise<boolean> {
  const client = new ImapFlow({ host, port: 993, secure: true, auth: { user, pass }, logger: false });
  try { await client.connect(); await client.logout(); return true; }
  catch { return false; }
}

async function ensureAccount(token: string, preferredLocalpart: string): Promise<any> {
  const existing = await http.get('/mail/account', auth(token));
  if (existing.status === 200) return existing.data;
  const created = await http.post('/mail/account', { localpart: preferredLocalpart }, auth(token));
  if (created.status >= 300) throw new Error(`create account failed: ${JSON.stringify(created.data)}`);
  return created.data;
}

async function main() {
  console.log(`Mail tests against ${BASE_URL}`);
  const t1 = await login(USER1);
  const t2 = await login(USER2);

  // 1. Availability + валидация
  const avFree = await http.get(`/mail/availability?localpart=free-${Date.now()}`, auth(t1));
  check('1. availability: свободный → available=true', avFree.status === 200 && avFree.data.available === true, avFree.data);
  const avReserved = await http.get('/mail/availability?localpart=admin', auth(t1));
  check('1b. availability: admin → RESERVED', avReserved.data.available === false && avReserved.data.reason === 'RESERVED', avReserved.data);
  const avInvalid = await http.get('/mail/availability?localpart=..bad..', auth(t1));
  check('1c. availability: невалидный → INVALID', avInvalid.data.available === false && avInvalid.data.reason === 'INVALID', avInvalid.data);

  // 2. Ящики обоих юзеров (идемпотентно: создаются один раз, дальше переиспользуются)
  const acc1 = await ensureAccount(t1, 'inttest1');
  const acc2 = await ensureAccount(t2, 'inttest2');
  check('2. user1 mail account ACTIVE', acc1.status === 'ACTIVE', acc1);
  check('2b. user2 mail account ACTIVE', acc2.status === 'ACTIVE', acc2);
  check('2c. занятый localpart недоступен', (await http.get(`/mail/availability?localpart=${acc1.localpart}`, auth(t2))).data.available === false);
  check('2d. повторное создание → 409', (await http.post('/mail/account', { localpart: 'other' }, auth(t1))).status === 409);
  const imapHost = acc1.clientSettings.host;

  // 3. App-пароль + реальный IMAP-логин
  const ap = await http.post('/mail/app-passwords', { label: `smoke-${Date.now()}` }, auth(t1));
  check('3. app-password создан, значение выдано', ap.status === 201 || ap.status === 200, ap.data);
  const apPassword = ap.data.password as string;
  const apId = ap.data.id as string;
  check('3b. IMAP login app-паролем работает', await tryImapLogin(imapHost, acc1.address, apPassword));
  const apList = await http.get('/mail/app-passwords', auth(t1));
  check('3c. app-password в списке', (apList.data as any[]).some((p) => p.id === apId));

  // 4. Отправка user1 → user2 через мост, доставка ≤60с
  const marker = `smoke-${Date.now()}`;
  const send = await http.post('/mail/messages', { to: acc2.address, subject: marker, text: `body ${marker}` }, auth(t1));
  check('4. POST /mail/messages → ok', send.status < 300, send.data);
  let deliveredUid: number | null = null;
  for (let i = 0; i < 20 && !deliveredUid; i++) {
    await new Promise((r) => setTimeout(r, 3000));
    const inbox = await http.get('/mail/messages', auth(t2));
    const found = (inbox.data.items as any[])?.find((m) => m.subject === marker);
    if (found) deliveredUid = found.uid;
  }
  check('4b. письмо доставлено в inbox user2 (≤60с)', deliveredUid !== null);

  // 5. Чтение письма + flags
  if (deliveredUid) {
    const msg = await http.get(`/mail/messages/${deliveredUid}`, auth(t2));
    check('5. GET message: тело содержит marker', msg.status === 200 && String(msg.data.text).includes(marker), msg.data?.subject);
    check('5b. from = адрес user1', msg.data.from?.includes(acc1.address));
    check('5c. mark unread → ok', (await http.post(`/mail/messages/${deliveredUid}/unread`, {}, auth(t2))).status < 300);
    const afterUnread = await http.get('/mail/messages', auth(t2));
    check('5d. seen=false после unread', (afterUnread.data.items as any[]).find((m) => m.uid === deliveredUid)?.seen === false);
    check('5e. delete message → ok', (await http.delete(`/mail/messages/${deliveredUid}`, auth(t2))).status < 300);
  } else { failed += 5; console.log('  ✗ 5.* пропущены — письмо не доставлено'); }

  // 6. Отзыв app-пароля → IMAP отваливается
  check('6. DELETE app-password → ok', (await http.delete(`/mail/app-passwords/${apId}`, auth(t1))).status < 300);
  await new Promise((r) => setTimeout(r, 3000)); // dovecot auth cache
  check('6b. IMAP login отозванным паролем НЕ работает', !(await tryImapLogin(imapHost, acc1.address, apPassword)));

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
```

- [x] **Step 4: Проверить компиляцию suite'а** — `npx tsc --noEmit mail_test.ts` (или просто запуск в Task 12; до деплоя бэкенда suite упадёт на 404 — это ожидаемо).

- [x] **Step 5: Commit (репо taler_id_tests)**

```bash
cd ~/Downloads/taler_id_tests && git add mail_test.ts package.json package-lock.json && git commit -m "test: mail hosting e2e suite (test:mail)"
```

---

### Task 12: Деплой на DEV + прогон test:mail

- [ ] **Step 1: Push бэкенда и деплой на DEV**

```bash
cd ~/Downloads/taler_id && git push origin dev
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm install && npx prisma migrate deploy && npm run build && pm2 restart taler-id-dev'
```
Перед рестартом убедиться, что в `~/taler-id/.env` на DEV добавлены: `MAILCOW_API_URL`, `MAILCOW_API_KEY` (Task 1), `MAIL_DOMAIN=mail-dev.taler.tirol`, `MAIL_CLIENT_HOST=mail.talerid.io`, `MAIL_MASTER_KEY=$(openssl rand -hex 32)`, `MAIL_SEND_DAILY_LIMIT=50`.

- [ ] **Step 2: Health + smoke endpoint**

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://staging.id.taler.tirol/health   # 200
```

- [ ] **Step 3: Прогнать suite**

```bash
cd ~/Downloads/taler_id_tests && npm run test:mail
```
Expected: `N passed, 0 failed` (≈16 проверок). При падениях — systematic-debugging, логи: `ssh dvolkov@89.169.55.217 'pm2 logs taler-id-dev --lines 100 --nostream'` и `ssh root@165.245.254.8 'cd /opt/mailcow-dockerized && docker compose logs --tail 50 dovecot-mailcow postfix-mailcow'`.

- [ ] **Step 4: Прогнать полный обязательный набор DEV-тестов** (регрессия): `cd ~/Downloads/taler_id_tests && npm test` → 29/29.

- [ ] **Step 5: Финальный коммит статуса** — отметить чекбоксы в этом плане, `git add docs/ && git commit -m "docs: mail phase1 plan progress"`.

---

### Task 13: Deliverability-гейт + мониторинг (ручной чек-лист)

- [ ] **Step 1: Внешняя доставка** — из DEV-ящика (`inttest1@mail-dev.taler.tirol`, через `POST /mail/messages`) отправить письмо на личный Gmail. Проверить: письмо НЕ в спаме, в headers `SPF: PASS`, `DKIM: PASS` (Show original в Gmail).

- [ ] **Step 2: Скоринг** — отправить на адрес, выданный https://www.mail-tester.com, добиться ≥8/10.

- [ ] **Step 3: Блэклисты** — проверить 165.245.254.8 на mxtoolbox.com/blacklists (или `dig +short 8.254.245.165.zen.spamhaus.org` → пусто = чисто).

- [ ] **Step 4: Мониторинг** — зарегистрировать бокс `mail` в taler-monitor по процедуре из CLAUDE.md («Регистрация нового бокса»): gen-token на monitor.taler.tirol → `./boxes/_lib/deploy.sh root@165.245.254.8` → `/etc/taler-monitor/push.env` с `DOCKER_CONTAINERS=postfix-mailcow,dovecot-mailcow,rspamd-mailcow,nginx-mailcow`, HTTP_CHECK на `https://mail.selyanska.eu`, disk-порог. `AUTOFIX_DENY=postfix*,dovecot*,mysql*,redis*`.

- [ ] **Step 5: Бэкапы** — проверить текущий бэкап-механизм Mailcow (`ssh root@165.245.254.8 'crontab -l; ls /opt/mailcow-dockerized/helper-scripts/'`). Если бэкапа нет — настроить `helper-scripts/backup_and_restore.sh backup all` в cron (daily) с выгрузкой в DO Spaces (s3cmd/rclone). Зафиксировать результат в stability.md.

---

## Что дальше (вне этого плана)

- **Phase 2 план** (отдельный документ): Flutter `lib/features/mail/` (онбординг-шаг, inbox/чтение/compose, app-пароли UI), assistant tools (`check_mail`/`read_mail`/`send_mail`), экран старых юзеров. Пишется после приёмки Phase 1 — API зафиксирован этим планом.
- Деплой TEST/PROD — по стандартному pipeline после Phase 2 (юзерам без UI фича не видна; бэкенд можно катить раньше безопасно).
- Push о новых письмах, платные квоты — бэклог из спеки.

## Self-review notes

- Spec coverage: инфра (T1-2), модели (T3), конфиг (T4), провижининг+retry (T8), app-пароли (T8/T10), мост+санитизация+rate-limit (T9), REST (T10), suite (T11-12), deliverability+мониторинг+бэкапы (T13). Онбординг-flow и suspend-при-удалении-аккаунта: онбординг — мобильная часть (Phase 2), backend-API готов (`POST /mail/account`); suspend при удалении юзера — отложено в Phase 2 (в Prisma стоит `onDelete: Cascade` для метаданных; Mailcow-ящик чистится reconcile-скриптом — добавить в Phase 2).
- Типы согласованы: `user.sub`, `RedisService.getClient()`, `requireActiveAccount()` используются единообразно в T8-T10.
- Известные точки сверки с реальностью (помечены в шагах): формат ответов Mailcow API (T7 Step 2), сигнатуры imapflow (T9 Step 3), путь RedisService (T8 Step 2).

---

## Status 2026-07-24 — PHASE 1 COMPLETE

- Task 1–2 (инфра): выполнены. Mailcow: домены talerid.io + mail-dev.taler.tirol, DKIM, acme SAN mail.talerid.io, admin@talerid.io + postmaster/abuse алиасы. DNS talerid.io — все 7 записей в DO DNS. **Ожидает Дмитрия:** 4 записи mail-dev в IONOS-зоне taler.tirol (см. таблицу Task 2 Step 2).
- Task 3–11 (код): выполнены, коммиты 296060b..eee4d92 (backend) + cac485d, 8f48402 (tests). Два ревью-раунда, все замечания исправлены.
- Task 12: задеплоено на DEV. `npm run test:mail` — **19/19**, регрессия `npm test` — 35/35. На DEV в деплой добавлять `npx prisma generate` после pull (иначе stale client).
- Task 13: письмо admin@talerid.io → Gmail отправлено (ручная проверка SPF/DKIM за Дмитрием); IP чист в zen.spamhaus/spamcop/barracuda/sorbs; monitor-бокс `mail` зарегистрирован и пушит; бэкапы — DO droplet backups (daily). dovecot auth_cache_ttl снижен до 1 min (отзыв app-паролей ≤60с).
- Отклонение от плана: mail-tester.com скоринг не автоматизирован — сделать вручную при выходе на PROD.
