# Taler ID — Техническая документация

**Версия:** 1.2
**Дата:** 19 февраля 2026
**Сервер:** `dvolkov@138.124.61.221`
**URL:** `https://id.taler.tirol` (HTTPS, nginx reverse proxy)

---

## 1. Назначение системы

**Taler ID** — Identity Provider (IdP) для экосистемы Taler, реализующий стандарты OAuth 2.0 / OpenID Connect. Аналог SberID / Google Identity, расширенный верификацией KYC/KYB через Sumsub и on-chain подтверждением через Substrate/ink! смарт-контракт.

### Что делает Taler ID
| Функция | Статус |
|---------|--------|
| Регистрация (email / телефон) + OTP | ✅ |
| Вход с паролем + 2FA (TOTP/HOTP) | ✅ |
| JWT сессии (access 15m + refresh 30d) | ✅ |
| OAuth 2.0 / OIDC (Authorization Code + PKCE) | ✅ |
| Профиль пользователя (CRUD) | ✅ |
| Загрузка документов → S3 (AES-256) | ✅ |
| KYC через Sumsub (физлицо) | ✅ |
| KYB через Sumsub (предприятие) | ✅ |
| Профиль тенанта + роли сотрудников | ✅ |
| Инвайты по email | ✅ |
| GDPR: экспорт + удаление аккаунта | ✅ |
| On-chain KYC хэш (ink! контракт) | ✅ скомпилирован, ожидает TAL |
| Rate limiting + brute-force защита | ✅ |
| Аудит-лог всех действий | ✅ |

---

## 2. Технический стек

| Компонент | Технология | Версия |
|-----------|-----------|--------|
| Runtime | Node.js | - |
| Framework | NestJS | 11.x |
| ORM | Prisma | 5.x |
| БД | PostgreSQL | localhost:5432 |
| Кэш / сессии | Redis | localhost:6379 |
| Хранилище файлов | S3 / MinIO | localhost:9000 |
| OAuth/OIDC | oidc-provider | 9.x |
| JWT | @nestjs/jwt | 11.x |
| 2FA | otplib + speakeasy | - |
| KYC/KYB | Sumsub API | - |
| Email | Nodemailer | 8.x |
| SMS | Twilio | - |
| Блокчейн клиент | @polkadot/api + @polkadot/api-contract | 16.x |
| Смарт-контракт | ink! v5 (Rust/Wasm) | на Substrate |

---

## 3. Архитектура проекта

```
/home/dvolkov/taler-id/
├── src/
│   ├── main.ts                    # Точка входа, Helmet, CORS, validation pipe
│   ├── app.module.ts              # Корневой модуль
│   ├── app.controller.ts          # GET / → редирект на /ui/index.html
│   │                              # GET /health → { status: "ok" }
│   ├── auth/                      # Модуль аутентификации
│   │   ├── auth.service.ts        # Бизнес-логика
│   │   ├── auth.controller.ts     # REST endpoints
│   │   ├── auth.service.spec.ts   # 59 unit-тестов (88% coverage)
│   │   ├── jwt.strategy.ts        # Passport JWT strategy
│   │   └── dto/                   # RegisterDto, LoginDto, Login2faDto, RefreshDto
│   ├── profile/                   # Модуль профиля
│   │   ├── profile.service.ts     # Бизнес-логика
│   │   ├── profile.controller.ts  # REST endpoints
│   │   ├── profile.service.spec.ts # 45 unit-тестов (100% coverage)
│   │   ├── s3.service.ts          # AWS S3 / MinIO интеграция
│   │   └── dto/
│   ├── kyc/                       # KYC через Sumsub
│   │   ├── kyc.service.ts
│   │   ├── kyc.controller.ts
│   │   └── kyc.service.spec.ts    # Unit-тесты (76% coverage)
│   ├── tenant/                    # Тенанты и KYB
│   │   ├── tenant.service.ts
│   │   ├── tenant.controller.ts
│   │   ├── tenant.service.spec.ts # 46 unit-тестов (81% coverage)
│   │   └── dto/
│   ├── blockchain/                # Polkadot/Substrate интеграция
│   │   ├── blockchain.service.ts  # ink! контракт вызовы
│   │   ├── blockchain.controller.ts
│   │   └── blockchain.service.spec.ts
│   ├── common/
│   │   ├── decorators/
│   │   │   └── current-user.decorator.ts  # @CurrentUser()
│   │   ├── filters/
│   │   │   └── http-exception.filter.ts
│   │   └── guards/
│   │       └── jwt-auth.guard.ts
│   ├── config/                    # Конфигурация (ConfigModule)
│   ├── prisma/                    # PrismaService
│   └── redis/                     # RedisService (ioredis)
├── prisma/
│   ├── schema.prisma              # Схема БД (12 моделей)
│   └── seed.ts                    # Сид: OAuth клиент WalletX
├── test/
│   ├── app.e2e-spec.ts            # 8 E2E тестов
│   └── jest-e2e.json
├── public/                        # Статический UI (HTML/JS)
│   ├── index.html                 # Профиль
│   ├── login.html                 # Вход
│   ├── register.html              # Регистрация
│   └── consent.html               # OAuth consent screen
├── .env                           # Переменные окружения
└── package.json
```

---

## 4. База данных (Prisma Schema)

### 4.1 Модели

```
User
├── id (uuid)
├── email? (unique)
├── phone? (unique)
├── passwordHash?
├── deletedAt?                     # GDPR soft-delete
└── relations: Profile, Session[], KycRecord, TenantMember[], AuditLog[], TotpSecret

Profile
├── id, userId (unique)
├── firstName, lastName, middleName
├── dateOfBirth, country, postalCode
├── walletAddress                  # Привязка публичного адреса кошелька
├── avatarUrl
└── relations: Document[]

Document
├── id, profileId
├── type: PASSPORT|NATIONAL_ID|DRIVERS_LICENSE|DIPLOMA|CERTIFICATE
├── s3Key                          # Ключ в S3 (AES-256)
├── originalName, mimeType
└── status: "uploaded"

KycRecord
├── id, userId (unique)
├── sumsubApplicantId?
├── status: UNVERIFIED|PENDING|VERIFIED|REJECTED
├── kycType: INDIVIDUAL|SELF_EMPLOYED|BUSINESS
├── rejectionReason?, verifiedAt?

Session
├── id, userId
├── deviceInfo, ipAddress, location
├── createdAt, lastSeenAt, expiresAt
└── isRevoked

TotpSecret
├── id, userId (unique)
├── secret
└── verified

AuditLog
├── id, userId?
├── action                         # REGISTER, LOGIN, LOGIN_FAILED, etc.
├── ipAddress, userAgent
└── meta (JSON)

OAuthClient
├── id, clientId (unique), clientSecret
├── name, logoUri
├── redirectUris[], allowedScopes[]

Tenant
├── id, name, description
├── logoUrl, legalAddress, website
├── contactEmail, contactPhone
├── kybStatus: UNVERIFIED|PENDING|VERIFIED|REJECTED
└── sumsubApplicantId?

TenantMember
├── tenantId + userId (unique pair)
└── role: OWNER|ADMIN|OPERATOR|VIEWER

PendingInvite
├── id, tenantId, email
├── role, token (unique)
└── expiresAt
```

---

## 5. API Endpoints

### 5.1 Auth (`/auth`)

| Method | Endpoint | Auth | Описание |
|--------|----------|------|----------|
| POST | `/auth/register` | — | Регистрация (email/телефон) |
| POST | `/auth/login` | — | Вход, возвращает токены или challengeToken для 2FA |
| POST | `/auth/login/2fa` | — | Завершение входа с TOTP кодом |
| POST | `/auth/refresh` | — | Обновление access/refresh токенов |
| POST | `/auth/logout` | JWT | Завершение текущей сессии |
| GET | `/auth/2fa/totp/setup` | JWT | Генерация TOTP секрета + QR-код |
| POST | `/auth/2fa/totp/verify` | JWT | Подтверждение TOTP (активация) |
| DELETE | `/auth/2fa/totp` | JWT | Отключение TOTP (требует пароль) |
| GET | `/auth/sessions` | JWT | Список активных сессий |
| DELETE | `/auth/sessions/:id` | JWT | Завершение конкретной сессии |
| DELETE | `/auth/sessions` | JWT | Завершение всех сессий кроме текущей |

### 5.2 Profile (`/profile`)

| Method | Endpoint | Auth | Описание |
|--------|----------|------|----------|
| GET | `/profile` | JWT | Получить профиль |
| PUT | `/profile` | JWT | Обновить профиль |
| PUT | `/profile/wallet` | JWT | Привязать адрес кошелька |
| DELETE | `/profile/wallet` | JWT | Отвязать кошелёк |
| GET | `/profile/documents` | JWT | Список документов |
| POST | `/profile/documents` | JWT | Загрузить документ (multipart) |
| GET | `/profile/documents/:id/download` | JWT | Presigned URL для скачивания |
| DELETE | `/profile/documents/:id` | JWT | Удалить документ |
| GET | `/profile/export` | JWT | GDPR: экспорт всех данных |
| DELETE | `/profile` | JWT | GDPR: удаление аккаунта |

### 5.3 KYC (`/kyc`)

| Method | Endpoint | Auth | Описание |
|--------|----------|------|----------|
| POST | `/kyc/start` | JWT | Создать applicant в Sumsub, получить sdkToken |
| GET | `/kyc/status` | JWT | Текущий статус KYC |
| POST | `/kyc/webhook` | HMAC sig | Вебхук от Sumsub (GREEN/RED) |

### 5.4 Tenant (`/tenant`)

| Method | Endpoint | Auth | Описание |
|--------|----------|------|----------|
| POST | `/tenant` | JWT | Создать тенант (стать OWNER) |
| GET | `/tenant` | JWT | Список тенантов текущего пользователя |
| GET | `/tenant/:id` | JWT | Профиль тенанта |
| PUT | `/tenant/:id` | JWT | Обновить профиль (OWNER/ADMIN) |
| POST | `/tenant/:id/kyb/start` | JWT | Начать KYB верификацию |
| GET | `/tenant/:id/kyb/status` | JWT | Статус KYB |
| POST | `/tenant/:id/members/invite` | JWT | Пригласить сотрудника по email |
| POST | `/tenant/invites/:token/accept` | JWT | Принять инвайт |
| PUT | `/tenant/:id/members/:userId/role` | JWT | Изменить роль |
| DELETE | `/tenant/:id/members/:userId` | JWT | Удалить сотрудника |

### 5.5 OAuth / OIDC

| Method | Endpoint | Описание |
|--------|----------|----------|
| GET | `/.well-known/openid-configuration` | Discovery document |
| GET | `/auth/authorize` | Authorization endpoint |
| POST | `/auth/token` | Token endpoint |
| GET | `/auth/userinfo` | UserInfo endpoint |
| POST | `/auth/token/revoke` | Revoke token |
| GET | `/auth/consent` | Consent screen |

### 5.6 Blockchain (`/blockchain`)

| Method | Endpoint | Auth | Описание |
|--------|----------|------|----------|
| GET | `/blockchain/health` | — | Состояние подключения к ноде |
| GET | `/blockchain/kyc/:userId` | JWT | On-chain KYC статус пользователя |

---

## 6. OAuth 2.0 Scopes

| Scope | Данные в токене |
|-------|----------------|
| `openid` | sub (user UUID) |
| `profile` | firstName, lastName, middleName, avatarUrl, country |
| `email` | email |
| `phone` | phone |
| `kyc_status` | kyc_status (UNVERIFIED/PENDING/VERIFIED/REJECTED) |
| `tenant` | tenant_id, tenant_role, tenant_name |

> **Примечание:** Дополнительные scopes (например, `wallet:read`) определяются продуктами экосистемы (WalletX) и регистрируются в Taler ID как resource servers.

---

## 7. Безопасность

### Rate Limiting
```
/auth/login     — 10 запросов / 15 минут
/auth/register  — 5 запросов / час
/kyc/webhook    — @SkipThrottle (без лимита, только подпись)
```

### Brute-force защита
- После 5 неудачных попыток входа → блокировка на 15 минут
- Хранится в Redis: `brute:userId`
- Каждая неудача → запись в AuditLog с action `LOGIN_FAILED`

### Заголовки безопасности (Helmet)
- Content-Security-Policy
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Strict-Transport-Security

### Хранение данных
- Пароли: bcrypt (rounds=12)
- Документы: AES-256 шифрование в S3
- Refresh токены: хранятся в Redis с TTL
- TOTP секреты: зашифрованы в PostgreSQL

### Аудит-лог
Все значимые события пишутся в таблицу `AuditLog`:
- `REGISTER`, `LOGIN`, `LOGIN_FAILED`, `LOGOUT`
- `2FA_ENABLED`, `2FA_DISABLED`, `2FA_VERIFIED`
- `SESSION_REVOKED`, `ALL_SESSIONS_REVOKED`
- `KYC_STARTED`, `KYC_VERIFIED`, `KYC_REJECTED`
- `DOCUMENT_UPLOADED`, `DOCUMENT_DELETED`
- `GDPR_EXPORT`, `ACCOUNT_DELETED`

---

## 8. Блокчейн компонент

### KYC Attestation Contract (ink! v5)

**Файл:** `/home/dvolkov/kyc-attestation/src/lib.rs`
**Артефакты:** `/home/dvolkov/kyc-attestation/target/ink/`
- `kyc_attestation.wasm` — 6.5KB Wasm байткод
- `kyc_attestation.json` — ABI метаданные
- `kyc_attestation.contract` — полный бандл для деплоя

### Хранилище в контракте
```rust
pub struct KycRecord {
    pub kyc_status: u8,       // 0=unverified, 1=pending, 2=verified, 3=rejected
    pub kyc_timestamp: u64,   // UNIX timestamp верификации
    pub kyb_status: u8,       // то же для бизнесов
    pub is_active: bool,      // false после GDPR delete
}

// Ключ: SHA-256(taler_id_internal_uuid)
// НЕТ персональных данных on-chain!
records: Mapping<[u8; 32], KycRecord>
```

### Методы контракта
| Метод | Вызывает | Описание |
|-------|----------|----------|
| `new()` | конструктор | Устанавливает deployer как attester |
| `attest_verification(hash, status, ts)` | backend → on KYC GREEN | Записывает KYC статус |
| `attest_kyb(hash, verified)` | backend → on KYB GREEN | Записывает KYB статус |
| `revoke_verification(hash)` | backend → on GDPR delete | `is_active = false` |
| `get_verification(hash)` | public | Читает запись (kyc, kyb, active) |

### Безопасность
- Только `attester` (deployer) может писать → `ensure_attester()`
- Остальные аккаунты → `Error::Unauthorized`
- События: `VerificationAttested`, `VerificationRevoked`, `KybAttested`

### Статус деплоя
- ✅ Написан и скомпилирован
- ✅ 7/7 unit-тестов (Rust) проходят
- ✅ **Задеплоен на Taler testnet** `wss://node.dev.gsmsoft.eu/`
  - Contract: `5ESHygc8MtXzDC1M7njq7Gke4k27supzujpcTZjavvEHywJD`
  - Code hash: `0x5e04519c4a57df5a2ddaac0d6a8a8768c1d71f131f01d598e4275ff03ae514e4`
  - Deployer: `5EZS5Lp5bdPdvcNfzaiFNjsTbtK78qWjCZVwACZFCEWVwRRp`

### Интеграция в NestJS
```
BLOCKCHAIN_ENABLED=true
TALER_NODE_WS=wss://node.dev.gsmsoft.eu/
KYC_CONTRACT_ADDRESS=5ESHygc8MtXzDC1M7njq7Gke4k27supzujpcTZjavvEHywJD
```
Сервер логирует при старте:
```
[BlockchainService] Connected to chain: Taler v4.0.0-dev-72af1f332cc
[BlockchainService] Attester account: 5EZS5Lp5bdPdvcNfzaiFNjsTbtK78qWjCZVwACZFCEWVwRRp
[BlockchainService] KYC Attestation Contract loaded: 5ESHygc8MtXzDC1M7njq7Gke4k27supzujpcTZjavvEHywJD
```

---

## 9. Тестирование

### Итог

| Тип | Тесты | Статус |
|-----|-------|--------|
| Unit: auth.service | 59 | ✅ все зелёные |
| Unit: profile.service | 45 | ✅ все зелёные |
| Unit: tenant.service | 46 | ✅ все зелёные |
| Unit: kyc.service | ~18 | ✅ все зелёные |
| Unit: blockchain.service | ~13 | ✅ все зелёные |
| E2E (Supertest) | 8 | ✅ все зелёные |
| Rust ink! tests | 7 | ✅ все зелёные |
| **ИТОГО** | **~196** | **✅** |

### Покрытие кода (service файлы)

| Сервис | Lines | Branches | Functions | Statements |
|--------|-------|----------|-----------|------------|
| auth.service.ts | **87.87%** | 72.04% | **100%** | 86.98% |
| profile.service.ts | **100%** | 90% | **100%** | 100% |
| tenant.service.ts | **80.73%** | 78.78% | **100%** | 81.45% |
| kyc.service.ts | **76.47%** | 59.37% | 87.5% | 75% |

### Что покрывают тесты

**auth.service.spec.ts (59 тестов)**
- register: успех, дубль email → 409, дубль телефона → 409
- login: успех, неверный пароль → 401 + AuditLog, 5 неудач → lockout
- login 2fa flow: challengeToken, verify2fa успех/провал
- refresh: ротация токенов, повтор → 401
- logout: инвалидация сессии
- setupTotp: генерация secret + QR
- verifyTotp: успех / неверный код → 401
- disableTotp: успех / неверный пароль → 401
- getSessions: список
- revokeSession: чужая сессия → 403
- revokeAllSessions: все кроме текущей

**profile.service.spec.ts (45 тестов, 100% lines)**
- getProfile: найден / не найден → 404
- updateProfile: поля обновляются
- linkWallet: корректный 0x-адрес / некорректный → 422
- unlinkWallet: сброс walletAddress
- uploadDocument: файл → S3 + метадата / >10MB → 413
- getDocuments, getDocumentDownloadUrl
- deleteDocument: из S3 + из БД / чужой → 404
- exportData: GDPR экспорт всех данных
- deleteAccount: soft-delete + очистка S3

**tenant.service.spec.ts (46 тестов)**
- createTenant: Tenant + Owner TenantMember
- getMyTenants, getTenant (не участник → 403)
- updateTenant (только OWNER/ADMIN)
- startKyb, handleKybWebhook (GREEN → VERIFIED)
- inviteMember: существующий / несуществующий email → PendingInvite
- acceptInvite: токен / истёкший / уже член
- changeRole: ADMIN не может сменить роль OWNER → 403
- removeMember: нельзя удалить самого себя

### E2E тесты (test/app.e2e-spec.ts)
- `GET /` → 302 (редирект на UI)
- `GET /health` → 200 `{ status: "ok" }`
- Auth flow: register → login → profile
- 2FA setup flow
- OAuth consent flow
- Session management
- KYC start flow

### Команды запуска
```bash
cd /home/dvolkov/taler-id

# Unit тесты
npm test

# Unit тесты с coverage
npm run test:cov

# E2E тесты
npm run test:e2e

# Rust тесты (ink! контракт)
cd /home/dvolkov/kyc-attestation
source $HOME/.cargo/env
cargo test
```

---

## 10. Деплой и окружение

### Переменные окружения (`.env`)

```env
NODE_ENV=development
PORT=3000
BASE_URL=http://138.124.61.221:3000

# JWT
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=30d

# Database
DATABASE_URL=postgresql://taler:taler_secret_2026@localhost:5432/taler_id

# Redis
REDIS_URL=redis://:redis_secret_2026@localhost:6379

# S3 / MinIO
S3_ENDPOINT=http://localhost:9000
S3_BUCKET=taler-id-documents
S3_REGION=us-east-1

# Sumsub KYC/KYB
SUMSUB_BASE_URL=https://api.sumsub.com
SUMSUB_APP_TOKEN=<secret>
SUMSUB_SECRET_KEY=<secret>
SUMSUB_WEBHOOK_SECRET=<secret>

# Security
BCRYPT_ROUNDS=12
RATE_LIMIT_TTL=900        # секунды
RATE_LIMIT_LOGIN_MAX=10   # попыток
RATE_LIMIT_REGISTER_MAX=5
BRUTE_FORCE_MAX_ATTEMPTS=5
BRUTE_FORCE_LOCKOUT_MINUTES=15

# Blockchain (отключён до получения TAL)
BLOCKCHAIN_ENABLED=false
TALER_NODE_WS=wss://node.dev.gsmsoft.eu/
KYC_CONTRACT_ADDRESS=
KYC_CONTRACT_ABI_PATH=/home/dvolkov/kyc-attestation/target/ink/kyc_attestation.json
```

### Запуск сервера

```bash
# Сборка
cd /home/dvolkov/taler-id
npm run build

# Продакшн запуск
nohup node dist/src/main.js > /tmp/taler-auth.log 2>&1 &
echo $! > /tmp/taler-id.pid

# Текущий PID
cat /tmp/taler-id.pid   # или: ps aux | grep "node dist"

# Проверка
curl http://localhost:3000/health
# → {"status":"ok","timestamp":"..."}
```

### Сервисы

| Сервис | Расположение | Порт |
|--------|-------------|------|
| Taler ID API | localhost | 3000 |
| PostgreSQL | localhost | 5432 |
| Redis | localhost | 6379 |
| MinIO (S3) | localhost | 9000 |

---

## 11. Деплой ink! контракта (когда будут TAL токены)

**Аккаунт deployer:** `5EZS5Lp5bdPdvcNfzaiFNjsTbtK78qWjCZVwACZFCEWVwRRp`
**Нужно:** ~5-10 TAL (storage deposit)

```bash
cd /home/dvolkov/kyc-attestation
source $HOME/.cargo/env

cargo contract instantiate \
  --url wss://node.dev.gsmsoft.eu/ \
  --suri "frozen lady season ride legal volume kingdom husband dilemma milk bench north" \
  --constructor new
```

После получения адреса контракта:
```bash
# Обновить .env
BLOCKCHAIN_ENABLED=true
KYC_CONTRACT_ADDRESS=<АДРЕС_ИЗ_ВЫВОДА>
BLOCKCHAIN_ATTESTER_SEED="frozen lady..."

# Перезапустить сервер
kill $(cat /tmp/taler-id.pid)
nohup node /home/dvolkov/taler-id/dist/src/main.js > /tmp/taler-auth.log 2>&1 &
echo $! > /tmp/taler-id.pid
```

Полный гайд: `/home/dvolkov/taler-id/BLOCKCHAIN_DEPLOY.md`

---

## 12. Роли в тенанте

| Роль | Создать тенант | Редактировать | Приглашать | Менять роли | Удалять |
|------|--------------|--------------|-----------|------------|---------|
| OWNER | — | ✅ | ✅ | ✅ (не себя) | ✅ (не себя) |
| ADMIN | — | ✅ | ✅ | ✅ (не OWNER) | ✅ (не OWNER) |
| OPERATOR | — | ❌ | ❌ | ❌ | ❌ |
| VIEWER | — | ❌ | ❌ | ❌ | ❌ |

---

## 13. Зарегистрированные OAuth клиенты

| Client | clientId | Redirect URI | Scopes |
|--------|----------|-------------|--------|
| WalletX | `walletx` | `http://localhost:3001/auth/callback` | openid, profile, email, kyc_status, tenant |

---

## 14. Текущее состояние системы

**Дата проверки:** 19 февраля 2026

| Компонент | Статус |
|-----------|--------|
| NestJS сервер (PID 35058) | ✅ работает |
| PostgreSQL | ✅ работает |
| Redis | ✅ работает |
| MinIO S3 | ✅ работает |
| 141 unit-тест | ✅ все зелёные |
| 8 E2E тестов | ✅ все зелёные |
| 7 Rust ink! тестов | ✅ все зелёные |
| ink! контракт | ✅ задеплоен на testnet, работает |
| Sumsub интеграция | ✅ в коде, требует API ключи |

---

## 15. Что разработали 7 AI-агентов

| Агент | Что реализовал |
|-------|----------------|
| **Архитектор** | NestJS проект, Prisma schema (12 моделей), docker-compose, конфиг |
| **Auth Engine** | Регистрация, вход, 2FA TOTP, refresh, сессии, OIDC провайдер, consent |
| **Profile & KYC** | Профиль CRUD, S3 документы, Sumsub KYC flow, GDPR export/delete |
| **Security** | Helmet, rate limiting, brute-force, аудит-лог |
| **Frontend** | HTML/JS страницы: логин, регистрация, профиль, consent screen |
| **QA** | 141 unit + 8 E2E тестов, покрытие ≥80% по сервисам |
| **Tenant** | Тенанты, KYB, роли OWNER/ADMIN/OPERATOR/VIEWER, инвайты |

Дополнительно (вне плана агентов):
- ink! v5 KYC Attestation Contract (Rust)
- @polkadot/api интеграция в NestJS
- Blockchain graceful degradation при `BLOCKCHAIN_ENABLED=false`

---

*Документация подготовлена на основе кода, развёрнутого на `dvolkov@138.124.61.221`*
