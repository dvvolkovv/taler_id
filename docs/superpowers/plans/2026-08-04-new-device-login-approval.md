# Подтверждение входа с нового устройства — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Вход с незнакомого устройства не выдаёт токены сразу — он ждёт подтверждения с уже доверенного устройства пользователя (пуш «Разрешить / Отклонить»), либо кода на почту как запасного канала.

**Architecture:** Клиент генерирует непрозрачный `deviceId` (UUID в secure storage) и шлёт его заголовком `X-Device-Id` на каждом запросе. Бэкенд ведёт таблицу `TrustedDevice` (userId + deviceId). После успешной проверки пароля (и TOTP, если включён) вход проходит через шлюз: знакомое устройство → токены как раньше; незнакомое → запись «ожидание» в Redis с TTL 10 минут, пуш на все остальные live-сессии пользователя, и клиенту `{ next: 'device_approval', approvalToken }` вместо токенов. Новое устройство опрашивает статус; одобрение с другого устройства (или верный код с почты) превращает ожидание в сессию.

**Tech Stack:** NestJS + Prisma/PostgreSQL + Redis (ioredis) + firebase-admin (FCM) + nodemailer; Flutter (BLoC, GetIt, Dio, go_router, flutter_secure_storage).

---

## Ключевые инварианты (нарушение любого = провал фичи)

1. **Пользователя нельзя запереть снаружи.** Если у аккаунта нет ни одного доверенного устройства — вход проходит без шлюза и устройство становится доверенным. Если доверенные есть, но пуши до них не доходят — всегда доступен код на почту.
2. **Секрет ожидания не уезжает в пуш.** У ожидания два идентификатора: `approvalToken` (секрет, только в теле ответа новому устройству — по нему выдаются токены) и `approvalId` (несекретный, едет в пуш — по нему одобряют). Превью уведомления на заблокированном экране не должно давать доступ к аккаунту.
3. **Старые клиенты не ломаются.** Запрос без `X-Device-Id` (десктоп, веб, версии до 1.1.24) ведёт себя ровно как сегодня. Шлюз включается только когда клиент прислал `deviceId`.
4. **Одобрение выдаёт ровно одну сессию.** Забор токенов — атомарный `GETDEL`; два параллельных опроса не дают две сессии.

## Решения, зафиксированные до начала

- **Тумблер `newDeviceApproval` на `Profile`, дефолт `false` в этом релизе.** Дефолт живёт одной константой `NEW_DEVICE_APPROVAL_DEFAULT` — после обкатки на DEV+TEST перевод в `true` это правка одной строки плюс миграция `UPDATE`.
- **Запасной канал — код на почту.** TOTP не годится: он включён у меньшинства.
- **Опрос статуса, не сокет.** Новое устройство ещё не аутентифицировано, Socket.IO-гейтвей требует JWT. Опрос раз в 3 с при TTL 10 мин — максимум 200 запросов, это ничто.
- **Доверие выдаётся в момент одобрения, а не в момент забора токенов.** Если ответ на заборе потеряется в сети, повторный вход пройдёт уже как со знакомого устройства — сценарий самозалечивается.

## Попутный баг, который чинится здесь же

Мобильный клиент никогда не мог пройти TOTP-вход: бэкенд отвечает `{ next: '2fa', challengeToken }`, а `auth_repository_impl.dart:37` проверяет `data['requires2FA'] == true` и в `verify2FA` шлёт `{email, code, tempToken}` — при `forbidNonWhitelisted: true` это 400, а до того `data['accessToken'] as String` падает на null. Раз мы вводим вторую ветку «next», приводим первую в порядок в той же работе (Task 14).

---

## Структура файлов

### Бэкенд (`~/Downloads/taler_id`)

| Файл | Ответственность |
|------|-----------------|
| `prisma/schema.prisma` | модель `TrustedDevice`, `Session.deviceId`, `Profile.newDeviceApproval` |
| `src/auth/device-approval.service.ts` | **новый.** Весь жизненный цикл ожидания: создание, пуш-рассылка, почтовый код, одобрение/отклонение, забор |
| `src/auth/device-approval.constants.ts` | **новый.** TTL, лимиты, ключи Redis, дефолт тумблера |
| `src/auth/dto/device-approval.dto.ts` | **новый.** DTO четырёх эндпоинтов |
| `src/auth/trusted-device.service.ts` | **новый.** Список / отзыв доверенных устройств |
| `src/auth/auth.service.ts` | шлюз в `login()` и `verify2fa()`, `createSession` пишет `deviceId` |
| `src/auth/auth.controller.ts` | эндпоинты, чтение заголовка `X-Device-Id` |
| `src/auth/auth.module.ts` | регистрация новых провайдеров + `FcmService` |
| `src/common/fcm.service.ts` | `sendDeviceApprovalRequest()` |
| `src/profile/dto/update-profile.dto.ts`, `src/profile/profile.service.ts` | тумблер через существующий `PATCH /profile` |

Тесты: `src/auth/device-approval.service.spec.ts`, `src/auth/auth.service.new-device.spec.ts`, `src/auth/trusted-device.service.spec.ts`.

### Мобилка (`~/Downloads/taler_id_mobile`)

| Файл | Ответственность |
|------|-----------------|
| `lib/core/services/device_id_service.dart` | **новый.** UUID устройства в secure storage |
| `lib/core/api/dio_client.dart` | заголовок `X-Device-Id` |
| `lib/core/di/service_locator.dart` | регистрация сервиса |
| `lib/features/auth/domain/entities/auth_entities.dart` | `DeviceApprovalRequiredException` |
| `lib/features/auth/data/datasources/auth_remote_datasource.dart` | четыре вызова ожидания + починка `verify2FA` |
| `lib/features/auth/data/repositories/auth_repository_impl.dart` | разбор `next` |
| `lib/features/auth/presentation/screens/device_approval_waiting_screen.dart` | **новый.** Экран ожидания + ввод кода с почты |
| `lib/features/auth/presentation/widgets/device_approval_sheet.dart` | **новый.** Лист «Разрешить / Отклонить» на доверенном устройстве |
| `lib/core/notifications/notification_service.dart` | тип пуша `device_approval` |
| `lib/features/settings/presentation/screens/trusted_devices_screen.dart` | **новый.** Список устройств + тумблер |

---

# ФАЗА A — схема и опознание устройства

### Task 1: Схема БД

**Files:**
- Modify: `prisma/schema.prisma`
- Create: `prisma/migrations/<timestamp>_trusted_devices/migration.sql` (генерируется)

- [ ] **Шаг 1: добавить модель `TrustedDevice`**

В `prisma/schema.prisma` сразу после модели `Session` (строка ~138):

```prisma
/// Устройство, с которого пользователь уже подтверждал вход. Ключ — непрозрачный
/// deviceId, который клиент генерирует один раз и хранит в secure storage;
/// сервер не пытается ничего из него вывести.
model TrustedDevice {
  id           String    @id @default(uuid())
  userId       String
  deviceId     String
  deviceInfo   String?
  label        String?
  lastIp       String?
  lastLocation String?
  firstSeenAt  DateTime  @default(now())
  lastSeenAt   DateTime  @default(now())
  revokedAt    DateTime?
  user         User      @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([userId, deviceId])
  @@index([userId, revokedAt])
}
```

- [ ] **Шаг 2: связать с `User`, `Session`, `Profile`**

В `model User` после строки `sessions Session[]` добавить:

```prisma
  trustedDevices       TrustedDevice[]
```

В `model Session` после `voipToken String?` добавить:

```prisma
  deviceId   String?
```

В `model Profile` после `assistantName String?` добавить:

```prisma
  newDeviceApproval    Boolean         @default(false)
```

- [ ] **Шаг 3: сгенерировать миграцию**

```bash
cd ~/Downloads/taler_id && npx prisma migrate dev --name trusted_devices --create-only
```

Ожидается: создан каталог `prisma/migrations/<timestamp>_trusted_devices/`. Открыть `migration.sql`, убедиться, что там `CREATE TABLE "TrustedDevice"`, `ALTER TABLE "Session" ADD COLUMN "deviceId"`, `ALTER TABLE "Profile" ADD COLUMN "newDeviceApproval"` — и **ни одного `DROP`**. Если есть `DROP` — схема разъехалась с базой, остановиться и разобраться, а не применять.

- [ ] **Шаг 4: применить и перегенерировать клиент**

```bash
cd ~/Downloads/taler_id && npx prisma migrate deploy && npx prisma generate
```

Ожидается: `All migrations have been successfully applied.` и `Generated Prisma Client`.

- [ ] **Шаг 5: коммит**

```bash
git add prisma/schema.prisma prisma/migrations
git commit -m "feat(auth): trusted device table, per-session device id, approval toggle"
```

---

### Task 2: Константы

**Files:**
- Create: `src/auth/device-approval.constants.ts`

- [ ] **Шаг 1: написать файл**

```ts
/** Сколько живёт ожидание подтверждения. */
export const APPROVAL_TTL_SECONDS = 10 * 60;

/** Сколько ещё помнится факт «токены уже забрали», чтобы повторный опрос
 *  получил внятный ответ, а не «истекло». */
export const APPROVAL_CLAIMED_TTL_SECONDS = 60;

/** Ожиданий на пользователя в час. Выше — 429. */
export const MAX_PENDING_PER_HOUR = 10;

/** Отправок кода на почту в рамках одного ожидания. */
export const MAX_EMAIL_SENDS = 3;

/** Пауза между отправками кода, секунды. */
export const EMAIL_RESEND_COOLDOWN_SECONDS = 60;

/** Неверных кодов, после которых ожидание сжигается. */
export const MAX_CODE_ATTEMPTS = 5;

/**
 * Требовать ли подтверждение по умолчанию для аккаунтов, которые тумблер не
 * трогали. В первом релизе false: фича обкатывается на тех, кто включил сам.
 * Перевод в true — правка этой строки плюс миграция
 * `UPDATE "Profile" SET "newDeviceApproval" = true`.
 */
export const NEW_DEVICE_APPROVAL_DEFAULT = false;

export const approvalKey = (token: string) => `device_approval:${token}`;
export const approvalIdKey = (id: string) => `device_approval_id:${id}`;
export const claimedKey = (token: string) => `device_approval_claimed:${token}`;
export const codeKey = (token: string) => `device_approval_code:${token}`;
export const codeAttemptsKey = (token: string) =>
  `device_approval_attempts:${token}`;
export const emailSendsKey = (token: string) =>
  `device_approval_sends:${token}`;
export const emailCooldownKey = (token: string) =>
  `device_approval_cooldown:${token}`;
export const rateKey = (userId: string) => `device_approval_rate:${userId}`;

export type ApprovalStatus = 'pending' | 'approved' | 'rejected';

export interface ApprovalRecord {
  approvalId: string;
  userId: string;
  deviceId: string;
  deviceInfo: string;
  ip: string;
  location: string | null;
  status: ApprovalStatus;
  createdAt: string;
}
```

- [ ] **Шаг 2: коммит**

```bash
git add src/auth/device-approval.constants.ts
git commit -m "feat(auth): device approval constants and redis key layout"
```

---

### Task 3: `createSession` запоминает устройство

**Files:**
- Modify: `src/auth/auth.service.ts:451-463`
- Test: `src/auth/auth.service.new-device.spec.ts`

- [ ] **Шаг 1: написать падающий тест**

Создать `src/auth/auth.service.new-device.spec.ts`:

```ts
import * as bcrypt from 'bcrypt';

jest.mock('otplib', () => ({
  generateSecret: jest.fn(() => 'SECRET'),
  generateURI: jest.fn(() => 'otpauth://totp/test'),
  verify: jest.fn(async () => ({ valid: true })),
}));

jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn().mockReturnValue('mock-key-content'),
}));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { AuthService } = require('./auth.service');

describe('AuthService device identity', () => {
  let service: any;
  let prisma: any;

  beforeEach(async () => {
    const passwordHash = await bcrypt.hash('pw', 4);
    prisma = {
      user: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'u1',
          email: 'a@b.c',
          passwordHash,
          totpSecret: null,
        }),
        findUnique: jest.fn().mockResolvedValue({ id: 'u1' }),
      },
      session: { create: jest.fn(async ({ data }: any) => ({ id: 's1', ...data })) },
      kycRecord: { findUnique: jest.fn().mockResolvedValue(null) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
      trustedDevice: {
        findFirst: jest.fn().mockResolvedValue(null),
        count: jest.fn().mockResolvedValue(0),
        upsert: jest.fn().mockResolvedValue({}),
      },
      profile: { findUnique: jest.fn().mockResolvedValue({ newDeviceApproval: false }) },
    };

    const redis = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn(),
      setEx: jest.fn(),
      del: jest.fn(),
      incr: jest.fn().mockResolvedValue(1),
      expire: jest.fn(),
    };

    service = new AuthService(
      prisma,
      { sign: jest.fn(() => 'jwt') },
      { get: jest.fn(() => undefined) },
      redis,
      { sendOtp: jest.fn() },
      { subscribeUser: jest.fn() },
      { createPending: jest.fn(), isTrusted: jest.fn(async () => false) },
    );
  });

  it('stamps the session with the device id the client sent', async () => {
    await service.login(
      { email: 'a@b.c', password: 'pw' },
      '1.2.3.4',
      'UA',
      'dev-abc',
    );

    expect(prisma.session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ deviceId: 'dev-abc' }),
      }),
    );
  });
});
```

- [ ] **Шаг 2: убедиться, что тест падает**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/auth.service.new-device.spec.ts
```

Ожидается: FAIL — `login` принимает три аргумента, `deviceId` не доходит до `session.create`.

- [ ] **Шаг 3: протащить `deviceId` через `createSession`**

`src/auth/auth.service.ts`, заменить `createSession`:

```ts
  private async createSession(
    userId: string,
    ip: string,
    userAgent: string,
    deviceId?: string,
  ) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days

    return this.prisma.session.create({
      data: {
        userId,
        ipAddress: ip,
        deviceInfo: userAgent?.substring(0, 200),
        deviceId: deviceId || null,
        expiresAt,
      },
    });
  }
```

Добавить четвёртый параметр `deviceId?: string` в сигнатуры `login()`, `verify2fa()`, `register()` и передать его в каждый вызов `createSession(...)` внутри них.

- [ ] **Шаг 4: убедиться, что тест проходит**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/auth.service.new-device.spec.ts
```

Ожидается: PASS.

- [ ] **Шаг 5: контроллер читает заголовок**

`src/auth/auth.controller.ts`. Добавить приватный хелпер в класс:

```ts
  /** Непрозрачный идентификатор устройства; старые клиенты его не шлют. */
  private deviceId(req: Request): string | undefined {
    const raw = req.headers['x-device-id'];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (!value) return undefined;
    const trimmed = String(value).trim();
    // Клиент шлёт uuid v4; всё, что не похоже, игнорируем, а не пишем в базу.
    return /^[0-9a-fA-F-]{16,64}$/.test(trimmed) ? trimmed : undefined;
  }
```

и передать `this.deviceId(req)` четвёртым аргументом в `register`, `login`, `verify2fa`.

- [ ] **Шаг 6: прогнать весь набор auth-тестов**

```bash
cd ~/Downloads/taler_id && npx jest src/auth
```

Ожидается: все PASS (существующие вызывают `login` с тремя аргументами — четвёртый необязательный, они не должны сломаться).

- [ ] **Шаг 7: коммит**

```bash
git add src/auth/auth.service.ts src/auth/auth.controller.ts src/auth/auth.service.new-device.spec.ts
git commit -m "feat(auth): carry a client device id into the session row"
```

---

# ФАЗА B — жизненный цикл ожидания

### Task 4: `DeviceApprovalService` — создание ожидания

**Files:**
- Create: `src/auth/device-approval.service.ts`
- Test: `src/auth/device-approval.service.spec.ts`

- [ ] **Шаг 1: написать падающий тест**

Создать `src/auth/device-approval.service.spec.ts`:

```ts
import { DeviceApprovalService } from './device-approval.service';

function makeRedis() {
  const store = new Map<string, string>();
  const counters = new Map<string, number>();
  return {
    store,
    counters,
    get: jest.fn(async (k: string) => store.get(k) ?? null),
    setEx: jest.fn(async (k: string, _t: number, v: string) => {
      store.set(k, v);
    }),
    del: jest.fn(async (k: string) => {
      store.delete(k);
    }),
    incr: jest.fn(async (k: string) => {
      const n = (counters.get(k) ?? 0) + 1;
      counters.set(k, n);
      return n;
    }),
    expire: jest.fn(async () => undefined),
    getClient: () => ({
      getdel: jest.fn(async (k: string) => {
        const v = store.get(k) ?? null;
        store.delete(k);
        return v;
      }),
    }),
  };
}

describe('DeviceApprovalService.createPending', () => {
  let service: DeviceApprovalService;
  let prisma: any;
  let redis: any;
  let fcm: any;

  beforeEach(() => {
    redis = makeRedis();
    prisma = {
      session: {
        findMany: jest.fn().mockResolvedValue([
          { id: 's-old', fcmToken: 'tok-old', deviceId: 'dev-old' },
        ]),
      },
      trustedDevice: { upsert: jest.fn().mockResolvedValue({}) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };
    fcm = { sendDeviceApprovalRequest: jest.fn().mockResolvedValue(undefined) };
    service = new DeviceApprovalService(
      prisma as any,
      redis as any,
      fcm as any,
      { sendOtp: jest.fn() } as any,
    );
  });

  it('returns a token, and pushes to every other live session', async () => {
    const result = await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });

    expect(result.approvalToken).toEqual(expect.any(String));
    expect(result.approverCount).toBe(1);
    expect(fcm.sendDeviceApprovalRequest).toHaveBeenCalledWith(
      'tok-old',
      expect.objectContaining({ approvalId: expect.any(String), deviceInfo: 'Pixel' }),
    );
  });

  it('never pushes the secret token — only the public approval id', async () => {
    await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });

    const pushed = JSON.stringify(fcm.sendDeviceApprovalRequest.mock.calls[0][1]);
    const stored = [...redis.store.keys()].find((k) =>
      k.startsWith('device_approval:'),
    )!;
    const secret = stored.replace('device_approval:', '');
    expect(pushed).not.toContain(secret);
  });

  it('refuses once the hourly ceiling is reached', async () => {
    redis.counters.set('device_approval_rate:u1', 10);
    await expect(
      service.createPending({
        userId: 'u1',
        deviceId: 'dev-new',
        deviceInfo: 'Pixel',
        ip: '1.2.3.4',
        email: 'a@b.c',
      }),
    ).rejects.toThrow(/too many/i);
  });
});
```

- [ ] **Шаг 2: убедиться, что тест падает**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts
```

Ожидается: FAIL — `Cannot find module './device-approval.service'`.

- [ ] **Шаг 3: написать сервис (только `createPending`)**

Создать `src/auth/device-approval.service.ts`:

```ts
import {
  Injectable,
  Logger,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { FcmService } from '../common/fcm.service';
import { EmailService } from '../email/email.service';
import {
  APPROVAL_TTL_SECONDS,
  MAX_PENDING_PER_HOUR,
  ApprovalRecord,
  approvalKey,
  approvalIdKey,
  rateKey,
} from './device-approval.constants';

export interface CreatePendingInput {
  userId: string;
  deviceId: string;
  deviceInfo: string;
  ip: string;
  location?: string | null;
  email?: string | null;
}

@Injectable()
export class DeviceApprovalService {
  private readonly logger = new Logger(DeviceApprovalService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly fcm: FcmService,
    private readonly email: EmailService,
  ) {}

  /**
   * Заводит ожидание и будит доверенные устройства.
   *
   * Возвращает `approvalToken` — секрет, который уходит ТОЛЬКО в тело ответа
   * новому устройству. В пуш едет `approvalId`: превью уведомления на
   * заблокированном экране не должно давать никакого доступа к аккаунту.
   */
  async createPending(input: CreatePendingInput): Promise<{
    approvalToken: string;
    approverCount: number;
    emailAvailable: boolean;
    expiresIn: number;
  }> {
    const attempts = await this.redis.incr(rateKey(input.userId));
    await this.redis.expire(rateKey(input.userId), 3600);
    if (attempts > MAX_PENDING_PER_HOUR) {
      throw new HttpException(
        'Too many sign-in attempts from new devices. Try again later.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const approvalToken = uuidv4();
    const approvalId = uuidv4();

    const record: ApprovalRecord = {
      approvalId,
      userId: input.userId,
      deviceId: input.deviceId,
      deviceInfo: input.deviceInfo?.substring(0, 200) ?? '',
      ip: input.ip,
      location: input.location ?? null,
      status: 'pending',
      createdAt: new Date().toISOString(),
    };

    await this.redis.setEx(
      approvalKey(approvalToken),
      APPROVAL_TTL_SECONDS,
      JSON.stringify(record),
    );
    await this.redis.setEx(
      approvalIdKey(approvalId),
      APPROVAL_TTL_SECONDS,
      approvalToken,
    );

    const approvers = await this.prisma.session.findMany({
      where: {
        userId: input.userId,
        isRevoked: false,
        expiresAt: { gt: new Date() },
        fcmToken: { not: null },
        NOT: { deviceId: input.deviceId },
      },
      select: { id: true, fcmToken: true, deviceId: true },
    });

    for (const session of approvers) {
      if (!session.fcmToken) continue;
      try {
        await this.fcm.sendDeviceApprovalRequest(session.fcmToken, {
          approvalId,
          deviceInfo: record.deviceInfo,
          ip: record.ip,
          location: record.location,
        });
      } catch (e) {
        this.logger.warn(
          `approval push failed for session ${session.id}: ${(e as Error).message}`,
        );
      }
    }

    await this.prisma.auditLog.create({
      data: {
        userId: input.userId,
        action: 'DEVICE_APPROVAL_REQUESTED',
        ipAddress: input.ip,
        userAgent: record.deviceInfo,
        meta: { approvalId, approvers: approvers.length },
      },
    });

    return {
      approvalToken,
      approverCount: approvers.length,
      emailAvailable: Boolean(input.email),
      expiresIn: APPROVAL_TTL_SECONDS,
    };
  }
}
```

- [ ] **Шаг 4: убедиться, что тесты проходят**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts
```

Ожидается: 3 PASS.

- [ ] **Шаг 5: коммит**

```bash
git add src/auth/device-approval.service.ts src/auth/device-approval.service.spec.ts
git commit -m "feat(auth): create pending approvals and wake trusted devices"
```

---

### Task 5: Пуш на доверенное устройство

**Files:**
- Modify: `src/common/fcm.service.ts` (добавить метод после `sendContactRequest`, ~строка 379)

- [ ] **Шаг 1: написать метод**

```ts
  /**
   * Кто-то вводит верный пароль от аккаунта на устройстве, которого мы не
   * знаем. В payload едет только `approvalId` — по нему нельзя войти, можно
   * лишь одобрить, будучи уже аутентифицированным тем же пользователем.
   */
  async sendDeviceApprovalRequest(
    fcmToken: string,
    data: {
      approvalId: string;
      deviceInfo: string;
      ip: string;
      location?: string | null;
    },
  ): Promise<void> {
    if (!this.initialized || !fcmToken) return;
    const where = data.location ? `${data.location}, ` : '';
    const title = 'Вход в аккаунт';
    const body = `Попытка входа: ${data.deviceInfo || 'неизвестное устройство'} — ${where}${data.ip}`;
    try {
      await admin.messaging().send({
        token: fcmToken,
        data: {
          type: 'device_approval',
          approvalId: data.approvalId,
          deviceInfo: data.deviceInfo ?? '',
          ip: data.ip ?? '',
          location: data.location ?? '',
        },
        notification: { title, body },
        android: {
          priority: 'high',
          notification: {
            channelId: 'messages',
            defaultSound: true,
          },
        },
        apns: {
          payload: {
            aps: {
              sound: 'default',
              alert: { title, body },
            },
          },
          headers: {
            'apns-priority': '10',
            'apns-push-type': 'alert',
          },
        },
      });
    } catch (e) {
      this.logger.error('FCM sendDeviceApprovalRequest error:', e);
      this.handleSendError(fcmToken, e).catch(() => {});
    }
  }
```

- [ ] **Шаг 2: собрать проект**

```bash
cd ~/Downloads/taler_id && npx tsc --noEmit -p tsconfig.json
```

Ожидается: без ошибок.

- [ ] **Шаг 3: коммит**

```bash
git add src/common/fcm.service.ts
git commit -m "feat(push): device approval request notification"
```

---

### Task 6: Одобрение и отклонение

**Files:**
- Modify: `src/auth/device-approval.service.ts`
- Modify: `src/auth/device-approval.service.spec.ts`

- [ ] **Шаг 1: написать падающие тесты**

Добавить в `src/auth/device-approval.service.spec.ts` новый `describe` (фабрики `makeRedis`, `prisma`, `fcm` переиспользовать — вынести `beforeEach` в общий скоуп файла, если ещё не вынесен):

```ts
describe('DeviceApprovalService approve/reject', () => {
  let service: DeviceApprovalService;
  let prisma: any;
  let redis: any;

  const seed = async () => {
    const r = await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });
    const record = JSON.parse(redis.store.get(`device_approval:${r.approvalToken}`)!);
    return { token: r.approvalToken, approvalId: record.approvalId };
  };

  beforeEach(() => {
    redis = makeRedis();
    prisma = {
      session: { findMany: jest.fn().mockResolvedValue([]) },
      trustedDevice: { upsert: jest.fn().mockResolvedValue({}) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };
    service = new DeviceApprovalService(
      prisma as any,
      redis as any,
      { sendDeviceApprovalRequest: jest.fn() } as any,
      { sendOtp: jest.fn() } as any,
    );
  });

  it('marks the record approved and trusts the device right away', async () => {
    const { token, approvalId } = await seed();
    await service.approve('u1', approvalId);

    expect(JSON.parse(redis.store.get(`device_approval:${token}`)!).status).toBe(
      'approved',
    );
    expect(prisma.trustedDevice.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { userId_deviceId: { userId: 'u1', deviceId: 'dev-new' } },
      }),
    );
  });

  it('refuses to approve another user\'s pending login', async () => {
    const { approvalId } = await seed();
    await expect(service.approve('someone-else', approvalId)).rejects.toThrow(
      /not found/i,
    );
    expect(prisma.trustedDevice.upsert).not.toHaveBeenCalled();
  });

  it('rejection is terminal — the record cannot then be approved', async () => {
    const { token, approvalId } = await seed();
    await service.reject('u1', approvalId);

    expect(JSON.parse(redis.store.get(`device_approval:${token}`)!).status).toBe(
      'rejected',
    );
    await expect(service.approve('u1', approvalId)).rejects.toThrow(/rejected/i);
  });
});
```

- [ ] **Шаг 2: убедиться, что тесты падают**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts -t approve
```

Ожидается: FAIL — `service.approve is not a function`.

- [ ] **Шаг 3: реализовать**

Добавить в `DeviceApprovalService` (импортировать `NotFoundException`, `BadRequestException` из `@nestjs/common`):

```ts
  private async load(approvalId: string): Promise<{
    token: string;
    record: ApprovalRecord;
  }> {
    const token = await this.redis.get(approvalIdKey(approvalId));
    if (!token) throw new NotFoundException('Approval request not found');
    const raw = await this.redis.get(approvalKey(token));
    if (!raw) throw new NotFoundException('Approval request not found');
    return { token, record: JSON.parse(raw) as ApprovalRecord };
  }

  private async save(token: string, record: ApprovalRecord) {
    // TTL держим исходный: одобрение не должно продлевать окно.
    await this.redis.setEx(
      approvalKey(token),
      APPROVAL_TTL_SECONDS,
      JSON.stringify(record),
    );
  }

  /** Вызывается с уже доверенного устройства пользователя. */
  async approve(userId: string, approvalId: string) {
    const { token, record } = await this.load(approvalId);
    if (record.userId !== userId)
      throw new NotFoundException('Approval request not found');
    if (record.status === 'rejected')
      throw new BadRequestException('This request was already rejected');

    record.status = 'approved';
    await this.save(token, record);

    // Доверие выдаём здесь, а не при заборе токенов: если ответ на заборе
    // потеряется, повторный вход пройдёт уже как со знакомого устройства.
    await this.prisma.trustedDevice.upsert({
      where: {
        userId_deviceId: { userId, deviceId: record.deviceId },
      },
      create: {
        userId,
        deviceId: record.deviceId,
        deviceInfo: record.deviceInfo,
        lastIp: record.ip,
        lastLocation: record.location,
      },
      update: {
        revokedAt: null,
        lastSeenAt: new Date(),
        lastIp: record.ip,
        lastLocation: record.location,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        userId,
        action: 'DEVICE_APPROVED',
        ipAddress: record.ip,
        userAgent: record.deviceInfo,
        meta: { approvalId, deviceId: record.deviceId },
      },
    });

    return { success: true };
  }

  async reject(userId: string, approvalId: string) {
    const { token, record } = await this.load(approvalId);
    if (record.userId !== userId)
      throw new NotFoundException('Approval request not found');

    record.status = 'rejected';
    await this.save(token, record);

    await this.prisma.auditLog.create({
      data: {
        userId,
        action: 'DEVICE_REJECTED',
        ipAddress: record.ip,
        userAgent: record.deviceInfo,
        meta: { approvalId, deviceId: record.deviceId },
      },
    });

    return { success: true };
  }
```

- [ ] **Шаг 4: убедиться, что тесты проходят**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts
```

Ожидается: 6 PASS.

- [ ] **Шаг 5: коммит**

```bash
git add src/auth/device-approval.service.ts src/auth/device-approval.service.spec.ts
git commit -m "feat(auth): approve and reject a pending device login"
```

---

### Task 7: Забор токенов новым устройством

**Files:**
- Modify: `src/auth/device-approval.service.ts`
- Modify: `src/auth/device-approval.service.spec.ts`

- [ ] **Шаг 1: написать падающие тесты**

```ts
describe('DeviceApprovalService.claim', () => {
  // те же redis/prisma/service, что в предыдущем describe

  it('hands the pending record over exactly once', async () => {
    const { token, approvalId } = await seed();
    await service.approve('u1', approvalId);

    const first = await service.claim(token);
    expect(first.status).toBe('approved');
    expect(first.record?.deviceId).toBe('dev-new');

    const second = await service.claim(token);
    expect(second.status).toBe('claimed');
    expect(second.record).toBeUndefined();
  });

  it('reports pending while nobody has answered', async () => {
    const { token } = await seed();
    expect((await service.claim(token)).status).toBe('pending');
  });

  it('reports expired for an unknown token', async () => {
    expect((await service.claim('nope')).status).toBe('expired');
  });

  it('reports rejected and clears the record', async () => {
    const { token, approvalId } = await seed();
    await service.reject('u1', approvalId);
    expect((await service.claim(token)).status).toBe('rejected');
    expect(redis.store.has(`device_approval:${token}`)).toBe(false);
  });
});
```

- [ ] **Шаг 2: убедиться, что тесты падают**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts -t claim
```

Ожидается: FAIL — `service.claim is not a function`.

- [ ] **Шаг 3: реализовать**

```ts
  /**
   * Опрашивается новым устройством. Забор одобренной записи атомарный
   * (`GETDEL`): два параллельных опроса не должны дать две сессии.
   */
  async claim(approvalToken: string): Promise<{
    status: 'pending' | 'approved' | 'rejected' | 'expired' | 'claimed';
    record?: ApprovalRecord;
  }> {
    const raw = await this.redis.get(approvalKey(approvalToken));

    if (!raw) {
      const claimed = await this.redis.get(claimedKey(approvalToken));
      return { status: claimed ? 'claimed' : 'expired' };
    }

    const record = JSON.parse(raw) as ApprovalRecord;

    if (record.status === 'pending') return { status: 'pending' };

    if (record.status === 'rejected') {
      await this.redis.del(approvalKey(approvalToken));
      await this.redis.del(approvalIdKey(record.approvalId));
      return { status: 'rejected' };
    }

    const taken = await this.redis.getClient().getdel(approvalKey(approvalToken));
    if (!taken) return { status: 'claimed' };

    await this.redis.del(approvalIdKey(record.approvalId));
    await this.redis.setEx(
      claimedKey(approvalToken),
      APPROVAL_CLAIMED_TTL_SECONDS,
      '1',
    );

    return { status: 'approved', record };
  }
```

Дописать в импорт констант `claimedKey`, `APPROVAL_CLAIMED_TTL_SECONDS`.

- [ ] **Шаг 4: убедиться, что тесты проходят**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts
```

Ожидается: 10 PASS.

- [ ] **Шаг 5: коммит**

```bash
git add src/auth/device-approval.service.ts src/auth/device-approval.service.spec.ts
git commit -m "feat(auth): claim an approved device login exactly once"
```

---

### Task 8: Запасной канал — код на почту

**Files:**
- Modify: `src/auth/device-approval.service.ts`
- Modify: `src/auth/device-approval.service.spec.ts`

- [ ] **Шаг 1: написать падающие тесты**

```ts
describe('DeviceApprovalService email fallback', () => {
  // redis/prisma/service как выше, но email — отдельный мок:
  //   email = { sendOtp: jest.fn() }

  it('sends a six-digit code to the account address', async () => {
    const { token } = await seed();
    await service.sendEmailCode(token, 'a@b.c');

    expect(email.sendOtp).toHaveBeenCalledWith(
      'a@b.c',
      expect.stringMatching(/^\d{6}$/),
      expect.any(String),
    );
  });

  it('refuses a second send inside the cooldown', async () => {
    const { token } = await seed();
    await service.sendEmailCode(token, 'a@b.c');
    await expect(service.sendEmailCode(token, 'a@b.c')).rejects.toThrow(
      /wait/i,
    );
  });

  it('a correct code approves the login', async () => {
    const { token } = await seed();
    await service.sendEmailCode(token, 'a@b.c');
    const code = redis.store.get(`device_approval_code:${token}`)!;

    await service.verifyEmailCode(token, code);
    expect(JSON.parse(redis.store.get(`device_approval:${token}`)!).status).toBe(
      'approved',
    );
  });

  it('burns the request after five wrong codes', async () => {
    const { token } = await seed();
    await service.sendEmailCode(token, 'a@b.c');

    for (let i = 0; i < 4; i++) {
      await expect(service.verifyEmailCode(token, '000000')).rejects.toThrow(
        /invalid/i,
      );
    }
    await expect(service.verifyEmailCode(token, '000000')).rejects.toThrow(
      /again/i,
    );
    expect(redis.store.has(`device_approval:${token}`)).toBe(false);
  });
});
```

- [ ] **Шаг 2: убедиться, что тесты падают**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts -t email
```

Ожидается: FAIL — `service.sendEmailCode is not a function`.

- [ ] **Шаг 3: реализовать**

```ts
  /**
   * Единственный путь для человека, у которого одно устройство или до
   * остальных не доходят пуши. Без него фича превращается в способ потерять
   * доступ к собственному аккаунту.
   */
  async sendEmailCode(approvalToken: string, email: string) {
    const raw = await this.redis.get(approvalKey(approvalToken));
    if (!raw) throw new NotFoundException('Approval request not found');
    const record = JSON.parse(raw) as ApprovalRecord;
    if (record.status !== 'pending')
      throw new BadRequestException('This request is already resolved');

    if (await this.redis.get(emailCooldownKey(approvalToken))) {
      throw new BadRequestException(
        `Please wait ${EMAIL_RESEND_COOLDOWN_SECONDS} seconds before requesting another code`,
      );
    }

    const sends = await this.redis.incr(emailSendsKey(approvalToken));
    await this.redis.expire(emailSendsKey(approvalToken), APPROVAL_TTL_SECONDS);
    if (sends > MAX_EMAIL_SENDS)
      throw new BadRequestException('Too many codes requested — sign in again');

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await this.redis.setEx(
      codeKey(approvalToken),
      APPROVAL_TTL_SECONDS,
      code,
    );
    await this.redis.setEx(
      emailCooldownKey(approvalToken),
      EMAIL_RESEND_COOLDOWN_SECONDS,
      '1',
    );
    await this.email.sendOtp(email, code, 'New device sign-in');

    return { sent: true };
  }

  async verifyEmailCode(approvalToken: string, code: string) {
    const raw = await this.redis.get(approvalKey(approvalToken));
    if (!raw) throw new NotFoundException('Approval request not found');
    const record = JSON.parse(raw) as ApprovalRecord;

    const stored = await this.redis.get(codeKey(approvalToken));
    if (!stored || stored !== code) {
      const attempts = await this.redis.incr(codeAttemptsKey(approvalToken));
      await this.redis.expire(
        codeAttemptsKey(approvalToken),
        APPROVAL_TTL_SECONDS,
      );
      if (attempts >= MAX_CODE_ATTEMPTS) {
        await this.redis.del(approvalKey(approvalToken));
        await this.redis.del(approvalIdKey(record.approvalId));
        await this.redis.del(codeKey(approvalToken));
        throw new BadRequestException('Too many invalid codes — sign in again');
      }
      throw new BadRequestException('Invalid or expired code');
    }

    await this.redis.del(codeKey(approvalToken));
    await this.redis.del(codeAttemptsKey(approvalToken));

    record.status = 'approved';
    await this.save(approvalToken, record);
    await this.prisma.trustedDevice.upsert({
      where: {
        userId_deviceId: {
          userId: record.userId,
          deviceId: record.deviceId,
        },
      },
      create: {
        userId: record.userId,
        deviceId: record.deviceId,
        deviceInfo: record.deviceInfo,
        lastIp: record.ip,
        lastLocation: record.location,
      },
      update: { revokedAt: null, lastSeenAt: new Date() },
    });
    await this.prisma.auditLog.create({
      data: {
        userId: record.userId,
        action: 'DEVICE_APPROVED',
        ipAddress: record.ip,
        userAgent: record.deviceInfo,
        meta: { via: 'email', deviceId: record.deviceId },
      },
    });

    return { success: true };
  }
```

Дописать в импорт констант: `codeKey`, `codeAttemptsKey`, `emailSendsKey`, `emailCooldownKey`, `MAX_EMAIL_SENDS`, `MAX_CODE_ATTEMPTS`, `EMAIL_RESEND_COOLDOWN_SECONDS`.

- [ ] **Шаг 4: убедиться, что тесты проходят**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts
```

Ожидается: 14 PASS.

- [ ] **Шаг 5: коммит**

```bash
git add src/auth/device-approval.service.ts src/auth/device-approval.service.spec.ts
git commit -m "feat(auth): email code as the fallback approval channel"
```

---

### Task 9: Проверка «знакомое ли устройство»

**Files:**
- Modify: `src/auth/device-approval.service.ts`
- Modify: `src/auth/device-approval.service.spec.ts`

- [ ] **Шаг 1: написать падающие тесты**

```ts
describe('DeviceApprovalService.gateDecision', () => {
  it('lets a legacy client through — no device id, no gate', async () => {
    prisma.trustedDevice.count = jest.fn().mockResolvedValue(3);
    const d = await service.gateDecision('u1', undefined, true);
    expect(d).toBe('allow');
  });

  it('lets the very first device through and trusts it', async () => {
    prisma.trustedDevice.count = jest.fn().mockResolvedValue(0);
    prisma.trustedDevice.findFirst = jest.fn().mockResolvedValue(null);
    expect(await service.gateDecision('u1', 'dev-1', true)).toBe('allow');
  });

  it('lets a known device through', async () => {
    prisma.trustedDevice.count = jest.fn().mockResolvedValue(2);
    prisma.trustedDevice.findFirst = jest
      .fn()
      .mockResolvedValue({ id: 't1', revokedAt: null });
    expect(await service.gateDecision('u1', 'dev-1', true)).toBe('allow');
  });

  it('gates an unknown device when the toggle is on', async () => {
    prisma.trustedDevice.count = jest.fn().mockResolvedValue(2);
    prisma.trustedDevice.findFirst = jest.fn().mockResolvedValue(null);
    expect(await service.gateDecision('u1', 'dev-new', true)).toBe('approve');
  });

  it('does not gate when the user has the toggle off', async () => {
    prisma.trustedDevice.count = jest.fn().mockResolvedValue(2);
    prisma.trustedDevice.findFirst = jest.fn().mockResolvedValue(null);
    expect(await service.gateDecision('u1', 'dev-new', false)).toBe('allow');
  });

  it('gates a revoked device — revoking must actually mean something', async () => {
    prisma.trustedDevice.count = jest.fn().mockResolvedValue(2);
    prisma.trustedDevice.findFirst = jest.fn().mockResolvedValue(null); // запрос фильтрует revokedAt
    expect(await service.gateDecision('u1', 'dev-old', true)).toBe('approve');
  });
});
```

- [ ] **Шаг 2: убедиться, что тесты падают**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts -t gateDecision
```

Ожидается: FAIL — `service.gateDecision is not a function`.

- [ ] **Шаг 3: реализовать**

```ts
  /**
   * Единственное место, где решается, нужен ли шлюз. Три случая пропускают
   * вход без вопросов, и каждый — сознательный:
   *   - клиент не прислал deviceId (десктоп, веб, мобилки до 1.1.24);
   *   - тумблер у пользователя выключен;
   *   - у аккаунта ещё нет ни одного доверенного устройства — подтверждать
   *     было бы нечем, и это заперло бы человека снаружи.
   */
  async gateDecision(
    userId: string,
    deviceId: string | undefined,
    approvalEnabled: boolean,
  ): Promise<'allow' | 'approve'> {
    if (!deviceId) return 'allow';
    if (!approvalEnabled) return 'allow';

    const known = await this.prisma.trustedDevice.findFirst({
      where: { userId, deviceId, revokedAt: null },
    });
    if (known) return 'allow';

    const trustedCount = await this.prisma.trustedDevice.count({
      where: { userId, revokedAt: null },
    });
    if (trustedCount === 0) return 'allow';

    return 'approve';
  }

  /** Отмечает устройство как виденное; создаёт запись, если её ещё нет. */
  async touch(
    userId: string,
    deviceId: string | undefined,
    deviceInfo: string,
    ip: string,
  ) {
    if (!deviceId) return;
    await this.prisma.trustedDevice.upsert({
      where: { userId_deviceId: { userId, deviceId } },
      create: {
        userId,
        deviceId,
        deviceInfo: deviceInfo?.substring(0, 200) ?? '',
        lastIp: ip,
      },
      update: { lastSeenAt: new Date(), lastIp: ip },
    });
  }
```

- [ ] **Шаг 4: убедиться, что тесты проходят**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/device-approval.service.spec.ts
```

Ожидается: 20 PASS.

- [ ] **Шаг 5: коммит**

```bash
git add src/auth/device-approval.service.ts src/auth/device-approval.service.spec.ts
git commit -m "feat(auth): decide when a login needs approval"
```

---

# ФАЗА C — включение шлюза во вход

### Task 10: Шлюз в `login()` и `verify2fa()`

**Files:**
- Modify: `src/auth/auth.service.ts`
- Modify: `src/auth/auth.service.new-device.spec.ts`

- [ ] **Шаг 1: написать падающие тесты**

Добавить в `src/auth/auth.service.new-device.spec.ts`:

```ts
  it('withholds tokens and returns an approval token for an unknown device', async () => {
    prisma.profile.findUnique.mockResolvedValue({ newDeviceApproval: true });
    service.deviceApproval.gateDecision = jest.fn().mockResolvedValue('approve');
    service.deviceApproval.createPending = jest.fn().mockResolvedValue({
      approvalToken: 'tok',
      approverCount: 2,
      emailAvailable: true,
      expiresIn: 600,
    });

    const result = await service.login(
      { email: 'a@b.c', password: 'pw' },
      '1.2.3.4',
      'UA',
      'dev-new',
    );

    expect(result).toEqual(
      expect.objectContaining({ next: 'device_approval', approvalToken: 'tok' }),
    );
    expect(result.accessToken).toBeUndefined();
    expect(prisma.session.create).not.toHaveBeenCalled();
  });

  it('2FA does not bypass the device gate', async () => {
    prisma.profile.findUnique.mockResolvedValue({ newDeviceApproval: true });
    prisma.user.findUnique.mockResolvedValue({
      id: 'u1',
      email: 'a@b.c',
      totpSecret: { secret: 'SECRET', verified: true },
    });
    service.deviceApproval.gateDecision = jest.fn().mockResolvedValue('approve');
    service.deviceApproval.createPending = jest.fn().mockResolvedValue({
      approvalToken: 'tok2',
      approverCount: 1,
      emailAvailable: true,
      expiresIn: 600,
    });
    (service as any).redis.get = jest.fn().mockResolvedValue('u1');

    const result = await service.verify2fa('chal', '123456', '1.2.3.4', 'UA', 'dev-new');

    expect(result.next).toBe('device_approval');
    expect(prisma.session.create).not.toHaveBeenCalled();
  });
```

- [ ] **Шаг 2: убедиться, что тесты падают**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/auth.service.new-device.spec.ts
```

Ожидается: FAIL — `service.deviceApproval` не определён.

- [ ] **Шаг 3: внедрить сервис и добавить шлюз**

В конструктор `AuthService` добавить седьмым параметром:

```ts
    private readonly deviceApproval: DeviceApprovalService,
```

с импортом `import { DeviceApprovalService } from './device-approval.service';` и `import { NEW_DEVICE_APPROVAL_DEFAULT } from './device-approval.constants';`.

Добавить приватный метод:

```ts
  /**
   * Общий хвост успешной аутентификации. Либо сессия и токены, либо ожидание
   * подтверждения — решает DeviceApprovalService.gateDecision.
   */
  private async completeLogin(
    user: any,
    ip: string,
    userAgent: string,
    deviceId: string | undefined,
  ) {
    const profile = await this.prisma.profile.findUnique({
      where: { userId: user.id },
      select: { newDeviceApproval: true },
    });
    const enabled = profile?.newDeviceApproval ?? NEW_DEVICE_APPROVAL_DEFAULT;

    const decision = await this.deviceApproval.gateDecision(
      user.id,
      deviceId,
      enabled,
    );

    if (decision === 'approve') {
      const pending = await this.deviceApproval.createPending({
        userId: user.id,
        deviceId: deviceId!,
        deviceInfo: userAgent,
        ip,
        email: user.email,
      });
      return { next: 'device_approval', ...pending };
    }

    await this.deviceApproval.touch(user.id, deviceId, userAgent, ip);
    await this.auditLog(user.id, 'LOGIN_SUCCESS', ip, userAgent);
    const session = await this.createSession(user.id, ip, userAgent, deviceId);
    return this.generateTokens(user, session.id);
  }
```

Заменить хвост `login()` (строки 173-175) на:

```ts
    return this.completeLogin(user, ip, userAgent, deviceId);
```

Заменить хвост `verify2fa()` (строки 226-228) на:

```ts
    return this.completeLogin(user, ip, userAgent, deviceId);
```

`register()` не трогаем: у нового аккаунта доверенных устройств нет, `gateDecision` всё равно вернёт `allow`, но лишний запрос ни к чему — вместо этого после `createSession` добавить `await this.deviceApproval.touch(user.id, deviceId, userAgent, ip);`.

- [ ] **Шаг 4: убедиться, что тесты проходят**

```bash
cd ~/Downloads/taler_id && npx jest src/auth
```

Ожидается: все PASS. Если существующие спеки падают на числе аргументов конструктора — дописать седьмым моком `{ gateDecision: jest.fn(async () => 'allow'), touch: jest.fn(), createPending: jest.fn() }`.

- [ ] **Шаг 5: коммит**

```bash
git add src/auth/auth.service.ts src/auth/auth.service.new-device.spec.ts
git commit -m "feat(auth): gate logins from unknown devices behind approval"
```

---

### Task 11: DTO и эндпоинты

**Files:**
- Create: `src/auth/dto/device-approval.dto.ts`
- Modify: `src/auth/auth.controller.ts`
- Modify: `src/auth/auth.module.ts`

- [ ] **Шаг 1: DTO**

Создать `src/auth/dto/device-approval.dto.ts`:

```ts
import { IsString, Length } from 'class-validator';

export class ApprovalTokenDto {
  @IsString()
  approvalToken: string;
}

export class ApprovalCodeDto {
  @IsString()
  approvalToken: string;

  @IsString()
  @Length(6, 6)
  code: string;
}
```

- [ ] **Шаг 2: эндпоинты в контроллере**

Добавить в `src/auth/auth.controller.ts` (импортировать `DeviceApprovalService`, DTO, `UnauthorizedException`):

```ts
  // ── Подтверждение входа с нового устройства ──

  /** Опрос новым устройством, пока оно ждёт ответа. */
  @Post('login/device-approval/status')
  @HttpCode(HttpStatus.OK)
  async approvalStatus(@Body() dto: ApprovalTokenDto, @Req() req: Request) {
    return this.authService.claimDeviceApproval(
      dto.approvalToken,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  /** Запасной канал: прислать код на почту аккаунта. */
  @Post('login/device-approval/email')
  @HttpCode(HttpStatus.OK)
  async approvalEmail(@Body() dto: ApprovalTokenDto) {
    return this.authService.sendDeviceApprovalEmail(dto.approvalToken);
  }

  @Post('login/device-approval/verify')
  @HttpCode(HttpStatus.OK)
  async approvalVerify(@Body() dto: ApprovalCodeDto, @Req() req: Request) {
    await this.deviceApproval.verifyEmailCode(dto.approvalToken, dto.code);
    return this.authService.claimDeviceApproval(
      dto.approvalToken,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }

  /** Вызывается с уже доверенного устройства. */
  @Post('devices/approvals/:approvalId/approve')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async approveDevice(
    @CurrentUser() user: any,
    @Param('approvalId') approvalId: string,
  ) {
    return this.deviceApproval.approve(user.sub, approvalId);
  }

  @Post('devices/approvals/:approvalId/reject')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async rejectDevice(
    @CurrentUser() user: any,
    @Param('approvalId') approvalId: string,
  ) {
    return this.deviceApproval.reject(user.sub, approvalId);
  }
```

и в конструктор:

```ts
  constructor(
    private readonly authService: AuthService,
    private readonly deviceApproval: DeviceApprovalService,
  ) {}
```

- [ ] **Шаг 3: `claimDeviceApproval` в сервисе**

Добавить в `AuthService`:

```ts
  /** Забор токенов новым устройством после одобрения. */
  async claimDeviceApproval(
    approvalToken: string,
    ip: string,
    userAgent: string,
  ) {
    const outcome = await this.deviceApproval.claim(approvalToken);

    if (outcome.status !== 'approved') return { status: outcome.status };

    const record = outcome.record!;
    const user = await this.prisma.user.findUnique({
      where: { id: record.userId },
    });
    if (!user) throw new UnauthorizedException('User not found');

    await this.auditLog(user.id, 'LOGIN_SUCCESS', ip, userAgent, {
      via: 'device_approval',
    });
    const session = await this.createSession(
      user.id,
      record.ip,
      record.deviceInfo,
      record.deviceId,
    );
    const tokens = await this.generateTokens(user, session.id);
    return { status: 'approved', ...tokens };
  }

  async sendDeviceApprovalEmail(approvalToken: string) {
    const outcome = await this.deviceApproval.peek(approvalToken);
    const user = await this.prisma.user.findUnique({
      where: { id: outcome.userId },
      select: { email: true },
    });
    if (!user?.email)
      throw new BadRequestException('No email address on this account');
    return this.deviceApproval.sendEmailCode(approvalToken, user.email);
  }
```

Добавить в `DeviceApprovalService`:

```ts
  /** Чтение записи без изменения статуса. */
  async peek(approvalToken: string): Promise<ApprovalRecord> {
    const raw = await this.redis.get(approvalKey(approvalToken));
    if (!raw) throw new NotFoundException('Approval request not found');
    return JSON.parse(raw) as ApprovalRecord;
  }
```

- [ ] **Шаг 4: модуль**

`src/auth/auth.module.ts` — заменить блок providers:

```ts
  providers: [AuthService, JwtStrategy, DeviceApprovalService, FcmService],
  exports: [AuthService, JwtStrategy, DeviceApprovalService],
```

с импортами `DeviceApprovalService` и `FcmService` (`../common/fcm.service`).

- [ ] **Шаг 5: собрать**

```bash
cd ~/Downloads/taler_id && npm run build
```

Ожидается: сборка без ошибок.

- [ ] **Шаг 6: коммит**

```bash
git add src/auth/
git commit -m "feat(auth): device approval endpoints"
```

---

### Task 12: Управление доверенными устройствами

**Files:**
- Create: `src/auth/trusted-device.service.ts`
- Create: `src/auth/trusted-device.service.spec.ts`
- Modify: `src/auth/auth.controller.ts`, `src/auth/auth.module.ts`

- [ ] **Шаг 1: написать падающий тест**

Создать `src/auth/trusted-device.service.spec.ts`:

```ts
import { TrustedDeviceService } from './trusted-device.service';

describe('TrustedDeviceService', () => {
  let service: TrustedDeviceService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      trustedDevice: {
        findMany: jest.fn().mockResolvedValue([
          { id: 't1', deviceId: 'dev-1', deviceInfo: 'Pixel', label: null },
        ]),
        findFirst: jest.fn().mockResolvedValue({ id: 't1', deviceId: 'dev-1' }),
        update: jest.fn().mockResolvedValue({}),
      },
      session: { updateMany: jest.fn().mockResolvedValue({ count: 2 }) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };
    service = new TrustedDeviceService(prisma as any);
  });

  it('marks the current device in the list', async () => {
    const list = await service.list('u1', 'dev-1');
    expect(list[0].isCurrent).toBe(true);
  });

  it('revoking a device also kills its live sessions', async () => {
    await service.revoke('u1', 't1', '1.2.3.4', 'UA');

    expect(prisma.trustedDevice.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: { revokedAt: expect.any(Date) } }),
    );
    expect(prisma.session.updateMany).toHaveBeenCalledWith({
      where: { userId: 'u1', deviceId: 'dev-1', isRevoked: false },
      data: { isRevoked: true },
    });
  });

  it('refuses to revoke a device belonging to somebody else', async () => {
    prisma.trustedDevice.findFirst.mockResolvedValue(null);
    await expect(service.revoke('u2', 't1', '', '')).rejects.toThrow(/not found/i);
  });
});
```

- [ ] **Шаг 2: убедиться, что тест падает**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/trusted-device.service.spec.ts
```

Ожидается: FAIL — модуль не найден.

- [ ] **Шаг 3: реализовать**

Создать `src/auth/trusted-device.service.ts`:

```ts
import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class TrustedDeviceService {
  constructor(private readonly prisma: PrismaService) {}

  async list(userId: string, currentDeviceId?: string) {
    const devices = await this.prisma.trustedDevice.findMany({
      where: { userId, revokedAt: null },
      orderBy: { lastSeenAt: 'desc' },
      select: {
        id: true,
        deviceId: true,
        deviceInfo: true,
        label: true,
        lastIp: true,
        lastLocation: true,
        firstSeenAt: true,
        lastSeenAt: true,
      },
    });
    return devices.map((d) => ({
      ...d,
      isCurrent: Boolean(currentDeviceId) && d.deviceId === currentDeviceId,
    }));
  }

  /**
   * Отзыв должен что-то значить: помимо снятия доверия гасим живые сессии
   * этого устройства, иначе выданный ему 30-дневный refresh продолжит работать.
   */
  async revoke(userId: string, id: string, ip: string, userAgent: string) {
    const device = await this.prisma.trustedDevice.findFirst({
      where: { id, userId },
    });
    if (!device) throw new NotFoundException('Device not found');

    await this.prisma.trustedDevice.update({
      where: { id },
      data: { revokedAt: new Date() },
    });
    await this.prisma.session.updateMany({
      where: { userId, deviceId: device.deviceId, isRevoked: false },
      data: { isRevoked: true },
    });
    await this.prisma.auditLog.create({
      data: {
        userId,
        action: 'TRUSTED_DEVICE_REVOKED',
        ipAddress: ip,
        userAgent: userAgent?.substring(0, 200),
        meta: { deviceId: device.deviceId },
      },
    });

    return { success: true };
  }
}
```

- [ ] **Шаг 4: убедиться, что тесты проходят**

```bash
cd ~/Downloads/taler_id && npx jest src/auth/trusted-device.service.spec.ts
```

Ожидается: 3 PASS.

- [ ] **Шаг 5: эндпоинты**

В `src/auth/auth.controller.ts`:

```ts
  @Get('devices')
  @UseGuards(JwtAuthGuard)
  async listDevices(@CurrentUser() user: any, @Req() req: Request) {
    return this.trustedDevices.list(user.sub, this.deviceId(req));
  }

  @Delete('devices/:id')
  @UseGuards(JwtAuthGuard)
  async revokeDevice(
    @CurrentUser() user: any,
    @Param('id') id: string,
    @Req() req: Request,
  ) {
    return this.trustedDevices.revoke(
      user.sub,
      id,
      req.ip ?? '',
      req.headers['user-agent'] ?? '',
    );
  }
```

Добавить `private readonly trustedDevices: TrustedDeviceService` в конструктор и `TrustedDeviceService` в providers/exports модуля.

- [ ] **Шаг 6: собрать и закоммитить**

```bash
cd ~/Downloads/taler_id && npm run build
git add src/auth/
git commit -m "feat(auth): list and revoke trusted devices"
```

---

### Task 13: Тумблер в профиле

**Files:**
- Modify: `src/profile/dto/update-profile.dto.ts`
- Modify: `src/profile/profile.service.ts`

- [ ] **Шаг 1: DTO**

В `src/profile/dto/update-profile.dto.ts` добавить:

```ts
  @IsOptional()
  @IsBoolean()
  newDeviceApproval?: boolean;
```

(импортировать `IsBoolean` из `class-validator`, если ещё не импортирован.)

- [ ] **Шаг 2: сохранение**

В `src/profile/profile.service.ts`, в блоке обновления профиля, добавить `newDeviceApproval` в объект `data` рядом с прочими полями профиля — по тому же образцу, что `aiTwinEnabled`.

- [ ] **Шаг 3: отдача**

Убедиться, что `GET /profile` возвращает `newDeviceApproval` (если select перечисляет поля явно — добавить).

- [ ] **Шаг 4: проверить руками на локальном бэкенде**

```bash
cd ~/Downloads/taler_id && npm run build && node -r dotenv/config dist/main.js &
sleep 8
TOKEN=$(curl -s -X POST localhost:3000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"integration_test@taler-test.com","password":"IntegrationTest123!"}' | jq -r .accessToken)
curl -s -X PATCH localhost:3000/profile -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"newDeviceApproval":true}' | jq .newDeviceApproval
```

Ожидается: `true`.

- [ ] **Шаг 5: коммит**

```bash
git add src/profile/
git commit -m "feat(profile): new device approval toggle"
```

---

# ФАЗА D — мобилка

### Task 14: Починить сломанный TOTP-вход

**Files:**
- Modify: `lib/features/auth/data/datasources/auth_remote_datasource.dart:36-44`
- Modify: `lib/features/auth/data/repositories/auth_repository_impl.dart:34-53`
- Modify: `lib/features/auth/domain/entities/auth_entities.dart`
- Test: `test/features/auth/login_next_step_test.dart`

- [ ] **Шаг 1: написать падающий тест**

Создать `test/features/auth/login_next_step_test.dart`:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/auth/domain/entities/auth_entities.dart';

void main() {
  group('login response shape', () {
    test('a 2FA challenge carries the backend field name', () {
      final e = TwoFARequiredException(challengeToken: 'chal', email: 'a@b.c');
      expect(e.challengeToken, 'chal');
    });

    test('a device approval carries its token and channel hints', () {
      final e = DeviceApprovalRequiredException(
        approvalToken: 'tok',
        approverCount: 2,
        emailAvailable: true,
        expiresIn: 600,
      );
      expect(e.approvalToken, 'tok');
      expect(e.approverCount, 2);
      expect(e.emailAvailable, isTrue);
    });
  });
}
```

- [ ] **Шаг 2: убедиться, что тест падает**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/features/auth/login_next_step_test.dart
```

Ожидается: FAIL — `TwoFARequiredException` не имеет `challengeToken`, `DeviceApprovalRequiredException` не определён.

- [ ] **Шаг 3: исправить исключения**

В `lib/features/auth/domain/entities/auth_entities.dart` заменить `TwoFARequiredException` и добавить новое:

```dart
/// Бэкенд отвечает `{ next: '2fa', challengeToken }`. Клиент до 1.1.24 читал
/// несуществующее `requires2FA`/`tempToken`, поэтому вход с включённым TOTP
/// падал на приведении null к String — и ни один тестировщик этого не ловил,
/// потому что TOTP включён у единиц.
class TwoFARequiredException implements Exception {
  final String challengeToken;
  final String email;
  const TwoFARequiredException({
    required this.challengeToken,
    required this.email,
  });
}

/// Пароль верный, но устройство незнакомое: токены выдадут после подтверждения
/// с другого устройства или по коду с почты.
class DeviceApprovalRequiredException implements Exception {
  final String approvalToken;
  final int approverCount;
  final bool emailAvailable;
  final int expiresIn;
  const DeviceApprovalRequiredException({
    required this.approvalToken,
    required this.approverCount,
    required this.emailAvailable,
    required this.expiresIn,
  });
}
```

- [ ] **Шаг 4: исправить разбор ответа**

В `lib/features/auth/data/repositories/auth_repository_impl.dart` заменить блок в `login` (строки 35-43):

```dart
    final data = await remote.login(email, password);

    switch (data['next'] as String?) {
      case '2fa':
        throw TwoFARequiredException(
          challengeToken: data['challengeToken'] as String,
          email: email,
        );
      case 'device_approval':
        throw DeviceApprovalRequiredException(
          approvalToken: data['approvalToken'] as String,
          approverCount: (data['approverCount'] as num?)?.toInt() ?? 0,
          emailAvailable: data['emailAvailable'] as bool? ?? false,
          expiresIn: (data['expiresIn'] as num?)?.toInt() ?? 600,
        );
    }
```

- [ ] **Шаг 5: исправить тело запроса `/auth/login/2fa`**

В `lib/features/auth/data/datasources/auth_remote_datasource.dart`:

```dart
  Future<Map<String, dynamic>> verify2FA({
    required String challengeToken,
    required String code,
  }) {
    return client.post<Map<String, dynamic>>(
      '/auth/login/2fa',
      // Бэкенд поднят с forbidNonWhitelisted: любое лишнее поле здесь — 400.
      data: {'challengeToken': challengeToken, 'code': code},
      fromJson: (data) => Map<String, dynamic>.from(data),
    );
  }
```

Поправить вызывающий код в `auth_repository_impl.dart` и `two_fa_screen.dart` под новую сигнатуру.

- [ ] **Шаг 6: убедиться, что тест проходит**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/features/auth/login_next_step_test.dart && flutter analyze --no-fatal-infos
```

Ожидается: PASS и analyze без ошибок.

- [ ] **Шаг 7: коммит**

```bash
git add lib/features/auth test/features/auth
git commit -m "fix(auth): speak the backend's next-step protocol, unbreaking TOTP login"
```

---

### Task 15: Идентификатор устройства

**Files:**
- Create: `lib/core/services/device_id_service.dart`
- Modify: `lib/core/api/dio_client.dart`, `lib/core/di/service_locator.dart`
- Test: `test/core/services/device_id_service_test.dart`

- [ ] **Шаг 1: написать падающий тест**

Создать `test/core/services/device_id_service_test.dart`:

```dart
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/core/services/device_id_service.dart';

class _FakeStore implements DeviceIdStore {
  String? value;
  int writes = 0;
  @override
  Future<String?> read() async => value;
  @override
  Future<void> write(String v) async {
    value = v;
    writes++;
  }
}

void main() {
  test('generates once and keeps the same id across restarts', () async {
    final store = _FakeStore();

    final first = DeviceIdService(store);
    await first.init();
    final id = first.deviceId;

    expect(id, isNotEmpty);
    expect(store.writes, 1);

    final second = DeviceIdService(store);
    await second.init();

    expect(second.deviceId, id);
    expect(store.writes, 1);
  });
}
```

- [ ] **Шаг 2: убедиться, что тест падает**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/core/services/device_id_service_test.dart
```

Ожидается: FAIL — файл не существует.

- [ ] **Шаг 3: реализовать**

Создать `lib/core/services/device_id_service.dart`:

```dart
import 'package:uuid/uuid.dart';

import '../storage/secure_storage_service.dart';

/// Абстракция поверх хранилища — чтобы сервис можно было тестировать без
/// платформенного канала flutter_secure_storage.
abstract class DeviceIdStore {
  Future<String?> read();
  Future<void> write(String value);
}

class SecureDeviceIdStore implements DeviceIdStore {
  static const _key = 'device_id';
  final SecureStorageService storage;
  SecureDeviceIdStore(this.storage);

  @override
  Future<String?> read() => storage.read(_key);

  @override
  Future<void> write(String value) => storage.write(_key, value);
}

/// Непрозрачный идентификатор этой установки приложения. Бэкенд по нему
/// отличает знакомое устройство от нового; ничего личного он не несёт и
/// пересоздаётся при переустановке — тогда вход просто потребует подтверждения.
class DeviceIdService {
  final DeviceIdStore _store;
  String _deviceId = '';

  DeviceIdService(this._store);

  String get deviceId => _deviceId;

  Future<void> init() async {
    final existing = await _store.read();
    if (existing != null && existing.isNotEmpty) {
      _deviceId = existing;
      return;
    }
    _deviceId = const Uuid().v4();
    await _store.write(_deviceId);
  }
}
```

Если у `SecureStorageService` нет обобщённых `read`/`write` — добавить `readDeviceId()`/`saveDeviceId()` по образцу существующих методов и использовать их.

- [ ] **Шаг 4: убедиться, что тест проходит**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/core/services/device_id_service_test.dart
```

Ожидается: PASS.

- [ ] **Шаг 5: заголовок в Dio**

В `lib/core/api/dio_client.dart` после добавления `authInterceptor` (строка ~113) вставить:

```dart
    dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) {
        final id = deviceIdService.deviceId;
        if (id.isNotEmpty) options.headers['X-Device-Id'] = id;
        handler.next(options);
      },
    ));
```

передав `DeviceIdService` в конструктор `DioClient` рядом с `authInterceptor`.

- [ ] **Шаг 6: регистрация в DI**

В `lib/core/di/service_locator.dart` — до создания `DioClient`:

```dart
  final deviceIdService = DeviceIdService(
    SecureDeviceIdStore(getIt<SecureStorageService>()),
  );
  await deviceIdService.init();
  getIt.registerSingleton<DeviceIdService>(deviceIdService);
```

- [ ] **Шаг 7: проверить**

```bash
cd ~/Downloads/taler_id_mobile && flutter analyze --no-fatal-infos && flutter test
```

Ожидается: analyze чист, все тесты зелёные.

- [ ] **Шаг 8: коммит**

```bash
git add lib/core test/core
git commit -m "feat(auth): stable per-install device id sent as X-Device-Id"
```

---

### Task 16: Экран ожидания подтверждения

**Files:**
- Create: `lib/features/auth/presentation/screens/device_approval_waiting_screen.dart`
- Modify: `lib/features/auth/data/datasources/auth_remote_datasource.dart`
- Modify: `lib/core/router/app_router.dart`, `lib/features/auth/presentation/screens/login_screen.dart`

- [ ] **Шаг 1: методы датасорса**

В `auth_remote_datasource.dart`:

```dart
  Future<Map<String, dynamic>> deviceApprovalStatus(String approvalToken) {
    return client.post<Map<String, dynamic>>(
      '/auth/login/device-approval/status',
      data: {'approvalToken': approvalToken},
      fromJson: (data) => Map<String, dynamic>.from(data),
    );
  }

  Future<void> sendDeviceApprovalEmail(String approvalToken) =>
      client.post('/auth/login/device-approval/email',
          data: {'approvalToken': approvalToken});

  Future<Map<String, dynamic>> verifyDeviceApprovalCode({
    required String approvalToken,
    required String code,
  }) {
    return client.post<Map<String, dynamic>>(
      '/auth/login/device-approval/verify',
      data: {'approvalToken': approvalToken, 'code': code},
      fromJson: (data) => Map<String, dynamic>.from(data),
    );
  }
```

- [ ] **Шаг 2: экран**

Создать `lib/features/auth/presentation/screens/device_approval_waiting_screen.dart`. Содержимое:
- принимает `approvalToken`, `approverCount`, `emailAvailable`, `expiresIn`;
- `Timer.periodic(Duration(seconds: 3))` → `deviceApprovalStatus`;
- `approved` → сохранить токены через репозиторий, `context.go('/messenger')`;
- `rejected` → показать «Вход отклонён», кнопка «Назад ко входу»;
- `expired` → «Время истекло», кнопка «Войти снова»;
- обратный отсчёт от `expiresIn`;
- если `emailAvailable` — кнопка «Отправить код на почту» → поле ввода 6 цифр → `verifyDeviceApprovalCode`;
- **таймер обязательно гасить в `dispose()`** — иначе он переживёт экран и будет дёргать сеть после выхода.

Тексты на русском и английском добавить в `lib/l10n/app_ru.arb` и `app_en.arb`, затем `flutter gen-l10n`.

- [ ] **Шаг 3: маршрут и переход**

В `lib/core/router/app_router.dart` добавить маршрут `/device-approval`. В `login_screen.dart` — поймать `DeviceApprovalRequiredException` рядом с существующей обработкой `TwoFARequiredException` и уйти на этот маршрут.

- [ ] **Шаг 4: проверить**

```bash
cd ~/Downloads/taler_id_mobile && flutter gen-l10n && flutter analyze --no-fatal-infos && flutter test
```

Ожидается: чисто.

- [ ] **Шаг 5: коммит**

```bash
git add lib test
git commit -m "feat(auth): waiting screen for a login pending approval"
```

---

### Task 17: Лист подтверждения на доверенном устройстве

**Files:**
- Create: `lib/features/auth/presentation/widgets/device_approval_sheet.dart`
- Modify: `lib/core/notifications/notification_service.dart`

- [ ] **Шаг 1: лист**

Создать `device_approval_sheet.dart` — модальный лист, показывающий устройство, IP и город из payload, с кнопками «Разрешить» (`POST /auth/devices/approvals/:id/approve`) и «Это не я» (`.../reject`). Вторая кнопка визуально акцентная (красная): в этом диалоге опасен именно ошибочный «Разрешить».

- [ ] **Шаг 2: обработчик пуша**

В `lib/core/notifications/notification_service.dart`, в разборе `message.data['type']`, добавить ветку:

```dart
      case 'device_approval':
        showDeviceApprovalSheet(
          approvalId: data['approvalId'] ?? '',
          deviceInfo: data['deviceInfo'] ?? '',
          ip: data['ip'] ?? '',
          location: data['location'] ?? '',
        );
        break;
```

- [ ] **Шаг 3: проверить**

```bash
cd ~/Downloads/taler_id_mobile && flutter analyze --no-fatal-infos && flutter test
```

- [ ] **Шаг 4: коммит**

```bash
git add lib
git commit -m "feat(auth): approve or reject a new-device login from a push"
```

---

### Task 18: Настройки — тумблер и список устройств

**Files:**
- Create: `lib/features/settings/presentation/screens/trusted_devices_screen.dart`
- Modify: экран настроек, `lib/core/router/app_router.dart`

- [ ] **Шаг 1: экран**

Список из `GET /auth/devices`: модель, город, «последний вход», пометка «это устройство». Свайп/кнопка «Отозвать» → `DELETE /auth/devices/:id` с подтверждением. Сверху — тумблер «Подтверждать вход с новых устройств», пишущий `newDeviceApproval` через `PATCH /profile`.

- [ ] **Шаг 2: маршрут + пункт в настройках**

- [ ] **Шаг 3: проверить и закоммитить**

```bash
cd ~/Downloads/taler_id_mobile && flutter gen-l10n && flutter analyze --no-fatal-infos && flutter test
git add lib
git commit -m "feat(settings): trusted devices screen and approval toggle"
```

---

# ФАЗА E — проверка и выкатка

### Task 19: Интеграционный тест против DEV

**Files:**
- Create: `~/Downloads/taler_id_tests/test-device-approval.js`
- Modify: `~/Downloads/taler_id_tests/package.json`

- [ ] **Шаг 1: сценарий**

По образцу существующих suite'ов (`test-channels.js`) написать:
1. логин `integration_test@taler-test.com` с `X-Device-Id: dev-known-<uuid>` → токены (первое устройство, шлюза нет);
2. `PATCH /profile {newDeviceApproval:true}`;
3. логин с новым `X-Device-Id` → `next: 'device_approval'`, есть `approvalToken`, **нет** `accessToken`;
4. `POST /auth/login/device-approval/status` → `pending`;
5. с токенов первого устройства `POST /auth/devices/approvals/:id/approve` — `approvalId` взять из audit-лога либо вернуть его отдельным тестовым эндпоинтом; проще: пройти почтовым путём и проверить push-ветку вручную на устройстве;
6. `POST /auth/login/device-approval/status` → `approved` + токены;
7. повторный опрос → `claimed`, второй сессии не создалось;
8. повторный логин тем же новым `X-Device-Id` → токены сразу (устройство стало доверенным);
9. `GET /auth/devices` → два устройства;
10. `DELETE /auth/devices/:id` второго → `GET /auth/devices` показывает одно;
11. вернуть `newDeviceApproval:false`.

- [ ] **Шаг 2: скрипт в package.json**

```json
    "test:device-approval": "node test-device-approval.js",
    "test:device-approval:prod": "BASE_URL=https://id.taler.tirol node test-device-approval.js",
```

- [ ] **Шаг 3: прогнать против DEV**

```bash
cd ~/Downloads/taler_id_tests && npm run test:device-approval
```

Ожидается: все проверки зелёные.

- [ ] **Шаг 4: коммит**

---

### Task 20: Деплой DEV

- [ ] **Шаг 1: смёржить в `dev` и выкатить**

```bash
cd ~/Downloads/taler_id && git push origin <branch>
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npx prisma migrate deploy && npx prisma generate && npm run build && pm2 restart taler-id-dev'
```

Миграция обязательна — она в этом релизе есть. Проверка до рестарта: `npx prisma migrate status`.

- [ ] **Шаг 2: полный набор тестов по CLAUDE.md**

```bash
cd ~/Downloads/taler_id_tests && npm test && npm run test:device-approval
```

Ожидается: 29/29 + новый suite.

- [ ] **Шаг 3: ручная проверка пуш-пути на двух устройствах**

Войти на эмуляторе с аккаунта, у которого уже есть сессия на телефоне; убедиться, что на телефоне приходит уведомление, «Разрешить» пускает эмулятор внутрь, а «Это не я» показывает на эмуляторе «Вход отклонён».

- [ ] **Шаг 4: проверить, что старые клиенты не задеты**

```bash
curl -s -X POST https://staging.id.taler.tirol/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"integration_test@taler-test.com","password":"IntegrationTest123!"}' | jq 'has("accessToken")'
```

Ожидается: `true` — запрос без `X-Device-Id` проходит как раньше.

---

### Task 21: Деплой TEST, затем PROD

- [ ] TEST: `ssh dvolkov@138.124.61.221 'cd ~/taler-id && git pull && npx prisma migrate deploy && npx prisma generate && npm run build && pm2 restart taler-id'`, затем `npm run test:prod` + `npm run test:device-approval:prod`.
- [ ] PROD **только по явной команде пользователя**: rolling по одной ноде через `do-app-1` / `do-app-2` с `npx prisma migrate deploy` перед сборкой, health-gate между нодами.
- [ ] Мобильный релиз: bump pubspec, `latest` + запись в `APP_RELEASES` в `src/app.controller.ts`, шесть сборок, TestFlight-заметки — по регламенту CLAUDE.md.
