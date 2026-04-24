# Taler AI Billing — Backend + Agents Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the server-side and Python-agent parts of the TAL-token-based AI billing system to DEV in dry-run mode, so real usage can be metered and the pricebook calibrated before mobile UI lands.

**Architecture:** NestJS `BillingModule` with PricingService (USD×markup→planck), atomic `LedgerService` over PostgreSQL, `GatingService` for pre-check + feature toggles, cron-based `MeteringService` for periodic deduction, custodial `WalletService` + `DepositWatcher` in existing `BlockchainModule`. All 6 AI features (voice_assistant, web_search, ai_twin, outbound_call, whisper_transcribe, meeting_summary) hook into `gating.startSession()` before paid work. Python agents patched to report actual usage via shared-secret HTTP callback.

**Tech Stack:** NestJS 11, Prisma, PostgreSQL, `@nestjs/schedule` (cron), `@polkadot/api` (existing), Socket.io (reuse existing messenger gateway), Jest.

**Precondition:** Design spec at [`docs/superpowers/specs/2026-04-24-taler-ai-billing-design.md`](../specs/2026-04-24-taler-ai-billing-design.md). All decisions there are authoritative; this plan only implements them.

---

## File Structure

### New files

**Billing module (`src/billing/`):**
| File | Responsibility |
|---|---|
| `billing.module.ts` | NestJS module wiring |
| `constants/feature-keys.ts` | Frozen list of 6 feature keys as const enum |
| `constants/packages.ts` | Three package definitions (amounts + unit equivalents) |
| `services/pricing.service.ts` | Pure cost calculation (USD × markup ÷ rate → planck) with in-memory cache |
| `services/ledger.service.ts` | Atomic credit/debit/refund over `UserWallet` + `BillingTransaction` |
| `services/gating.service.ts` | `startSession` / `endSession` with toggle + minReserve checks, respects `billingEnforced` flag |
| `services/metering.service.ts` | Cron (10s) debits active sessions, emits `ai_session_terminated` on exhaustion |
| `exceptions/insufficient-funds.exception.ts` | Carries required/available/suggestedPackage |
| `exceptions/feature-disabled.exception.ts` | Thrown when `UserFeatureToggle.enabled=false` |
| `filters/billing-exception.filter.ts` | Maps both exceptions to HTTP 402/403 with structured body |
| `controllers/billing.controller.ts` | GET balance/packages/wallet/transactions/pricebook/toggles, POST purchase/withdraw, PATCH toggles |
| `controllers/metering.controller.ts` | Internal `/metering/report` + `/metering/heartbeat` |
| `controllers/admin-billing.controller.ts` | `/admin/billing/*` guarded by `isAdmin` |
| `guards/metering-secret.guard.ts` | Shared-secret header check for agent callbacks |
| `dto/balance.dto.ts` | Response shape |
| `dto/purchase.dto.ts` | Purchase request |
| `dto/toggle.dto.ts` | Feature-toggle PATCH body |
| `dto/report.dto.ts` | Metering report body |
| `dto/admin.dto.ts` | Admin patch bodies |
| `scripts/wallets-ensure.ts` | One-shot script: create `UserWallet` for every `User` missing one |
| `scripts/welcome-bonus.ts` | One-shot script: credit 50 μTAL to every user once (idempotent via metadata) |

**Blockchain module additions (`src/blockchain/`):**
| File | Responsibility |
|---|---|
| `wallet.service.ts` | Custodial keypair gen, encrypted storage, `signAndSubmitTransfer` for withdraw |
| `deposit-watcher.service.ts` | Subscribes to `balances.Transfer` events, credits ledger on incoming to custodial addresses |
| `crypto/encryption.ts` | AES-256-GCM helpers for custodial key encryption |

**Prisma:**
| File | Responsibility |
|---|---|
| `prisma/migrations/20260424000001_taler_ai_billing/migration.sql` | All new tables + seed pricebook/config |

**External tests:**
| File | Responsibility |
|---|---|
| `~/Downloads/taler_id_tests/billing-smoke.js` | End-to-end smoke test run against DEV |

### Files modified

| File | Change |
|---|---|
| `prisma/schema.prisma` | Add `AiPricebook`, `BillingConfig`, `UserWallet`, `BillingTransaction`, `AiSession`, `UserFeatureToggle`, `UsageLog` + reverse relations on `User` |
| `src/app.module.ts` | Import `BillingModule` |
| `src/blockchain/blockchain.module.ts` | Register + export `WalletService` and `DepositWatcher` |
| `src/voice/voice.service.ts` | 3 hooks: `voice_assistant` (line 194–214), `whisper_transcribe` (line 768–830), `meeting_summary` (line 836–869) |
| `src/voice/voice.module.ts` | Import `BillingModule` |
| `src/assistant/assistant.service.ts` | 1 hook: `web_search` (line 15–52) |
| `src/assistant/assistant.module.ts` | Import `BillingModule` |
| `src/messenger/ai-twin.service.ts` | 1 hook: `ai_twin` (line 299), plus termination helper |
| `src/messenger/messenger.gateway.ts` | 4 new Socket.io events |
| `src/messenger/messenger.module.ts` | Import `BillingModule` |
| `src/outbound-bot/outbound-bot.service.ts` | 1 hook: `outbound_call` (line 82–126) |
| `src/outbound-bot/outbound-bot.controller.ts` | Accept `units` field in call-callback, forward to `MeteringService` |
| `src/outbound-bot/outbound-bot.module.ts` | Import `BillingModule` |
| `.env.example` | `WALLET_ENCRYPTION_KEY`, `METERING_SHARED_SECRET` |
| `~/ai-twin-agent/agent.py` | Include `units: duration_seconds / 60` in POST `/voice/ai-twin/callback` |
| `outbound-call-agent/agent.py` | Include `units` in POST `/outbound-bot/call-callback` |
| `~/Downloads/taler_id_tests/package.json` | Add `"test:billing": "..."` + `"test:billing:prod"` |
| `/Users/dmitry/CLAUDE.md` | Add "Тест биллинга (DEV)" to pre-deploy checklist |

---

## Part A — Schema & Foundation

### Task 1: Prisma schema, migration, seed

**Files:**
- Modify: `prisma/schema.prisma`
- Create: `prisma/migrations/20260424000001_taler_ai_billing/migration.sql`

- [ ] **Step 1: Add models to schema.prisma**

Append to `prisma/schema.prisma` (do NOT touch existing models except to add reverse relations on `User`):

```prisma
model AiPricebook {
  id                 String   @id @default(cuid())
  featureKey         String   @unique
  unit               String
  costUsdPerUnit     Decimal  @db.Decimal(12, 8)
  markupMultiplier   Decimal  @default(2.0) @db.Decimal(4, 2)
  minReservePlanck   BigInt
  updatedAt          DateTime @updatedAt
}

model BillingConfig {
  id                 String   @id @default("singleton")
  talUsdRate         Decimal  @db.Decimal(14, 4)
  billingEnforced    Boolean  @default(false)
  welcomeBonusPlanck BigInt   @default(50000000)
  lastSeenBlock      Int?
  updatedAt          DateTime @updatedAt
}

model UserWallet {
  userId           String   @id
  user             User     @relation(fields: [userId], references: [id])
  custodialAddress String   @unique
  custodialKeyEnc  String
  balancePlanck    BigInt   @default(0)
  createdAt        DateTime @default(now())
  updatedAt        DateTime @updatedAt
}

enum TxType {
  TOPUP_STUB
  TOPUP_ONCHAIN
  SPEND
  REFUND
  ADMIN_CREDIT
  ADMIN_DEBIT
  WITHDRAW
}

enum TxStatus {
  PENDING
  COMPLETED
  FAILED
  REVERSED
}

model BillingTransaction {
  id           String   @id @default(cuid())
  userId       String
  user         User     @relation(fields: [userId], references: [id])
  type         TxType
  status       TxStatus @default(COMPLETED)
  amountPlanck BigInt
  featureKey   String?
  sessionId    String?  @db.Uuid
  chainTxHash  String?
  metadata     Json?
  createdAt    DateTime @default(now())

  @@index([userId, createdAt])
  @@index([sessionId])
}

model AiSession {
  id               String    @id @default(uuid()) @db.Uuid
  userId           String
  user             User      @relation(fields: [userId], references: [id])
  featureKey       String
  contextRef       String?
  status           String    @default("active")
  startedAt        DateTime  @default(now())
  lastMeteredAt    DateTime  @default(now())
  endedAt          DateTime?
  totalSpentPlanck BigInt    @default(0)
  metadata         Json?

  @@index([userId, status])
  @@index([contextRef])
}

model UserFeatureToggle {
  userId     String
  featureKey String
  enabled    Boolean
  updatedAt  DateTime @updatedAt

  @@id([userId, featureKey])
}

model UsageLog {
  id         String   @id @default(cuid())
  userId     String
  sessionId  String?  @db.Uuid
  featureKey String
  unit       String
  units      Decimal  @db.Decimal(14, 4)
  reporter   String
  createdAt  DateTime @default(now())

  @@index([userId, createdAt])
}
```

Then add these back-relation fields inside the existing `model User { … }` block (anywhere in the field list):

```prisma
  wallet              UserWallet?
  billingTransactions BillingTransaction[]
  aiSessions          AiSession[]
```

- [ ] **Step 2: Generate migration**

Run: `cd ~/Downloads/taler_id && npx prisma migrate dev --name taler_ai_billing --create-only`

This creates `prisma/migrations/20260424000001_taler_ai_billing/migration.sql`. Verify the file contains `CREATE TABLE "AiPricebook"`, `"BillingConfig"`, `"UserWallet"`, `"BillingTransaction"`, `"AiSession"`, `"UserFeatureToggle"`, `"UsageLog"` and the `TxType`/`TxStatus` enums.

- [ ] **Step 3: Append seed rows to the migration SQL**

Open the generated `migration.sql` and append:

```sql
-- Seed pricebook (costs in USD, planck = 10⁻¹² TAL)
-- At rate 1 TAL = $11,700, voice_assistant $0.30/min = 25.6M planck/min,
-- so minReservePlanck ≈ 60s of usage at the configured markup.
INSERT INTO "AiPricebook" (id, "featureKey", unit, "costUsdPerUnit", "markupMultiplier", "minReservePlanck", "updatedAt") VALUES
  ('pb_voice_assistant',    'voice_assistant',    'minute',    0.15,  2.0, 26000000, NOW()),
  ('pb_web_search',         'web_search',         'request',   0.005, 2.0,  1000000, NOW()),
  ('pb_ai_twin',            'ai_twin',            'minute',    0.15,  2.0, 26000000, NOW()),
  ('pb_outbound_call',      'outbound_call',      'minute',    0.20,  2.0, 35000000, NOW()),
  ('pb_whisper_transcribe', 'whisper_transcribe', 'minute',    0.006, 2.0,  5000000, NOW()),
  ('pb_meeting_summary',    'meeting_summary',    '1k_tokens', 0.01,  2.0,  4000000, NOW());

-- Singleton config row
INSERT INTO "BillingConfig" (id, "talUsdRate", "billingEnforced", "welcomeBonusPlanck", "updatedAt")
  VALUES ('singleton', 11700, false, 50000000, NOW());
```

- [ ] **Step 4: Apply migration**

Run: `cd ~/Downloads/taler_id && npx prisma migrate dev`
Expected: migration applies, Prisma Client regenerates.

- [ ] **Step 5: Verify**

Run: `cd ~/Downloads/taler_id && npx prisma studio` (open in browser) OR
```bash
psql "$DATABASE_URL" -c 'SELECT "featureKey", "costUsdPerUnit", "markupMultiplier", "minReservePlanck" FROM "AiPricebook";'
```
Expected: six rows matching the seed.

- [ ] **Step 6: Commit**

```bash
cd ~/Downloads/taler_id
git add prisma/schema.prisma prisma/migrations/20260424000001_taler_ai_billing/
git commit -m "feat(billing): add schema for TAL-token billing

Adds AiPricebook, BillingConfig, UserWallet, BillingTransaction,
AiSession, UserFeatureToggle, UsageLog. Seeds pricebook for all
6 AI features with 2.0 markup and 60-second reserves."
```

---

## Part B — Core Services

### Task 2: `PricingService` + feature keys constant

**Files:**
- Create: `src/billing/constants/feature-keys.ts`
- Create: `src/billing/services/pricing.service.ts`
- Create: `src/billing/services/pricing.service.spec.ts`

- [ ] **Step 1: Write the feature-keys constant**

Create `src/billing/constants/feature-keys.ts`:

```typescript
export const FEATURE_KEYS = {
  VOICE_ASSISTANT: 'voice_assistant',
  WEB_SEARCH: 'web_search',
  AI_TWIN: 'ai_twin',
  OUTBOUND_CALL: 'outbound_call',
  WHISPER_TRANSCRIBE: 'whisper_transcribe',
  MEETING_SUMMARY: 'meeting_summary',
} as const;

export type FeatureKey = (typeof FEATURE_KEYS)[keyof typeof FEATURE_KEYS];

export const ALL_FEATURE_KEYS: FeatureKey[] = Object.values(FEATURE_KEYS);
```

- [ ] **Step 2: Write the failing test**

Create `src/billing/services/pricing.service.spec.ts`:

```typescript
import { Test } from '@nestjs/testing';
import { PricingService } from './pricing.service';
import { PrismaService } from '../../prisma/prisma.service';

describe('PricingService', () => {
  let service: PricingService;
  let prisma: {
    aiPricebook: { findUnique: jest.Mock };
    billingConfig: { findUnique: jest.Mock };
  };

  beforeEach(async () => {
    prisma = {
      aiPricebook: { findUnique: jest.fn() },
      billingConfig: { findUnique: jest.fn() },
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        PricingService,
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();

    service = moduleRef.get(PricingService);
  });

  it('calculates planck cost for voice_assistant 1 minute at 2x markup and $11,700 rate', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue({
      featureKey: 'voice_assistant',
      unit: 'minute',
      costUsdPerUnit: '0.15',
      markupMultiplier: '2.0',
      minReservePlanck: 26000000n,
    });
    prisma.billingConfig.findUnique.mockResolvedValue({
      id: 'singleton',
      talUsdRate: '11700',
    });

    const planck = await service.calculatePlanckCost('voice_assistant', 1);
    // $0.30 / $11,700 * 1e12 = 25_641_025.64…  rounded up
    expect(planck).toBe(25641026n);
  });

  it('rounds up in favor of the service', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue({
      featureKey: 'web_search',
      unit: 'request',
      costUsdPerUnit: '0.005',
      markupMultiplier: '2.0',
      minReservePlanck: 1000000n,
    });
    prisma.billingConfig.findUnique.mockResolvedValue({
      id: 'singleton',
      talUsdRate: '11700',
    });

    // 1 request: $0.01 / $11,700 * 1e12 = 854_700.85… → 854_701
    const planck = await service.calculatePlanckCost('web_search', 1);
    expect(planck).toBe(854701n);
  });

  it('throws on unknown featureKey', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue(null);
    prisma.billingConfig.findUnique.mockResolvedValue({ talUsdRate: '11700' });

    await expect(service.calculatePlanckCost('nope', 1)).rejects.toThrow(/unknown feature/i);
  });

  it('caches pricebook rows for 60 seconds', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue({
      featureKey: 'voice_assistant',
      unit: 'minute',
      costUsdPerUnit: '0.15',
      markupMultiplier: '2.0',
      minReservePlanck: 26000000n,
    });
    prisma.billingConfig.findUnique.mockResolvedValue({ talUsdRate: '11700' });

    await service.calculatePlanckCost('voice_assistant', 1);
    await service.calculatePlanckCost('voice_assistant', 2);
    expect(prisma.aiPricebook.findUnique).toHaveBeenCalledTimes(1);
  });

  it('exposes getMinReserve', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue({
      featureKey: 'voice_assistant',
      minReservePlanck: 26000000n,
    } as any);
    prisma.billingConfig.findUnique.mockResolvedValue({ talUsdRate: '11700' });

    expect(await service.getMinReservePlanck('voice_assistant')).toBe(26000000n);
  });
});
```

- [ ] **Step 3: Run test — expect fail**

Run: `cd ~/Downloads/taler_id && npx jest src/billing/services/pricing.service.spec.ts`
Expected: FAIL (no `pricing.service.ts` yet).

- [ ] **Step 4: Implement PricingService**

Create `src/billing/services/pricing.service.ts`:

```typescript
import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

const CACHE_TTL_MS = 60_000;

type PricebookRow = {
  featureKey: string;
  unit: string;
  costUsdPerUnit: string | number | bigint | { toString(): string };
  markupMultiplier: string | number | bigint | { toString(): string };
  minReservePlanck: bigint;
};

type ConfigRow = {
  talUsdRate: string | number | bigint | { toString(): string };
};

@Injectable()
export class PricingService {
  private pricebookCache = new Map<string, { row: PricebookRow; ts: number }>();
  private configCache: { row: ConfigRow; ts: number } | null = null;

  constructor(private readonly prisma: PrismaService) {}

  invalidateCache(): void {
    this.pricebookCache.clear();
    this.configCache = null;
  }

  async getPricebook(featureKey: string): Promise<PricebookRow> {
    const cached = this.pricebookCache.get(featureKey);
    if (cached && Date.now() - cached.ts < CACHE_TTL_MS) return cached.row;

    const row = await this.prisma.aiPricebook.findUnique({ where: { featureKey } });
    if (!row) throw new NotFoundException(`unknown feature ${featureKey}`);
    this.pricebookCache.set(featureKey, { row: row as unknown as PricebookRow, ts: Date.now() });
    return row as unknown as PricebookRow;
  }

  async getConfig(): Promise<ConfigRow> {
    if (this.configCache && Date.now() - this.configCache.ts < CACHE_TTL_MS) {
      return this.configCache.row;
    }
    const row = await this.prisma.billingConfig.findUnique({ where: { id: 'singleton' } });
    if (!row) throw new NotFoundException('billing config not seeded');
    this.configCache = { row: row as unknown as ConfigRow, ts: Date.now() };
    return row as unknown as ConfigRow;
  }

  async calculatePlanckCost(featureKey: string, units: number): Promise<bigint> {
    const [pb, cfg] = await Promise.all([this.getPricebook(featureKey), this.getConfig()]);

    const costUsd =
      units * Number(pb.costUsdPerUnit.toString()) * Number(pb.markupMultiplier.toString());
    const talRate = Number(cfg.talUsdRate.toString());
    const costTal = costUsd / talRate;
    const planckFloat = costTal * 1e12;
    return BigInt(Math.ceil(planckFloat));
  }

  async getMinReservePlanck(featureKey: string): Promise<bigint> {
    const pb = await this.getPricebook(featureKey);
    return pb.minReservePlanck;
  }
}
```

- [ ] **Step 5: Run test — expect pass**

Run: `cd ~/Downloads/taler_id && npx jest src/billing/services/pricing.service.spec.ts`
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add src/billing/constants/feature-keys.ts src/billing/services/pricing.service.ts src/billing/services/pricing.service.spec.ts
git commit -m "feat(billing): add PricingService with USD×markup→planck formula"
```

---

### Task 3: `LedgerService` — atomic credit/debit/refund + exceptions + exception filter

**Files:**
- Create: `src/billing/exceptions/insufficient-funds.exception.ts`
- Create: `src/billing/exceptions/feature-disabled.exception.ts`
- Create: `src/billing/filters/billing-exception.filter.ts`
- Create: `src/billing/services/ledger.service.ts`
- Create: `src/billing/services/ledger.service.spec.ts`

- [ ] **Step 1: Write exceptions**

Create `src/billing/exceptions/insufficient-funds.exception.ts`:

```typescript
export class InsufficientFundsException extends Error {
  constructor(
    public readonly featureKey: string,
    public readonly requiredPlanck: bigint,
    public readonly availablePlanck: bigint,
    public readonly suggestedPackage?: string,
  ) {
    super(`insufficient funds for ${featureKey}: need ${requiredPlanck}, have ${availablePlanck}`);
  }
}
```

Create `src/billing/exceptions/feature-disabled.exception.ts`:

```typescript
export class FeatureDisabledException extends Error {
  constructor(public readonly featureKey: string) {
    super(`feature ${featureKey} disabled by user`);
  }
}
```

- [ ] **Step 2: Write the exception filter**

Create `src/billing/filters/billing-exception.filter.ts`:

```typescript
import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';
import { FeatureDisabledException } from '../exceptions/feature-disabled.exception';

@Catch(InsufficientFundsException, FeatureDisabledException)
export class BillingExceptionFilter
  implements ExceptionFilter<InsufficientFundsException | FeatureDisabledException>
{
  catch(exception: InsufficientFundsException | FeatureDisabledException, host: ArgumentsHost) {
    const res = host.switchToHttp().getResponse<Response>();

    if (exception instanceof InsufficientFundsException) {
      res.status(HttpStatus.PAYMENT_REQUIRED).json({
        error: 'insufficient_funds',
        featureKey: exception.featureKey,
        requiredPlanck: exception.requiredPlanck.toString(),
        availablePlanck: exception.availablePlanck.toString(),
        suggestedPackage: exception.suggestedPackage ?? 'starter',
      });
      return;
    }

    res.status(HttpStatus.FORBIDDEN).json({
      error: 'feature_disabled',
      featureKey: exception.featureKey,
    });
  }
}
```

- [ ] **Step 3: Write failing test for LedgerService**

Create `src/billing/services/ledger.service.spec.ts`:

```typescript
import { Test } from '@nestjs/testing';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerService } from './ledger.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';

describe('LedgerService', () => {
  let service: LedgerService;
  let prisma: any;

  beforeEach(async () => {
    const walletUpdate = jest.fn();
    const walletFindUnique = jest.fn();
    const txCreate = jest.fn();

    prisma = {
      $transaction: jest.fn(async (fn: any) =>
        fn({
          userWallet: { findUnique: walletFindUnique, update: walletUpdate },
          billingTransaction: { create: txCreate },
          $executeRaw: jest.fn(),
        }),
      ),
      userWallet: { findUnique: walletFindUnique, update: walletUpdate },
      billingTransaction: { create: txCreate, findUnique: jest.fn(), update: jest.fn() },
      _walletFindUnique: walletFindUnique,
      _walletUpdate: walletUpdate,
      _txCreate: txCreate,
    };

    const moduleRef = await Test.createTestingModule({
      providers: [LedgerService, { provide: PrismaService, useValue: prisma }],
    }).compile();

    service = moduleRef.get(LedgerService);
  });

  it('credit increases balance and records TOPUP_STUB transaction', async () => {
    prisma._walletFindUnique.mockResolvedValue({ userId: 'u1', balancePlanck: 100n });
    prisma._walletUpdate.mockResolvedValue({ userId: 'u1', balancePlanck: 600n });
    prisma._txCreate.mockResolvedValue({ id: 'tx1' });

    await service.credit('u1', 500n, 'TOPUP_STUB', { note: 'test' });

    expect(prisma._walletUpdate).toHaveBeenCalledWith({
      where: { userId: 'u1' },
      data: { balancePlanck: { increment: 500n } },
    });
    expect(prisma._txCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          userId: 'u1',
          type: 'TOPUP_STUB',
          amountPlanck: 500n,
          metadata: { note: 'test' },
        }),
      }),
    );
  });

  it('debit throws InsufficientFundsException when balance below amount', async () => {
    prisma._walletFindUnique.mockResolvedValue({ userId: 'u1', balancePlanck: 10n });

    await expect(
      service.debit('u1', 500n, 'SPEND', { featureKey: 'voice_assistant' }),
    ).rejects.toThrow(InsufficientFundsException);

    expect(prisma._walletUpdate).not.toHaveBeenCalled();
    expect(prisma._txCreate).not.toHaveBeenCalled();
  });

  it('debit succeeds when balance sufficient and records SPEND', async () => {
    prisma._walletFindUnique.mockResolvedValue({ userId: 'u1', balancePlanck: 1000n });
    prisma._walletUpdate.mockResolvedValue({ userId: 'u1', balancePlanck: 500n });
    prisma._txCreate.mockResolvedValue({ id: 'tx2' });

    await service.debit('u1', 500n, 'SPEND', { featureKey: 'voice_assistant', sessionId: 's1' });

    expect(prisma._walletUpdate).toHaveBeenCalledWith({
      where: { userId: 'u1' },
      data: { balancePlanck: { decrement: 500n } },
    });
    expect(prisma._txCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          type: 'SPEND',
          amountPlanck: 500n,
          featureKey: 'voice_assistant',
          sessionId: 's1',
        }),
      }),
    );
  });

  it('refund credits the inverse and marks original REVERSED', async () => {
    prisma.billingTransaction.findUnique.mockResolvedValue({
      id: 'txOrig',
      userId: 'u1',
      type: 'SPEND',
      amountPlanck: 500n,
      status: 'COMPLETED',
    });
    prisma._walletFindUnique.mockResolvedValue({ userId: 'u1', balancePlanck: 0n });
    prisma._walletUpdate.mockResolvedValue({ userId: 'u1', balancePlanck: 500n });
    prisma._txCreate.mockResolvedValue({ id: 'txRefund' });

    await service.refund('txOrig', 'openai 5xx');

    expect(prisma.billingTransaction.update).toHaveBeenCalledWith({
      where: { id: 'txOrig' },
      data: { status: 'REVERSED' },
    });
    expect(prisma._txCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          type: 'REFUND',
          amountPlanck: 500n,
          metadata: expect.objectContaining({ originalTxId: 'txOrig', reason: 'openai 5xx' }),
        }),
      }),
    );
  });
});
```

- [ ] **Step 4: Run test — expect fail**

Run: `cd ~/Downloads/taler_id && npx jest src/billing/services/ledger.service.spec.ts`
Expected: FAIL (`ledger.service.ts` missing).

- [ ] **Step 5: Implement LedgerService**

Create `src/billing/services/ledger.service.ts`:

```typescript
import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';
import type { TxType, Prisma } from '@prisma/client';

@Injectable()
export class LedgerService {
  constructor(private readonly prisma: PrismaService) {}

  async credit(
    userId: string,
    amountPlanck: bigint,
    type: TxType,
    metadata?: Prisma.JsonObject,
    extras?: { sessionId?: string; featureKey?: string; chainTxHash?: string },
  ): Promise<{ id: string }> {
    if (amountPlanck <= 0n) throw new Error('credit amount must be > 0');

    return this.prisma.$transaction(async (tx) => {
      // Row-level lock on the wallet to serialize concurrent updates.
      await tx.$executeRaw`SELECT 1 FROM "UserWallet" WHERE "userId" = ${userId} FOR UPDATE`;

      await tx.userWallet.update({
        where: { userId },
        data: { balancePlanck: { increment: amountPlanck } },
      });

      return tx.billingTransaction.create({
        data: {
          userId,
          type,
          status: 'COMPLETED',
          amountPlanck,
          featureKey: extras?.featureKey,
          sessionId: extras?.sessionId,
          chainTxHash: extras?.chainTxHash,
          metadata: metadata as Prisma.InputJsonValue,
        },
      });
    });
  }

  async debit(
    userId: string,
    amountPlanck: bigint,
    type: TxType,
    extras: { featureKey?: string; sessionId?: string; metadata?: Prisma.JsonObject } = {},
  ): Promise<{ id: string }> {
    if (amountPlanck <= 0n) throw new Error('debit amount must be > 0');

    return this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT 1 FROM "UserWallet" WHERE "userId" = ${userId} FOR UPDATE`;

      const wallet = await tx.userWallet.findUnique({ where: { userId } });
      if (!wallet) throw new NotFoundException(`no wallet for user ${userId}`);

      if (wallet.balancePlanck < amountPlanck) {
        throw new InsufficientFundsException(
          extras.featureKey ?? 'unknown',
          amountPlanck,
          wallet.balancePlanck,
        );
      }

      await tx.userWallet.update({
        where: { userId },
        data: { balancePlanck: { decrement: amountPlanck } },
      });

      return tx.billingTransaction.create({
        data: {
          userId,
          type,
          status: 'COMPLETED',
          amountPlanck,
          featureKey: extras.featureKey,
          sessionId: extras.sessionId,
          metadata: extras.metadata as Prisma.InputJsonValue,
        },
      });
    });
  }

  async refund(originalTxId: string, reason: string): Promise<{ id: string }> {
    return this.prisma.$transaction(async (tx) => {
      const orig = await tx.billingTransaction.findUnique({ where: { id: originalTxId } });
      if (!orig) throw new NotFoundException(`transaction ${originalTxId} not found`);
      if (orig.status === 'REVERSED') throw new Error(`transaction ${originalTxId} already reversed`);

      await tx.$executeRaw`SELECT 1 FROM "UserWallet" WHERE "userId" = ${orig.userId} FOR UPDATE`;

      await tx.userWallet.update({
        where: { userId: orig.userId },
        data: { balancePlanck: { increment: orig.amountPlanck } },
      });

      await tx.billingTransaction.update({
        where: { id: originalTxId },
        data: { status: 'REVERSED' },
      });

      return tx.billingTransaction.create({
        data: {
          userId: orig.userId,
          type: 'REFUND',
          status: 'COMPLETED',
          amountPlanck: orig.amountPlanck,
          featureKey: orig.featureKey,
          sessionId: orig.sessionId,
          metadata: { originalTxId, reason } as Prisma.InputJsonValue,
        },
      });
    });
  }

  async getBalance(userId: string): Promise<bigint> {
    const w = await this.prisma.userWallet.findUnique({ where: { userId } });
    return w?.balancePlanck ?? 0n;
  }
}
```

- [ ] **Step 6: Run test — expect pass**

Run: `cd ~/Downloads/taler_id && npx jest src/billing/services/ledger.service.spec.ts`
Expected: 4 passed.

- [ ] **Step 7: Commit**

```bash
git add src/billing/exceptions/ src/billing/filters/ src/billing/services/ledger.service.ts src/billing/services/ledger.service.spec.ts
git commit -m "feat(billing): add LedgerService with atomic credit/debit/refund + exception filter"
```

---

### Task 4: `GatingService`

**Files:**
- Create: `src/billing/services/gating.service.ts`
- Create: `src/billing/services/gating.service.spec.ts`

- [ ] **Step 1: Write the failing test**

Create `src/billing/services/gating.service.spec.ts`:

```typescript
import { Test } from '@nestjs/testing';
import { GatingService } from './gating.service';
import { PricingService } from './pricing.service';
import { LedgerService } from './ledger.service';
import { PrismaService } from '../../prisma/prisma.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';
import { FeatureDisabledException } from '../exceptions/feature-disabled.exception';

describe('GatingService', () => {
  let service: GatingService;
  let pricing: any;
  let ledger: any;
  let prisma: any;

  beforeEach(async () => {
    pricing = {
      getMinReservePlanck: jest.fn(),
      getConfig: jest.fn(),
    };
    ledger = { getBalance: jest.fn() };
    prisma = {
      userFeatureToggle: { findUnique: jest.fn() },
      aiSession: { create: jest.fn(), update: jest.fn() },
      billingConfig: { findUnique: jest.fn() },
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        GatingService,
        { provide: PricingService, useValue: pricing },
        { provide: LedgerService, useValue: ledger },
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();

    service = moduleRef.get(GatingService);
  });

  const baseConfig = { billingEnforced: true };

  it('throws FeatureDisabledException when toggle is off', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: false });

    await expect(service.startSession('u1', 'voice_assistant')).rejects.toThrow(
      FeatureDisabledException,
    );
  });

  it('throws InsufficientFundsException when balance below minReserve', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: true });
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);
    ledger.getBalance.mockResolvedValue(1_000n);

    await expect(service.startSession('u1', 'voice_assistant')).rejects.toThrow(
      InsufficientFundsException,
    );
  });

  it('creates an active AiSession on success', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: true });
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);
    ledger.getBalance.mockResolvedValue(100_000_000n);
    prisma.aiSession.create.mockResolvedValue({ id: 's1', status: 'active' });

    const session = await service.startSession('u1', 'voice_assistant', 'room42');

    expect(prisma.aiSession.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        userId: 'u1',
        featureKey: 'voice_assistant',
        contextRef: 'room42',
        status: 'active',
      }),
    });
    expect(session.id).toBe('s1');
  });

  it('treats missing toggle row as enabled (default-on)', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue(null);
    pricing.getMinReservePlanck.mockResolvedValue(1n);
    ledger.getBalance.mockResolvedValue(1_000_000n);
    prisma.aiSession.create.mockResolvedValue({ id: 's2' });

    await expect(service.startSession('u1', 'web_search')).resolves.toBeDefined();
  });

  it('skips both gates when billingEnforced=false but still creates session', async () => {
    pricing.getConfig.mockResolvedValue({ billingEnforced: false });
    prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: false });
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);
    ledger.getBalance.mockResolvedValue(0n);
    prisma.aiSession.create.mockResolvedValue({ id: 's3' });

    const s = await service.startSession('u1', 'voice_assistant');
    expect(s.id).toBe('s3');
  });

  it('endSession marks completed', async () => {
    prisma.aiSession.update.mockResolvedValue({ id: 's1', status: 'completed' });

    await service.endSession('s1', 'completed');

    expect(prisma.aiSession.update).toHaveBeenCalledWith({
      where: { id: 's1' },
      data: { status: 'completed', endedAt: expect.any(Date) },
    });
  });
});
```

- [ ] **Step 2: Run test — expect fail**

Run: `cd ~/Downloads/taler_id && npx jest src/billing/services/gating.service.spec.ts`
Expected: FAIL.

- [ ] **Step 3: Implement GatingService**

Create `src/billing/services/gating.service.ts`:

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { PricingService } from './pricing.service';
import { LedgerService } from './ledger.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';
import { FeatureDisabledException } from '../exceptions/feature-disabled.exception';

export type SessionTerminationReason = 'completed' | 'terminated_no_funds' | 'failed';

@Injectable()
export class GatingService {
  private readonly log = new Logger(GatingService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly pricing: PricingService,
    private readonly ledger: LedgerService,
  ) {}

  async startSession(
    userId: string,
    featureKey: string,
    contextRef?: string,
  ): Promise<{ id: string }> {
    const cfg = await this.pricing.getConfig();
    const enforced = (cfg as unknown as { billingEnforced: boolean }).billingEnforced;

    const toggle = await this.prisma.userFeatureToggle.findUnique({
      where: { userId_featureKey: { userId, featureKey } },
    });
    const toggleEnabled = toggle === null ? true : toggle.enabled;

    if (!toggleEnabled) {
      if (enforced) throw new FeatureDisabledException(featureKey);
      this.log.warn(`[dry-run] feature ${featureKey} disabled for ${userId} — would block`);
    }

    const minReserve = await this.pricing.getMinReservePlanck(featureKey);
    const balance = await this.ledger.getBalance(userId);
    if (balance < minReserve) {
      if (enforced) {
        throw new InsufficientFundsException(featureKey, minReserve, balance);
      }
      this.log.warn(
        `[dry-run] insufficient funds for ${userId}/${featureKey}: need ${minReserve}, have ${balance}`,
      );
    }

    return this.prisma.aiSession.create({
      data: {
        userId,
        featureKey,
        contextRef,
        status: 'active',
      },
      select: { id: true },
    });
  }

  async endSession(sessionId: string, reason: SessionTerminationReason): Promise<void> {
    await this.prisma.aiSession.update({
      where: { id: sessionId },
      data: { status: reason, endedAt: new Date() },
    });
  }
}
```

- [ ] **Step 4: Run test — expect pass**

Run: `cd ~/Downloads/taler_id && npx jest src/billing/services/gating.service.spec.ts`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/billing/services/gating.service.ts src/billing/services/gating.service.spec.ts
git commit -m "feat(billing): add GatingService with toggle + minReserve pre-check"
```

---

### Task 5: `MeteringService` — cron deduction

**Files:**
- Create: `src/billing/services/metering.service.ts`
- Create: `src/billing/services/metering.service.spec.ts`

- [ ] **Step 1: Write failing test**

Create `src/billing/services/metering.service.spec.ts`:

```typescript
import { Test } from '@nestjs/testing';
import { MeteringService } from './metering.service';
import { PricingService } from './pricing.service';
import { LedgerService } from './ledger.service';
import { GatingService } from './gating.service';
import { PrismaService } from '../../prisma/prisma.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';

describe('MeteringService', () => {
  let service: MeteringService;
  let prisma: any;
  let pricing: any;
  let ledger: any;
  let gating: any;
  let gateway: any;

  beforeEach(async () => {
    prisma = {
      aiSession: { findMany: jest.fn(), update: jest.fn() },
      usageLog: { create: jest.fn() },
    };
    pricing = { calculatePlanckCost: jest.fn(), getMinReservePlanck: jest.fn(), getConfig: jest.fn() };
    ledger = { debit: jest.fn(), getBalance: jest.fn() };
    gating = { endSession: jest.fn() };
    gateway = { emitToUser: jest.fn() };

    const moduleRef = await Test.createTestingModule({
      providers: [
        MeteringService,
        { provide: PrismaService, useValue: prisma },
        { provide: PricingService, useValue: pricing },
        { provide: LedgerService, useValue: ledger },
        { provide: GatingService, useValue: gating },
        { provide: 'MESSENGER_GATEWAY', useValue: gateway },
      ],
    }).compile();

    service = moduleRef.get(MeteringService);
  });

  it('debits elapsed time for each active voice_assistant session', async () => {
    const now = new Date('2026-04-24T10:00:30Z');
    const startedAt = new Date('2026-04-24T10:00:00Z');

    jest.useFakeTimers().setSystemTime(now);
    prisma.aiSession.findMany.mockResolvedValue([
      {
        id: 's1',
        userId: 'u1',
        featureKey: 'voice_assistant',
        status: 'active',
        lastMeteredAt: startedAt,
        totalSpentPlanck: 0n,
      },
    ]);
    pricing.calculatePlanckCost.mockResolvedValue(12_820_000n); // ~30 sec at rate
    pricing.getConfig.mockResolvedValue({ billingEnforced: true });
    ledger.debit.mockResolvedValue({ id: 'tx1' });
    ledger.getBalance.mockResolvedValue(999_999_999n);
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);

    await service.tick();

    expect(pricing.calculatePlanckCost).toHaveBeenCalledWith('voice_assistant', 0.5); // 30s = 0.5 min
    expect(ledger.debit).toHaveBeenCalledWith(
      'u1',
      12_820_000n,
      'SPEND',
      expect.objectContaining({ featureKey: 'voice_assistant', sessionId: 's1' }),
    );
    expect(prisma.aiSession.update).toHaveBeenCalledWith({
      where: { id: 's1' },
      data: expect.objectContaining({ totalSpentPlanck: { increment: 12_820_000n }, lastMeteredAt: now }),
    });

    jest.useRealTimers();
  });

  it('terminates session and emits ai_session_terminated on InsufficientFunds', async () => {
    prisma.aiSession.findMany.mockResolvedValue([
      {
        id: 's1',
        userId: 'u1',
        featureKey: 'voice_assistant',
        lastMeteredAt: new Date(Date.now() - 10_000),
        totalSpentPlanck: 0n,
        contextRef: 'room42',
      },
    ]);
    pricing.calculatePlanckCost.mockResolvedValue(5_000_000n);
    pricing.getConfig.mockResolvedValue({ billingEnforced: true });
    ledger.debit.mockRejectedValue(
      new InsufficientFundsException('voice_assistant', 5_000_000n, 100n),
    );

    await service.tick();

    expect(gating.endSession).toHaveBeenCalledWith('s1', 'terminated_no_funds');
    expect(gateway.emitToUser).toHaveBeenCalledWith('u1', 'ai_session_terminated', {
      sessionId: 's1',
      reason: 'no_funds',
      featureKey: 'voice_assistant',
      contextRef: 'room42',
    });
  });

  it('emits low_balance_warning when balance < 3× minReserve', async () => {
    prisma.aiSession.findMany.mockResolvedValue([
      {
        id: 's1',
        userId: 'u1',
        featureKey: 'voice_assistant',
        lastMeteredAt: new Date(Date.now() - 10_000),
        totalSpentPlanck: 0n,
      },
    ]);
    pricing.calculatePlanckCost.mockResolvedValue(1_000_000n);
    pricing.getConfig.mockResolvedValue({ billingEnforced: true });
    ledger.debit.mockResolvedValue({ id: 'tx1' });
    ledger.getBalance.mockResolvedValue(50_000_000n); // between 1× and 3× of 26M
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);

    await service.tick();

    expect(gateway.emitToUser).toHaveBeenCalledWith(
      'u1',
      'billing_low_balance_warning',
      expect.objectContaining({ sessionId: 's1' }),
    );
  });

  it('in dry-run, debit errors are swallowed and session continues', async () => {
    prisma.aiSession.findMany.mockResolvedValue([
      {
        id: 's1',
        userId: 'u1',
        featureKey: 'voice_assistant',
        lastMeteredAt: new Date(Date.now() - 10_000),
        totalSpentPlanck: 0n,
      },
    ]);
    pricing.calculatePlanckCost.mockResolvedValue(1_000_000n);
    pricing.getConfig.mockResolvedValue({ billingEnforced: false });
    ledger.debit.mockRejectedValue(new InsufficientFundsException('voice_assistant', 1n, 0n));

    await service.tick();

    expect(gating.endSession).not.toHaveBeenCalled();
    expect(gateway.emitToUser).not.toHaveBeenCalledWith(
      'u1',
      'ai_session_terminated',
      expect.anything(),
    );
  });

  it('reportUsage writes a final adjustment when agent reports more than cron debited', async () => {
    prisma.aiSession.findMany.mockResolvedValue([]);
    pricing.calculatePlanckCost.mockResolvedValue(20_000_000n);
    pricing.getConfig.mockResolvedValue({ billingEnforced: true });
    ledger.debit.mockResolvedValue({ id: 'txAdj' });
    ledger.getBalance.mockResolvedValue(100_000_000n);

    // session already debited 15M; agent says total should be 20M
    prisma.aiSession.update.mockResolvedValue({});
    const getSession = jest.fn().mockResolvedValue({
      id: 's1',
      userId: 'u1',
      featureKey: 'voice_assistant',
      totalSpentPlanck: 15_000_000n,
      status: 'active',
    });
    (prisma.aiSession as any).findUnique = getSession;

    await service.reportUsage('s1', 1.0, 'ai-twin-agent');

    expect(ledger.debit).toHaveBeenCalledWith(
      'u1',
      5_000_000n,
      'SPEND',
      expect.objectContaining({ sessionId: 's1' }),
    );
  });
});
```

- [ ] **Step 2: Run test — expect fail**

Run: `cd ~/Downloads/taler_id && npx jest src/billing/services/metering.service.spec.ts`
Expected: FAIL.

- [ ] **Step 3: Implement MeteringService**

Create `src/billing/services/metering.service.ts`:

```typescript
import { Inject, Injectable, Logger } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import { PrismaService } from '../../prisma/prisma.service';
import { PricingService } from './pricing.service';
import { LedgerService } from './ledger.service';
import { GatingService } from './gating.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';

export interface MeteringGateway {
  emitToUser(userId: string, event: string, payload: unknown): void;
}

// units-per-minute default: for minute-based features, elapsed time is the unit.
// For token-based features, we only react to reportUsage calls.
const MINUTE_BASED = new Set(['voice_assistant', 'ai_twin', 'outbound_call', 'whisper_transcribe']);

@Injectable()
export class MeteringService {
  private readonly log = new Logger(MeteringService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly pricing: PricingService,
    private readonly ledger: LedgerService,
    private readonly gating: GatingService,
    @Inject('MESSENGER_GATEWAY') private readonly gateway: MeteringGateway,
  ) {}

  @Interval(10_000)
  async tick(): Promise<void> {
    const sessions = await this.prisma.aiSession.findMany({ where: { status: 'active' } });
    const cfg = (await this.pricing.getConfig()) as unknown as { billingEnforced: boolean };

    for (const s of sessions) {
      if (!MINUTE_BASED.has(s.featureKey)) continue;

      const now = new Date();
      const elapsedMs = now.getTime() - new Date(s.lastMeteredAt).getTime();
      const elapsedMinutes = elapsedMs / 60_000;
      if (elapsedMinutes <= 0) continue;

      try {
        const cost = await this.pricing.calculatePlanckCost(s.featureKey, elapsedMinutes);
        await this.ledger.debit(s.userId, cost, 'SPEND', {
          featureKey: s.featureKey,
          sessionId: s.id,
          metadata: { unitsUsed: elapsedMinutes, reporter: 'backend-cron' },
        });
        await this.prisma.aiSession.update({
          where: { id: s.id },
          data: { lastMeteredAt: now, totalSpentPlanck: { increment: cost } },
        });
        await this.prisma.usageLog.create({
          data: {
            userId: s.userId,
            sessionId: s.id,
            featureKey: s.featureKey,
            unit: 'minute',
            units: elapsedMinutes.toFixed(4),
            reporter: 'backend',
          },
        });
        await this.checkLowBalanceWarning(s);
      } catch (err) {
        if (err instanceof InsufficientFundsException) {
          if (cfg.billingEnforced) {
            await this.gating.endSession(s.id, 'terminated_no_funds');
            this.gateway.emitToUser(s.userId, 'ai_session_terminated', {
              sessionId: s.id,
              reason: 'no_funds',
              featureKey: s.featureKey,
              contextRef: s.contextRef,
            });
          } else {
            this.log.warn(`[dry-run] would terminate ${s.id} for ${s.userId} — continuing`);
          }
        } else {
          this.log.error(`metering failed for session ${s.id}: ${String(err)}`);
        }
      }
    }
  }

  private async checkLowBalanceWarning(s: { id: string; userId: string; featureKey: string }): Promise<void> {
    const [balance, minReserve] = await Promise.all([
      this.ledger.getBalance(s.userId),
      this.pricing.getMinReservePlanck(s.featureKey),
    ]);
    if (balance < minReserve * 3n && balance >= minReserve) {
      this.gateway.emitToUser(s.userId, 'billing_low_balance_warning', {
        sessionId: s.id,
        balancePlanck: balance.toString(),
        minReservePlanck: minReserve.toString(),
      });
    }
  }

  /**
   * Final adjustment from a client or agent at session end.
   * If agent-reported total > what backend cron already debited, we debit the difference.
   * Never a credit — if agent reports less, we keep the cron-debited amount (trust cron).
   */
  async reportUsage(sessionId: string, totalUnits: number, reporter: string): Promise<void> {
    const s = await this.prisma.aiSession.findUnique({ where: { id: sessionId } });
    if (!s) throw new Error(`session ${sessionId} not found`);

    const totalExpected = await this.pricing.calculatePlanckCost(s.featureKey, totalUnits);
    const diff = totalExpected - s.totalSpentPlanck;

    await this.prisma.usageLog.create({
      data: {
        userId: s.userId,
        sessionId,
        featureKey: s.featureKey,
        unit: 'minute',
        units: totalUnits.toFixed(4),
        reporter,
      },
    });

    if (diff <= 0n) return;

    try {
      await this.ledger.debit(s.userId, diff, 'SPEND', {
        featureKey: s.featureKey,
        sessionId,
        metadata: { unitsUsed: totalUnits, reporter, adjustment: true },
      });
      await this.prisma.aiSession.update({
        where: { id: sessionId },
        data: { totalSpentPlanck: { increment: diff } },
      });
    } catch (err) {
      if (err instanceof InsufficientFundsException) {
        this.log.warn(`final adjustment for ${sessionId} skipped: insufficient funds`);
      } else {
        throw err;
      }
    }
  }

  async heartbeat(sessionId: string): Promise<void> {
    // Just touch lastMeteredAt presence — liveness only, actual deduction happens on cron.
    await this.prisma.aiSession.update({
      where: { id: sessionId },
      data: {}, // no-op update; we rely on cron to drive time-based billing
    });
  }
}
```

- [ ] **Step 4: Run test — expect pass**

Run: `cd ~/Downloads/taler_id && npx jest src/billing/services/metering.service.spec.ts`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/billing/services/metering.service.ts src/billing/services/metering.service.spec.ts
git commit -m "feat(billing): add MeteringService with cron deduction and session termination"
```

---

## Part C — Blockchain Wallet & DepositWatcher

### Task 6: Encryption helper + `WalletService`

**Files:**
- Create: `src/blockchain/crypto/encryption.ts`
- Create: `src/blockchain/wallet.service.ts`
- Create: `src/blockchain/wallet.service.spec.ts`
- Modify: `.env.example`

- [ ] **Step 1: Write encryption helper**

Create `src/blockchain/crypto/encryption.ts`:

```typescript
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const ALG = 'aes-256-gcm';
const IV_LEN = 12;
const SALT_LEN = 16;
const TAG_LEN = 16;

function keyFromSecret(secret: string, salt: Buffer): Buffer {
  return scryptSync(secret, salt, 32);
}

export function encrypt(plaintext: string, secret: string): string {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = keyFromSecret(secret, salt);
  const cipher = createCipheriv(ALG, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, enc]).toString('base64');
}

export function decrypt(ciphertextB64: string, secret: string): string {
  const buf = Buffer.from(ciphertextB64, 'base64');
  const salt = buf.subarray(0, SALT_LEN);
  const iv = buf.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const tag = buf.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const enc = buf.subarray(SALT_LEN + IV_LEN + TAG_LEN);
  const key = keyFromSecret(secret, salt);
  const decipher = createDecipheriv(ALG, key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString('utf8');
}
```

- [ ] **Step 2: Append env vars to `.env.example`**

Append to `.env.example`:

```
# --- TAL Billing ---
WALLET_ENCRYPTION_KEY=change_me_32_bytes_min_for_aes256gcm_derivation
METERING_SHARED_SECRET=change_me_long_random_hex
```

- [ ] **Step 3: Write failing test**

Create `src/blockchain/wallet.service.spec.ts`:

```typescript
import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { WalletService } from './wallet.service';
import { PrismaService } from '../prisma/prisma.service';

jest.mock('@polkadot/api', () => ({
  ApiPromise: { create: jest.fn() },
  WsProvider: jest.fn(),
  Keyring: jest.fn().mockImplementation(() => ({
    addFromMnemonic: jest.fn().mockReturnValue({
      address: '5TestSS58Address',
      sign: jest.fn(),
    }),
  })),
}));
jest.mock('@polkadot/util-crypto', () => ({
  mnemonicGenerate: jest.fn().mockReturnValue('word '.repeat(12).trim()),
  cryptoWaitReady: jest.fn().mockResolvedValue(true),
}));

describe('WalletService', () => {
  let service: WalletService;
  let prisma: any;

  beforeEach(async () => {
    prisma = {
      userWallet: {
        findUnique: jest.fn(),
        create: jest.fn(),
      },
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        WalletService,
        { provide: PrismaService, useValue: prisma },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((k: string) =>
              k === 'WALLET_ENCRYPTION_KEY' ? 'unit-test-secret-key-32chars-xxxxxxxx' : undefined,
            ),
          },
        },
      ],
    }).compile();
    service = moduleRef.get(WalletService);
  });

  it('getOrCreate creates wallet with encrypted mnemonic when missing', async () => {
    prisma.userWallet.findUnique.mockResolvedValue(null);
    prisma.userWallet.create.mockImplementation(({ data }: any) =>
      Promise.resolve({ ...data, userId: 'u1', balancePlanck: 0n }),
    );

    const w = await service.getOrCreate('u1');
    expect(prisma.userWallet.create).toHaveBeenCalled();
    const createdArg = prisma.userWallet.create.mock.calls[0][0].data;
    expect(createdArg.userId).toBe('u1');
    expect(createdArg.custodialAddress).toBe('5TestSS58Address');
    expect(createdArg.custodialKeyEnc).not.toContain('word'); // encrypted, not plain
    expect(w.custodialAddress).toBe('5TestSS58Address');
  });

  it('getOrCreate returns existing wallet without re-creating', async () => {
    prisma.userWallet.findUnique.mockResolvedValue({
      userId: 'u1',
      custodialAddress: 'existing',
      custodialKeyEnc: 'x',
      balancePlanck: 42n,
    });

    const w = await service.getOrCreate('u1');
    expect(prisma.userWallet.create).not.toHaveBeenCalled();
    expect(w.custodialAddress).toBe('existing');
  });
});
```

- [ ] **Step 4: Run test — expect fail**

Run: `cd ~/Downloads/taler_id && npx jest src/blockchain/wallet.service.spec.ts`
Expected: FAIL.

- [ ] **Step 5: Implement WalletService**

Create `src/blockchain/wallet.service.ts`:

```typescript
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Keyring } from '@polkadot/api';
import { mnemonicGenerate, cryptoWaitReady } from '@polkadot/util-crypto';
import { PrismaService } from '../prisma/prisma.service';
import { encrypt, decrypt } from './crypto/encryption';

const SS58_PREFIX = 10960;

@Injectable()
export class WalletService implements OnModuleInit {
  private readonly log = new Logger(WalletService.name);
  private keyring?: Keyring;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  async onModuleInit() {
    await cryptoWaitReady();
    this.keyring = new Keyring({ type: 'sr25519', ss58Format: SS58_PREFIX });
  }

  private getEncryptionKey(): string {
    const k = this.config.get<string>('WALLET_ENCRYPTION_KEY');
    if (!k || k.length < 32) {
      throw new Error('WALLET_ENCRYPTION_KEY must be set (>=32 chars)');
    }
    return k;
  }

  async getOrCreate(userId: string): Promise<{
    userId: string;
    custodialAddress: string;
    balancePlanck: bigint;
  }> {
    const existing = await this.prisma.userWallet.findUnique({ where: { userId } });
    if (existing) return existing;

    if (!this.keyring) {
      await cryptoWaitReady();
      this.keyring = new Keyring({ type: 'sr25519', ss58Format: SS58_PREFIX });
    }

    const mnemonic = mnemonicGenerate();
    const pair = this.keyring.addFromMnemonic(mnemonic);
    const enc = encrypt(mnemonic, this.getEncryptionKey());

    const w = await this.prisma.userWallet.create({
      data: {
        userId,
        custodialAddress: pair.address,
        custodialKeyEnc: enc,
        balancePlanck: 0n,
      },
    });

    this.log.log(`created custodial wallet ${pair.address} for user ${userId}`);
    return w;
  }

  /**
   * Decrypt a user's mnemonic for signing. Never return this over the wire.
   */
  async loadKeypairForSigning(userId: string) {
    const w = await this.prisma.userWallet.findUnique({ where: { userId } });
    if (!w) throw new Error(`no wallet for user ${userId}`);
    const mnemonic = decrypt(w.custodialKeyEnc, this.getEncryptionKey());
    if (!this.keyring) {
      await cryptoWaitReady();
      this.keyring = new Keyring({ type: 'sr25519', ss58Format: SS58_PREFIX });
    }
    return this.keyring.addFromMnemonic(mnemonic);
  }
}
```

- [ ] **Step 6: Run test — expect pass**

Run: `cd ~/Downloads/taler_id && npx jest src/blockchain/wallet.service.spec.ts`
Expected: 2 passed.

- [ ] **Step 7: Commit**

```bash
git add src/blockchain/crypto/ src/blockchain/wallet.service.ts src/blockchain/wallet.service.spec.ts .env.example
git commit -m "feat(blockchain): add custodial WalletService with AES-GCM key encryption"
```

---

### Task 7: `DepositWatcher`

**Files:**
- Create: `src/blockchain/deposit-watcher.service.ts`
- Modify: `src/blockchain/blockchain.module.ts`

- [ ] **Step 1: Implement DepositWatcher**

Create `src/blockchain/deposit-watcher.service.ts`:

```typescript
import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ApiPromise, WsProvider } from '@polkadot/api';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { LedgerService } from '../billing/services/ledger.service';

@Injectable()
export class DepositWatcher implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger(DepositWatcher.name);
  private api?: ApiPromise;
  private unsubscribe?: () => void;

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly ledger: LedgerService,
  ) {}

  async onModuleInit(): Promise<void> {
    if (this.config.get<string>('BLOCKCHAIN_ENABLED') !== 'true') {
      this.log.warn('BLOCKCHAIN_ENABLED != true, skipping deposit watcher');
      return;
    }
    const url = this.config.get<string>('BLOCKCHAIN_NODE_URL', 'wss://node.dev.gsmsoft.eu/');
    const provider = new WsProvider(url);
    this.api = await ApiPromise.create({ provider });
    this.log.log(`deposit watcher connected to ${url}`);

    this.unsubscribe = await this.api.query.system.events(async (events: any) => {
      for (const record of events) {
        const { event } = record;
        if (event.section !== 'balances' || event.method !== 'Transfer') continue;
        const [from, to, amount] = event.data.toJSON() as [string, string, string | number];
        try {
          await this.handleTransfer(String(to), String(from), BigInt(amount));
        } catch (err) {
          this.log.error(`failed to handle transfer: ${String(err)}`);
        }
      }
    });
  }

  async onModuleDestroy(): Promise<void> {
    try { this.unsubscribe?.(); } catch {}
    try { await this.api?.disconnect(); } catch {}
  }

  private async handleTransfer(toAddress: string, fromAddress: string, amount: bigint): Promise<void> {
    const wallet = await this.prisma.userWallet.findUnique({ where: { custodialAddress: toAddress } });
    if (!wallet) return; // transfer to unrelated address

    // Idempotency: skip if already credited by chainTxHash — but events() does not
    // give us block+index reliably here. Accept that for MVP we rely on events() being fired
    // once per subscription, and we log raw event data in metadata for debugging.
    await this.ledger.credit(wallet.userId, amount, 'TOPUP_ONCHAIN', {
      fromAddress,
      toAddress,
    });
    this.log.log(`credited ${amount} planck to ${wallet.userId} from ${fromAddress}`);
  }
}
```

- [ ] **Step 2: Register in BlockchainModule**

Modify `src/blockchain/blockchain.module.ts`:

```typescript
import { Module, forwardRef } from '@nestjs/common';
import { BlockchainService } from './blockchain.service';
import { BlockchainController } from './blockchain.controller';
import { WalletService } from './wallet.service';
import { DepositWatcher } from './deposit-watcher.service';
import { PrismaModule } from '../prisma/prisma.module';
import { BillingModule } from '../billing/billing.module';

@Module({
  imports: [PrismaModule, forwardRef(() => BillingModule)],
  providers: [BlockchainService, WalletService, DepositWatcher],
  controllers: [BlockchainController],
  exports: [BlockchainService, WalletService],
})
export class BlockchainModule {}
```

- [ ] **Step 3: Commit**

```bash
git add src/blockchain/deposit-watcher.service.ts src/blockchain/blockchain.module.ts
git commit -m "feat(blockchain): add DepositWatcher for on-chain TAL top-ups"
```

Note: This step has no unit test — the watcher is I/O-heavy and best tested via the smoke-test end-to-end (Task 20). Integration test verifies on DEV that sending TAL to a custodial address credits the user.

---

## Part D — REST API, Socket.io, Admin

### Task 8: `BillingModule` + user endpoints + DTOs + packages constant

**Files:**
- Create: `src/billing/billing.module.ts`
- Create: `src/billing/constants/packages.ts`
- Create: `src/billing/dto/balance.dto.ts`
- Create: `src/billing/dto/purchase.dto.ts`
- Create: `src/billing/dto/toggle.dto.ts`
- Create: `src/billing/controllers/billing.controller.ts`
- Modify: `src/app.module.ts`

- [ ] **Step 1: Write packages constant**

Create `src/billing/constants/packages.ts`:

```typescript
export interface BillingPackage {
  id: 'starter' | 'pro' | 'business';
  amountPlanck: bigint;
  priceEurCents: number; // display-only stub
  label: { ru: string; en: string };
  highlights: { ru: string[]; en: string[] };
}

export const PACKAGES: BillingPackage[] = [
  {
    id: 'starter',
    amountPlanck: 430_000_000n, // 430 μTAL
    priceEurCents: 464,
    label: { ru: 'Starter', en: 'Starter' },
    highlights: {
      ru: ['~17 мин ассистента', '~500 веб-поисков', '~12 мин обзвона'],
      en: ['~17 min assistant', '~500 web searches', '~12 min outbound'],
    },
  },
  {
    id: 'pro',
    amountPlanck: 2_140_000_000n,
    priceEurCents: 2311,
    label: { ru: 'Pro', en: 'Pro' },
    highlights: {
      ru: ['~83 мин ассистента', '~2500 веб-поисков', '~62 мин обзвона'],
      en: ['~83 min assistant', '~2500 web searches', '~62 min outbound'],
    },
  },
  {
    id: 'business',
    amountPlanck: 10_260_000_000n,
    priceEurCents: 11081,
    label: { ru: 'Business', en: 'Business' },
    highlights: {
      ru: ['~400 мин ассистента', '~12 000 веб-поисков', '~300 мин обзвона'],
      en: ['~400 min assistant', '~12k web searches', '~300 min outbound'],
    },
  },
];

export const PACKAGES_BY_ID = Object.fromEntries(PACKAGES.map((p) => [p.id, p]));
```

- [ ] **Step 2: Write DTOs**

Create `src/billing/dto/balance.dto.ts`:

```typescript
export class BalanceResponseDto {
  balancePlanck!: string;
  balanceMicroTal!: string; // 2 decimals
  recentTx!: Array<{
    id: string;
    type: string;
    amountPlanck: string;
    featureKey: string | null;
    createdAt: string;
  }>;
}
```

Create `src/billing/dto/purchase.dto.ts`:

```typescript
export class PurchaseResponseDto {
  txId!: string;
  newBalancePlanck!: string;
  packageId!: string;
}
```

Create `src/billing/dto/toggle.dto.ts`:

```typescript
import { IsBoolean } from 'class-validator';

export class UpdateToggleDto {
  @IsBoolean()
  enabled!: boolean;
}
```

- [ ] **Step 3: Write user BillingController**

Create `src/billing/controllers/billing.controller.ts`:

```typescript
import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Post,
  UseFilters,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerService } from '../services/ledger.service';
import { PricingService } from '../services/pricing.service';
import { WalletService } from '../../blockchain/wallet.service';
import { BillingExceptionFilter } from '../filters/billing-exception.filter';
import { PACKAGES, PACKAGES_BY_ID } from '../constants/packages';
import { ALL_FEATURE_KEYS } from '../constants/feature-keys';
import { UpdateToggleDto } from '../dto/toggle.dto';

function planckToMicroTal(p: bigint): string {
  // 1 μTAL = 10^6 planck
  const whole = p / 1_000_000n;
  const frac = Number(p % 1_000_000n) / 1_000_000;
  return (Number(whole) + frac).toFixed(2);
}

@Controller('billing')
@UseGuards(AuthGuard('jwt'))
@UseFilters(BillingExceptionFilter)
export class BillingController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
    private readonly wallet: WalletService,
  ) {}

  @Get('balance')
  async getBalance(@CurrentUser() userId: string) {
    const [balance, txs] = await Promise.all([
      this.ledger.getBalance(userId),
      this.prisma.billingTransaction.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: 10,
      }),
    ]);
    return {
      balancePlanck: balance.toString(),
      balanceMicroTal: planckToMicroTal(balance),
      recentTx: txs.map((t) => ({
        id: t.id,
        type: t.type,
        amountPlanck: t.amountPlanck.toString(),
        featureKey: t.featureKey,
        createdAt: t.createdAt.toISOString(),
      })),
    };
  }

  @Get('packages')
  async getPackages() {
    return PACKAGES.map((p) => ({
      ...p,
      amountPlanck: p.amountPlanck.toString(),
    }));
  }

  @Post('purchase/:pkgId')
  async purchase(@CurrentUser() userId: string, @Param('pkgId') pkgId: string) {
    const pkg = PACKAGES_BY_ID[pkgId];
    if (!pkg) throw new Error(`unknown package ${pkgId}`);

    // Ensure wallet exists before crediting
    await this.wallet.getOrCreate(userId);

    const tx = await this.ledger.credit(userId, pkg.amountPlanck, 'TOPUP_STUB', {
      packageId: pkgId,
      source: 'stub',
    });
    const newBalance = await this.ledger.getBalance(userId);
    return {
      txId: tx.id,
      newBalancePlanck: newBalance.toString(),
      packageId: pkgId,
    };
  }

  @Get('wallet')
  async getWallet(@CurrentUser() userId: string) {
    const w = await this.wallet.getOrCreate(userId);
    return { custodialAddress: w.custodialAddress };
  }

  @Get('transactions')
  async getTransactions(@CurrentUser() userId: string) {
    const txs = await this.prisma.billingTransaction.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });
    return txs.map((t) => ({
      id: t.id,
      type: t.type,
      status: t.status,
      amountPlanck: t.amountPlanck.toString(),
      featureKey: t.featureKey,
      sessionId: t.sessionId,
      metadata: t.metadata,
      createdAt: t.createdAt.toISOString(),
    }));
  }

  @Get('pricebook')
  async getPricebook() {
    const rows = await this.prisma.aiPricebook.findMany();
    return rows.map((r) => ({
      featureKey: r.featureKey,
      unit: r.unit,
      costUsdPerUnit: r.costUsdPerUnit.toString(),
      markupMultiplier: r.markupMultiplier.toString(),
      minReservePlanck: r.minReservePlanck.toString(),
    }));
  }

  @Get('settings/toggles')
  async getToggles(@CurrentUser() userId: string) {
    const rows = await this.prisma.userFeatureToggle.findMany({ where: { userId } });
    const map = new Map(rows.map((r) => [r.featureKey, r.enabled]));
    return ALL_FEATURE_KEYS.map((f) => ({
      featureKey: f,
      enabled: map.has(f) ? map.get(f) : true,
    }));
  }

  @Patch('settings/toggles/:featureKey')
  async patchToggle(
    @CurrentUser() userId: string,
    @Param('featureKey') featureKey: string,
    @Body() body: UpdateToggleDto,
  ) {
    await this.prisma.userFeatureToggle.upsert({
      where: { userId_featureKey: { userId, featureKey } },
      create: { userId, featureKey, enabled: body.enabled },
      update: { enabled: body.enabled },
    });
    return { featureKey, enabled: body.enabled };
  }
}

// Simple decorator that extracts user id from JWT payload. If the project already has one,
// use it and remove this duplicate.
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
export const CurrentUser = createParamDecorator((_: unknown, ctx: ExecutionContext) => {
  const req = ctx.switchToHttp().getRequest();
  return req.user?.sub ?? req.user?.id;
});
```

Before running, check if `@CurrentUser()` or equivalent already exists in the project. Run: `grep -rn "createParamDecorator\|@CurrentUser" src/auth src/common 2>/dev/null | head -5`. If so, import that one and delete the local redefinition at the bottom of this file.

- [ ] **Step 4: Write BillingModule**

Create `src/billing/billing.module.ts`:

```typescript
import { Module, forwardRef } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from '../prisma/prisma.module';
import { BlockchainModule } from '../blockchain/blockchain.module';
import { PricingService } from './services/pricing.service';
import { LedgerService } from './services/ledger.service';
import { GatingService } from './services/gating.service';
import { MeteringService } from './services/metering.service';
import { BillingController } from './controllers/billing.controller';

@Module({
  imports: [PrismaModule, ScheduleModule.forRoot(), forwardRef(() => BlockchainModule)],
  providers: [
    PricingService,
    LedgerService,
    GatingService,
    MeteringService,
    // MESSENGER_GATEWAY provider is wired in messenger.module.ts via global or forward-ref
    // For now, provide a stub that no-ops; messenger.module will override on import
    {
      provide: 'MESSENGER_GATEWAY',
      useValue: {
        emitToUser: () => {
          /* no-op; real impl wired in messenger.module */
        },
      },
    },
  ],
  controllers: [BillingController],
  exports: [PricingService, LedgerService, GatingService, MeteringService],
})
export class BillingModule {}
```

- [ ] **Step 5: Register in AppModule**

Modify `src/app.module.ts` — add to the imports array:

```typescript
import { BillingModule } from './billing/billing.module';
// … inside @Module({ imports: [..., BillingModule, ...] }) …
```

Find the line starting with `imports:` and append `BillingModule`.

- [ ] **Step 6: Build and smoke-test endpoints locally**

Run:
```bash
cd ~/Downloads/taler_id
npm run build
```
Expected: build passes with no type errors.

Then start dev:
```bash
npm run start:dev
```
In a separate shell, curl `/billing/packages` (no auth required for this endpoint? If your `JWT` guard is per-controller, this whole controller is guarded — test with a real JWT). Run:
```bash
# Obtain a JWT (example):
TOKEN=$(curl -s -X POST http://localhost:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"integration_test@taler-test.com","password":"IntegrationTest123!"}' \
  | jq -r .accessToken)
curl -s http://localhost:3000/billing/packages -H "authorization: Bearer $TOKEN" | jq
```
Expected: JSON array with 3 packages including `amountPlanck` as string.

- [ ] **Step 7: Commit**

```bash
git add src/billing/ src/app.module.ts
git commit -m "feat(billing): add BillingModule with user REST endpoints and 3 package defs"
```

---

### Task 9: Metering endpoints + shared-secret guard

**Files:**
- Create: `src/billing/guards/metering-secret.guard.ts`
- Create: `src/billing/dto/report.dto.ts`
- Create: `src/billing/controllers/metering.controller.ts`
- Modify: `src/billing/billing.module.ts`

- [ ] **Step 1: Write guard**

Create `src/billing/guards/metering-secret.guard.ts`:

```typescript
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MeteringSecretGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const header = req.headers['x-metering-secret'];
    const expected = this.config.get<string>('METERING_SHARED_SECRET');
    if (!expected) throw new UnauthorizedException('metering secret not configured');
    if (header !== expected) throw new UnauthorizedException('bad metering secret');
    return true;
  }
}
```

- [ ] **Step 2: Write DTO**

Create `src/billing/dto/report.dto.ts`:

```typescript
import { IsNumber, IsString, Min } from 'class-validator';

export class ReportUsageDto {
  @IsString()
  sessionId!: string;

  @IsNumber()
  @Min(0)
  units!: number;

  @IsString()
  reporter!: string;
}

export class HeartbeatDto {
  @IsString()
  sessionId!: string;
}
```

- [ ] **Step 3: Write controller**

Create `src/billing/controllers/metering.controller.ts`:

```typescript
import { Body, Controller, Post, UseFilters, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { MeteringService } from '../services/metering.service';
import { MeteringSecretGuard } from '../guards/metering-secret.guard';
import { ReportUsageDto, HeartbeatDto } from '../dto/report.dto';
import { BillingExceptionFilter } from '../filters/billing-exception.filter';

@Controller('metering')
@UseFilters(BillingExceptionFilter)
export class MeteringController {
  constructor(private readonly metering: MeteringService) {}

  // Agents (ai-twin-agent, outbound-call-agent) call this with shared-secret header.
  @Post('report')
  @UseGuards(MeteringSecretGuard)
  async report(@Body() body: ReportUsageDto) {
    await this.metering.reportUsage(body.sessionId, body.units, body.reporter);
    return { ok: true };
  }

  // Mobile clients call this for liveness — JWT-authenticated.
  @Post('heartbeat')
  @UseGuards(AuthGuard('jwt'))
  async heartbeat(@Body() body: HeartbeatDto) {
    await this.metering.heartbeat(body.sessionId);
    return { ok: true };
  }
}
```

- [ ] **Step 4: Register controller**

Modify `src/billing/billing.module.ts` — add to `controllers` array:

```typescript
import { MeteringController } from './controllers/metering.controller';
// ...
controllers: [BillingController, MeteringController],
```

- [ ] **Step 5: Build**

Run: `cd ~/Downloads/taler_id && npm run build`
Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add src/billing/guards/ src/billing/dto/report.dto.ts src/billing/controllers/metering.controller.ts src/billing/billing.module.ts
git commit -m "feat(billing): add metering endpoints (report for agents, heartbeat for clients)"
```

---

### Task 10: Admin endpoints

**Files:**
- Create: `src/billing/dto/admin.dto.ts`
- Create: `src/billing/controllers/admin-billing.controller.ts`
- Modify: `src/billing/billing.module.ts`

- [ ] **Step 1: Write DTOs**

Create `src/billing/dto/admin.dto.ts`:

```typescript
import { IsOptional, IsNumberString, IsString, IsBoolean, IsNumber } from 'class-validator';

export class AdminCreditDto {
  @IsNumberString()
  amountPlanck!: string;

  @IsString()
  reason!: string;
}

export class AdminUpdatePricebookDto {
  @IsOptional()
  @IsNumberString()
  costUsdPerUnit?: string;

  @IsOptional()
  @IsNumberString()
  markupMultiplier?: string;

  @IsOptional()
  @IsNumberString()
  minReservePlanck?: string;
}

export class AdminUpdateConfigDto {
  @IsOptional()
  @IsNumberString()
  talUsdRate?: string;

  @IsOptional()
  @IsBoolean()
  billingEnforced?: boolean;

  @IsOptional()
  @IsNumberString()
  welcomeBonusPlanck?: string;
}
```

- [ ] **Step 2: Write controller**

Create `src/billing/controllers/admin-billing.controller.ts`:

```typescript
import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerService } from '../services/ledger.service';
import { PricingService } from '../services/pricing.service';
import { AdminCreditDto, AdminUpdatePricebookDto, AdminUpdateConfigDto } from '../dto/admin.dto';
import { CurrentUser } from './billing.controller';

@Controller('admin/billing')
@UseGuards(AuthGuard('jwt'))
export class AdminBillingController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
  ) {}

  private async assertAdmin(userId: string): Promise<void> {
    const u = await this.prisma.user.findUnique({ where: { id: userId }, select: { isAdmin: true } });
    if (!u?.isAdmin) throw new ForbiddenException('admin only');
  }

  @Get('users/:id')
  async getUser(@CurrentUser() actor: string, @Param('id') targetId: string) {
    await this.assertAdmin(actor);
    const [wallet, txs, sessions] = await Promise.all([
      this.prisma.userWallet.findUnique({ where: { userId: targetId } }),
      this.prisma.billingTransaction.findMany({
        where: { userId: targetId },
        orderBy: { createdAt: 'desc' },
        take: 50,
      }),
      this.prisma.aiSession.findMany({
        where: { userId: targetId },
        orderBy: { startedAt: 'desc' },
        take: 20,
      }),
    ]);
    return {
      wallet: wallet
        ? { address: wallet.custodialAddress, balancePlanck: wallet.balancePlanck.toString() }
        : null,
      transactions: txs.map((t) => ({ ...t, amountPlanck: t.amountPlanck.toString() })),
      sessions: sessions.map((s) => ({
        ...s,
        totalSpentPlanck: s.totalSpentPlanck.toString(),
      })),
    };
  }

  @Post('users/:id/credit')
  async credit(@CurrentUser() actor: string, @Param('id') targetId: string, @Body() body: AdminCreditDto) {
    await this.assertAdmin(actor);
    const tx = await this.ledger.credit(targetId, BigInt(body.amountPlanck), 'ADMIN_CREDIT', {
      actor,
      reason: body.reason,
    });
    return { txId: tx.id };
  }

  @Patch('pricebook/:featureKey')
  async updatePricebook(
    @CurrentUser() actor: string,
    @Param('featureKey') featureKey: string,
    @Body() body: AdminUpdatePricebookDto,
  ) {
    await this.assertAdmin(actor);
    const data: any = {};
    if (body.costUsdPerUnit !== undefined) data.costUsdPerUnit = body.costUsdPerUnit;
    if (body.markupMultiplier !== undefined) data.markupMultiplier = body.markupMultiplier;
    if (body.minReservePlanck !== undefined) data.minReservePlanck = BigInt(body.minReservePlanck);
    const row = await this.prisma.aiPricebook.update({ where: { featureKey }, data });
    this.pricing.invalidateCache();
    return row;
  }

  @Patch('config')
  async updateConfig(@CurrentUser() actor: string, @Body() body: AdminUpdateConfigDto) {
    await this.assertAdmin(actor);
    const data: any = {};
    if (body.talUsdRate !== undefined) data.talUsdRate = body.talUsdRate;
    if (body.billingEnforced !== undefined) data.billingEnforced = body.billingEnforced;
    if (body.welcomeBonusPlanck !== undefined)
      data.welcomeBonusPlanck = BigInt(body.welcomeBonusPlanck);
    const row = await this.prisma.billingConfig.update({ where: { id: 'singleton' }, data });
    this.pricing.invalidateCache();
    return row;
  }
}
```

- [ ] **Step 3: Register controller**

Modify `src/billing/billing.module.ts` controllers array:

```typescript
import { AdminBillingController } from './controllers/admin-billing.controller';
// ...
controllers: [BillingController, MeteringController, AdminBillingController],
```

- [ ] **Step 4: Build and test**

Run: `cd ~/Downloads/taler_id && npm run build` → expect pass.

Manual smoke:
```bash
# Set an admin JWT (use an account with isAdmin=true in DB first)
curl -s -X PATCH http://localhost:3000/admin/billing/pricebook/voice_assistant \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"markupMultiplier":"2.5"}' | jq
```
Expected: updated row with new markup.

- [ ] **Step 5: Commit**

```bash
git add src/billing/dto/admin.dto.ts src/billing/controllers/admin-billing.controller.ts src/billing/billing.module.ts
git commit -m "feat(billing): add admin endpoints for users/pricebook/config"
```

---

### Task 11: Socket.io events in messenger gateway

**Files:**
- Modify: `src/messenger/messenger.gateway.ts`
- Modify: `src/messenger/messenger.module.ts`
- Modify: `src/billing/billing.module.ts`

- [ ] **Step 1: Inspect existing messenger gateway**

Run: `grep -n "emitToUser\|@WebSocketGateway\|@SubscribeMessage\|server:" ~/Downloads/taler_id/src/messenger/messenger.gateway.ts | head -30`

Note existing emit pattern. The goal is to expose the already-existing per-user emit helper as the `MESSENGER_GATEWAY` provider token so `MeteringService` can call `emitToUser(userId, event, payload)`.

- [ ] **Step 2: Add `emitToUser` helper if missing, otherwise verify**

Modify `src/messenger/messenger.gateway.ts`. Inside the `MessengerGateway` class, add (if not already present):

```typescript
  /**
   * Emit an event to every socket connected by the given user.
   * Used by BillingModule (MESSENGER_GATEWAY provider) for balance and session events.
   */
  emitToUser(userId: string, event: string, payload: unknown): void {
    this.server.to(`user:${userId}`).emit(event, payload);
  }
```

Verify sockets join a `user:${userId}` room on connect — most existing emit logic already does this. If not, add in the connection handler:

```typescript
  // Inside handleConnection or equivalent:
  client.join(`user:${user.id}`);
```

- [ ] **Step 3: Register gateway as MESSENGER_GATEWAY provider**

Modify `src/messenger/messenger.module.ts`. Replace the `providers` array to include a re-export under the token:

```typescript
import { MessengerGateway } from './messenger.gateway';
// ... existing imports

@Module({
  // ... existing imports/controllers
  providers: [
    /* existing providers */
    MessengerGateway,
    { provide: 'MESSENGER_GATEWAY', useExisting: MessengerGateway },
  ],
  exports: [
    /* existing exports */
    MessengerGateway,
    'MESSENGER_GATEWAY',
  ],
})
export class MessengerModule {}
```

- [ ] **Step 4: Remove stub provider from BillingModule**

Modify `src/billing/billing.module.ts`: delete the stub `{ provide: 'MESSENGER_GATEWAY', useValue: … }` block. Instead, import `MessengerModule` with `forwardRef`:

```typescript
import { forwardRef } from '@nestjs/common';
import { MessengerModule } from '../messenger/messenger.module';

@Module({
  imports: [PrismaModule, ScheduleModule.forRoot(), forwardRef(() => BlockchainModule), forwardRef(() => MessengerModule)],
  // ... rest unchanged, no MESSENGER_GATEWAY stub
})
```

- [ ] **Step 5: Build and verify wiring**

Run: `cd ~/Downloads/taler_id && npm run build`
Expected: pass. If "Nest can't resolve dependencies of MeteringService (?)" — the forward-ref to MessengerModule is the fix.

- [ ] **Step 6: Emit `billing_balance_changed` after every ledger operation**

Modify `src/billing/services/ledger.service.ts` to emit the balance-change event. Add the gateway dep to the constructor and emit after each successful `credit`, `debit`, `refund`. The shape is: refactor each method from returning directly to storing the result, emitting, then returning.

```typescript
import { Inject } from '@nestjs/common';
import type { MeteringGateway } from './metering.service';

  constructor(
    private readonly prisma: PrismaService,
    @Inject('MESSENGER_GATEWAY') private readonly gateway: MeteringGateway,
  ) {}

  private async emitBalance(userId: string, reason: string, txId: string): Promise<void> {
    const w = await this.prisma.userWallet.findUnique({
      where: { userId },
      select: { balancePlanck: true },
    });
    this.gateway.emitToUser(userId, 'billing_balance_changed', {
      balancePlanck: w?.balancePlanck.toString(),
      reason,
      txId,
    });
  }
```

Then refactor each public method:

```typescript
  async credit(userId, amountPlanck, type, metadata?, extras?) {
    // ... validation unchanged
    const result = await this.prisma.$transaction(async (tx) => {
      // ... existing body unchanged, still returns tx.billingTransaction.create(...)
    });
    await this.emitBalance(userId, type, result.id);
    return result;
  }

  async debit(userId, amountPlanck, type, extras = {}) {
    // ... validation unchanged
    const result = await this.prisma.$transaction(async (tx) => {
      // ... existing body unchanged
    });
    await this.emitBalance(userId, type, result.id);
    return result;
  }

  async refund(originalTxId, reason) {
    const result = await this.prisma.$transaction(async (tx) => {
      // ... existing body unchanged
    });
    // result.userId isn't on the return shape — fetch from orig inside tx and hoist out,
    // OR re-read:
    const refundTx = await this.prisma.billingTransaction.findUnique({ where: { id: result.id } });
    if (refundTx) await this.emitBalance(refundTx.userId, 'REFUND', result.id);
    return result;
  }
```

Update `src/billing/services/ledger.service.spec.ts` to pass a mock gateway:

```typescript
const gateway = { emitToUser: jest.fn() };
// Add to providers:
    { provide: 'MESSENGER_GATEWAY', useValue: gateway },
// Add assertions in each test:
    expect(gateway.emitToUser).toHaveBeenCalledWith(
      'u1',
      'billing_balance_changed',
      expect.objectContaining({ reason: 'TOPUP_STUB' }),
    );
```

Rerun: `npx jest src/billing/services/ledger.service.spec.ts` → expect pass.

- [ ] **Step 7: Emit `ai_session_started` in GatingService.startSession**

Modify `src/billing/services/gating.service.ts`. Inject the gateway and emit right before returning the session:

```typescript
  constructor(
    private readonly prisma: PrismaService,
    private readonly pricing: PricingService,
    private readonly ledger: LedgerService,
    @Inject('MESSENGER_GATEWAY') private readonly gateway: { emitToUser: (u: string, e: string, p: unknown) => void },
  ) {}

  // At the tail of startSession, after creating the AiSession:
    this.gateway.emitToUser(userId, 'ai_session_started', {
      sessionId: session.id,
      featureKey,
    });
    return session;
```

Also emit `ai_session_terminated` from `endSession` when `reason !== 'completed'` (so `failed` also notifies client):

```typescript
  async endSession(sessionId: string, reason: SessionTerminationReason): Promise<void> {
    const session = await this.prisma.aiSession.update({
      where: { id: sessionId },
      data: { status: reason, endedAt: new Date() },
    });
    if (reason !== 'completed') {
      this.gateway.emitToUser(session.userId, 'ai_session_terminated', {
        sessionId,
        reason: reason === 'terminated_no_funds' ? 'no_funds' : 'failed',
        featureKey: session.featureKey,
      });
    }
  }
```

Update `gating.service.spec.ts` to pass the mock gateway provider (same pattern as ledger test above) and add one assertion per startSession success test.

Rerun: `npx jest src/billing/services/gating.service.spec.ts` → expect pass.

- [ ] **Step 8: Commit**

```bash
git add src/messenger/messenger.gateway.ts src/messenger/messenger.module.ts src/billing/
git commit -m "feat(billing): wire MessengerGateway + emit balance_changed and ai_session_* events"
```

---

## Part E — Feature Integrations

For every feature, the integration pattern is:

1. Import `GatingService` (+ `MeteringService` / `LedgerService` + `PricingService` if needed).
2. Before starting paid work, call `gating.startSession(userId, featureKey, contextRef)`. Let `InsufficientFundsException` / `FeatureDisabledException` propagate (filters map to 402/403).
3. For one-shot features (web_search, whisper, summary): after the API call, either `ledger.debit` exact amount (happy path) or `ledger.refund` (on error). Then `gating.endSession(sessionId, 'completed')`.
4. For time-based features (voice_assistant, ai_twin, outbound_call): cron handles ongoing deduction. At session close, call `metering.reportUsage` with actual duration, then `gating.endSession`.

### Task 12: `voice_assistant` integration

**Files:**
- Modify: `src/voice/voice.service.ts`
- Modify: `src/voice/voice.module.ts`

- [ ] **Step 1: Import BillingModule in VoiceModule**

Modify `src/voice/voice.module.ts`:

```typescript
import { Module } from "@nestjs/common";
import { VoiceController } from "./voice.controller";
import { VoiceService } from "./voice.service";
import { FileStorageService } from "../common/file-storage.service";
import { BillingModule } from "../billing/billing.module";
import { PrismaModule } from "../prisma/prisma.module";

@Module({
  imports: [BillingModule, PrismaModule],
  controllers: [VoiceController],
  providers: [VoiceService, FileStorageService],
})
export class VoiceModule {}
```

- [ ] **Step 2: Inject services into VoiceService constructor**

Modify `src/voice/voice.service.ts` — locate the class constructor and add:

```typescript
import { GatingService } from '../billing/services/gating.service';
import { MeteringService } from '../billing/services/metering.service';
import { LedgerService } from '../billing/services/ledger.service';
import { PricingService } from '../billing/services/pricing.service';
import { FEATURE_KEYS } from '../billing/constants/feature-keys';

// In the constructor parameter list, add:
  constructor(
    // ... existing deps
    private readonly gating: GatingService,
    private readonly metering: MeteringService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
  ) { /* ... */ }
```

- [ ] **Step 3: Wrap `createVoiceSession` with gating**

Find `createVoiceSession` around line 194 of `src/voice/voice.service.ts`. Wrap the current body:

```typescript
async createVoiceSession(userId: string, /* existing args */) {
  const session = await this.gating.startSession(userId, FEATURE_KEYS.VOICE_ASSISTANT);

  try {
    // ... existing code that POSTs to api.openai.com/v1/realtime/sessions
    const clientSecret = /* ... existing value ... */;
    return { clientSecret, billingSessionId: session.id }; // expose sessionId so client can heartbeat and report
  } catch (err) {
    await this.gating.endSession(session.id, 'failed');
    throw err;
  }
}
```

Verify by reading the method — any place that returned `{ clientSecret }` now returns `{ clientSecret, billingSessionId }`.

- [ ] **Step 4: Add session-close endpoint**

Find the voice controller (`src/voice/voice.controller.ts`). Add a new endpoint:

```typescript
@Post('session/:sessionId/close')
@UseGuards(AuthGuard('jwt'))
async closeSession(
  @Param('sessionId') sessionId: string,
  @Body() body: { durationSec: number },
  @Req() req: any,
) {
  await this.voice.closeVoiceSession(req.user.sub ?? req.user.id, sessionId, body.durationSec);
  return { ok: true };
}
```

And in `voice.service.ts`:

```typescript
async closeVoiceSession(userId: string, sessionId: string, durationSec: number): Promise<void> {
  const durationMin = durationSec / 60;
  await this.metering.reportUsage(sessionId, durationMin, 'client');
  await this.gating.endSession(sessionId, 'completed');
}
```

- [ ] **Step 5: Build and test**

Run: `cd ~/Downloads/taler_id && npm run build` → expect pass.

Manual smoke (requires DB with a user that has balance, or billingEnforced=false):
```bash
curl -s -X POST http://localhost:3000/voice/session \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{}' | jq
```
Expected with balance: `{ clientSecret: "...", billingSessionId: "uuid" }`.
Expected with `billingEnforced=true` and no balance: HTTP 402 with `insufficient_funds` body.

- [ ] **Step 6: Commit**

```bash
git add src/voice/voice.service.ts src/voice/voice.controller.ts src/voice/voice.module.ts
git commit -m "feat(billing): gate voice_assistant session with billing pre-check and close endpoint"
```

---

### Task 13: `web_search` integration

**Files:**
- Modify: `src/assistant/assistant.service.ts`
- Modify: `src/assistant/assistant.module.ts`

- [ ] **Step 1: Import BillingModule in AssistantModule**

Modify `src/assistant/assistant.module.ts` — add `BillingModule` to imports (mirror Task 12 step 1).

- [ ] **Step 2: Inject services**

Inject `GatingService`, `LedgerService`, `PricingService` into `AssistantService` constructor.

- [ ] **Step 3: Wrap `webSearch`**

Find `webSearch` around line 15 of `src/assistant/assistant.service.ts`:

```typescript
async webSearch(userId: string, query: string /*, other args */) {
  let session: { id: string } | null = null;
  try {
    session = await this.gating.startSession(userId, FEATURE_KEYS.WEB_SEARCH);
    // Debit exact amount up-front (1 request).
    const cost = await this.pricing.calculatePlanckCost(FEATURE_KEYS.WEB_SEARCH, 1);
    const tx = await this.ledger.debit(userId, cost, 'SPEND', {
      featureKey: FEATURE_KEYS.WEB_SEARCH,
      sessionId: session.id,
      metadata: { query: query.slice(0, 200) },
    });

    try {
      // ... existing Perplexity call ...
      const result = /* existing logic */;
      await this.gating.endSession(session.id, 'completed');
      return result;
    } catch (err) {
      // On Perplexity 5xx, refund.
      await this.ledger.refund(tx.id, `perplexity error: ${String(err).slice(0, 200)}`);
      await this.gating.endSession(session.id, 'failed');
      throw err;
    }
  } catch (err) {
    // Pre-check failures (InsufficientFunds / FeatureDisabled) propagate as 402/403.
    // For calls originating inside the assistant's tool path, the caller wraps this and
    // returns { error: 'insufficient_funds' } to OpenAI Realtime.
    if (session && !session.id) {
      // already handled
    }
    throw err;
  }
}
```

- [ ] **Step 4: Handle the tool-call case**

Find the code that registers `web_search` as an OpenAI Realtime tool (search for `web_search` in `src/assistant/` or `src/voice/`). On `InsufficientFundsException` or `FeatureDisabledException` caught from within the tool invocation, return `{ error: 'insufficient_funds' }` / `{ error: 'feature_disabled' }` so OpenAI's tool-result protocol handles it gracefully. The assistant will verbalize this to the user.

Example wrapper:

```typescript
try {
  return await this.webSearch(userId, query);
} catch (e) {
  if (e instanceof InsufficientFundsException) return { error: 'insufficient_funds' };
  if (e instanceof FeatureDisabledException) return { error: 'feature_disabled' };
  throw e;
}
```

- [ ] **Step 5: Build and manually test**

Run: `cd ~/Downloads/taler_id && npm run build` → expect pass.

- [ ] **Step 6: Commit**

```bash
git add src/assistant/
git commit -m "feat(billing): gate web_search with one-shot debit and refund on Perplexity error"
```

---

### Task 14: `ai_twin` integration + Python agent patch

**Files:**
- Modify: `src/messenger/ai-twin.service.ts`
- Modify: `src/messenger/messenger.module.ts`
- Modify: `~/ai-twin-agent/agent.py`

- [ ] **Step 1: Import BillingModule in MessengerModule**

Modify `src/messenger/messenger.module.ts` — add `BillingModule` to imports (forward-ref if needed because of Task 11 wiring).

- [ ] **Step 2: Inject GatingService + MeteringService into AiTwinService**

Modify `src/messenger/ai-twin.service.ts` — add constructor deps.

- [ ] **Step 3: Wrap `dispatchAgent`**

Find `dispatchAgent` around line 299. Wrap:

```typescript
async dispatchAgent(calleeUserId: string, roomName: string /* ... */) {
  let session: { id: string };
  try {
    session = await this.gating.startSession(calleeUserId, FEATURE_KEYS.AI_TWIN, roomName);
  } catch (err) {
    if (err instanceof InsufficientFundsException || err instanceof FeatureDisabledException) {
      // Fallback: do not dispatch, let caller see existing "twin unavailable" path.
      this.log.warn(`ai-twin not dispatched for ${calleeUserId}: ${err.message}`);
      return null;
    }
    throw err;
  }

  try {
    // ... existing AgentDispatchClient.createDispatch(...) code ...
    // Pass session.id into the agent payload so the agent can include it in its callback:
    const dispatch = await this.dispatchClient.createDispatch({
      agent_name: 'ai-twin-agent',
      room: roomName,
      metadata: JSON.stringify({ billingSessionId: session.id, calleeUserId }),
    });
    return { dispatch, billingSessionId: session.id };
  } catch (err) {
    await this.gating.endSession(session.id, 'failed');
    throw err;
  }
}
```

- [ ] **Step 4: Extend callback handler to accept `units`**

Find the existing callback endpoint (search: `grep -n "ai-twin/callback" src/ -r`). Extend the handler to accept `units?: number` and `billingSessionId?: string`. If both present:

```typescript
if (body.billingSessionId && typeof body.units === 'number') {
  await this.metering.reportUsage(body.billingSessionId, body.units, 'ai-twin-agent');
  await this.gating.endSession(body.billingSessionId, 'completed');
}
```

- [ ] **Step 5: Extend `takeoverCall` termination**

Find `takeoverCall` in `ai-twin.service.ts`. After `removeParticipant`, if the session is still active in DB, end it:

```typescript
// After removing the agent from the room
if (billingSessionId) {
  await this.gating.endSession(billingSessionId, 'completed');
  // metering cron will stop deducting automatically once status != 'active'
}
```

- [ ] **Step 6: Patch `~/ai-twin-agent/agent.py`**

Open `~/ai-twin-agent/agent.py` and find the block (around line 93-131) that POSTs to `/voice/ai-twin/callback`. Extend the payload:

```python
# Around line 93-131, inside the callback POST construction
callback_payload = {
    # ... existing fields: roomName, transcript, summary, etc.
    "billingSessionId": job_metadata.get("billingSessionId"),
    "units": round(duration_seconds / 60.0, 4),   # minutes, 4 decimals
}
requests.post(
    f"{BACKEND_URL}/voice/ai-twin/callback",
    json=callback_payload,
    headers={"X-Metering-Secret": os.environ["METERING_SHARED_SECRET"]},
    timeout=30,
)
```

Add to `.env` on DEV server: `METERING_SHARED_SECRET=<same value as backend>`.

Restart: `ssh dvolkov@89.169.55.217 'pm2 restart ai-twin-agent'`.

- [ ] **Step 7: Build backend and commit**

```bash
cd ~/Downloads/taler_id && npm run build
git add src/messenger/
git commit -m "feat(billing): gate ai_twin dispatch (payer=callee) with callback reporting"

# Agent patch lives in a separate repo on the server; commit there:
ssh dvolkov@89.169.55.217 'cd ~/ai-twin-agent && git add agent.py && git commit -m "feat: report usage minutes to backend metering"' || true
```

(If `~/ai-twin-agent/` is not a git repo on the server, just `scp` the patched file from local or sed-patch in-place — document in the deploy step.)

---

### Task 15: `outbound_call` integration + Python agent patch

**Files:**
- Modify: `src/outbound-bot/outbound-bot.service.ts`
- Modify: `src/outbound-bot/outbound-bot.controller.ts`
- Modify: `src/outbound-bot/outbound-bot.module.ts`
- Modify: `outbound-call-agent/agent.py` (inside `~/Downloads/taler_id/outbound-call-agent/`)

- [ ] **Step 1: Import BillingModule in OutboundBotModule**

Modify `src/outbound-bot/outbound-bot.module.ts` — add `BillingModule` to imports.

- [ ] **Step 2: Inject deps in OutboundBotService**

Add `GatingService`, `MeteringService`, `LedgerService`, `PricingService`.

- [ ] **Step 3: Wrap `executeCalls`**

Find `executeCalls` around line 82-126 in `src/outbound-bot/outbound-bot.service.ts`. Inside the loop that processes each call:

```typescript
for (const callPlan of campaign.callPlan) {
  let session: { id: string };
  try {
    session = await this.gating.startSession(
      campaign.userId,
      FEATURE_KEYS.OUTBOUND_CALL,
      callPlan.callId,
    );
  } catch (err) {
    if (err instanceof InsufficientFundsException) {
      // Pause campaign
      await this.prisma.outboundCampaign.update({
        where: { id: campaign.id },
        data: { status: 'paused' },
      });
      // Post system message to chat topic
      await this.postBotMessage(campaign, {
        type: 'system',
        text: 'Кампания приостановлена — недостаточно средств на балансе.',
      });
      break;
    }
    throw err;
  }

  try {
    // ... existing dispatch code ...
    const dispatchResult = await this.sipService.dispatchAgent({
      // ... existing args ...
      metadata: { billingSessionId: session.id, campaignId: campaign.id },
    });
    // Attach session id to the OutboundCall row so callback can find it:
    await this.prisma.outboundCall.update({
      where: { id: callPlan.callId },
      data: { billingSessionId: session.id } as any,
    });
  } catch (err) {
    await this.gating.endSession(session.id, 'failed');
    throw err;
  }
}
```

Note: `billingSessionId` column on `OutboundCall` — if not in schema, the simplest fix is to stash it in `OutboundCall.metadata` JSON rather than adding a column. If `OutboundCall` has no `metadata` JSON field, use the existing `roomName` as `contextRef` instead and look it up in the callback by `roomName`.

- [ ] **Step 4: Extend call-callback handler**

In `src/outbound-bot/outbound-bot.controller.ts` `handleCallCallback` (path `/outbound-bot/call-callback`), accept `units` and `billingSessionId`:

```typescript
async handleCallCallback(@Body() body: CallCallbackDto) {
  // ... existing logic: save transcript, summary, trigger recording fetch, etc.

  if (body.billingSessionId && typeof body.units === 'number') {
    await this.metering.reportUsage(body.billingSessionId, body.units, 'outbound-call-agent');
    await this.gating.endSession(body.billingSessionId, 'completed');
  }

  return { ok: true };
}
```

Ensure the callback controller has `@UseGuards(MeteringSecretGuard)` or equivalent (it already has some auth — keep existing semantics, just make sure agent sends `X-Metering-Secret`).

- [ ] **Step 5: Patch `outbound-call-agent/agent.py`**

Open `~/Downloads/taler_id/outbound-call-agent/agent.py`. Find the callback POST block (search for `call-callback`). Extend payload:

```python
callback_payload = {
    # ... existing fields
    "billingSessionId": job_metadata.get("billingSessionId"),
    "units": round(call_duration_seconds / 60.0, 4),
}
requests.post(
    f"{BACKEND_URL}/outbound-bot/call-callback",
    json=callback_payload,
    headers={"X-Metering-Secret": os.environ["METERING_SHARED_SECRET"]},
    timeout=30,
)
```

- [ ] **Step 6: Build, test, commit**

Run: `cd ~/Downloads/taler_id && npm run build && npx jest --testPathPattern billing`
Expected: all billing unit tests still pass.

```bash
git add src/outbound-bot/ outbound-call-agent/agent.py
git commit -m "feat(billing): gate outbound_call per-dispatch with pause-on-insufficient"
```

---

### Task 16: `whisper_transcribe` and `meeting_summary` integrations

**Files:**
- Modify: `src/voice/voice.service.ts` (two methods)

- [ ] **Step 1: Wrap Whisper transcription (line 768-830)**

In `src/voice/voice.service.ts`, find the Whisper call around line 768. The call is one-shot, recording duration is known before the API call.

```typescript
async transcribeRecording(userId: string, recording: { durationSec: number; /* ... */ }) {
  const durationMin = recording.durationSec / 60;
  const session = await this.gating.startSession(userId, FEATURE_KEYS.WHISPER_TRANSCRIBE);
  const cost = await this.pricing.calculatePlanckCost(FEATURE_KEYS.WHISPER_TRANSCRIBE, durationMin);

  let tx: { id: string };
  try {
    tx = await this.ledger.debit(userId, cost, 'SPEND', {
      featureKey: FEATURE_KEYS.WHISPER_TRANSCRIBE,
      sessionId: session.id,
      metadata: { durationMin, recording: recording /* minimal ref */ },
    });
  } catch (err) {
    await this.gating.endSession(session.id, 'failed');
    throw err;
  }

  try {
    // ... existing Whisper API call ...
    const transcript = /* existing */;
    await this.gating.endSession(session.id, 'completed');
    return transcript;
  } catch (err) {
    await this.ledger.refund(tx.id, `whisper error: ${String(err).slice(0, 200)}`);
    await this.gating.endSession(session.id, 'failed');
    throw err;
  }
}
```

- [ ] **Step 2: Wrap Meeting Summary (line 836-869)**

Summary uses GPT-4o, which returns exact `usage.total_tokens` in response. So pre-check with minReserve, debit after call with exact tokens:

```typescript
async summarizeMeeting(userId: string, transcript: string) {
  const session = await this.gating.startSession(userId, FEATURE_KEYS.MEETING_SUMMARY);

  try {
    // ... existing GPT-4o call ...
    const response = /* existing OpenAI response with usage.total_tokens */;
    const tokensK = response.usage.total_tokens / 1000;
    const cost = await this.pricing.calculatePlanckCost(FEATURE_KEYS.MEETING_SUMMARY, tokensK);

    try {
      const tx = await this.ledger.debit(userId, cost, 'SPEND', {
        featureKey: FEATURE_KEYS.MEETING_SUMMARY,
        sessionId: session.id,
        metadata: { totalTokens: response.usage.total_tokens },
      });
      await this.gating.endSession(session.id, 'completed');
      return response.choices[0].message.content;
    } catch (err) {
      // Post-call debit failed — still return the summary (best-effort). Log for follow-up.
      this.log.error(`post-call debit failed for ${userId}/${session.id}: ${String(err)}`);
      await this.gating.endSession(session.id, 'failed');
      throw err;
    }
  } catch (err) {
    if (session) await this.gating.endSession(session.id, 'failed');
    throw err;
  }
}
```

- [ ] **Step 3: Build and commit**

```bash
cd ~/Downloads/taler_id && npm run build
git add src/voice/voice.service.ts
git commit -m "feat(billing): gate whisper_transcribe and meeting_summary with exact post-call debit"
```

---

## Part F — One-shot Commands

### Task 17: `wallets:ensure` and `welcome-bonus` scripts

**Files:**
- Create: `src/billing/scripts/wallets-ensure.ts`
- Create: `src/billing/scripts/welcome-bonus.ts`
- Modify: `package.json`

- [ ] **Step 1: Write `wallets-ensure.ts`**

Create `src/billing/scripts/wallets-ensure.ts`:

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { WalletService } from '../../blockchain/wallet.service';

async function main() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const prisma = app.get(PrismaService);
  const wallet = app.get(WalletService);

  const users = await prisma.user.findMany({
    where: { wallet: null, deletedAt: null },
    select: { id: true },
  });
  console.log(`${users.length} users need a wallet`);

  let created = 0;
  for (const u of users) {
    await wallet.getOrCreate(u.id);
    created++;
    if (created % 10 === 0) console.log(`...${created}`);
  }
  console.log(`created ${created} wallets`);
  await app.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
```

- [ ] **Step 2: Write `welcome-bonus.ts`**

Create `src/billing/scripts/welcome-bonus.ts`:

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerService } from '../services/ledger.service';

async function main() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const prisma = app.get(PrismaService);
  const ledger = app.get(LedgerService);

  const cfg = await prisma.billingConfig.findUnique({ where: { id: 'singleton' } });
  if (!cfg) throw new Error('billing config not seeded');
  const amount = cfg.welcomeBonusPlanck;
  console.log(`welcome bonus amount: ${amount} planck`);

  const users = await prisma.user.findMany({
    where: { deletedAt: null },
    select: { id: true },
  });

  let credited = 0;
  let skipped = 0;
  for (const u of users) {
    // Idempotency: skip if already credited an initial_bonus transaction
    const already = await prisma.billingTransaction.findFirst({
      where: {
        userId: u.id,
        type: 'ADMIN_CREDIT',
        metadata: { path: ['source'], equals: 'initial_bonus' },
      },
    });
    if (already) {
      skipped++;
      continue;
    }
    await ledger.credit(u.id, amount, 'ADMIN_CREDIT', {
      source: 'initial_bonus',
      reason: 'welcome bonus at billing enforcement turn-on',
    });
    credited++;
    if (credited % 10 === 0) console.log(`...${credited} credited`);
  }

  console.log(`credited ${credited}, skipped ${skipped} (already bonused)`);
  await app.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
```

- [ ] **Step 3: Add npm scripts**

Modify `package.json` — add under `scripts`:

```json
    "billing:wallets-ensure": "ts-node -r tsconfig-paths/register src/billing/scripts/wallets-ensure.ts",
    "billing:welcome-bonus": "ts-node -r tsconfig-paths/register src/billing/scripts/welcome-bonus.ts"
```

- [ ] **Step 4: Test locally in dev DB**

```bash
cd ~/Downloads/taler_id
npm run billing:wallets-ensure
# Expect: "N users need a wallet" then "created N wallets"

npm run billing:welcome-bonus
# Expect: credited = N, skipped = 0 on first run
npm run billing:welcome-bonus
# Expect: credited = 0, skipped = N on second run (idempotency check)
```

- [ ] **Step 5: Commit**

```bash
git add src/billing/scripts/ package.json
git commit -m "feat(billing): add wallets:ensure and welcome-bonus one-shot scripts"
```

---

## Part G — Smoke Tests

### Task 18: Billing smoke test in `taler_id_tests`

**Files:**
- Create: `~/Downloads/taler_id_tests/billing-smoke.js`
- Modify: `~/Downloads/taler_id_tests/package.json`
- Modify: `/Users/dmitry/CLAUDE.md`

- [ ] **Step 1: Inspect existing test style**

Run: `ls ~/Downloads/taler_id_tests && head -40 ~/Downloads/taler_id_tests/package.json && head -50 ~/Downloads/taler_id_tests/$(ls ~/Downloads/taler_id_tests | grep -E '\.(js|ts)$' | head -1)`

Note the assertion library + HTTP client used by existing tests. Match that style.

- [ ] **Step 2: Write the smoke test**

Create `~/Downloads/taler_id_tests/billing-smoke.js` (adapt imports to match existing tests' style):

```javascript
/**
 * Billing smoke test — runs against DEV or PROD depending on BASE_URL env.
 * Verifies: wallet creation, package list, purchase stub, transaction history,
 * pricebook, toggles GET/PATCH, insufficient-funds 402 on drained account.
 */
const axios = require('axios');
const assert = require('assert');

const BASE_URL = process.env.BASE_URL || 'https://staging.id.taler.tirol';
const EMAIL_1 = 'integration_test@taler-test.com';
const PASS = 'IntegrationTest123!';

async function login() {
  const r = await axios.post(`${BASE_URL}/auth/login`, { email: EMAIL_1, password: PASS });
  return r.data.accessToken;
}

function api(token) {
  return axios.create({
    baseURL: BASE_URL,
    headers: { authorization: `Bearer ${token}` },
    validateStatus: () => true,
  });
}

async function test_packages(client) {
  const r = await client.get('/billing/packages');
  assert.strictEqual(r.status, 200, `packages: ${r.status}`);
  assert.strictEqual(r.data.length, 3, 'expected 3 packages');
  for (const id of ['starter', 'pro', 'business']) {
    assert.ok(r.data.find((p) => p.id === id), `missing package ${id}`);
  }
  console.log('✓ packages');
}

async function test_balance(client) {
  const r = await client.get('/billing/balance');
  assert.strictEqual(r.status, 200, `balance: ${r.status}`);
  assert.ok('balancePlanck' in r.data);
  assert.ok('balanceMicroTal' in r.data);
  console.log(`✓ balance: ${r.data.balanceMicroTal} μTAL`);
  return BigInt(r.data.balancePlanck);
}

async function test_wallet(client) {
  const r = await client.get('/billing/wallet');
  assert.strictEqual(r.status, 200);
  assert.ok(r.data.custodialAddress && r.data.custodialAddress.length > 10);
  console.log(`✓ wallet address: ${r.data.custodialAddress}`);
}

async function test_purchase_stub(client) {
  const before = await client.get('/billing/balance');
  const b0 = BigInt(before.data.balancePlanck);

  const r = await client.post('/billing/purchase/starter');
  assert.strictEqual(r.status, 201, `purchase: ${r.status}`);
  const b1 = BigInt(r.data.newBalancePlanck);
  assert.ok(b1 > b0, 'balance did not increase after stub purchase');
  console.log(`✓ starter purchase: +${b1 - b0} planck`);
}

async function test_pricebook(client) {
  const r = await client.get('/billing/pricebook');
  assert.strictEqual(r.status, 200);
  const keys = r.data.map((p) => p.featureKey);
  for (const k of ['voice_assistant', 'web_search', 'ai_twin', 'outbound_call', 'whisper_transcribe', 'meeting_summary']) {
    assert.ok(keys.includes(k), `pricebook missing ${k}`);
  }
  console.log('✓ pricebook has all 6 features');
}

async function test_toggles(client) {
  const r = await client.get('/billing/settings/toggles');
  assert.strictEqual(r.status, 200);
  assert.ok(Array.isArray(r.data) && r.data.length === 6);

  // Toggle web_search off then on
  const off = await client.patch('/billing/settings/toggles/web_search', { enabled: false });
  assert.strictEqual(off.status, 200);
  assert.strictEqual(off.data.enabled, false);

  const on = await client.patch('/billing/settings/toggles/web_search', { enabled: true });
  assert.strictEqual(on.status, 200);
  assert.strictEqual(on.data.enabled, true);
  console.log('✓ toggles PATCH works');
}

async function main() {
  console.log(`smoke against ${BASE_URL}`);
  const token = await login();
  const client = api(token);

  await test_packages(client);
  await test_balance(client);
  await test_wallet(client);
  await test_purchase_stub(client);
  await test_pricebook(client);
  await test_toggles(client);

  console.log('all billing smoke tests passed ✓');
}

main().catch((e) => {
  console.error(e?.response?.data ?? e);
  process.exit(1);
});
```

- [ ] **Step 3: Add npm scripts**

Modify `~/Downloads/taler_id_tests/package.json` — add under `scripts`:

```json
    "test:billing": "BASE_URL=https://staging.id.taler.tirol node billing-smoke.js",
    "test:billing:prod": "BASE_URL=https://id.taler.tirol node billing-smoke.js"
```

If the file uses TypeScript instead of JS, rename to `.ts` and adjust.

- [ ] **Step 4: Add to CLAUDE.md deploy checklist**

Modify `/Users/dmitry/CLAUDE.md`. After the existing "Тест каналов (DEV)" (section 8), add:

```markdown
### 9. Тест биллинга (DEV)
E2E: пакеты, баланс, stub-покупка, кошелёк, pricebook, тумблеры.
```bash
cd ~/Downloads/taler_id_tests && npm run test:billing
```
- 6 тестов. Включает покупку Starter-пакета (stub) — после прогона баланс тестового аккаунта увеличится.
```

And update the PROD post-deploy line to include `test:billing:prod`.

- [ ] **Step 5: Commit (in both repos)**

```bash
cd ~/Downloads/taler_id_tests
git add billing-smoke.js package.json
git commit -m "test(billing): smoke test for balance/packages/purchase/toggles"

# CLAUDE.md is not in a git repo (it's in /Users/dmitry/) — user will commit or track manually.
```

---

## Part H — Deploy to DEV (dry-run)

### Task 19: Deploy backend to DEV in dry-run mode

**Files:** none (deployment)

- [ ] **Step 1: Push all commits to GitHub dev branch**

```bash
cd ~/Downloads/taler_id
git status  # verify clean
git log --oneline -20  # sanity check of billing commits
# If the repo uses a "dev" branch for DEV deploys, switch to it. If using "main" directly on DEV server, keep as is.
git push origin main
```

- [ ] **Step 2: Deploy on DEV server**

```bash
ssh dvolkov@89.169.55.217 <<'REMOTE'
set -e
cd ~/taler-id
git pull
npm install
npx prisma migrate deploy
npm run build
# Ensure env vars are set
grep -q '^WALLET_ENCRYPTION_KEY=' .env || echo "!! ADD WALLET_ENCRYPTION_KEY to .env before pm2 restart !!"
grep -q '^METERING_SHARED_SECRET=' .env || echo "!! ADD METERING_SHARED_SECRET to .env before pm2 restart !!"
pm2 restart taler-id-dev
pm2 logs taler-id-dev --lines 30
REMOTE
```

If either env var is missing, STOP and edit `.env` on the server before proceeding.

- [ ] **Step 3: Ensure wallets for existing users**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && npm run billing:wallets-ensure'
```
Expected: "N users need a wallet" then "created N wallets".

- [ ] **Step 4: Update the Python agent's env on DEV**

```bash
ssh dvolkov@89.169.55.217 <<'REMOTE'
grep -q '^METERING_SHARED_SECRET=' ~/ai-twin-agent/.env || \
  echo "METERING_SHARED_SECRET=$(grep '^METERING_SHARED_SECRET=' ~/taler-id/.env | cut -d= -f2-)" >> ~/ai-twin-agent/.env
pm2 restart ai-twin-agent
pm2 logs ai-twin-agent --lines 10 --nostream
REMOTE
```

Do the same for `outbound-call-agent` if it's also separate. (The current deploy strategy co-locates it inside `~/taler-id/outbound-call-agent/` per CLAUDE.md — in that case env is already on the host.)

- [ ] **Step 5: Run smoke tests**

From local:
```bash
cd ~/Downloads/taler_id_tests
npm run test:billing
```
Expected: all 6 smoke tests pass.

- [ ] **Step 6: Manual verification of dry-run behavior**

With `BILLING_ENFORCED=false` (the default from seed), make a real voice assistant session on the DEV mobile build and watch logs:

```bash
ssh dvolkov@89.169.55.217 'pm2 logs taler-id-dev --lines 200 | grep -E "billing|metering|GatingService|MeteringService"'
```
Expected: log lines like `[dry-run] insufficient funds for <user>/<feature>` if balance is zero — confirming gating is evaluating but not blocking.

Also verify `BillingTransaction` rows are appearing for elapsed time:
```bash
ssh dvolkov@89.169.55.217 'psql $DATABASE_URL -c "SELECT \"userId\", type, \"amountPlanck\", \"featureKey\", \"createdAt\" FROM \"BillingTransaction\" ORDER BY \"createdAt\" DESC LIMIT 20;"'
```

- [ ] **Step 7: Give tests account some balance for ongoing CI**

```bash
# Get the admin user id for actor
ssh dvolkov@89.169.55.217 'psql $DATABASE_URL -c "SELECT id, email, \"isAdmin\" FROM \"User\" WHERE \"isAdmin\" = true;"'

# Get the integration-test user id
ssh dvolkov@89.169.55.217 'psql $DATABASE_URL -c "SELECT id, email FROM \"User\" WHERE email IN (\x27integration_test@taler-test.com\x27, \x27integration_test_2@taler-test.com\x27);"'

# Curl admin credit: 500 μTAL = 500_000_000 planck each
ADMIN_TOKEN=$(...)  # obtain via /auth/login as admin
curl -s -X POST https://staging.id.taler.tirol/admin/billing/users/<uid>/credit \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"amountPlanck":"500000000","reason":"CI balance topup"}' | jq
```

- [ ] **Step 8: Declare Plan 1 complete**

Create a status note by running:

```bash
ssh dvolkov@89.169.55.217 'psql $DATABASE_URL -c "SELECT COUNT(*) as total_users, COUNT(\"walletId\") FROM \"UserWallet\";"'
ssh dvolkov@89.169.55.217 'psql $DATABASE_URL -c "SELECT \"featureKey\", COUNT(*) FROM \"UsageLog\" GROUP BY \"featureKey\";"' 2>/dev/null || true
```

Leave `BILLING_ENFORCED=false`. **Do NOT switch to true yet** — that happens at the end of Plan 2 (mobile) once the UI is ready to surface paywalls and purchase flows to real users.

Plan 1 end-state:
- Backend shipped to DEV with full gating/metering/ledger wiring
- All 6 features are hooked up; in dry-run mode they log intended debits but don't block
- Python agents report usage
- Admin endpoints work for calibration
- UsageLog is accumulating real data for pricebook tuning

Plan 2 will build mobile UI on top of this working API.

---

## Self-Review

See running log at the end of this document. All issues found during self-review are fixed inline above.

### Spec coverage

Each spec section maps to tasks:
- Spec §3 Architecture → Tasks 2–11 collectively
- Spec §4 Data model → Task 1
- Spec §5 Services (Pricing/Ledger/Gating/Metering/Wallet/DepositWatcher) → Tasks 2–7
- Spec §6 REST API → Tasks 8–10
- Spec §6.4 Socket.io events → Task 11
- Spec §7.1 voice_assistant → Task 12
- Spec §7.2 web_search → Task 13
- Spec §7.3 ai_twin (+ agent patch) → Task 14
- Spec §7.4 outbound_call (+ agent patch) → Task 15
- Spec §7.5 whisper_transcribe → Task 16
- Spec §7.6 meeting_summary → Task 16
- Spec §9.1 data migrations (wallets:ensure, welcome-bonus) → Tasks 17 + 19
- Spec §9.2 seeds → Task 1
- Spec §9 rollout phases 0–1 → Task 19 (dry-run deploy)

Spec §8 (mobile) is intentionally out of scope — Plan 2.

### Known open items (carry to Plan 2 or implementation)

- Exact `CurrentUser` decorator — Task 8 step 3 includes a fallback; the implementer must check if `src/auth/` or `src/common/` already has one and use that instead.
- `OutboundCall.billingSessionId` column vs stash-in-metadata (Task 15 step 3 notes this trade-off).
- `AppConfig.showBilling` flag on mobile — Plan 2 concern.
- WALLET_ENCRYPTION_KEY rotation strategy — explicit out-of-scope in spec §2 (Phase 2 KMS).
