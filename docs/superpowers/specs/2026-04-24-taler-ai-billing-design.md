# Taler AI Billing — Design Spec

**Date:** 2026-04-24
**Status:** Approved, ready for implementation planning
**Scope:** NestJS backend (`~/taler-id/`), Flutter mobile (`~/taler_id_mobile/`), Python agents (`~/ai-twin-agent/`, `outbound-call-agent/`)

## 1. Goal

Introduce a paid-service layer in TalerID so users pay for AI features using the on-chain **TAL** token (Taler blockchain, `wss://node.dev.gsmsoft.eu/`, decimals 12, ss58 prefix 10960). Users top up via one of three packages, spend on any of six AI features, and the service gates usage when balance is insufficient.

A separate settings screen gives per-feature on/off toggles (assistant, web-search, AI-twin, outbound bot, transcription, summary), independent of balance.

Per-feature markup (default `2.0`) is the single knob the operator turns to control margin.

## 2. Scope boundaries

**In scope:**
- Custodial TAL wallet per user with on-chain deposit watcher and withdraw endpoint
- PostgreSQL ledger (double-entry) with atomic debit/credit
- Pricebook in USD × markup_multiplier → planck, with admin-editable rows
- Gating middleware: pre-check before session start, periodic deduction during, graceful termination on insufficient funds
- Integration into all 6 existing AI entry points (voice assistant, web search, AI-twin, outbound bot, Whisper transcription, GPT-4o summary)
- Purchase flow with three packages (stub — real payment integration is Phase 4, outside this spec)
- Mobile UI: balance chip, wallet screen, AI-toggles settings screen, paywall bottom sheet
- Feature flag `BILLING_ENFORCED` for dry-run period
- Welcome bonus for existing users at enforcement turn-on

**Out of scope (not this spec):**
- Real payment providers (Stripe / App Store IAP / on-chain swap) — contract for `/billing/purchase/:pkgId` is stable so they plug in later
- Monthly subscriptions, referrals, promo codes
- Mobile UI for withdraw (endpoint exists, UI Phase 2)
- Admin web panel (curl on REST is enough for MVP)
- Multi-tenant billing (billed-per-org rather than per-user)
- Separate `sip_trunk` feature-key (Novofon minutes rolled into `outbound_call` markup for now)

## 3. Architecture

### 3.1 High-level

```
┌──────────────┐                ┌────────────────────────────────┐
│  Flutter App │                │      NestJS Backend            │
│              │                │                                │
│ • Balance    │◄─Socket.io─────┤  BillingModule                 │
│   widget     │                │  ├─ PricingService             │
│ • Paywall    │─REST /billing─►│  ├─ LedgerService (atomic)     │
│ • Settings   │                │  ├─ GatingService              │
│   toggles    │                │  ├─ MeteringService (periodic) │
│ • Purchase   │                │  └─ AdminBillingController     │
└──────────────┘                │                                │
                                │  BlockchainModule (existing)   │
                                │  ├─ WalletService (new)        │
                                │  └─ DepositWatcher (new)       │
                                └──────┬─────────────────────────┘
                                       │
                        ┌──────────────┼──────────────┐
                        ▼              ▼              ▼
                 PostgreSQL     Taler Chain    Python agents
                 (ledger)       (deposit/      (report usage via
                                withdraw)      HTTP callback)
```

### 3.2 Key principles

- **Ledger in PostgreSQL**, double-entry: `UserWallet.balancePlanck` + corresponding `BillingTransaction` row, always updated inside a `prisma.$transaction` with row-level lock on `UserWallet`.
- **Blockchain only on boundary**: `DepositWatcher` credits balance on incoming transfers, `signAndSubmitTransfer` handles withdraw. Per-call spending never touches the chain.
- **Agents report usage**: `ai-twin-agent` and `outbound-call-agent` POST actual duration/tokens to `/metering/report` via shared secret. Realtime voice assistant is backend-blind to WebRTC, so backend uses elapsed-time as source of truth and client heartbeat as liveness signal.
- **Dry-run toggle** via `BillingConfig.billingEnforced`: when `false`, middleware logs usage but does not block or debit.

### 3.3 Units and conversion

| Constant | Value |
|---|---|
| Chain | Taler (`wss://node.dev.gsmsoft.eu/`) |
| Token | TAL, decimals 12, ss58 prefix 10960, non-Ethereum |
| DB unit | `BigInt` in planck (10⁻¹² TAL) |
| UI unit | μTAL (10⁶ planck), 2 decimal places |
| TAL→USD rate | `BillingConfig.talUsdRate`, initial $11 700 (from €10 800 at 1.085 USD/EUR) |
| Markup | `AiPricebook.markupMultiplier`, per-feature, default 2.0 |

**Pricing formula** (in `PricingService.calculatePlanckCost`):
```
costUsd = units × costUsdPerUnit × markupMultiplier
costTal = costUsd / talUsdRate
planck = ceil(costTal × 1e12)     // round up in favor of the service
```

Pricebook and config cached in memory with 60-second TTL to avoid per-call DB hits.

## 4. Data model (Prisma additions)

```prisma
model AiPricebook {
  id                 String   @id @default(cuid())
  featureKey         String   @unique
  unit               String                 // "minute" | "1k_tokens" | "request" | "character"
  costUsdPerUnit     Decimal  @db.Decimal(12,8)
  markupMultiplier   Decimal  @default(2.0) @db.Decimal(4,2)
  minReservePlanck   BigInt                 // gate-check minimum before session start
  updatedAt          DateTime @updatedAt
}

model BillingConfig {             // single row, id = "singleton"
  id                 String   @id @default("singleton")
  talUsdRate         Decimal  @db.Decimal(14,4)
  billingEnforced    Boolean  @default(false)
  welcomeBonusPlanck BigInt   @default(50000000)    // 50 μTAL
  lastSeenBlock      Int?                            // for DepositWatcher catch-up
}

model UserWallet {
  userId           String   @id
  user             User     @relation(fields: [userId], references: [id])
  custodialAddress String   @unique                  // ss58 10960
  custodialKeyEnc  String                            // encrypted with WALLET_ENCRYPTION_KEY
  balancePlanck    BigInt   @default(0)
  createdAt        DateTime @default(now())
}

enum TxType  { TOPUP_STUB  TOPUP_ONCHAIN  SPEND  REFUND  ADMIN_CREDIT  ADMIN_DEBIT  WITHDRAW }
enum TxStatus { PENDING  COMPLETED  FAILED  REVERSED }

model BillingTransaction {
  id             String   @id @default(cuid())
  userId         String
  user           User     @relation(fields: [userId], references: [id])
  type           TxType
  status         TxStatus @default(COMPLETED)
  amountPlanck   BigInt                         // + credit, − debit (sign by type)
  featureKey     String?                        // set for SPEND / REFUND
  sessionId      String?  @db.Uuid              // groups SPEND rows inside one session
  chainTxHash    String?                        // for on-chain ops
  metadata       Json?                          // { unitsUsed, costUsd, talRate, markup }
  createdAt      DateTime @default(now())
  @@index([userId, createdAt])
  @@index([sessionId])
}

model AiSession {
  id               String    @id @default(uuid()) @db.Uuid
  userId           String                         // who pays (!= caller for ai_twin)
  featureKey       String
  contextRef       String?                        // roomName / conversationId / campaignId
  status           String                         // "active" | "completed" | "terminated_no_funds" | "failed"
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

model UsageLog {                    // raw events for audit / calibration
  id         String   @id @default(cuid())
  userId     String
  sessionId  String?  @db.Uuid
  featureKey String
  unit       String
  units      Decimal  @db.Decimal(14,4)
  reporter   String                  // "backend" | "ai-twin-agent" | "outbound-agent" | "client"
  createdAt  DateTime @default(now())
  @@index([userId, createdAt])
}
```

**Existing Profile fields stay** (`aiTwinEnabled`, `aiTwinTimeoutSeconds`, `aiTwinPrompt`, `aiTwinVoiceId`) — not dropped for backward compatibility. A migration copies `aiTwinEnabled` into `UserFeatureToggle(featureKey='ai_twin')`.

### 4.1 Feature-keys (fixed TypeScript const enum)

```
voice_assistant     — OpenAI Realtime session (assistant)
web_search          — Perplexity (tool inside assistant)
ai_twin             — AI-twin voice conversation with caller
outbound_call       — outbound bot call minute
whisper_transcribe  — Whisper transcription of a recording
meeting_summary     — GPT-4o call summary
```

## 5. Services

### 5.1 `PricingService`

Single public method `calculatePlanckCost(featureKey, units): bigint` applies the formula above. Pricebook + config kept in 60-second TTL memory cache. Cache invalidated on admin PATCH.

### 5.2 `LedgerService`

All operations inside `prisma.$transaction` with row-level lock (`SELECT … FOR UPDATE`) on `UserWallet`:
- `credit(userId, amount, type, metadata) → BillingTransaction`
- `debit(userId, amount, type, metadata) → BillingTransaction` — throws `InsufficientFundsError` if balance < amount
- `refund(originalTxId, reason) → BillingTransaction` — inverse SPEND, marks original as `REVERSED`

`InsufficientFundsError` is mapped by a NestJS exception filter to **HTTP 402 Payment Required** with body:
```json
{
  "error": "insufficient_funds",
  "requiredPlanck": "30000000",
  "availablePlanck": "12000000",
  "suggestedPackage": "starter",
  "featureKey": "voice_assistant"
}
```

### 5.3 `GatingService`

Public surface used by every feature hook:
- `startSession(userId, featureKey, contextRef?) → AiSession`
  1. Check `UserFeatureToggle` — if disabled, throw `FeatureDisabledError` → HTTP 403.
  2. Check `balancePlanck ≥ pricebook.minReservePlanck` — if not, throw `InsufficientFundsError` → HTTP 402.
  3. Create `AiSession(status='active')`.
  4. If `BillingConfig.billingEnforced = false`, steps 1–2 log but do not throw.
- `endSession(sessionId, finalUnits?) → void` — closes the session, performs final adjustment debit if `finalUnits` exceeds already-metered total.

### 5.4 `MeteringService`

Two trigger paths:

**Cron `@Interval(10_000)`** — every 10 seconds:
```
for each AiSession where status='active':
  elapsed = now - lastMeteredAt
  if feature uses pull-only reporting: skip
  units = elapsed (in minutes, or tokens per client-report for assistant)
  cost = PricingService.calculate(featureKey, units)
  ledger.debit(userId, cost, SPEND, { sessionId, unitsUsed })
  session.lastMeteredAt = now
  session.totalSpentPlanck += cost
  if balancePlanck < minReservePlanck:
    session.status = 'terminated_no_funds'
    socketGateway.emit(userId, 'ai_session_terminated', { sessionId, reason: 'no_funds' })
    feature-specific teardown hook (kick agent, close LiveKit room, …)
```

**Direct calls** from agent callbacks and client reports via `/metering/report`.

### 5.5 `WalletService` (in `BlockchainModule`)

- `createWalletForUser(userId)` — generates Substrate keypair (ss58=10960), encrypts private key with `WALLET_ENCRYPTION_KEY` (32-byte symmetric from env), stores `UserWallet`.
- `getOrCreate(userId)` — idempotent, used on first request.
- `getOnchainBalance(address)` — for reconciliation / admin.
- `signAndSubmitTransfer(fromUserId, toAddress, amountPlanck)` — decrypt key, sign `balances.transfer`, submit, return tx hash. Used for withdraw.

Key material is in env for MVP; move to KMS/Vault in Phase 2.

### 5.6 `DepositWatcher`

On service start: subscribe to `api.query.system.events()`. For every `balances.Transfer`:
```
if to is a known custodial address:
  find userId by address
  ledger.credit(userId, amount, TOPUP_ONCHAIN, { chainTxHash, fromAddress })
  socketGateway.emit(userId, 'billing_balance_changed', { ... })
```

Catch-up on startup: read `BillingConfig.lastSeenBlock`, replay blocks forward via `api.derive.chain.subscribeFinalizedHeads()`; update `lastSeenBlock` after each processed block.

## 6. REST API

### 6.1 User endpoints (JWT-guarded)

| Method | Path | Purpose |
|---|---|---|
| GET | `/billing/balance` | `{ balancePlanck, balanceMicroTal, recentTx: [..10] }` |
| GET | `/billing/packages` | list of 3 packages with prices and unit-equivalents |
| POST | `/billing/purchase/:pkgId` | **stub**: `ledger.credit(userId, pkg.amount, TOPUP_STUB)` |
| GET | `/billing/wallet` | `{ custodialAddress }` for on-chain top-up (client renders QR locally) |
| POST | `/billing/withdraw` | `{ toAddress, amountPlanck }` → `signAndSubmitTransfer` |
| GET | `/billing/transactions?cursor=…&type=…` | paginated |
| GET | `/billing/pricebook` | public (per-feature prices for UI) |
| GET | `/billing/settings/toggles` | all `UserFeatureToggle` rows |
| PATCH | `/billing/settings/toggles/:featureKey` | `{ enabled: bool }` |

### 6.2 Internal endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/metering/report` | shared secret header | agents/client post actual usage |
| POST | `/metering/heartbeat` | JWT | client liveness ping for assistant |

### 6.3 Admin endpoints (role guard `ADMIN`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/billing/users/:id` | balance, tx list, usage totals |
| POST | `/admin/billing/users/:id/credit` | `{ amountPlanck, reason }` — compensation |
| POST | `/admin/billing/users/:id/debit` | manual debit (rare) |
| PATCH | `/admin/billing/pricebook/:featureKey` | `{ costUsdPerUnit?, markupMultiplier?, minReservePlanck? }` |
| PATCH | `/admin/billing/config` | `{ talUsdRate?, billingEnforced?, welcomeBonusPlanck? }` |

### 6.4 Socket.io events (existing `/messenger` namespace)

| Direction | Event | Payload |
|---|---|---|
| server→client | `billing_balance_changed` | `{ balancePlanck, reason, txId }` |
| server→client | `ai_session_started` | `{ sessionId, featureKey }` |
| server→client | `ai_session_terminated` | `{ sessionId, reason: 'no_funds'\|'completed'\|'failed' }` |
| server→client | `billing_low_balance_warning` | fires when balance drops below 2× minReserve of active session |

## 7. Per-feature integration

For each feature: entry-point file, unit, who pays, pre-check hook, metering approach, termination behavior.

### 7.1 Voice Assistant — `voice_assistant`
- **Entry:** `src/voice/voice.service.ts:194-214` (`createVoiceSession`).
- **Unit:** minute of audio at ~$0.15/min × 2.0.
- **Payer:** account owner (JWT user).
- **Pre-check:** wrap method start with `gating.startSession`. On 402, do not return `client_secret`.
- **Metering:**
  - Client heartbeat (`POST /metering/heartbeat` every 10s). Missing heartbeat ≥ 30s → session auto-closed, debit by elapsed.
  - Session close → `POST /metering/report { sessionId, units }` with actual duration.
  - Cron-based elapsed-time debiting is source of truth; client report only for final adjustment.
- **Termination:** on `no_funds` event, client calls `peerConnection.close()` and shows snackbar.

### 7.2 Web Search — `web_search`
- **Entry:** `src/assistant/assistant.service.ts:15-52` (`webSearch`).
- **Unit:** request at $0.005 × 2.0 = $0.01/req ≈ 1 μTAL.
- **Payer:** JWT user (even when invoked from assistant's tool).
- **Pre-check + debit in one step** (operation is atomic/one-shot). Pre-check succeeds only if balance ≥ `minReservePlanck`.
- **On insufficient funds:** return `{ error: "insufficient_funds" }` to the tool call; OpenAI Realtime treats it as normal tool result and tells the user "top up required."

### 7.3 AI Twin — `ai_twin`
- **Entry:** `src/messenger/ai-twin.service.ts:299` (`dispatchAgent`), agent: `~/ai-twin-agent/agent.py`.
- **Unit:** minute of conversation at ~$0.15/min × 2.0.
- **Payer:** **callee** (the twin owner), **not** caller.
- **Pre-check:** before `dispatchAgent`, `gating.startSession(calleeUserId, 'ai_twin', { contextRef: roomName })`. On 402, do not dispatch — caller sees existing "twin unavailable, leave text message" fallback.
- **Metering:** cron every 10s debits by elapsed. Agent `agent.py` callback (`voice/ai-twin/callback`, line 93-131) gets new `units` field for final adjustment.
- **Termination:** `no_funds` → `removeParticipant(agent-*)` (same code path as `takeoverCall`), caller sees "twin disconnected."
- **Trust:** agent → backend POST authenticated by `METERING_SHARED_SECRET` header.

### 7.4 Outbound Bot — `outbound_call`
- **Entry:** `src/outbound-bot/outbound-bot.service.ts:82-126` (`executeCalls`), agent: `outbound-call-agent/agent.py`.
- **Unit:** minute at ~$0.20/min × 2.0 = $0.40/min. Novofon SIP minutes bundled into markup for now; separate `sip_trunk` feature-key added post-TEST-MODE.
- **Payer:** campaign owner (`OutboundCampaign.userId`).
- **Pre-check:** before each dispatch, `gating.startSession(campaign.userId, 'outbound_call', { contextRef: callId })`. On 402, campaign paused (`status='paused'`), system message posted to chat topic: "кампания приостановлена — недостаточно средств."
- **Metering:** cron + agent callback with `units`. Existing 7-minute per-call cap remains as upper bound.
- **Termination:** mid-call `no_funds` → delete LiveKit room (existing teardown path), mark campaign paused.

### 7.5 Whisper Transcription — `whisper_transcribe`
- **Entry:** `src/voice/voice.service.ts:768-830`.
- **Unit:** minute of audio at $0.006 × 2.0.
- **Payer:** call initiator (room creator).
- **Pre-check + debit:** one-shot post-call. Recording duration is known → exact debit.
- **On 402:** skip transcription, write `{ error: 'insufficient_funds' }` into `MeetingSummary`.

### 7.6 Meeting Summary — `meeting_summary`
- **Entry:** `src/voice/voice.service.ts:836-869`.
- **Unit:** 1K tokens at $0.01 × 2.0 = $0.02/1K.
- **Payer:** call initiator.
- **Pre-check:** by `minReservePlanck` estimating ~2K tokens.
- **Metering:** exact — GPT-4o response contains `usage.total_tokens`, debit after the API call.
- **Refund:** on OpenAI 5xx, `ledger.refund(originalTxId)`.

### 7.7 Summary table

| Feature | Pre-check | Metering source | Precision | Refund case |
|---|---|---|---|---|
| voice_assistant | yes | cron + client heartbeat | averaged | client dropped session < 5s |
| web_search | yes | one-shot | exact | Perplexity 5xx → refund |
| ai_twin | yes | cron + agent callback | averaged → exact | agent failed to start |
| outbound_call | yes | cron + agent callback | averaged → exact | SIP didn't connect |
| whisper_transcribe | yes | recording length | exact | OpenAI 5xx → refund |
| meeting_summary | yes | `usage.total_tokens` | **exact** | OpenAI 5xx → refund |

## 8. Mobile (Flutter)

### 8.1 New feature module `lib/features/billing/`

```
billing/
├── data/
│   ├── datasources/billing_remote_datasource.dart
│   └── repositories/billing_repository_impl.dart
├── domain/
│   ├── entities/            # wallet, package, transaction, pricebook_item
│   └── repositories/billing_repository.dart
└── presentation/
    ├── bloc/                # balance_bloc, purchase_bloc, transactions_bloc
    ├── screens/
    │   ├── wallet_screen.dart
    │   ├── purchase_screen.dart
    │   ├── transactions_screen.dart
    │   ├── pricebook_screen.dart
    │   └── withdraw_screen.dart        # UI Phase 2, endpoint ready
    └── widgets/
        ├── balance_chip.dart
        ├── insufficient_funds_sheet.dart
        └── low_balance_banner.dart
```

### 8.2 Settings entry points

`settings_screen.dart` gains two new items:
- **"Кошелёк и баланс"** → `wallet_screen`
- **"AI-функции"** → `ai_toggles_screen`

### 8.3 `ai_toggles_screen.dart` (the user-requested toggles screen)

Toggles for: **voice_assistant, web_search (sub-toggle), ai_twin (with link to existing ai_twin_screen), outbound_call, whisper_transcribe, meeting_summary.** Stored in `UserFeatureToggle` via PATCH `/billing/settings/toggles/:featureKey`. Existing `Profile.aiTwinEnabled` is copied into the toggle table at migration time but kept as obsolete column for old-client compatibility.

### 8.4 `wallet_screen.dart`

Sections:
- Balance card: `X.XX μTAL ≈ €Y.YY`
- Action buttons: "Купить пакет", "Пополнить" (shows QR + custodial address)
- Three package cards (Starter / Pro / Business) with unit-equivalent copy computed from current pricebook (Starter ≈ 17 min assistant / 500 web searches / 12 min outbound; Pro ≈ 83 min / 2500 searches / 62 min; Business ≈ 400 min / 12 000 searches / 300 min), CTA "Купить"
- Recent transactions (last 10, link to full screen)

Purchase button → `POST /billing/purchase/:pkgId` (stub) → success animation → balance reflected via Socket.io.

### 8.5 Paywall — `insufficient_funds_sheet.dart`

Triggered centrally from `DioClient` interceptor on HTTP 402 across the app. Bottom sheet displays required amount, current balance, suggested package CTA. No per-feature duplication.

### 8.6 Live widgets

- **`balance_chip.dart`** in dashboard AppBar — live-subscribed to `billing_balance_changed`.
- **`low_balance_banner.dart`** — non-dismissable banner during an active AI session when `balance < minReserve × 3` or `billing_low_balance_warning` received.
- **`ai_session_terminated` handler** — listens in `VoiceCallScreen` and chat screens. On `reason='no_funds'`, closes WebRTC / bottom sheet and shows snackbar. The existing `_aiTwinActive` guard (which prevents iOS CallKit 60s-timeout races) extends to balance-triggered terminations.

### 8.7 Localization

All new strings in `lib/l10n/app_ru.arb` and `app_en.arb` with `billing_` key prefix. μTAL formatter: 2 decimals, thousand separator. EUR via `NumberFormat.currency`.

### 8.8 Assistant-first compliance

Per CLAUDE.md "Assistant-first" principle, add OpenAI Realtime tools:
- `get_balance()` → current balance
- `get_packages()` → package list
- `list_recent_transactions(limit)` → history
- `toggle_feature(featureKey, enabled)` → enable/disable a feature

**Explicitly excluded from voice control:** purchase and withdraw (require explicit UI confirmation).

## 9. Rollout plan

### Phase 0 — Development (local)

Prisma migrations, services, middleware, UI shell. `BILLING_ENFORCED=false` by default. Unit tests: `PricingService` (formula, rounding), `LedgerService` (double-entry, `InsufficientFundsError`, refund). One integration test: topup → start session → metering → `terminated_no_funds`.

### Phase 1 — DEV dry-run (1-2 weeks)

- Backend deploy to `89.169.55.217` with `BILLING_ENFORCED=false`.
- Mobile: billing UI gated behind `AppConfig.showBilling` feature flag (dev-flavor only).
- Cron and metering write to `BillingTransaction` and `UsageLog`; `debit()` in dry-run mode logs intended deductions but does not touch balance.
- Goal: observe real usage, calibrate `costUsdPerUnit`.

### Phase 2 — DEV enforcement

- Set `BILLING_ENFORCED=true` on DEV.
- Migration runs welcome-bonus crediting of 50 μTAL to every existing user.
- Mobile: `showBilling=true` on dev-flavor.
- Test accounts `integration_test@` / `integration_test_2@` get +500 μTAL via admin endpoint so existing CI tests pass.
- **Update to `CLAUDE.md` deploy tests:** new `npm run test:billing` in `taler_id_tests` checking balance GET, purchase-stub, 402 on empty account.

### Phase 3 — PROD deploy

- Only on explicit instruction (per project convention).
- Welcome bonus 50 μTAL for all live users.
- Enable `BILLING_ENFORCED=true`.
- Monitor PM2 logs first 24h; alert on unexpected 402 ratio.

### Phase 4 (outside this spec) — Real payments

Replace stub in `/billing/purchase/:pkgId` with Stripe / App Store IAP / on-chain swap. Endpoint contract stable. Markup and pricebook already admin-editable from day 1.

### 9.1 Data migrations

1. **Pricebook + BillingConfig seed** (Prisma migration).
2. **UserWallet ensure** (`wallets:ensure` idempotent command) — generates custodial wallet for every existing User. Not in Prisma migration (key generation in migrations is risky).
3. **UserFeatureToggle seed from Profile** — copy `aiTwinEnabled`; default all other features to `enabled=true`.
4. **Welcome bonus** — idempotent `billing:welcome-bonus` command, guarded by `Transaction.metadata.source='initial_bonus'` uniqueness. Runs at enforcement turn-on.

### 9.2 Seed values

```sql
-- minReservePlanck sized to cover ~60s of usage at the chosen markup
-- (voice_assistant $0.30/min ÷ $11 700/TAL × 1e12 ≈ 25.6M planck/min)
INSERT INTO "AiPricebook"(featureKey, unit, costUsdPerUnit, markupMultiplier, minReservePlanck) VALUES
  ('voice_assistant',    'minute',    0.15,  2.0, 26000000),   -- ~60s reserve
  ('web_search',         'request',   0.005, 2.0,  1000000),   -- ~1 request ahead
  ('ai_twin',            'minute',    0.15,  2.0, 26000000),   -- ~60s reserve
  ('outbound_call',      'minute',    0.20,  2.0, 35000000),   -- ~60s reserve
  ('whisper_transcribe', 'minute',    0.006, 2.0,  5000000),   -- ~5 min typical call
  ('meeting_summary',    '1k_tokens', 0.01,  2.0,  4000000);   -- ~2K tokens typical

INSERT INTO "BillingConfig"(id, talUsdRate, billingEnforced, welcomeBonusPlanck)
  VALUES ('singleton', 11700, false, 50000000);
```

`minReservePlanck` values are initial estimates — re-verified during Phase 1 dry-run calibration.

### 9.3 Package seed

```sql
-- Three packages stored as constants in code or a PricePackage table
-- amounts in planck (= μTAL × 10^6)
starter  :  430 μTAL  = 430000000 planck    ≈ €4.64
pro      : 2140 μTAL  = 2140000000 planck   ≈ €23.11
business :10260 μTAL  = 10260000000 planck  ≈ €110.81
```

## 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Agents under-report usage | Shared-secret auth + backend cron as source of truth; agent report cannot lower already-metered total. |
| Race between cron and `session_terminated` | All ledger ops in `prisma.$transaction` with row-lock on `UserWallet`; strict commit order (check, then update). |
| Realtime assistant drifts into negative because of network lag before client heartbeat | Cron ticks every 10s while `minReservePlanck` covers 60s; worst-case overrun is one tick (~4 μTAL ≈ €0.04). Acceptable per-session loss. |
| Loss of custodial key (corrupted env, reinstalled server) | Keys encrypted by `WALLET_ENCRYPTION_KEY` from env; key backed up in 1Password. Phase 2: move to KMS/Vault. |
| `DepositWatcher` misses blocks during downtime | `BillingConfig.lastSeenBlock` used for catch-up on service start. |
| 2× markup doesn't actually cover costs | Phase 1 dry-run exists for this. Admin can adjust any row in seconds via PATCH. |
| User disputes a debit | Full audit trail in `BillingTransaction.metadata` (units, costUsd, talRate, markup). Admin sees everything via `/admin/billing/users/:id`. |

## 11. Effort estimate

- **Backend**: ~12 new files in `src/billing/` and `src/blockchain/`, ~6 migrations, hooks in 4 existing services (voice, assistant, messenger/ai-twin, outbound-bot). ~2-3 days.
- **Python agents**: patch `ai-twin-agent/agent.py` and `outbound-call-agent/agent.py` to add `units` in callback payload. ~0.5 day.
- **Mobile**: new `billing/` feature module, settings integration, paywall interceptor, `balance_chip`. ~3-4 days.
- **Tests**: update `taler_id_tests/` + new billing-smoke. ~1 day.

**Total:** ~1.5 weeks of focused single-developer work.

## 12. Open items (to resolve during implementation planning)

- Exact `minReservePlanck` values per feature after Phase 1 calibration.
- `PricePackage` as a DB table or a TypeScript constant (leaning toward code constant since only 3 items and they are admin-tuned rarely).
- Choice of encryption scheme for `custodialKeyEnc` (AES-GCM with derived key is the default).
- Whether withdraw requires a confirmation step (email/2FA) — likely yes, but decide during implementation plan.
