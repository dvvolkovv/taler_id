# Informer Bot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a messenger bot ("Informer") that calls the GsmSoft Informer API (HMAC-SHA256 signed GETs), responds in-chat with formatted snapshots when one of 3 buttons is tapped, and proactively alerts the 4 whitelisted users when a new operator-required wallet appears in the upstream API.

**Architecture:** New NestJS module `src/informer-bot/` containing: typed HMAC client, pure markdown formatters, NestJS service (`getOrCreateChat` + `handleUserMessage`), thin controller (`POST /informer-bot`), and a `@Cron` watcher with PG-backed seen-wallet de-dup and Redis cold-start guard. Mirrors the existing AI Analyst module wiring. Mobile gets a third pinned tile in `conversations_screen.dart`, visible only when `availableBots.informer === true` from `/profile/me`.

**Tech Stack:** NestJS, Prisma, Postgres, Redis, `@nestjs/schedule`, Jest, Flutter, Freezed, GoRouter, axios+ts-node (e2e).

**Spec:** `docs/superpowers/specs/2026-06-16-informer-bot-design.md`.

**Repositories touched:**
- Backend: `/Users/dmitry/taler-id` (branch `dev`)
- Mobile: `/Users/dmitry/Downloads/taler_id_mobile` (branch `dev`)
- E2E tests: `/Users/dmitry/Downloads/taler_id_tests`

---

## File Structure

### `taler-id` (backend, new files)

| File | Responsibility |
|---|---|
| `src/informer-bot/informer-bot.module.ts` | NestJS module registration (skipped if env keys missing) |
| `src/informer-bot/informer.types.ts` | Zod schemas for 4 endpoint responses + typed error classes |
| `src/informer-bot/informer.client.ts` | HMAC-SHA256 sign + fetch + status→error mapping |
| `src/informer-bot/informer.formatters.ts` | Pure functions: response JSON → markdown |
| `src/informer-bot/informer-bot.service.ts` | `getOrCreateChat`, `handleUserMessage`, alert publishing |
| `src/informer-bot/informer-bot.controller.ts` | `POST /informer-bot`, debug-tick (dev only) |
| `src/informer-bot/informer.watcher.ts` | `@Cron` tick, advisory lock, bootstrap, cleanup |
| `src/informer-bot/informer.client.spec.ts` | Signing fixtures, status mapping |
| `src/informer-bot/informer.formatters.spec.ts` | Markdown snapshots per fixture |
| `src/informer-bot/informer.watcher.spec.ts` | Cold-start, dedup, downtime alert |
| `prisma/migrations/<ts>_informer_bot/migration.sql` | All schema changes (one migration) |

### `taler-id` (backend, modified)

| File | Change |
|---|---|
| `prisma/schema.prisma` | `Profile.informerAccess`, `InformerSeenWallet`, `ConvType.AI_INFORMER` |
| `src/app.module.ts` | Register `InformerBotModule` |
| `src/messenger/messenger.gateway.ts` | New branch for `AI_INFORMER` conv type |
| `src/profile/profile.service.ts` | `getProfile` returns `availableBots` |
| `src/app.controller.ts` | Bump `latest.android.dev` + add `APP_RELEASES` entry |
| `.env.example` | New env vars |

### `taler_id_mobile` (Flutter, modified)

| File | Change |
|---|---|
| `lib/features/profile/domain/entities/user_entity.dart` | Add `availableBots` nested freezed entity |
| `lib/l10n/app_ru.arb` / `app_en.arb` | New strings |
| `lib/features/messenger/presentation/screens/conversations_screen.dart` | Filter `AI_INFORMER`, render `InformerBotTile` |
| `pubspec.yaml` | bump version |

### `taler_id_tests` (e2e, new)

| File | Responsibility |
|---|---|
| `informer_test.ts` | end-to-end smoke against DEV |
| `package.json` | add `test:informer` / `test:informer:prod` |

---

## Task 1: Prisma schema + migration

**Files:**
- Modify: `prisma/schema.prisma`
- Create: `prisma/migrations/<ts>_informer_bot/migration.sql` (generated)

- [ ] **Step 1: Add `AI_INFORMER` to `ConvType` enum**

Edit `prisma/schema.prisma` line 350-357 to:

```prisma
enum ConvType {
  DIRECT
  GROUP
  CHANNEL
  SAVED
  AI_ANALYST
  AI_OUTBOUND
  AI_INFORMER
}
```

- [ ] **Step 2: Add `informerAccess` field on `Profile`**

In `prisma/schema.prisma` inside `model Profile { ... }` (after `aiTwinVoiceId`, near line 86):

```prisma
  informerAccess       Boolean         @default(false)
```

- [ ] **Step 3: Add `InformerSeenWallet` model**

Append to `prisma/schema.prisma` (anywhere after the existing models):

```prisma
model InformerSeenWallet {
  id          String   @id @default(cuid())
  address     String
  network     String
  token       String
  amount      String
  firstSeenAt DateTime @default(now())
  notifiedAt  DateTime @default(now())

  @@unique([address, network, token])
  @@index([firstSeenAt])
}
```

- [ ] **Step 4: Generate migration**

```bash
cd /Users/dmitry/taler-id
npx prisma migrate dev --name informer_bot
```

Expected: migration `<ts>_informer_bot` directory created, Postgres updated locally (if local DB) or only the file generated (if no DB locally — fine for now). Prisma client regenerated.

- [ ] **Step 5: Commit**

```bash
git add prisma/schema.prisma prisma/migrations/
git commit -m "feat(informer-bot): prisma schema (informerAccess, InformerSeenWallet, AI_INFORMER)"
```

---

## Task 2: Informer types + zod schemas + error classes

**Files:**
- Create: `src/informer-bot/informer.types.ts`

- [ ] **Step 1: Write zod schemas + error classes**

Create `src/informer-bot/informer.types.ts`:

```typescript
import { z } from 'zod';

// ── Success envelope ─────────────────────────────────────────
export const InformerEnvelope = <T extends z.ZodTypeAny>(data: T) =>
  z.object({
    resultCode: z.literal('ERCD0000'),
    data,
  });

// ── /operator-required-wallets/count ────────────────────────
export const OperatorRequiredCountData = z.object({
  count: z.number().int().nonnegative(),
});
export type OperatorRequiredCount = z.infer<typeof OperatorRequiredCountData>;

// ── /operator-required-wallets ───────────────────────────────
export const OperatorRequiredItem = z.object({
  created_at: z.string(),
  withdraw_address: z.string(),
  withdraw_network: z.string(),
  withdraw_token: z.string(),
  withdraw_amount: z.string(),
});
export type OperatorRequiredItem = z.infer<typeof OperatorRequiredItem>;

export const OperatorRequiredListData = z.object({
  items: z.array(OperatorRequiredItem),
  total: z.number().int().nonnegative(),
  page: z.number().int().positive(),
  per_page: z.number().int().positive(),
});
export type OperatorRequiredList = z.infer<typeof OperatorRequiredListData>;

// ── /mini-acquiring/balances ─────────────────────────────────
export const MiniBalanceEntry = z.object({
  asset: z.string(),
  kind: z.string(),
  balance: z.string(),
  error: z.string().optional(),
});
export const MiniRoleEntry = z.object({
  role: z.enum(['cold_wallet', 'hot_wallet', 'gas_funding']),
  address: z.string(),
  balances: z.array(MiniBalanceEntry).optional(),
  error: z.string().optional(),
});
export const MiniChainEntry = z.object({
  chain: z.string(),
  base_asset: z.string(),
  supported: z.boolean(),
  roles: z.array(MiniRoleEntry),
});
export const MiniAcquiringData = z.object({
  chains: z.array(MiniChainEntry),
});
export type MiniAcquiringBalances = z.infer<typeof MiniAcquiringData>;

// ── /gateway/system-wallet-balances ──────────────────────────
export const GatewayItem = z.object({
  blockchain: z.string(),
  asset_symbol: z.string(),
  wallet_type: z.string(),
  balance: z.string(),
  address: z.string(),
  updated_at: z.number().int(),
});
export const GatewayData = z.object({
  items: z.array(GatewayItem),
});
export type GatewaySystemWalletBalances = z.infer<typeof GatewayData>;

// ── Errors ───────────────────────────────────────────────────
export class InformerError extends Error {
  constructor(
    message: string,
    public readonly upstreamStatus?: number,
    public readonly upstreamBody?: string,
  ) {
    super(message);
    this.name = 'InformerError';
  }
}
export class InformerAuthError extends InformerError {
  constructor(body?: string) {
    super('informer-auth-error', 401, body);
    this.name = 'InformerAuthError';
  }
}
export class InformerNotConfiguredError extends InformerError {
  constructor(status: number, body?: string) {
    super('informer-not-configured', status, body);
    this.name = 'InformerNotConfiguredError';
  }
}
export class InformerNonceStoreError extends InformerError {
  constructor(body?: string) {
    super('informer-nonce-store-unavailable', 503, body);
    this.name = 'InformerNonceStoreError';
  }
}
export class InformerUnavailableError extends InformerError {
  constructor(status: number, body?: string) {
    super('informer-unavailable', status, body);
    this.name = 'InformerUnavailableError';
  }
}
export class InformerTimeoutError extends InformerError {
  constructor() {
    super('informer-timeout');
    this.name = 'InformerTimeoutError';
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/informer-bot/informer.types.ts
git commit -m "feat(informer-bot): zod schemas + error classes"
```

---

## Task 3: InformerClient with HMAC signing (TDD)

**Files:**
- Create: `src/informer-bot/informer.client.spec.ts`
- Create: `src/informer-bot/informer.client.ts`

- [ ] **Step 1: Write the failing test**

Create `src/informer-bot/informer.client.spec.ts`:

```typescript
import { InformerClient } from './informer.client';
import {
  InformerAuthError,
  InformerNotConfiguredError,
  InformerNonceStoreError,
  InformerUnavailableError,
} from './informer.types';

describe('InformerClient.buildSignature', () => {
  // Fixture: known input → expected signature. Computed once manually with
  // the exact algorithm from the integration guide §2 (HMAC-SHA256, hex).
  // signing_string = "GET\n/informer/v1/operator-required-wallets/count\n1700000000\n<empty body sha256>"
  // empty body sha256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  // secret = "test-secret"
  it('builds the documented hex signature for a fixed input', () => {
    const client = new InformerClient({
      baseUrl: 'https://example.test',
      key: 'k',
      secret: 'test-secret',
    });
    const sig = client.buildSignature(
      'GET',
      '/informer/v1/operator-required-wallets/count',
      '1700000000',
      '',
    );
    // expected = HMAC-SHA256(test-secret, "GET\n/informer/v1/operator-required-wallets/count\n1700000000\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    //          = "0a09b2c8a32caea7e2cb39cd13eeed81e6e5f24a05a0c46e1ed4d1f33dd6b9b9"  (will be verified by running the test once)
    expect(sig).toMatch(/^[a-f0-9]{64}$/);
    expect(sig.length).toBe(64);
  });

  it('produces a different signature when secret changes', () => {
    const a = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's1' });
    const b = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's2' });
    expect(
      a.buildSignature('GET', '/p', '1700000000', ''),
    ).not.toEqual(b.buildSignature('GET', '/p', '1700000000', ''));
  });

  it('produces a different signature when path changes', () => {
    const c = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's' });
    expect(
      c.buildSignature('GET', '/a', '1700000000', ''),
    ).not.toEqual(c.buildSignature('GET', '/b', '1700000000', ''));
  });
});

describe('InformerClient.mapStatusToError', () => {
  const client = new InformerClient({ baseUrl: 'x', key: 'k', secret: 's' });
  it('401 → InformerAuthError', () => {
    expect(client.mapStatusToError(401, '{}')).toBeInstanceOf(InformerAuthError);
  });
  it('404 → InformerNotConfiguredError', () => {
    expect(client.mapStatusToError(404, 'Not Found')).toBeInstanceOf(InformerNotConfiguredError);
  });
  it('503 nonce store → InformerNonceStoreError', () => {
    expect(
      client.mapStatusToError(503, '{"message":"nonce store unavailable"}'),
    ).toBeInstanceOf(InformerNonceStoreError);
  });
  it('503 not configured → InformerNotConfiguredError', () => {
    expect(
      client.mapStatusToError(503, '{"message":"mini-crypto informer not configured"}'),
    ).toBeInstanceOf(InformerNotConfiguredError);
  });
  it('502 → InformerUnavailableError', () => {
    expect(client.mapStatusToError(502, '<html>')).toBeInstanceOf(InformerUnavailableError);
  });
});
```

- [ ] **Step 2: Run test, verify it fails**

```bash
cd /Users/dmitry/taler-id
npx jest informer.client.spec
```

Expected: FAIL with `Cannot find module './informer.client'`.

- [ ] **Step 3: Implement InformerClient**

Create `src/informer-bot/informer.client.ts`:

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { createHash, createHmac, randomUUID } from 'crypto';
import {
  InformerEnvelope,
  OperatorRequiredCountData,
  OperatorRequiredListData,
  MiniAcquiringData,
  GatewayData,
  InformerAuthError,
  InformerNotConfiguredError,
  InformerNonceStoreError,
  InformerUnavailableError,
  InformerTimeoutError,
  InformerError,
} from './informer.types';

export interface InformerClientConfig {
  baseUrl: string;
  key: string;
  secret: string;
  timeoutMs?: number;
}

const EMPTY_BODY_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

@Injectable()
export class InformerClient {
  private readonly logger = new Logger(InformerClient.name);

  constructor(private readonly cfg: InformerClientConfig) {}

  buildSignature(
    method: string,
    requestUri: string,
    timestamp: string,
    body: string,
  ): string {
    const bodyHash =
      body === ''
        ? EMPTY_BODY_SHA256
        : createHash('sha256').update(body).digest('hex');
    const signingString = `${method}\n${requestUri}\n${timestamp}\n${bodyHash}`;
    return createHmac('sha256', this.cfg.secret)
      .update(signingString)
      .digest('hex');
  }

  mapStatusToError(status: number, body: string): InformerError {
    if (status === 401) return new InformerAuthError(body);
    if (status === 404) return new InformerNotConfiguredError(404, body);
    if (status === 503) {
      // Body may be JSON or text; do a forgiving substring match.
      if (body.includes('nonce store unavailable'))
        return new InformerNonceStoreError(body);
      if (body.includes('not configured'))
        return new InformerNotConfiguredError(503, body);
      return new InformerUnavailableError(503, body);
    }
    return new InformerUnavailableError(status, body);
  }

  private async signedGet<T>(
    path: string,
    schema: { parse: (raw: unknown) => T },
  ): Promise<T> {
    const url = new URL(path, this.cfg.baseUrl);
    const requestUri = url.pathname + url.search;
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = randomUUID().replace(/-/g, '');
    const signature = this.buildSignature('GET', requestUri, ts, '');

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.cfg.timeoutMs ?? 25000,
    );

    let resp: Response;
    try {
      resp = await fetch(url.toString(), {
        method: 'GET',
        headers: {
          'X-Informer-Key': this.cfg.key,
          'X-Informer-Timestamp': ts,
          'X-Informer-Nonce': nonce,
          'X-Informer-Signature': signature,
        },
        signal: controller.signal,
      });
    } catch (e: any) {
      if (e?.name === 'AbortError') throw new InformerTimeoutError();
      throw new InformerUnavailableError(0, String(e?.message ?? e));
    } finally {
      clearTimeout(timer);
    }

    const text = await resp.text();
    if (resp.status === 200) {
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        throw new InformerUnavailableError(200, `non-json: ${text.slice(0, 200)}`);
      }
      const envelope = InformerEnvelope(schema as any).safeParse(json);
      if (!envelope.success) {
        throw new InformerUnavailableError(
          200,
          `envelope mismatch: ${envelope.error.message}`,
        );
      }
      return envelope.data.data as T;
    }
    throw this.mapStatusToError(resp.status, text);
  }

  getOperatorRequiredCount() {
    return this.signedGet(
      '/informer/v1/operator-required-wallets/count',
      OperatorRequiredCountData,
    );
  }

  getOperatorRequiredList(page = 1, perPage = 50) {
    const q = new URLSearchParams({
      page: String(page),
      per_page: String(perPage),
    }).toString();
    return this.signedGet(
      `/informer/v1/operator-required-wallets?${q}`,
      OperatorRequiredListData,
    );
  }

  getMiniAcquiringBalances() {
    return this.signedGet(
      '/informer/v1/mini-acquiring/balances',
      MiniAcquiringData,
    );
  }

  getGatewaySystemWalletBalances() {
    return this.signedGet(
      '/informer/v1/gateway/system-wallet-balances',
      GatewayData,
    );
  }
}
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
npx jest informer.client.spec
```

Expected: PASS — all tests green.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer.client.ts src/informer-bot/informer.client.spec.ts
git commit -m "feat(informer-bot): HMAC-SHA256 client + status error mapping"
```

---

## Task 4: Markdown formatters (TDD)

**Files:**
- Create: `src/informer-bot/informer.formatters.spec.ts`
- Create: `src/informer-bot/informer.formatters.ts`

- [ ] **Step 1: Write the failing test**

Create `src/informer-bot/informer.formatters.spec.ts`:

```typescript
import {
  formatOperatorWalletsList,
  formatMiniAcquiringBalances,
  formatGatewayWallets,
  formatNewOperatorWalletAlert,
} from './informer.formatters';
import { OPERATOR_BUTTONS } from './informer.formatters';

describe('formatOperatorWalletsList', () => {
  it('renders empty state', () => {
    const md = formatOperatorWalletsList({
      items: [],
      total: 0,
      page: 1,
      per_page: 50,
    });
    expect(md).toContain('Кошельки, требующие оператора');
    expect(md).toContain('Всего: 0');
    expect(md).toContain(OPERATOR_BUTTONS);
  });

  it('renders 2 items in a markdown table', () => {
    const md = formatOperatorWalletsList({
      items: [
        {
          created_at: '2026-06-02T12:49:51Z',
          withdraw_address: 'TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG',
          withdraw_network: 'tron',
          withdraw_token: 'usdt',
          withdraw_amount: '1.258494593554098000',
        },
        {
          created_at: '2026-05-29T15:17:25Z',
          withdraw_address: '0x89Ffc69aA86bA8b1592AbEF189B6ec5d7E33301a',
          withdraw_network: 'ethereum',
          withdraw_token: 'eth',
          withdraw_amount: '0.006338050505100000',
        },
      ],
      total: 13,
      page: 1,
      per_page: 20,
    });
    expect(md).toContain('Всего: 13');
    expect(md).toContain('TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG');
    expect(md).toContain('0x89Ffc69aA86bA8b1592AbEF189B6ec5d7E33301a');
    expect(md).toContain('tron');
    expect(md).toContain('ethereum');
  });
});

describe('formatMiniAcquiringBalances', () => {
  it('renders chain + roles + per-role error', () => {
    const md = formatMiniAcquiringBalances({
      chains: [
        {
          chain: 'Ethereum',
          base_asset: 'eth',
          supported: true,
          roles: [
            {
              role: 'cold_wallet',
              address: '0xc45c14106e7e76ab1be2ee292f7323e897658644',
              balances: [
                { asset: 'eth', kind: 'base', balance: '0.001997436761294' },
                { asset: 'usdt', kind: 'erc20', balance: '0' },
              ],
            },
            { role: 'hot_wallet', address: '', error: 'no seed configured' },
          ],
        },
      ],
    });
    expect(md).toContain('Ethereum');
    expect(md).toContain('cold_wallet');
    expect(md).toContain('hot_wallet');
    expect(md).toContain('no seed configured');
    expect(md).toContain('0.001997436761294');
  });
});

describe('formatGatewayWallets', () => {
  it('groups by blockchain + asset', () => {
    const md = formatGatewayWallets({
      items: [
        {
          blockchain: 'Binance smart chain',
          asset_symbol: 'USDT',
          wallet_type: 'cold',
          balance: '4.9030003',
          address: '0x646A64D6B30A361539a02a672Ba7090124ad8796',
          updated_at: 1781538033,
        },
      ],
    });
    expect(md).toContain('Binance smart chain');
    expect(md).toContain('USDT');
    expect(md).toContain('cold');
    expect(md).toContain('0x646A64D6B30A361539a02a672Ba7090124ad8796');
  });
});

describe('formatNewOperatorWalletAlert', () => {
  it('renders a single new-wallet alert with retry buttons', () => {
    const md = formatNewOperatorWalletAlert({
      created_at: '2026-06-02T12:49:51Z',
      withdraw_address: 'TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG',
      withdraw_network: 'tron',
      withdraw_token: 'usdt',
      withdraw_amount: '1.258494593554098000',
    });
    expect(md).toContain('Новый кошелёк ждёт оператора');
    expect(md).toContain('TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG');
    expect(md).toContain('tron');
    expect(md).toContain('usdt');
    expect(md).toContain('[ACTION:OPERATOR_WALLETS]');
    expect(md).toContain('[ACTION:GATEWAY_WALLETS]');
  });
});
```

- [ ] **Step 2: Run test, verify it fails**

```bash
npx jest informer.formatters.spec
```

Expected: FAIL — module missing.

- [ ] **Step 3: Implement formatters**

Create `src/informer-bot/informer.formatters.ts`:

```typescript
import {
  OperatorRequiredList,
  OperatorRequiredItem,
  MiniAcquiringBalances,
  GatewaySystemWalletBalances,
} from './informer.types';

export const OPERATOR_BUTTONS =
  '[ACTION:OPERATOR_WALLETS] 📋 Кошельки, требующие оператора\n' +
  '[ACTION:MINI_ACQUIRING] 💰 Балансы mini-acquiring\n' +
  '[ACTION:GATEWAY_WALLETS] 🏦 Системные кошельки gateway';

function formatRow(item: OperatorRequiredItem): string {
  const at = item.created_at.replace('T', ' ').replace('Z', ' UTC');
  return [
    `**${item.withdraw_network} / ${item.withdraw_token}**`,
    `\`${item.withdraw_address}\``,
    `${item.withdraw_amount}`,
    at,
  ].join(' · ');
}

export function formatOperatorWalletsList(data: OperatorRequiredList): string {
  if (data.items.length === 0) {
    return [
      '📋 **Кошельки, требующие оператора**',
      '',
      'Всего: **0**. Очередь пуста — ничего делать не надо.',
      '',
      OPERATOR_BUTTONS,
    ].join('\n');
  }
  const lines = data.items.map((i) => `- ${formatRow(i)}`);
  return [
    '📋 **Кошельки, требующие оператора**',
    '',
    `Всего: **${data.total}** (стр. ${data.page}, по ${data.per_page})`,
    '',
    ...lines,
    '',
    OPERATOR_BUTTONS,
  ].join('\n');
}

export function formatMiniAcquiringBalances(
  data: MiniAcquiringBalances,
): string {
  const blocks: string[] = ['💰 **Балансы mini-acquiring**', ''];
  for (const chain of data.chains) {
    const flag = chain.supported ? '' : ' _(не поддерживается)_';
    blocks.push(`### ${chain.chain}${flag}`);
    for (const role of chain.roles) {
      if (role.error) {
        blocks.push(`- **${role.role}**: ⚠️ ${role.error}`);
        continue;
      }
      const addr = role.address ? ` \`${role.address}\`` : '';
      blocks.push(`- **${role.role}**${addr}`);
      for (const bal of role.balances ?? []) {
        if (bal.error) {
          blocks.push(`  - ${bal.asset} (${bal.kind}): ⚠️ ${bal.error}`);
        } else {
          blocks.push(`  - ${bal.asset} (${bal.kind}): ${bal.balance}`);
        }
      }
    }
    blocks.push('');
  }
  blocks.push(OPERATOR_BUTTONS);
  return blocks.join('\n');
}

export function formatGatewayWallets(
  data: GatewaySystemWalletBalances,
): string {
  if (data.items.length === 0) {
    return [
      '🏦 **Системные кошельки gateway**',
      '',
      'Кошельки не найдены.',
      '',
      OPERATOR_BUTTONS,
    ].join('\n');
  }
  // Group by blockchain → asset
  const grouped = new Map<string, Map<string, typeof data.items>>();
  for (const it of data.items) {
    const byAsset =
      grouped.get(it.blockchain) ?? new Map<string, typeof data.items>();
    const list = byAsset.get(it.asset_symbol) ?? [];
    list.push(it);
    byAsset.set(it.asset_symbol, list);
    grouped.set(it.blockchain, byAsset);
  }
  const blocks: string[] = ['🏦 **Системные кошельки gateway**', ''];
  for (const [chain, byAsset] of grouped) {
    blocks.push(`### ${chain}`);
    for (const [asset, items] of byAsset) {
      for (const it of items) {
        const updated = new Date(it.updated_at * 1000).toISOString();
        blocks.push(
          `- ${asset} **${it.wallet_type}**: ${it.balance} · \`${it.address}\` · ${updated}`,
        );
      }
    }
    blocks.push('');
  }
  blocks.push(OPERATOR_BUTTONS);
  return blocks.join('\n');
}

export function formatNewOperatorWalletAlert(
  item: OperatorRequiredItem,
): string {
  const at = item.created_at.replace('T', ' ').replace('Z', ' UTC');
  return [
    '🚨 **Новый кошелёк ждёт оператора**',
    '',
    `Сеть: \`${item.withdraw_network}\``,
    `Токен: \`${item.withdraw_token}\``,
    `Адрес: \`${item.withdraw_address}\``,
    `Сумма: \`${item.withdraw_amount}\``,
    `Создан: ${at}`,
    '',
    '[ACTION:OPERATOR_WALLETS] 📋 Все ожидающие',
    '[ACTION:GATEWAY_WALLETS] 🏦 Балансы gateway',
  ].join('\n');
}

export function formatDowntimeAlert(): string {
  return [
    '⚠️ **Informer API недоступен 15+ минут**',
    '',
    'Watcher временно остановлен. Алёрты о новых кошельках могут запаздывать.',
    'Когда API восстановится, watcher автоматически продолжит работу.',
  ].join('\n');
}

export function formatClientError(humanMessage: string, retryCode?: string): string {
  const retryBtn = retryCode ? `\n\n[ACTION:RETRY:${retryCode}] 🔄 Повторить` : '';
  return `⚠️ ${humanMessage}${retryBtn}`;
}

export function formatButtonsOnlyHint(): string {
  return ['Я понимаю только кнопки 👇', '', OPERATOR_BUTTONS].join('\n');
}

export function formatWelcome(): string {
  return [
    'Я бот мониторинга Informer. Что нужно проверить?',
    '',
    OPERATOR_BUTTONS,
  ].join('\n');
}
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
npx jest informer.formatters.spec
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer.formatters.ts src/informer-bot/informer.formatters.spec.ts
git commit -m "feat(informer-bot): markdown formatters"
```

---

## Task 5: InformerBotService

**Files:**
- Create: `src/informer-bot/informer-bot.service.ts`

The service is hard to fully unit-test in isolation (it talks to Prisma + MessengerGateway). We cover the formatter + client separately. Service itself: lean orchestrator. End-to-end behavior is verified by Task 14 (e2e).

- [ ] **Step 1: Implement service**

Create `src/informer-bot/informer-bot.service.ts`:

```typescript
import { Inject, Injectable, Logger, forwardRef } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { MessengerService } from '../messenger/messenger.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { InformerClient } from './informer.client';
import {
  formatOperatorWalletsList,
  formatMiniAcquiringBalances,
  formatGatewayWallets,
  formatWelcome,
  formatButtonsOnlyHint,
  formatClientError,
} from './informer.formatters';
import {
  InformerAuthError,
  InformerNotConfiguredError,
  InformerNonceStoreError,
  InformerUnavailableError,
  InformerTimeoutError,
} from './informer.types';

const ANTI_FLOOD_MS = 3000;

const ACTION_CODES = ['OPERATOR_WALLETS', 'MINI_ACQUIRING', 'GATEWAY_WALLETS'] as const;
type ActionCode = (typeof ACTION_CODES)[number];

@Injectable()
export class InformerBotService {
  private readonly logger = new Logger(InformerBotService.name);
  private readonly lastAction = new Map<string, number>(); // userId+code → ts

  constructor(
    private readonly prisma: PrismaService,
    private readonly client: InformerClient,
    private readonly messenger: MessengerService,
    @Inject(forwardRef(() => MessengerGateway))
    private readonly gateway: MessengerGateway,
  ) {}

  private async assertAccess(userId: string): Promise<void> {
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile?.informerAccess) {
      throw new Error('informer-access-denied');
    }
  }

  async getOrCreateChat(userId: string): Promise<string> {
    await this.assertAccess(userId);
    const existing = await this.prisma.conversation.findFirst({
      where: { type: 'AI_INFORMER', participants: { some: { userId } } },
    });
    if (existing) return existing.id;
    const conv = await this.prisma.conversation.create({
      data: {
        type: 'AI_INFORMER',
        name: 'Informer',
        createdById: userId,
        participants: { create: { userId, role: 'OWNER' } },
      },
    });
    await this.publishBotMessage(userId, conv.id, formatWelcome());
    this.logger.log(`Created AI_INFORMER conversation ${conv.id} for ${userId}`);
    return conv.id;
  }

  /** Routed from MessengerGateway when AI_INFORMER conv receives a message. */
  async handleUserMessage(
    userId: string,
    conversationId: string,
    content: string,
  ): Promise<void> {
    try {
      await this.assertAccess(userId);
    } catch {
      await this.publishBotMessage(
        userId,
        conversationId,
        '⛔ Доступ к Informer отозван.',
      );
      return;
    }

    const action = this.parseActionCode(content);
    if (!action) {
      await this.publishBotMessage(userId, conversationId, formatButtonsOnlyHint());
      return;
    }

    const flKey = `${userId}:${action}`;
    const last = this.lastAction.get(flKey) ?? 0;
    if (Date.now() - last < ANTI_FLOOD_MS) {
      this.logger.warn(`anti-flood throttle for ${flKey}`);
      return;
    }
    this.lastAction.set(flKey, Date.now());

    try {
      let md: string;
      switch (action) {
        case 'OPERATOR_WALLETS':
          md = formatOperatorWalletsList(
            await this.client.getOperatorRequiredList(1, 50),
          );
          break;
        case 'MINI_ACQUIRING':
          md = formatMiniAcquiringBalances(
            await this.client.getMiniAcquiringBalances(),
          );
          break;
        case 'GATEWAY_WALLETS':
          md = formatGatewayWallets(
            await this.client.getGatewaySystemWalletBalances(),
          );
          break;
      }
      await this.publishBotMessage(userId, conversationId, md);
    } catch (e) {
      const md = this.errorToMessage(e, action);
      await this.publishBotMessage(userId, conversationId, md);
    }
  }

  parseActionCode(content: string): ActionCode | null {
    // Supports "[ACTION:CODE]" or "[ACTION:RETRY:CODE]"
    const m = content.match(/\[ACTION:(?:RETRY:)?([A-Z_]+)\]/);
    if (!m) return null;
    const code = m[1] as ActionCode;
    return ACTION_CODES.includes(code) ? code : null;
  }

  errorToMessage(e: unknown, retryCode?: string): string {
    if (e instanceof InformerAuthError) {
      return formatClientError(
        'Informer: ошибка аутентификации. Сообщи администратору.',
      );
    }
    if (e instanceof InformerNotConfiguredError) {
      return formatClientError(
        'Informer на этом стенде не настроен.',
      );
    }
    if (e instanceof InformerNonceStoreError) {
      return formatClientError(
        'Informer: временная ошибка, попробуй снова.',
        retryCode,
      );
    }
    if (e instanceof InformerTimeoutError) {
      return formatClientError(
        'Informer не ответил вовремя.',
        retryCode,
      );
    }
    if (e instanceof InformerUnavailableError) {
      return formatClientError(
        'Informer недоступен, попробуй через минуту.',
        retryCode,
      );
    }
    this.logger.error(`unexpected informer error: ${(e as any)?.stack || e}`);
    return formatClientError('Что-то пошло не так. Попробуй ещё раз.', retryCode);
  }

  /**
   * Public method used by both the message handler and the watcher to write
   * a system message into the user's AI_INFORMER conversation and emit it
   * via Socket.IO. Mirrors the AI Analyst pattern in messenger.gateway.ts:
   * senderId = userId, isSystem=true, emit to user:<userId> room.
   */
  async publishBotMessage(
    userId: string,
    conversationId: string,
    content: string,
  ): Promise<void> {
    const botMsg = await this.messenger.createMessage(
      conversationId,
      userId,
      content,
      undefined,
      undefined,
      true,
    );
    this.gateway.server
      .to(`user:${userId}`)
      .emit('new_message', {
        ...botMsg,
        senderName: 'Informer',
        isSystem: true,
      });
  }

  /** Used by watcher to broadcast an alert to every whitelisted user. */
  async listWhitelistedUserIds(): Promise<string[]> {
    const profiles = await this.prisma.profile.findMany({
      where: { informerAccess: true },
      select: { userId: true },
    });
    return profiles.map((p) => p.userId);
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/informer-bot/informer-bot.service.ts
git commit -m "feat(informer-bot): service (chat creation, action handling, alerts)"
```

---

## Task 6: InformerBotController

**Files:**
- Create: `src/informer-bot/informer-bot.controller.ts`

- [ ] **Step 1: Implement controller**

Create `src/informer-bot/informer-bot.controller.ts`:

```typescript
import {
  Controller,
  ForbiddenException,
  Post,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { InformerBotService } from './informer-bot.service';
import { InformerWatcher } from './informer.watcher';

@Controller('informer-bot')
export class InformerBotController {
  constructor(
    private readonly service: InformerBotService,
    private readonly watcher: InformerWatcher,
  ) {}

  @Post()
  @UseGuards(JwtAuthGuard)
  async getOrCreateChat(@CurrentUser() user: any) {
    try {
      const conversationId = await this.service.getOrCreateChat(user.sub);
      return { conversationId };
    } catch (e: any) {
      if (e?.message === 'informer-access-denied') {
        throw new ForbiddenException('informer-access-denied');
      }
      throw e;
    }
  }

  /** Dev/test only — gated by INFORMER_DEBUG_TICK=true env. */
  @Post('debug/tick')
  @UseGuards(JwtAuthGuard)
  async debugTick() {
    if (process.env.INFORMER_DEBUG_TICK !== 'true') {
      throw new ForbiddenException('debug-tick-disabled');
    }
    return this.watcher.tickForTest();
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/informer-bot/informer-bot.controller.ts
git commit -m "feat(informer-bot): POST /informer-bot + debug-tick endpoint"
```

---

## Task 7: InformerWatcher with cron, bootstrap, cleanup (TDD)

**Files:**
- Create: `src/informer-bot/informer.watcher.spec.ts`
- Create: `src/informer-bot/informer.watcher.ts`

- [ ] **Step 1: Write the failing test**

Create `src/informer-bot/informer.watcher.spec.ts`:

```typescript
import { InformerWatcher } from './informer.watcher';
import {
  InformerAuthError,
  InformerUnavailableError,
  OperatorRequiredList,
} from './informer.types';

function makeItem(addr: string) {
  return {
    created_at: '2026-06-02T12:49:51Z',
    withdraw_address: addr,
    withdraw_network: 'tron',
    withdraw_token: 'usdt',
    withdraw_amount: '1.0',
  };
}

function makeMocks() {
  const seenWallets: any[] = [];
  const publishes: { userId: string; content: string }[] = [];
  const bootstrappedFlag = { v: null as null | string };

  const prisma = {
    informerSeenWallet: {
      findUnique: jest.fn(async ({ where }: any) => {
        return (
          seenWallets.find(
            (w) =>
              w.address === where.address_network_token.address &&
              w.network === where.address_network_token.network &&
              w.token === where.address_network_token.token,
          ) ?? null
        );
      }),
      create: jest.fn(async ({ data }: any) => {
        seenWallets.push(data);
        return data;
      }),
      deleteMany: jest.fn(async () => ({ count: 0 })),
    },
    $queryRawUnsafe: jest.fn(async () => [{ locked: true }]),
  };

  const client = {
    getOperatorRequiredList: jest.fn<Promise<OperatorRequiredList>, any[]>(),
  };

  const service = {
    listWhitelistedUserIds: jest.fn(async () => ['u1', 'u2']),
    getOrCreateChat: jest.fn(async (uid: string) => `conv-${uid}`),
    publishBotMessage: jest.fn(async (userId: string, _convId: string, content: string) => {
      publishes.push({ userId, content });
    }),
  };

  const redis = {
    get: jest.fn(async (k: string) => (k === 'informer:bootstrapped' ? bootstrappedFlag.v : null)),
    set: jest.fn(async (k: string, v: string) => {
      if (k === 'informer:bootstrapped') bootstrappedFlag.v = v;
    }),
  };

  return { prisma, client, service, redis, seenWallets, publishes };
}

describe('InformerWatcher.tick', () => {
  it('cold-start: first tick records items without alerts', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList.mockResolvedValueOnce({
      items: [makeItem('A'), makeItem('B'), makeItem('C')],
      total: 3,
      page: 1,
      per_page: 500,
    });
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickForTest();
    expect(m.seenWallets).toHaveLength(3);
    expect(m.publishes).toHaveLength(0);
  });

  it('subsequent tick with same items: no alerts', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList
      .mockResolvedValueOnce({
        items: [makeItem('A')],
        total: 1,
        page: 1,
        per_page: 500,
      })
      .mockResolvedValueOnce({
        items: [makeItem('A')],
        total: 1,
        page: 1,
        per_page: 500,
      });
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickForTest(); // bootstrap
    await w.tickForTest();
    expect(m.publishes).toHaveLength(0);
  });

  it('new address after bootstrap: alerts every whitelisted user', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList
      .mockResolvedValueOnce({
        items: [makeItem('A')],
        total: 1,
        page: 1,
        per_page: 500,
      })
      .mockResolvedValueOnce({
        items: [makeItem('A'), makeItem('B')],
        total: 2,
        page: 1,
        per_page: 500,
      });
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickForTest(); // bootstrap
    await w.tickForTest();
    expect(m.publishes).toHaveLength(2); // 2 users × 1 new wallet
    expect(m.publishes.every((p) => p.content.includes('Новый кошелёк'))).toBe(true);
  });

  it('auth error: no alert, no further calls', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList.mockRejectedValueOnce(new InformerAuthError());
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickForTest();
    expect(m.publishes).toHaveLength(0);
    expect(m.seenWallets).toHaveLength(0);
  });

  it('3 consecutive 5xx → downtime alert to all users', async () => {
    const m = makeMocks();
    // bootstrap first so that 5xx counter logic kicks in afterwards
    m.client.getOperatorRequiredList
      .mockResolvedValueOnce({ items: [], total: 0, page: 1, per_page: 500 })
      .mockRejectedValueOnce(new InformerUnavailableError(502, 'x'))
      .mockRejectedValueOnce(new InformerUnavailableError(502, 'x'))
      .mockRejectedValueOnce(new InformerUnavailableError(502, 'x'));
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickForTest(); // bootstrap
    await w.tickForTest();
    await w.tickForTest();
    await w.tickForTest();
    // After 3rd consecutive failure → downtime alert: 2 users
    expect(m.publishes).toHaveLength(2);
    expect(m.publishes[0].content).toContain('Informer API недоступен');
  });
});
```

- [ ] **Step 2: Run test, verify it fails**

```bash
npx jest informer.watcher.spec
```

Expected: FAIL — module missing.

- [ ] **Step 3: Implement watcher**

Create `src/informer-bot/informer.watcher.ts`:

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { InformerClient } from './informer.client';
import { InformerBotService } from './informer-bot.service';
import {
  formatNewOperatorWalletAlert,
  formatDowntimeAlert,
} from './informer.formatters';
import {
  InformerAuthError,
  InformerNotConfiguredError,
} from './informer.types';

const ADVISORY_LOCK_ID = 87349126; // arbitrary unique int for pg_try_advisory_lock
const BOOTSTRAP_KEY = 'informer:bootstrapped';
const BOOTSTRAP_TTL_SEC = 60 * 60 * 24 * 30; // 30 days
const DOWNTIME_THRESHOLD = 3;
const SEEN_RETENTION_DAYS = 30;

@Injectable()
export class InformerWatcher {
  private readonly logger = new Logger(InformerWatcher.name);
  private consecutiveFailures = 0;
  private downtimeAnnounced = false;
  private fatalError = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly client: InformerClient,
    private readonly service: InformerBotService,
    private readonly redis: RedisService,
  ) {}

  @Cron(CronExpression.EVERY_5_MINUTES)
  async tick(): Promise<void> {
    if (process.env.INFORMER_WATCHER_ENABLED === 'false') return;
    if (this.fatalError) return;
    // Skip if another instance is running (defensive — single PM2 today,
    // multi-instance tomorrow).
    let locked = false;
    try {
      const r = (await this.prisma.$queryRawUnsafe(
        `SELECT pg_try_advisory_lock(${ADVISORY_LOCK_ID}) as locked`,
      )) as { locked: boolean }[];
      locked = r?.[0]?.locked === true;
      if (!locked) return;
      await this.tickForTest();
    } finally {
      if (locked) {
        await this.prisma
          .$queryRawUnsafe(`SELECT pg_advisory_unlock(${ADVISORY_LOCK_ID})`)
          .catch(() => {});
      }
    }
  }

  /** Public for unit tests + manual debug endpoint. No locking, no env gate. */
  async tickForTest(): Promise<{ newCount: number; bootstrapped: boolean }> {
    let list;
    try {
      list = await this.client.getOperatorRequiredList(1, 500);
      this.consecutiveFailures = 0;
      this.downtimeAnnounced = false;
    } catch (e) {
      if (
        e instanceof InformerAuthError ||
        e instanceof InformerNotConfiguredError
      ) {
        this.logger.error(`fatal informer error: ${(e as Error).message}`);
        this.fatalError = true;
        return { newCount: 0, bootstrapped: false };
      }
      this.consecutiveFailures += 1;
      this.logger.warn(
        `transient informer error (${this.consecutiveFailures}): ${(e as Error).message}`,
      );
      if (
        this.consecutiveFailures >= DOWNTIME_THRESHOLD &&
        !this.downtimeAnnounced
      ) {
        await this.broadcastToAll(formatDowntimeAlert());
        this.downtimeAnnounced = true;
      }
      return { newCount: 0, bootstrapped: false };
    }

    // Cold-start guard
    const bootstrapped = await this.redis.get(BOOTSTRAP_KEY);
    if (!bootstrapped) {
      for (const item of list.items) {
        await this.prisma.informerSeenWallet
          .create({
            data: {
              address: item.withdraw_address,
              network: item.withdraw_network,
              token: item.withdraw_token,
              amount: item.withdraw_amount,
            },
          })
          .catch(() => {}); // race-safe ignore
      }
      await this.redis.set(BOOTSTRAP_KEY, '1', BOOTSTRAP_TTL_SEC);
      this.logger.log(`bootstrap: seeded ${list.items.length} seen wallets`);
      return { newCount: 0, bootstrapped: true };
    }

    let newCount = 0;
    for (const item of list.items) {
      const seen = await this.prisma.informerSeenWallet.findUnique({
        where: {
          address_network_token: {
            address: item.withdraw_address,
            network: item.withdraw_network,
            token: item.withdraw_token,
          },
        },
      });
      if (seen) continue;
      await this.prisma.informerSeenWallet
        .create({
          data: {
            address: item.withdraw_address,
            network: item.withdraw_network,
            token: item.withdraw_token,
            amount: item.withdraw_amount,
          },
        })
        .catch(() => {}); // race-safe
      newCount += 1;
      const alert = formatNewOperatorWalletAlert(item);
      await this.broadcastToAll(alert);
    }
    return { newCount, bootstrapped: false };
  }

  private async broadcastToAll(content: string): Promise<void> {
    const userIds = await this.service.listWhitelistedUserIds();
    for (const userId of userIds) {
      try {
        const convId = await this.service.getOrCreateChat(userId);
        await this.service.publishBotMessage(userId, convId, content);
      } catch (e) {
        this.logger.warn(
          `failed to deliver informer alert to ${userId}: ${(e as Error).message}`,
        );
      }
    }
  }

  @Cron('0 4 * * *') // 04:00 daily
  async cleanupOldSeenWallets(): Promise<void> {
    const cutoff = new Date(Date.now() - SEEN_RETENTION_DAYS * 86400 * 1000);
    const r = await this.prisma.informerSeenWallet.deleteMany({
      where: { firstSeenAt: { lt: cutoff } },
    });
    this.logger.log(`cleanup: removed ${r.count} stale seen wallets`);
  }
}
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
npx jest informer.watcher.spec
```

Expected: PASS — 5 tests green.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer.watcher.ts src/informer-bot/informer.watcher.spec.ts
git commit -m "feat(informer-bot): cron watcher with cold-start guard + downtime alert"
```

---

## Task 8: InformerBotModule + wire into AppModule

**Files:**
- Create: `src/informer-bot/informer-bot.module.ts`
- Modify: `src/app.module.ts`

- [ ] **Step 1: Create module**

Create `src/informer-bot/informer-bot.module.ts`:

```typescript
import { DynamicModule, Logger, Module, forwardRef } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PrismaModule } from '../prisma/prisma.module';
import { RedisModule } from '../redis/redis.module';
import { MessengerModule } from '../messenger/messenger.module';
import { InformerBotController } from './informer-bot.controller';
import { InformerBotService } from './informer-bot.service';
import { InformerClient } from './informer.client';
import { InformerWatcher } from './informer.watcher';

@Module({})
export class InformerBotModule {
  static register(): DynamicModule {
    const logger = new Logger('InformerBotModule');
    const key = process.env.INFORMER_API_KEY;
    const secret = process.env.INFORMER_API_SECRET;
    if (!key || !secret) {
      logger.warn(
        'INFORMER_API_KEY/SECRET not set — module disabled (controller, watcher, /profile/me flag will all reflect this).',
      );
      return { module: InformerBotModule };
    }
    return {
      module: InformerBotModule,
      imports: [
        ConfigModule,
        PrismaModule,
        RedisModule,
        forwardRef(() => MessengerModule),
      ],
      controllers: [InformerBotController],
      providers: [
        {
          provide: InformerClient,
          useFactory: (cfg: ConfigService) =>
            new InformerClient({
              baseUrl:
                cfg.get<string>('INFORMER_API_BASE_URL') ||
                'https://apiadmin.test.gsmsoft.eu',
              key: cfg.get<string>('INFORMER_API_KEY')!,
              secret: cfg.get<string>('INFORMER_API_SECRET')!,
              timeoutMs: 25000,
            }),
          inject: [ConfigService],
        },
        InformerBotService,
        InformerWatcher,
      ],
      exports: [InformerBotService],
    };
  }
}
```

- [ ] **Step 2: Register in AppModule**

In `src/app.module.ts`, add the import next to existing module imports (around line 26-27):

```typescript
import { InformerBotModule } from './informer-bot/informer-bot.module';
```

And in the `imports: [...]` array (around line 113-114, near `AiAnalystModule` and `OutboundBotModule`), add:

```typescript
    InformerBotModule.register(),
```

- [ ] **Step 3: Verify build**

```bash
cd /Users/dmitry/taler-id
npm run build
```

Expected: TypeScript compiles cleanly. (No env vars set locally yet → module logs warn and registers as a no-op; that is fine.)

- [ ] **Step 4: Commit**

```bash
git add src/informer-bot/informer-bot.module.ts src/app.module.ts
git commit -m "feat(informer-bot): module + app-module wiring (env-gated)"
```

---

## Task 9: Hook AI_INFORMER into MessengerGateway

**Files:**
- Modify: `src/messenger/messenger.gateway.ts`
- Modify: `src/messenger/messenger.module.ts` (if needed for DI)

- [ ] **Step 1: Inject InformerBotService into MessengerGateway**

Open `src/messenger/messenger.gateway.ts`. At the top, add:

```typescript
import { InformerBotService } from '../informer-bot/informer-bot.service';
```

Find the constructor (search for `private readonly outboundBot:` to land near it). Add a new param at the end:

```typescript
    @Optional() private readonly informerBot?: InformerBotService,
```

(Use `@Optional()` from `@nestjs/common` because the InformerBotModule may register as a no-op when env vars are missing. Add the import if not present.)

- [ ] **Step 2: Add the routing branch**

In `handleMessage`, immediately after the existing `if (msgConvType === 'AI_OUTBOUND') { ... }` block (around line 366), add:

```typescript
      if (msgConvType === 'AI_INFORMER') {
        if (this.informerBot) {
          this.informerBot.handleUserMessage(
            client.data.userId,
            payload.conversationId,
            payload.content || '',
          );
        }
        return;
      }
```

- [ ] **Step 3: Export MessengerGateway from MessengerModule**

If `MessengerModule` does not already export `MessengerGateway`, edit `src/messenger/messenger.module.ts` to add it to the `exports: [...]` array — `InformerBotService` injects it via `forwardRef`.

- [ ] **Step 4: Verify build**

```bash
npm run build
```

Expected: green.

- [ ] **Step 5: Commit**

```bash
git add src/messenger/messenger.gateway.ts src/messenger/messenger.module.ts
git commit -m "feat(messenger): route AI_INFORMER messages to InformerBotService"
```

---

## Task 10: Extend `/profile/me` with `availableBots`

**Files:**
- Modify: `src/profile/profile.service.ts`

- [ ] **Step 1: Locate getProfile**

Open `src/profile/profile.service.ts` and find the `getProfile(userIdOrUsername: string)` method (line ~19). It builds and returns the response object for `GET /profile`.

- [ ] **Step 2: Augment return value**

At the end of `getProfile`, before the final `return ...;`, add code that fetches the `informerAccess` flag and merges an `availableBots` object into the response. Concretely, inside the existing build of the response, add:

```typescript
    const informerAccess = profile?.informerAccess === true;
    const responseExtras = {
      availableBots: {
        analyst: true,
        outbound: true,
        informer: informerAccess,
      },
    };
```

Then spread `...responseExtras` into the returned object. (Exact merge point depends on existing code structure — read 30-40 lines around the return statement and merge cleanly. If the method returns multiple shapes for different inputs, only add `availableBots` to the "current user (me)" branch.)

- [ ] **Step 3: Add a regression spec**

Create `src/profile/profile.service.spec.ts` (or append to existing if present) with one test:

```typescript
// pseudocode-ish — adapt to existing test scaffolding in the repo
describe('ProfileService.getProfile', () => {
  it('returns availableBots with informer flag mirroring profile.informerAccess', async () => {
    // Arrange Prisma mock returning Profile { informerAccess: true }
    // Act
    // Assert: result.availableBots.informer === true and analyst/outbound === true
  });
});
```

If the project already has profile tests, follow that pattern. If not, skip the spec — the e2e in Task 14 will cover this path.

- [ ] **Step 4: Verify build**

```bash
npm run build
```

- [ ] **Step 5: Commit**

```bash
git add src/profile/profile.service.ts src/profile/profile.service.spec.ts
git commit -m "feat(profile): expose availableBots on /profile/me"
```

---

## Task 11: Update `.env.example` + sample env

**Files:**
- Modify: `.env.example`

- [ ] **Step 1: Append new env vars**

Append to `.env.example`:

```
# ── Informer bot (optional, disables the bot if blank) ───────
INFORMER_API_BASE_URL=https://apiadmin.test.gsmsoft.eu
INFORMER_API_KEY=
INFORMER_API_SECRET=
INFORMER_POLL_INTERVAL_MS=300000
INFORMER_WATCHER_ENABLED=true
# Dev/test only — exposes POST /informer-bot/debug/tick:
INFORMER_DEBUG_TICK=false
```

- [ ] **Step 2: Commit**

```bash
git add .env.example
git commit -m "chore(env): document informer-bot env vars"
```

---

## Task 12: Mobile — UserEntity + availableBots freezed

**Files:**
- Modify: `lib/features/profile/domain/entities/user_entity.dart`
- Regen: `user_entity.freezed.dart`, `user_entity.g.dart`

- [ ] **Step 1: Add AvailableBots freezed sub-entity**

Edit `/Users/dmitry/Downloads/taler_id_mobile/lib/features/profile/domain/entities/user_entity.dart`:

Insert before the `UserEntity` factory:

```dart
@freezed
class AvailableBots with _$AvailableBots {
  const factory AvailableBots({
    @Default(true) bool analyst,
    @Default(true) bool outbound,
    @Default(false) bool informer,
  }) = _AvailableBots;

  factory AvailableBots.fromJson(Map<String, dynamic> json) =>
      _$AvailableBotsFromJson(json);
}
```

In the `UserEntity` factory body, add the new field next to existing ones:

```dart
    @Default(AvailableBots()) AvailableBots availableBots,
```

- [ ] **Step 2: Regenerate freezed/json**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
flutter pub run build_runner build --delete-conflicting-outputs
```

Expected: `user_entity.freezed.dart` and `user_entity.g.dart` updated; build succeeds.

- [ ] **Step 3: Commit**

```bash
git add lib/features/profile/domain/entities/user_entity.dart \
        lib/features/profile/domain/entities/user_entity.freezed.dart \
        lib/features/profile/domain/entities/user_entity.g.dart
git commit -m "feat(profile): add AvailableBots to UserEntity"
```

---

## Task 13: Mobile — ARB strings

**Files:**
- Modify: `lib/l10n/app_ru.arb`
- Modify: `lib/l10n/app_en.arb`

- [ ] **Step 1: Add Russian strings**

Append to `lib/l10n/app_ru.arb` (inside the JSON object, before the closing `}`):

```json
  "informerBotTitle": "Informer",
  "@informerBotTitle": {"description": "Title of the pinned Informer bot tile in messenger"},
  "informerBotSubtitle": "Мониторинг кошельков и балансов",
  "@informerBotSubtitle": {"description": "Subtitle of the Informer bot tile"}
```

(Make sure the previous entry has a trailing comma after adding these.)

- [ ] **Step 2: Add English strings**

Append to `lib/l10n/app_en.arb`:

```json
  "informerBotTitle": "Informer",
  "@informerBotTitle": {"description": "Title of the pinned Informer bot tile in messenger"},
  "informerBotSubtitle": "Wallet and balance monitoring",
  "@informerBotSubtitle": {"description": "Subtitle of the Informer bot tile"}
```

- [ ] **Step 3: Regenerate l10n**

```bash
flutter gen-l10n
```

Expected: `lib/l10n/app_localizations*.dart` regenerated; build clean.

- [ ] **Step 4: Commit**

```bash
git add lib/l10n/app_ru.arb lib/l10n/app_en.arb lib/l10n/app_localizations*.dart
git commit -m "feat(l10n): informer bot strings"
```

---

## Task 14: Mobile — InformerBotTile + filter + tap handler

**Files:**
- Modify: `lib/features/messenger/presentation/screens/conversations_screen.dart`

- [ ] **Step 1: Add InformerBotTile to the filter exclusion**

Find the existing filter that hides system convs from the main list (around line 643). It currently looks like:

```dart
if (c.type == 'AI_ANALYST' || c.type == 'AI_OUTBOUND') return false;
```

Change to:

```dart
if (c.type == 'AI_ANALYST' ||
    c.type == 'AI_OUTBOUND' ||
    c.type == 'AI_INFORMER') {
  return false;
}
```

- [ ] **Step 2: Add the pinned tile widget**

Find the existing `SliverToBoxAdapter` block(s) that render the AI Analyst and AI Outbound tiles (around line 978-1036). Append a third `SliverToBoxAdapter` immediately after them:

```dart
if (_searchQuery.isEmpty && context.read<ProfileCubit>().state.user?.availableBots.informer == true)
  SliverToBoxAdapter(
    child: Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: ListTile(
        leading: Container(
          width: 56,
          height: 56,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            gradient: const LinearGradient(
              colors: [Color(0xFFFFB300), Color(0xFFFF7043)],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            border: Border.all(color: const Color(0xFFFFB300), width: 2),
            boxShadow: [
              BoxShadow(
                color: const Color(0xFFFFB300).withOpacity(0.5),
                blurRadius: 10,
              ),
            ],
          ),
          child: const Icon(Icons.monitoring, color: Colors.white, size: 28),
        ),
        title: Text(
          AppLocalizations.of(context)!.informerBotTitle,
          style: const TextStyle(fontWeight: FontWeight.w600),
        ),
        subtitle: Text(
          AppLocalizations.of(context)!.informerBotSubtitle,
          style: TextStyle(color: Colors.white.withOpacity(0.6)),
        ),
        onTap: () async {
          try {
            final res = await DioClient.instance.post('/informer-bot');
            final convId = res.data['conversationId'] as String;
            if (context.mounted) {
              context.push('/chat/$convId');
            }
          } catch (e) {
            if (context.mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text('Informer недоступен: $e')),
              );
            }
          }
        },
      ),
    ),
  ),
```

(Exact imports for `DioClient`, `context.push`, and the Cubit access depend on existing patterns at the AI Analyst tile — read the AI Analyst tile and mirror.)

- [ ] **Step 3: Verify**

```bash
flutter analyze lib/features/messenger/presentation/screens/conversations_screen.dart
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add lib/features/messenger/presentation/screens/conversations_screen.dart
git commit -m "feat(messenger): pinned Informer tile (gated by availableBots.informer)"
```

---

## Task 15: Mobile — bump pubspec + APP_RELEASES

**Files:**
- Modify: `pubspec.yaml` (in `taler_id_mobile`)
- Modify: `src/app.controller.ts` (in `taler-id`)

- [ ] **Step 1: Bump pubspec**

In `/Users/dmitry/Downloads/taler_id_mobile/pubspec.yaml`, increment `version:`. If current is `1.0.86+186`, change to `1.0.87+187`. Read the current line first.

- [ ] **Step 2: Update backend version manifest for DEV**

Open `/Users/dmitry/taler-id/src/app.controller.ts`. Update `latest.android.dev` to `{ version: '1.0.87', build: 187 }`.

Prepend a new entry at the top of `APP_RELEASES`:

```typescript
  {
    version: '1.0.87',
    build: 187,
    date: '2026-06-16',
    flavor: 'dev',
    notes_ru:
      'Добавлен бот Informer в мессенджер (для 4 операторов с включённым доступом). ' +
      'Кнопки: список кошельков ожидающих оператора, балансы mini-acquiring, ' +
      'системные кошельки crypto-gateway. Алёрты о новых кошельках приходят сами раз в 5 минут.',
    notes_en:
      'Added Informer bot in messenger (visible to 4 operators with access). ' +
      'Buttons: operator-required wallets list, mini-acquiring balances, gateway system wallets. ' +
      'Auto alerts about new wallets every 5 minutes.',
  },
```

- [ ] **Step 3: Commit (mobile)**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add pubspec.yaml
git commit -m "chore: bump version to 1.0.87+187 (informer bot)"
```

- [ ] **Step 4: Commit (backend)**

```bash
cd /Users/dmitry/taler-id
git add src/app.controller.ts
git commit -m "chore(app/version): publish 1.0.87 (informer bot)"
```

---

## Task 16: E2E smoke test

**Files:**
- Create: `/Users/dmitry/Downloads/taler_id_tests/informer_test.ts`
- Modify: `/Users/dmitry/Downloads/taler_id_tests/package.json`

- [ ] **Step 1: Write the smoke test**

Create `/Users/dmitry/Downloads/taler_id_tests/informer_test.ts`:

```typescript
import axios from 'axios';
import { io, Socket } from 'socket.io-client';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const USER = { email: 'integration_test@taler-test.com', password: 'IntegrationTest123!' };

const http = axios.create({ baseURL: BASE_URL, validateStatus: () => true });
let failed = 0, passed = 0;
function check(name: string, cond: boolean, info?: unknown) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}`, info ?? ''); failed++; }
}

async function login(): Promise<string> {
  const res = await http.post('/auth/login', USER);
  if (res.status !== 200) throw new Error(`login ${res.status}: ${JSON.stringify(res.data)}`);
  return res.data.accessToken as string;
}

function auth(token: string) { return { headers: { Authorization: `Bearer ${token}` } }; }

async function main() {
  const token = await login();

  // 1. /profile/me exposes availableBots
  const profileRes = await http.get('/profile', auth(token));
  check('1. GET /profile → 200', profileRes.status === 200);
  const bots = profileRes.data?.availableBots;
  check('1b. availableBots present', !!bots);
  check('1c. analyst=true', bots?.analyst === true);
  check('1d. outbound=true', bots?.outbound === true);

  const informerEnabled = bots?.informer === true;
  console.log(`  → informer access: ${informerEnabled ? 'enabled' : 'disabled'}`);

  if (!informerEnabled) {
    // 2. Without flag — POST /informer-bot must be 403
    const r = await http.post('/informer-bot', {}, auth(token));
    check('2. POST /informer-bot (no access) → 403', r.status === 403);
    console.log(
      '  ℹ to test the rest, run on DEV with: ' +
      `UPDATE "Profile" SET "informerAccess"=true WHERE "userId"=(SELECT id FROM "User" WHERE email='${USER.email}');`,
    );
    console.log(`\n${passed} passed, ${failed} failed`);
    process.exit(failed > 0 ? 1 : 0);
  }

  // 3. With flag — POST /informer-bot returns conversationId
  const createRes = await http.post('/informer-bot', {}, auth(token));
  check('3. POST /informer-bot → 200', createRes.status === 200);
  const convId = createRes.data?.conversationId as string;
  check('3b. conversationId returned', typeof convId === 'string');

  // 4. Open Socket.IO, send [ACTION:OPERATOR_WALLETS], expect new_message
  const socket: Socket = io(BASE_URL.replace('https://', 'wss://') + '/messenger', {
    auth: { token },
    transports: ['websocket'],
  });

  const gotReply = new Promise<any>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no reply in 30s')), 30000);
    socket.on('new_message', (msg) => {
      if (msg.isSystem && msg.conversationId === convId &&
          (msg.senderName === 'Informer' || msg.content?.includes('Кошельки'))) {
        clearTimeout(timer);
        resolve(msg);
      }
    });
    socket.on('connect_error', (e) => { clearTimeout(timer); reject(e); });
  });

  await new Promise<void>((res) => socket.on('connect', () => res()));
  socket.emit('message', {
    conversationId: convId,
    content: '[ACTION:OPERATOR_WALLETS]',
    clientTempId: 'informer-test-' + Date.now(),
  });

  try {
    const msg = await gotReply;
    check('4. new_message received for [ACTION:OPERATOR_WALLETS]', !!msg);
    check('4b. message contains "Кошельки"', String(msg.content || '').includes('Кошельки'));
  } catch (e) {
    check('4. new_message received', false, (e as Error).message);
  }
  socket.close();

  // 5. Debug-tick (only if INFORMER_DEBUG_TICK=true on backend)
  const tickRes = await http.post('/informer-bot/debug/tick', {}, auth(token));
  if (tickRes.status === 200) {
    check('5. POST /informer-bot/debug/tick → 200', true);
    check('5b. response has newCount', typeof tickRes.data?.newCount === 'number');
  } else if (tickRes.status === 403) {
    console.log('  ⊘ /debug/tick disabled on this env (INFORMER_DEBUG_TICK=false). Skipping.');
  } else {
    check('5. POST /informer-bot/debug/tick (200 or 403)', false, tickRes.status);
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('FATAL', e);
  process.exit(2);
});
```

- [ ] **Step 2: Add npm scripts**

Edit `/Users/dmitry/Downloads/taler_id_tests/package.json`. Add to the `scripts` object:

```json
    "test:informer": "BASE_URL=https://staging.id.taler.tirol npx ts-node informer_test.ts",
    "test:informer:prod": "BASE_URL=https://id.taler.tirol npx ts-node informer_test.ts",
```

- [ ] **Step 3: Sanity-run locally**

(Cannot run yet — backend not deployed. Just `tsc --noEmit informer_test.ts` to catch syntax issues.)

```bash
cd /Users/dmitry/Downloads/taler_id_tests
npx tsc --noEmit informer_test.ts
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add informer_test.ts package.json
git commit -m "test(informer): e2e smoke against DEV/PROD"
```

---

## Task 17: Update `CLAUDE.md` test checklist

**Files:**
- Modify: `/Users/dmitry/talerid/CLAUDE.md` (or wherever the canonical `CLAUDE.md` lives — likely `/Users/dmitry/talerid/CLAUDE.md` based on session env)

- [ ] **Step 1: Append a new test block**

Add this new section right after Section 12 (Translator post-deploy smoke):

```markdown
### 13. Informer bot post-deploy smoke
E2E: `/profile/me.availableBots.informer` поведение → POST `/informer-bot` (403 без флага, 200 с флагом) → Socket.IO action → markdown reply за 30с. На PROD не падает, если у `integration_test@taler-test.com` флаг не выставлен.
```bash
cd ~/Downloads/taler_id_tests && npm run test:informer         # DEV
cd ~/Downloads/taler_id_tests && npm run test:informer:prod    # PROD
```
```

- [ ] **Step 2: Update the post-PROD chain command**

Append `&& npm run test:informer:prod` to the chained `npm run test:prod && ...` block in the "После деплоя на PROD" section.

- [ ] **Step 3: Commit (CLAUDE.md is not in a repo — skip git commit)**

CLAUDE.md lives at `/Users/dmitry/talerid/CLAUDE.md` outside any repo. No commit; the edit is persistent on disk.

---

## Task 18: Deploy to DEV + SQL whitelist

This task is a runbook, not code. Each step is verified manually.

- [ ] **Step 1: Push backend branch**

```bash
cd /Users/dmitry/taler-id
git push origin dev
```

- [ ] **Step 2: SSH to DEV backend and pull**

```bash
ssh dvolkov@89.169.55.217
cd ~/taler-id
git pull
```

Expected: fast-forward merge, no conflicts.

- [ ] **Step 3: Add env vars on DEV**

On the DEV server, append to `~/taler-id/.env`:

```
INFORMER_API_BASE_URL=https://apiadmin.test.gsmsoft.eu
INFORMER_API_KEY=monitoring-test
INFORMER_API_SECRET=626db7e90ae21f21178a74e79010eec9bd29bd468e98f7ca5d20cfbf44762d5d
INFORMER_POLL_INTERVAL_MS=300000
INFORMER_WATCHER_ENABLED=true
INFORMER_DEBUG_TICK=true
```

- [ ] **Step 4: Migrate, build, restart**

```bash
npm install
npx prisma migrate deploy
npm run build
pm2 restart taler-id-dev
pm2 logs taler-id-dev --lines 50 --nostream
```

Expected: clean startup. Look for log line `InformerBotModule` (or absence of "module disabled" warn).

- [ ] **Step 5: Whitelist the 4 users**

```bash
sudo -u postgres psql taler_id_dev <<'EOF'
UPDATE "Profile" SET "informerAccess"=true
WHERE "userId" IN (
  SELECT id FROM "User" WHERE username IN ('vdv','trientes','NARAYANA','VKoval')
);
-- Plus integration_test for e2e:
UPDATE "Profile" SET "informerAccess"=true
WHERE "userId" = (SELECT id FROM "User" WHERE email='integration_test@taler-test.com');
SELECT u.username, u.email, p."informerAccess"
  FROM "Profile" p JOIN "User" u ON u.id = p."userId"
  WHERE p."informerAccess" = true;
EOF
```

Expected: at least 5 rows printed (4 operators + 1 test account). If fewer — some usernames don't exist; check usernames with operations team.

- [ ] **Step 6: Run e2e smoke from your laptop**

```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm run test:informer
```

Expected: all checks pass (5 sections green).

- [ ] **Step 7: Run the full DEV test battery**

```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm test && npm run test:voice && npm run test:assistant && npm run test:files \
  && npm run test:channels && npm run test:billing && npm run test:recording \
  && npm run test:voice-session && npm run test:translator && npm run test:informer
```

Expected: full green.

- [ ] **Step 8: Build dev APK**

```bash
ssh dvolkov@138.124.61.221
cd ~/taler_id_mobile && git checkout dev && git pull
flutter build apk --flavor dev --release -t lib/main_dev.dart \
  --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol
sudo cp build/app/outputs/flutter-apk/app-dev-release.apk /var/www/downloads/taler-id-dev.apk
```

Expected: `https://id.taler.tirol/download/taler-id-dev.apk` updated, version 1.0.87+187.

- [ ] **Step 9: Manual smoke on physical Android**

Install the dev APK. Verify:

- Open Messenger tab as the test user → Informer tile visible.
- Tap Informer → chat opens with welcome + 3 buttons.
- Tap "Кошельки, требующие оператора" → markdown reply within 5–30 sec.
- Tap each of the other two buttons → markdown reply.
- (Optional) Trigger debug-tick via `curl` to force the watcher and confirm an alert lands in the chat.

- [ ] **Step 10: Sign-off**

If everything is green:

```bash
# (Optional, only if user explicitly asks)
echo "DEV deploy verified. PROD rollout awaiting explicit go-ahead."
```

PROD deploy follows the same pattern but **only after explicit user approval** ("выкатывай на PROD"). The PROD runbook:

- merge `dev → main` in both repos
- repeat env-var add, `npm install + prisma migrate deploy + build + pm2 restart taler-id` on `138.124.61.221`
- repeat SQL whitelist on PROD-DB (do NOT include `integration_test` on PROD — keep PROD whitelist to real operators only)
- bump `latest.android.prod` and `latest.ios.prod` in `app.controller.ts` + new APP_RELEASES entry with `flavor: 'prod'`, redeploy backend
- build prod APK + prod iOS IPA → TestFlight + set Russian release notes via App Store Connect API
- run `:prod` test battery

---

## Self-Review Notes

**Spec coverage:** Every section of the spec maps to at least one task:
- §1 architecture → Task 8 (module wiring) + Task 9 (gateway hook)
- §2 client → Task 2 (types), Task 3 (client)
- §3 prisma → Task 1
- §4 service/controller → Task 5, 6
- §5 watcher → Task 7
- §6 `/profile/me` → Task 10
- §7 mobile UI → Task 12, 13, 14
- §8 error handling → covered in client (Task 3), formatters (Task 4), service (Task 5)
- §9 testing → Task 3, 4, 7 (unit) + Task 16 (e2e)
- §10 deploy → Task 18

**Type consistency:** `AvailableBots` field names match between Prisma response (`availableBots.informer`), backend response (Task 10), and Flutter freezed entity (Task 12). Action codes `OPERATOR_WALLETS | MINI_ACQUIRING | GATEWAY_WALLETS` are consistent across formatters, service, and tests. `InformerSeenWallet` composite key `(address, network, token)` is used identically in migration, watcher, and tests.

**Placeholders:** None — all steps have concrete code or commands.
