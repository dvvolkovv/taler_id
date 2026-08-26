# Informer Refund Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить в чат-бота Informer возврат средств по кошельку (пошаговый мастер с TOTP) и показ причины отказа в списке кошельков оператора.

**Architecture:** Три новых модуля рядом с существующим `informer-bot.service.ts`: типизированное pending-состояние оператора в Redis (один ключ вместо нынешнего `pending_totp`), чистый автомат мастера возврата (без Redis и HTTP внутри), классификатор текстов отказа `502`. Сервис остаётся диспетчером: читает состояние, зовёт автомат, ходит в клиент, публикует сообщения. Мобильное приложение не трогаем — оно generic-рендерер `[ACTION:метка]`.

**Tech Stack:** NestJS, TypeScript, Jest, ioredis (через `RedisService`), Prisma. Тесты — `npm test` (jest, `testRegex: .*\.spec\.ts$`), запуск одного файла: `npx jest src/informer-bot/<file>.spec.ts`.

**Спека:** `docs/superpowers/specs/2026-08-26-informer-refund-design.md`

---

## Файловая структура

| Файл | Ответственность | Статус |
|---|---|---|
| `src/informer-bot/informer.pending-state.ts` | Тип `PendingOp` + чтение/запись/очистка одного Redis-ключа `informer:pending_op:{userId}` | создать |
| `src/informer-bot/informer.pending-state.spec.ts` | Тесты сериализации и TTL | создать |
| `src/informer-bot/informer.refund-errors.ts` | `classifyRefundFailure(message)` → размеченный вид отказа | создать |
| `src/informer-bot/informer.refund-errors.spec.ts` | По кейсу на вид + незнакомые тексты | создать |
| `src/informer-bot/informer.refund-flow.ts` | Чистый автомат: `(state, input) → { next, messages }` | создать |
| `src/informer-bot/informer.refund-flow.spec.ts` | Таблица переходов целиком | создать |
| `src/informer-bot/informer.types.ts` | `+ last_error*` в `OperatorRequiredItem`, `+ OperatorWalletRefundResult`, `+ RefundTarget`, `+ WalletCtx` | изменить |
| `src/informer-bot/informer.client.ts` | `+ refundOperatorWallet`, override таймаута в `signedRequest` | изменить |
| `src/informer-bot/informer.client.spec.ts` | Тесты тела, флага, таймаута | изменить |
| `src/informer-bot/informer.formatters.ts` | Блок причины, сводка по событиям, карточки мастера | изменить |
| `src/informer-bot/informer.formatters.spec.ts` | Тесты новых форматтеров | изменить |
| `src/informer-bot/informer-bot.service.ts` | Диспетчер: миграция retry на общий ключ, ветки возврата, блокировка по кошельку | изменить |
| `src/informer-bot/informer-bot.service.spec.ts` | Тесты миграции и блокировки | изменить |

Порядок задач — снизу вверх по зависимостям: типы → классификатор → состояние → форматтеры → клиент → автомат → сервис. Каждая задача оставляет репозиторий с зелёными тестами.

---

## Task 1: Типы

**Files:**
- Modify: `src/informer-bot/informer.types.ts:27-51`

- [ ] **Step 1: Расширить `OperatorRequiredItem` и добавить новые типы**

В `src/informer-bot/informer.types.ts` заменить блок `OperatorRequiredItem` (строки 26–44) на:

```ts
// ── /operator-required-wallets ───────────────────────────────
export interface OperatorRequiredItem {
  // Optional because the public list response per current admin-API docs does
  // not include it, but the retry endpoint requires it. Tracked in
  // gsmsoft1/exchange/admin-api: when present, the chat renders a per-item
  // retry button; when absent, the button is omitted.
  wallet_id?: number;
  created_at: string;
  withdraw_address: string;
  withdraw_network: string;
  withdraw_token: string;
  withdraw_amount: string;

  // Last recorded failure for this wallet — the one that put it in the
  // operator queue. All three are optional and disappear together in two
  // very different cases: no failure was ever recorded for this wallet, OR
  // the platform's own journal is unavailable. Never render their absence
  // as "this wallet is fine".
  last_error_event?: string;
  // Prose for most events; for gate rejections the platform sends its
  // details-payload instead, e.g. {"reason":"withdrawal_intent_exists"}.
  // Union-typed so the formatter stringifies an object instead of crashing.
  last_error?: string | Record<string, unknown>;
  last_error_at?: string;
}

// ── /operator-required-wallets/{id}/retry ────────────────────
export interface OperatorWalletRetryResult {
  wallet_id: number;
  status: string;
}

// ── /operator-required-wallets/{id}/refund ───────────────────
export interface OperatorWalletRefundResult {
  wallet_id: number;
  status: string;
}

/**
 * Exactly one of the two shapes. The admin-API answers 400 with
 * "refund_address and refund_to_payer are mutually exclusive: send exactly
 * one" when both fields arrive together, so the union is enforced at the
 * type level rather than by runtime validation.
 */
export type RefundTarget =
  | { refundAddress: string }
  | { refundToPayer: true };

/**
 * Wallet facts captured at the moment the operator taps the refund button.
 * Carried through the wizard so the confirmation card can say
 * "50 usdt · BSC → 0xB1c4…" instead of a bare "#1611". The list may change
 * during the wizard; re-fetching on every step costs more and still gives
 * no guarantee.
 */
export interface WalletCtx {
  network: string;
  token: string;
  amount: string;
  address: string;
}
```

Затем **удалить** старый дублирующий блок `OperatorWalletRetryResult` (был на строках 40–44 до правки) — он перенесён выше, второй экземпляр вызовет ошибку компиляции.

- [ ] **Step 2: Проверить компиляцию**

Run: `cd /Users/dmitry/Downloads/taler_id && npx tsc --noEmit -p tsconfig.json`
Expected: без ошибок. Если появилась `Duplicate identifier 'OperatorWalletRetryResult'` — удалён не тот блок, оставить ровно одно объявление.

- [ ] **Step 3: Прогнать существующие тесты**

Run: `npx jest src/informer-bot`
Expected: PASS, все существующие наборы зелёные (новых полей никто пока не читает).

- [ ] **Step 4: Commit**

```bash
git add src/informer-bot/informer.types.ts
git commit -m "feat(informer): типы для last_error и возврата средств"
```

---

## Task 2: Классификатор отказов 502

**Files:**
- Create: `src/informer-bot/informer.refund-errors.ts`
- Test: `src/informer-bot/informer.refund-errors.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/informer-bot/informer.refund-errors.spec.ts`:

```ts
import { classifyRefundFailure } from './informer.refund-errors';

describe('classifyRefundFailure', () => {
  it('распознаёт гейт двойной выплаты', () => {
    const r = classifyRefundFailure(
      'refund would be a second payout for wallet 1611',
    );
    expect(r.kind).toBe('second_payout');
    expect(r.retryable).toBe(false);
  });

  it('распознаёт нехватку средств на hot-кошельке', () => {
    const r = classifyRefundFailure(
      'hot wallet holds 3 USDT but the refund needs 50 USDT',
    );
    expect(r.kind).toBe('insufficient_hot');
    // Ничего не отправлено — повтор безопасен после пополнения.
    expect(r.retryable).toBe(true);
  });

  it('распознаёт отсутствие исходящего hot-wallet пути', () => {
    const r = classifyRefundFailure(
      'network dash has no hot wallet payout path; refund manually',
    );
    expect(r.kind).toBe('no_payout_path');
    expect(r.retryable).toBe(false);
  });

  it('распознаёт недоступный узел', () => {
    const r = classifyRefundFailure(
      'refusing to send blind; retry once the node responds',
    );
    expect(r.kind).toBe('node_unavailable');
    expect(r.retryable).toBe(true);
  });

  it('распознаёт уже отправленный возврат и запрещает повтор', () => {
    const r = classifyRefundFailure(
      'refund operation already exists for this wallet',
    );
    expect(r.kind).toBe('already_exists');
    expect(r.retryable).toBe(false);
  });

  it('трактует ровно "refund failed" как отказ без деталей', () => {
    const r = classifyRefundFailure('refund failed');
    expect(r.kind).toBe('generic_business');
    expect(r.retryable).toBe(false);
  });

  it('незнакомый текст считает транспортным сбоем, но текст сохраняет', () => {
    const r = classifyRefundFailure('<html>502 Bad Gateway</html>');
    expect(r.kind).toBe('transport');
    expect(r.message).toBe('<html>502 Bad Gateway</html>');
    expect(r.retryable).toBe(false);
  });

  it('обрезанное длинное тело тоже транспортный сбой', () => {
    const r = classifyRefundFailure('upstream connect error or disconnect/re');
    expect(r.kind).toBe('transport');
  });

  it('пустое сообщение — транспортный сбой', () => {
    expect(classifyRefundFailure('').kind).toBe('transport');
  });

  it('матчит без учёта регистра', () => {
    expect(
      classifyRefundFailure('Refund Operation Already Exists For This Wallet')
        .kind,
    ).toBe('already_exists');
  });
});
```

- [ ] **Step 2: Прогнать тест, убедиться что падает**

Run: `npx jest src/informer-bot/informer.refund-errors.spec.ts`
Expected: FAIL — `Cannot find module './informer.refund-errors'`.

- [ ] **Step 3: Реализовать классификатор**

Создать `src/informer-bot/informer.refund-errors.ts`:

```ts
/**
 * The admin-API assigns no machine-readable error codes for refund
 * rejections — the reason arrives as prose in `message` with HTTP 502.
 * Match by substring, and always keep the original text: unmatched text is
 * still human-readable and belongs in front of the operator.
 */
export type RefundFailureKind =
  | 'second_payout'
  | 'insufficient_hot'
  | 'no_payout_path'
  | 'node_unavailable'
  | 'already_exists'
  | 'generic_business'
  | 'transport';

export interface RefundFailure {
  kind: RefundFailureKind;
  /** Original upstream text, verbatim. Never hidden from the operator. */
  message: string;
  /**
   * Whether re-sending the same refund is safe. True only where the
   * platform states nothing was sent. Never used to retry automatically —
   * it only decides whether a retry button is drawn.
   */
  retryable: boolean;
}

const RULES: Array<{
  kind: RefundFailureKind;
  needles: string[];
  retryable: boolean;
}> = [
  {
    kind: 'second_payout',
    needles: ['refund would be a second payout'],
    retryable: false,
  },
  {
    // Two needles because the amounts sit between them in the real message:
    // "hot wallet holds 3 USDT but the refund needs 50 USDT".
    kind: 'insufficient_hot',
    needles: ['hot wallet holds', 'the refund needs'],
    retryable: true,
  },
  {
    kind: 'no_payout_path',
    needles: ['has no hot wallet payout path'],
    retryable: false,
  },
  {
    kind: 'node_unavailable',
    needles: ['refusing to send blind'],
    retryable: true,
  },
  {
    kind: 'already_exists',
    needles: ['refund operation already exists'],
    retryable: false,
  },
];

export function classifyRefundFailure(rawMessage: string): RefundFailure {
  const message = rawMessage ?? '';
  const haystack = message.toLowerCase();

  for (const rule of RULES) {
    if (rule.needles.every((n) => haystack.includes(n))) {
      return { kind: rule.kind, message, retryable: rule.retryable };
    }
  }

  // The platform's generic wrapper. Known, but carries no actionable detail.
  if (haystack.trim() === 'refund failed') {
    return { kind: 'generic_business', message, retryable: false };
  }

  // Anything else: an intermediate proxy's response or a truncated body.
  // Classified as transport, but the text still travels to the operator —
  // the guide asks for both, and hiding it would lose real information.
  return { kind: 'transport', message, retryable: false };
}
```

- [ ] **Step 4: Прогнать тест, убедиться что проходит**

Run: `npx jest src/informer-bot/informer.refund-errors.spec.ts`
Expected: PASS, 10 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer.refund-errors.ts src/informer-bot/informer.refund-errors.spec.ts
git commit -m "feat(informer): классификатор текстов отказа возврата"
```

---

## Task 3: Pending-состояние

**Files:**
- Create: `src/informer-bot/informer.pending-state.ts`
- Test: `src/informer-bot/informer.pending-state.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Создать `src/informer-bot/informer.pending-state.spec.ts`:

```ts
import {
  PendingOp,
  PendingStateStore,
  PENDING_OP_TTL_SEC,
  pendingOpKey,
} from './informer.pending-state';

function makeRedisStub() {
  const store = new Map<string, string>();
  return {
    store,
    get: jest.fn(async (k: string) => store.get(k) ?? null),
    setEx: jest.fn(async (k: string, _ttl: number, v: string) => {
      store.set(k, v);
    }),
    del: jest.fn(async (k: string) => {
      store.delete(k);
    }),
  };
}

const CTX = {
  network: 'BSC',
  token: 'usdt',
  amount: '50',
  address: '0xcust',
};

describe('PendingStateStore', () => {
  it('кладёт состояние под ключ пользователя с TTL', async () => {
    const redis = makeRedisStub();
    const store = new PendingStateStore(redis as any);
    const op: PendingOp = { kind: 'retry', step: 'totp', walletId: 1611 };

    await store.save('u1', op);

    expect(redis.setEx).toHaveBeenCalledWith(
      'informer:pending_op:u1',
      PENDING_OP_TTL_SEC,
      JSON.stringify(op),
    );
  });

  it('читает обратно ровно то, что положили', async () => {
    const redis = makeRedisStub();
    const store = new PendingStateStore(redis as any);
    const op: PendingOp = {
      kind: 'refund',
      step: 'confirm',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
    };

    await store.save('u1', op);
    expect(await store.load('u1')).toEqual(op);
  });

  it('отдаёт null когда состояния нет', async () => {
    const store = new PendingStateStore(makeRedisStub() as any);
    expect(await store.load('nobody')).toBeNull();
  });

  it('отдаёт null и чистит ключ на битом JSON', async () => {
    const redis = makeRedisStub();
    redis.store.set('informer:pending_op:u1', '{not json');
    const store = new PendingStateStore(redis as any);

    expect(await store.load('u1')).toBeNull();
    expect(redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
  });

  it('отдаёт null и чистит ключ на неизвестном kind', async () => {
    const redis = makeRedisStub();
    redis.store.set(
      'informer:pending_op:u1',
      JSON.stringify({ kind: 'teleport', step: 'totp', walletId: 1 }),
    );
    const store = new PendingStateStore(redis as any);

    expect(await store.load('u1')).toBeNull();
    expect(redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
  });

  it('clear удаляет ключ', async () => {
    const redis = makeRedisStub();
    const store = new PendingStateStore(redis as any);
    await store.save('u1', { kind: 'retry', step: 'totp', walletId: 7 });

    await store.clear('u1');

    expect(await store.load('u1')).toBeNull();
    expect(redis.store.has('informer:pending_op:u1')).toBe(false);
  });

  it('новое состояние перетирает предыдущее — последняя кнопка выигрывает', async () => {
    const redis = makeRedisStub();
    const store = new PendingStateStore(redis as any);

    await store.save('u1', { kind: 'retry', step: 'totp', walletId: 1611 });
    await store.save('u1', {
      kind: 'refund',
      step: 'method',
      walletId: 1620,
      ctx: CTX,
    });

    const loaded = await store.load('u1');
    expect(loaded).toEqual({
      kind: 'refund',
      step: 'method',
      walletId: 1620,
      ctx: CTX,
    });
  });

  it('pendingOpKey строит ключ из userId', () => {
    expect(pendingOpKey('abc')).toBe('informer:pending_op:abc');
  });
});
```

- [ ] **Step 2: Прогнать тест, убедиться что падает**

Run: `npx jest src/informer-bot/informer.pending-state.spec.ts`
Expected: FAIL — `Cannot find module './informer.pending-state'`.

- [ ] **Step 3: Реализовать хранилище состояния**

Создать `src/informer-bot/informer.pending-state.ts`:

```ts
import { Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import { RefundTarget, WalletCtx } from './informer.types';

/**
 * TTL of the pending window. TOTP codes from authenticator apps live ~30s
 * (+/-1 step); 60s gives the operator one safe attempt per step: read the
 * card → act → send. An abandoned wizard expires on its own.
 */
export const PENDING_OP_TTL_SEC = 60;

export const pendingOpKey = (userId: string) => `informer:pending_op:${userId}`;

/**
 * Exactly one pending operation per operator, ever. Chat input is shared
 * across the whole conversation, so a bare "123456" must map to one
 * unambiguous operation — two independent pending states would resolve it
 * by whichever code path checked first, sending a TOTP into the wrong
 * (irreversible) operation. A new button overwrites the previous state:
 * last button wins.
 */
export type PendingOp =
  | { kind: 'retry'; step: 'totp'; walletId: number }
  | { kind: 'refund'; step: 'method'; walletId: number; ctx: WalletCtx }
  | { kind: 'refund'; step: 'address'; walletId: number; ctx: WalletCtx }
  | {
      kind: 'refund';
      step: 'confirm';
      walletId: number;
      ctx: WalletCtx;
      target: RefundTarget;
    }
  | {
      kind: 'refund';
      step: 'totp';
      walletId: number;
      ctx: WalletCtx;
      target: RefundTarget;
      verifiedAbsent: boolean;
    }
  | {
      kind: 'refund';
      step: 'gate';
      walletId: number;
      ctx: WalletCtx;
      target: RefundTarget;
      upstreamMessage: string;
    };

const KNOWN_KINDS = new Set(['retry', 'refund']);

export class PendingStateStore {
  private readonly logger = new Logger(PendingStateStore.name);

  constructor(private readonly redis: RedisService) {}

  async save(userId: string, op: PendingOp): Promise<void> {
    await this.redis.setEx(
      pendingOpKey(userId),
      PENDING_OP_TTL_SEC,
      JSON.stringify(op),
    );
  }

  /**
   * Returns null when there is nothing pending, and also when the stored
   * value is unreadable. Unreadable state is deleted rather than left to
   * expire: a corrupt entry would otherwise swallow every 6-digit message
   * for the rest of its TTL.
   */
  async load(userId: string): Promise<PendingOp | null> {
    const raw = await this.redis.get(pendingOpKey(userId));
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as PendingOp;
      if (!KNOWN_KINDS.has((parsed as { kind?: string })?.kind ?? '')) {
        throw new Error(`unknown kind: ${(parsed as any)?.kind}`);
      }
      return parsed;
    } catch (e) {
      this.logger.warn(
        `dropping unreadable pending state for ${userId}: ${(e as Error).message}`,
      );
      await this.clear(userId);
      return null;
    }
  }

  async clear(userId: string): Promise<void> {
    await this.redis.del(pendingOpKey(userId));
  }
}
```

- [ ] **Step 4: Прогнать тест, убедиться что проходит**

Run: `npx jest src/informer-bot/informer.pending-state.spec.ts`
Expected: PASS, 8 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer.pending-state.ts src/informer-bot/informer.pending-state.spec.ts
git commit -m "feat(informer): единое pending-состояние оператора в Redis"
```

---

## Task 4: Форматтер причины отказа в списке

**Files:**
- Modify: `src/informer-bot/informer.formatters.ts:67-110`
- Test: `src/informer-bot/informer.formatters.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Дописать в конец `src/informer-bot/informer.formatters.spec.ts`:

```ts
describe('formatOperatorWalletsList — причина отказа', () => {
  const base = {
    wallet_id: 1611,
    created_at: '2026-08-24T17:02:11Z',
    withdraw_address: '0xcust',
    withdraw_network: 'BSC',
    withdraw_token: 'usdt',
    withdraw_amount: '50',
  };

  it('рисует событие, текст и время в карточке', () => {
    const msgs = formatOperatorWalletsList({
      items: [
        {
          ...base,
          last_error_event: 'withdrawal_to_address_failed',
          last_error: 'insufficient balance: have 1, need 5',
          last_error_at: '2026-08-24T17:03:40Z',
        },
      ],
      total: 1,
      page: 1,
      per_page: 50,
    });
    const card = msgs[1];
    expect(card).toContain('withdrawal_to_address_failed');
    expect(card).toContain('insufficient balance: have 1, need 5');
    expect(card).toContain('2026-08-24 17:03:40 UTC');
  });

  it('приводит объектный last_error к тексту, а не падает', () => {
    const msgs = formatOperatorWalletsList({
      items: [
        {
          ...base,
          last_error_event: 'gate_rejected',
          last_error: { reason: 'withdrawal_intent_exists' },
          last_error_at: '2026-08-24T17:03:40Z',
        },
      ],
      total: 1,
      page: 1,
      per_page: 50,
    });
    expect(msgs[1]).toContain('withdrawal_intent_exists');
  });

  it('без полей причины не рисует ни блока, ни признака проблемы', () => {
    const msgs = formatOperatorWalletsList({
      items: [base],
      total: 1,
      page: 1,
      per_page: 50,
    });
    const card = msgs[1];
    expect(card).not.toContain('⚠️');
    expect(card).not.toContain('Причина');
    // Отсутствие причины НЕ означает «с кошельком всё в порядке».
    expect(card).not.toContain('ошибок нет');
  });

  it('рисует событие даже когда текста ошибки нет', () => {
    const msgs = formatOperatorWalletsList({
      items: [{ ...base, last_error_event: 'aml_refund_failed' }],
      total: 1,
      page: 1,
      per_page: 50,
    });
    expect(msgs[1]).toContain('aml_refund_failed');
  });

  it('складывает сводку по событиям в шапку', () => {
    const msgs = formatOperatorWalletsList({
      items: [
        { ...base, wallet_id: 1, last_error_event: 'withdrawal_to_address_failed' },
        { ...base, wallet_id: 2, last_error_event: 'withdrawal_to_address_failed' },
        { ...base, wallet_id: 3, last_error_event: 'withdrawal_to_address_failed' },
        { ...base, wallet_id: 4, last_error_event: 'aml_refund_failed' },
      ],
      total: 4,
      page: 1,
      per_page: 50,
    });
    const header = msgs[0];
    expect(header).toContain('3× withdrawal_to_address_failed');
    expect(header).toContain('1× aml_refund_failed');
  });

  it('не рисует сводку, когда причин нет ни у одного кошелька', () => {
    const msgs = formatOperatorWalletsList({
      items: [base, { ...base, wallet_id: 1612 }],
      total: 2,
      page: 1,
      per_page: 50,
    });
    expect(msgs[0]).not.toContain('Причины:');
  });

  it('добавляет кнопку возврата рядом с кнопкой повтора', () => {
    const msgs = formatOperatorWalletsList({
      items: [base],
      total: 1,
      page: 1,
      per_page: 50,
    });
    expect(msgs[1]).toContain('[ACTION:🔁 Повторить #1611]');
    expect(msgs[1]).toContain('[ACTION:💸 Вернуть #1611]');
  });

  it('без wallet_id не рисует ни повтор, ни возврат', () => {
    const { wallet_id, ...noId } = base;
    const msgs = formatOperatorWalletsList({
      items: [noId],
      total: 1,
      page: 1,
      per_page: 50,
    });
    expect(msgs[1]).not.toContain('Повторить');
    expect(msgs[1]).not.toContain('Вернуть');
  });
});
```

Убедиться, что `formatOperatorWalletsList` уже импортирован в шапке файла — он там есть.

- [ ] **Step 2: Прогнать тест, убедиться что падает**

Run: `npx jest src/informer-bot/informer.formatters.spec.ts -t 'причина отказа'`
Expected: FAIL — карточка не содержит `withdrawal_to_address_failed`.

- [ ] **Step 3: Реализовать**

В `src/informer-bot/informer.formatters.ts` добавить после функции `formatRow` (после строки 56):

```ts
/**
 * Renders the last recorded failure. Returns an empty array when the fields
 * are absent — they disappear both when nothing ever failed AND when the
 * platform's journal is down, so absence must render as nothing at all,
 * never as "no problems here".
 */
function reasonLines(item: OperatorRequiredItem): string[] {
  if (!item.last_error_event && !item.last_error && !item.last_error_at) {
    return [];
  }
  const lines: string[] = [];
  if (item.last_error_event) {
    lines.push(`⚠️ \`${item.last_error_event}\``);
  }
  const text = stringifyLastError(item.last_error);
  if (text) {
    lines.push(`   ${text}`);
  }
  if (item.last_error_at) {
    lines.push(`   ${item.last_error_at.replace('T', ' ').replace('Z', ' UTC')}`);
  }
  return lines;
}

/**
 * `last_error` is prose for most events, but gate rejections send their
 * details-payload instead, e.g. {"reason":"withdrawal_intent_exists"}.
 * Render either as text — the guide is explicit that clients should not
 * parse it.
 */
function stringifyLastError(
  err: string | Record<string, unknown> | undefined,
): string {
  if (err == null) return '';
  if (typeof err === 'string') return err.trim();
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

/**
 * Groups wallets by `last_error_event` so ten wallets sharing one event read
 * as one incident instead of ten problems. Sorted by count descending.
 */
function reasonSummaryLines(items: OperatorRequiredItem[]): string[] {
  const counts = new Map<string, number>();
  for (const i of items) {
    if (!i.last_error_event) continue;
    counts.set(i.last_error_event, (counts.get(i.last_error_event) ?? 0) + 1);
  }
  if (counts.size === 0) return [];
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  return ['', 'Причины:', ...sorted.map(([ev, n]) => `• ${n}× \`${ev}\``)];
}
```

Затем заменить тело `formatOperatorWalletsList` (строки 67–110) на:

```ts
export function formatOperatorWalletsList(
  data: OperatorRequiredList,
): string[] {
  if (data.items.length === 0) {
    return [
      [
        '📋 **Кошельки, требующие оператора**',
        '',
        'Всего: **0**. Очередь пуста — ничего делать не надо.',
        '',
        OPERATOR_BUTTONS,
      ].join('\n'),
    ];
  }
  const header = [
    '📋 **Кошельки, требующие оператора**',
    '',
    `Всего: **${data.total}** (стр. ${data.page}, по ${data.per_page})`,
    ...reasonSummaryLines(data.items),
  ].join('\n');

  const cards = data.items.map((i) => {
    const at = i.created_at.replace('T', ' ').replace('Z', ' UTC');
    const idLine =
      i.wallet_id != null
        ? `🪪 **#${i.wallet_id}** · ${i.withdraw_network} / ${i.withdraw_token}`
        : `🪪 ${i.withdraw_network} / ${i.withdraw_token}`;
    const lines = [
      idLine,
      `Адрес: \`${i.withdraw_address}\``,
      `Сумма: \`${i.withdraw_amount}\``,
      `Создан: ${at}`,
      ...reasonLines(i),
    ];
    if (i.wallet_id != null) {
      lines.push(
        '',
        `[ACTION:🔁 Повторить #${i.wallet_id}]`,
        `[ACTION:💸 Вернуть #${i.wallet_id}]`,
      );
    }
    return lines.join('\n');
  });

  // Trailer carries the navigation buttons so they don't pile up on every
  // wallet card.
  const trailer = OPERATOR_BUTTONS;

  return [header, ...cards, trailer];
}
```

Также добавить причину в алёрт вотчера — заменить `formatNewOperatorWalletAlert` (строки 236–252) на:

```ts
export function formatNewOperatorWalletAlert(
  item: OperatorRequiredItem,
): string {
  const at = item.created_at.replace('T', ' ').replace('Z', ' UTC');
  const reason = reasonLines(item);
  return [
    '🚨 **Новый кошелёк ждёт оператора**',
    '',
    `Сеть: \`${item.withdraw_network}\``,
    `Токен: \`${item.withdraw_token}\``,
    `Адрес: \`${item.withdraw_address}\``,
    `Сумма: \`${item.withdraw_amount}\``,
    `Создан: ${at}`,
    ...(reason.length > 0 ? ['', ...reason] : []),
    '',
    '[ACTION:📋 Все ожидающие]',
    '[ACTION:🏦 Балансы gateway]',
  ].join('\n');
}
```

- [ ] **Step 4: Прогнать тесты, убедиться что проходят**

Run: `npx jest src/informer-bot/informer.formatters.spec.ts`
Expected: PASS, включая 8 новых тестов и все существующие.

Run: `npx jest src/informer-bot`
Expected: PASS. Если упал `informer.watcher.spec.ts` из-за изменённого алёрта — проверить, ассертит ли он полное совпадение строки; поправить ожидание в тесте вотчера на `toContain`, поведение при отсутствии причины не изменилось.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer.formatters.ts src/informer-bot/informer.formatters.spec.ts src/informer-bot/informer.watcher.spec.ts
git commit -m "feat(informer): причина отказа в карточке кошелька и сводка в шапке"
```

---

## Task 5: Клиент — метод возврата

**Files:**
- Modify: `src/informer-bot/informer.client.ts:85-143`
- Test: `src/informer-bot/informer.client.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Дописать в конец `src/informer-bot/informer.client.spec.ts`:

```ts
describe('InformerClient.refundOperatorWallet', () => {
  let originalFetch: typeof global.fetch;
  beforeEach(() => {
    originalFetch = global.fetch;
  });
  afterEach(() => {
    global.fetch = originalFetch;
  });

  function makeClient() {
    return new InformerClient({
      baseUrl: 'https://example.test',
      key: 'k',
      secret: 's',
    });
  }

  function captureBody(): { body: () => any; url: () => string } {
    let captured: any;
    let capturedUrl = '';
    global.fetch = (async (url: any, init: any) => {
      capturedUrl = String(url);
      captured = JSON.parse(init.body);
      return {
        status: 200,
        text: async () =>
          JSON.stringify({
            resultCode: 'ERCD0000',
            data: { wallet_id: 1611, status: 'ok' },
          }),
      };
    }) as any;
    return { body: () => captured, url: () => capturedUrl };
  }

  it('шлёт refund_address и НЕ шлёт refund_to_payer', async () => {
    const cap = captureBody();
    await makeClient().refundOperatorWallet(
      1611,
      { refundAddress: '0xB1c4' },
      '123456',
    );
    expect(cap.body()).toEqual({
      wallet_id: 1611,
      refund_address: '0xB1c4',
      totp_code: '123456',
    });
    expect(cap.body()).not.toHaveProperty('refund_to_payer');
  });

  it('шлёт refund_to_payer и НЕ шлёт refund_address', async () => {
    const cap = captureBody();
    await makeClient().refundOperatorWallet(
      1611,
      { refundToPayer: true },
      '123456',
    );
    expect(cap.body()).toEqual({
      wallet_id: 1611,
      refund_to_payer: true,
      totp_code: '123456',
    });
    expect(cap.body()).not.toHaveProperty('refund_address');
  });

  it('не кладёт withdrawal_verified_absent когда флаг false', async () => {
    const cap = captureBody();
    await makeClient().refundOperatorWallet(
      1611,
      { refundAddress: '0xB1c4' },
      '123456',
      false,
    );
    expect(cap.body()).not.toHaveProperty('withdrawal_verified_absent');
  });

  it('кладёт withdrawal_verified_absent только когда флаг true', async () => {
    const cap = captureBody();
    await makeClient().refundOperatorWallet(
      1611,
      { refundAddress: '0xB1c4' },
      '123456',
      true,
    );
    expect(cap.body().withdrawal_verified_absent).toBe(true);
  });

  it('бьёт в правильный путь', async () => {
    const cap = captureBody();
    await makeClient().refundOperatorWallet(
      1611,
      { refundToPayer: true },
      '123456',
    );
    expect(cap.url()).toBe(
      'https://example.test/informer/v1/operator-required-wallets/1611/refund',
    );
  });

  it('подписывает ровно те байты, что уходят в теле', async () => {
    let sentBody = '';
    let sentSig = '';
    let sentTs = '';
    global.fetch = (async (_url: any, init: any) => {
      sentBody = init.body;
      sentSig = init.headers['X-Informer-Signature'];
      sentTs = init.headers['X-Informer-Timestamp'];
      return {
        status: 200,
        text: async () =>
          JSON.stringify({
            resultCode: 'ERCD0000',
            data: { wallet_id: 1611, status: 'ok' },
          }),
      };
    }) as any;

    const client = makeClient();
    await client.refundOperatorWallet(1611, { refundToPayer: true }, '123456');

    const expected = client.buildSignature(
      'POST',
      '/informer/v1/operator-required-wallets/1611/refund',
      sentTs,
      sentBody,
    );
    expect(sentSig).toBe(expected);
  });

  it('возвращает data из конверта', async () => {
    captureBody();
    const r = await makeClient().refundOperatorWallet(
      1611,
      { refundToPayer: true },
      '123456',
    );
    expect(r).toEqual({ wallet_id: 1611, status: 'ok' });
  });

  it('использует таймаут 45 секунд, а не общие 25', async () => {
    const client = makeClient();
    const spy = jest.spyOn(global, 'setTimeout');
    captureBody();

    await client.refundOperatorWallet(1611, { refundToPayer: true }, '123456');

    const delays = spy.mock.calls.map((c) => c[1]);
    expect(delays).toContain(45000);
    spy.mockRestore();
  });
});
```

- [ ] **Step 2: Прогнать тест, убедиться что падает**

Run: `npx jest src/informer-bot/informer.client.spec.ts -t 'refundOperatorWallet'`
Expected: FAIL — `client.refundOperatorWallet is not a function`.

- [ ] **Step 3: Реализовать**

В `src/informer-bot/informer.client.ts`:

1. Добавить импорты `OperatorWalletRefundResult` и `RefundTarget` в существующий блок импорта из `./informer.types`.

2. Заменить сигнатуры `signedRequest` / `signedPost` (строки 85–143) на:

```ts
  private async signedRequest<T>(
    method: 'GET' | 'POST',
    path: string,
    body: string,
    timeoutMsOverride?: number,
  ): Promise<T> {
    const url = new URL(path, this.cfg.baseUrl);
    const requestUri = url.pathname + url.search;
    const headers = this.buildAuthHeaders(method, requestUri, body);
    if (method === 'POST') headers['Content-Type'] = 'application/json';

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      timeoutMsOverride ?? this.cfg.timeoutMs ?? 25000,
    );

    let resp: Response;
    try {
      resp = await fetch(url.toString(), {
        method,
        headers,
        body: method === 'POST' ? body : undefined,
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
        throw new InformerUnavailableError(
          200,
          `non-json: ${text.slice(0, 200)}`,
        );
      }
      const envelope = assertEnvelope<T>(json);
      return envelope.data;
    }
    throw this.mapStatusToError(resp.status, text);
  }

  private signedGet<T>(path: string): Promise<T> {
    return this.signedRequest<T>('GET', path, '');
  }

  private signedPost<T>(
    path: string,
    payload: unknown,
    timeoutMsOverride?: number,
  ): Promise<T> {
    // Serialize once and pass the exact bytes to both sha256 (in signing
    // string) and fetch body. Any whitespace / key-order drift between the
    // two would yield 401 (signature mismatch).
    const body = JSON.stringify(payload);
    return this.signedRequest<T>('POST', path, body, timeoutMsOverride);
  }
```

3. Добавить в конец класса, после `retryOperatorWallet`:

```ts
  /**
   * Refund is a synchronous on-chain send with a 30s budget on the platform
   * side. A client that times out earlier cannot tell whether the money
   * left — so we wait longer than the platform does, and never retry
   * automatically.
   */
  private static readonly REFUND_TIMEOUT_MS = 45000;

  refundOperatorWallet(
    walletId: number,
    target: RefundTarget,
    totpCode: string,
    verifiedAbsent = false,
  ): Promise<OperatorWalletRefundResult> {
    // Exactly one of refund_address / refund_to_payer. Sending both is a
    // guaranteed 400 ("mutually exclusive: send exactly one").
    const targetField =
      'refundAddress' in target
        ? { refund_address: target.refundAddress }
        : { refund_to_payer: true as const };

    return this.signedPost<OperatorWalletRefundResult>(
      `/informer/v1/operator-required-wallets/${walletId}/refund`,
      {
        wallet_id: walletId,
        ...targetField,
        totp_code: totpCode,
        // Only ever sent when true — the guide asks not to send it by
        // default, and its presence is logged upstream as a deliberate
        // operator decision.
        ...(verifiedAbsent ? { withdrawal_verified_absent: true } : {}),
      },
      InformerClient.REFUND_TIMEOUT_MS,
    );
  }
```

- [ ] **Step 4: Прогнать тесты, убедиться что проходят**

Run: `npx jest src/informer-bot/informer.client.spec.ts`
Expected: PASS, включая 8 новых тестов.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer.client.ts src/informer-bot/informer.client.spec.ts
git commit -m "feat(informer): метод возврата средств с таймаутом 45с"
```

---

## Task 6: Форматтеры мастера возврата

**Files:**
- Modify: `src/informer-bot/informer.formatters.ts`
- Test: `src/informer-bot/informer.formatters.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Дописать в конец `src/informer-bot/informer.formatters.spec.ts`:

```ts
import {
  formatRefundMethodChoice,
  formatRefundAddressPrompt,
  formatRefundConfirm,
  formatRefundAwaitingTotp,
  formatRefundCancelled,
  formatRefundResult,
  formatRefundGate,
  formatRefundFailure,
  formatRefundTimeout,
  formatRefundInFlight,
} from './informer.formatters';
import { classifyRefundFailure } from './informer.refund-errors';

describe('мастер возврата — карточки', () => {
  const CTX = {
    network: 'BSC',
    token: 'usdt',
    amount: '50',
    address: '0xcust',
  };
  const TRON_CTX = { ...CTX, network: 'TRON' };

  it('на BSC предлагает только адрес и объясняет почему', () => {
    const md = formatRefundMethodChoice(1611, CTX);
    expect(md).toContain('[ACTION:📮 Указать адрес #1611]');
    expect(md).not.toContain('плательщику #1611]');
    expect(md).toContain('плательщик не определяется');
  });

  it('на TRON предлагает оба способа', () => {
    const md = formatRefundMethodChoice(1611, TRON_CTX);
    expect(md).toContain('[ACTION:📮 Указать адрес #1611]');
    expect(md).toContain('[ACTION:👤 Вернуть плательщику #1611]');
  });

  it('на незнакомой сети предлагает оба — fail-open', () => {
    const md = formatRefundMethodChoice(1611, { ...CTX, network: 'SOLANA' });
    expect(md).toContain('[ACTION:👤 Вернуть плательщику #1611]');
  });

  it('в каждой карточке мастера есть отмена', () => {
    expect(formatRefundMethodChoice(1611, CTX)).toContain('[ACTION:❌ Отмена возврата]');
    expect(formatRefundAddressPrompt(1611, CTX)).toContain('[ACTION:❌ Отмена возврата]');
    expect(formatRefundAwaitingTotp(1611, 60)).toContain('[ACTION:❌ Отмена возврата]');
  });

  it('подтверждение адреса показывает сумму, сеть и адрес назначения', () => {
    const md = formatRefundConfirm(1611, CTX, { refundAddress: '0xB1c4' });
    expect(md).toContain('50');
    expect(md).toContain('BSC');
    expect(md).toContain('0xB1c4');
    expect(md).toContain('необратим');
    expect(md).toContain('[ACTION:✅ Подтвердить возврат #1611]');
  });

  it('подтверждение возврата плательщику предупреждает про биржу и невидимый адрес', () => {
    const md = formatRefundConfirm(1611, TRON_CTX, { refundToPayer: true });
    expect(md).toContain('биржи');
    expect(md).toContain('показать');
    expect(md).toContain('необратим');
  });

  it('успешный возврат плательщику честно говорит, что адрес неизвестен', () => {
    const md = formatRefundResult({ wallet_id: 1611, status: 'ok' }, {
      refundToPayer: true,
    });
    expect(md).toContain('#1611');
    expect(md).toContain('адрес получателя платформа не сообщает');
  });

  it('успешный возврат на адрес показывает адрес', () => {
    const md = formatRefundResult({ wallet_id: 1611, status: 'ok' }, {
      refundAddress: '0xB1c4',
    });
    expect(md).toContain('0xB1c4');
  });

  it('карточка гейта перечисляет проверки и не содержит слова «повторить»', () => {
    const md = formatRefundGate(1611, CTX, 'refund would be a second payout');
    expect(md).toContain('[ACTION:✅ Сверил, выплаты не было #1611]');
    expect(md.toLowerCase()).not.toContain('повторить');
    expect(md).toContain('0xcust');
    expect(md).toContain('BSC');
    expect(md).toContain('логируется');
  });

  it('нехватка средств на hot даёт кнопку повтора и ведёт к балансам', () => {
    const f = classifyRefundFailure('hot wallet holds 3 but the refund needs 50');
    const md = formatRefundFailure(1611, f);
    expect(md).toContain('[ACTION:💸 Вернуть #1611]');
    expect(md).toContain('[ACTION:💰 Балансы mini-acquiring]');
  });

  it('«уже существует» не даёт кнопки повтора и объясняет, что первая попытка прошла', () => {
    const f = classifyRefundFailure('refund operation already exists for this wallet');
    const md = formatRefundFailure(1611, f);
    expect(md).not.toContain('[ACTION:💸 Вернуть');
    expect(md).toContain('первая попытка');
  });

  it('отсутствие hot-wallet пути — тупик без повтора', () => {
    const f = classifyRefundFailure('has no hot wallet payout path; refund manually');
    const md = formatRefundFailure(1611, f);
    expect(md).not.toContain('[ACTION:💸 Вернуть');
  });

  it('недоступный узел даёт повтор', () => {
    const f = classifyRefundFailure('refusing to send blind; retry once the node responds');
    const md = formatRefundFailure(1611, f);
    expect(md).toContain('[ACTION:💸 Вернуть #1611]');
  });

  it('незнакомый текст помечается транспортом, но печатается целиком', () => {
    const f = classifyRefundFailure('<html>502 Bad Gateway</html>');
    const md = formatRefundFailure(1611, f);
    expect(md).toContain('502 Bad Gateway');
    expect(md).toContain('транспорт');
    expect(md).not.toContain('[ACTION:💸 Вернуть');
  });

  it('таймаут прямо говорит, что деньги могли уйти, и не даёт повтора', () => {
    const md = formatRefundTimeout(1611);
    expect(md).toContain('могла');
    expect(md).not.toContain('[ACTION:💸 Вернуть');
  });

  it('параллельный возврат по тому же кошельку отклоняется', () => {
    expect(formatRefundInFlight(1611)).toContain('#1611');
  });
});
```

- [ ] **Step 2: Прогнать тест, убедиться что падает**

Run: `npx jest src/informer-bot/informer.formatters.spec.ts -t 'мастер возврата'`
Expected: FAIL — `formatRefundMethodChoice is not a function` / ошибка импорта.

- [ ] **Step 3: Реализовать**

В `src/informer-bot/informer.formatters.ts` добавить импорты в существующий блок из `./informer.types`: `OperatorWalletRefundResult`, `RefundTarget`, `WalletCtx`. Добавить новый импорт:

```ts
import { RefundFailure } from './informer.refund-errors';
```

Добавить в конец файла:

```ts
// ── Мастер возврата ──────────────────────────────────────────

export const REFUND_CANCEL_BUTTON = '[ACTION:❌ Отмена возврата]';

/**
 * Payer detection reads the transaction history, which the platform keeps
 * only for Tron and Taler. On the other six an empty refund_address is a
 * guaranteed 400.
 *
 * Networks are matched fail-open: an unrecognised network gets the payer
 * button, so a network the platform adds later works without a release on
 * our side. The cost of being wrong is one 400 with a readable message.
 */
const NETWORKS_WITHOUT_PAYER_DETECTION = new Set([
  'ethereum',
  'eth',
  'bsc',
  'binance-smart-chain',
  'bitcoin',
  'btc',
  'litecoin',
  'ltc',
  'dash',
  'polkadot',
  'dot',
]);

export function supportsPayerDetection(network: string): boolean {
  return !NETWORKS_WITHOUT_PAYER_DETECTION.has(
    (network ?? '').trim().toLowerCase(),
  );
}

function walletLine(walletId: number, ctx: WalletCtx): string {
  return `**#${walletId}** · ${ctx.amount} ${ctx.token} · ${ctx.network}`;
}

export function formatRefundMethodChoice(
  walletId: number,
  ctx: WalletCtx,
): string {
  const lines = [
    `💸 **Возврат средств** ${walletLine(walletId, ctx)}`,
    '',
    `Адрес вывода: \`${ctx.address}\``,
    '',
    'Куда вернуть?',
    '',
    `[ACTION:📮 Указать адрес #${walletId}]`,
  ];
  if (supportsPayerDetection(ctx.network)) {
    lines.push(`[ACTION:👤 Вернуть плательщику #${walletId}]`);
  } else {
    lines.push(
      '',
      `_В сети ${ctx.network} плательщик не определяется — нужен явный адрес._`,
    );
  }
  lines.push(REFUND_CANCEL_BUTTON);
  return lines.join('\n');
}

export function formatRefundAddressPrompt(
  walletId: number,
  ctx: WalletCtx,
): string {
  return [
    `📮 **Адрес возврата для ${walletLine(walletId, ctx)}**`,
    '',
    'Пришли адрес одним сообщением. Проверю только то, что он непустой — ' +
      'формат сверит платформа.',
    '',
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundAddressEmpty(walletId: number): string {
  return [
    '⚠️ Пустой адрес не подойдёт.',
    '',
    'Строка из одних пробелов на стороне платформы считается пустой, ' +
      'а пустой адрес без явного флага — это отказ, а не отправка ' +
      'плательщику. Пришли адрес ещё раз.',
    '',
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundConfirm(
  walletId: number,
  ctx: WalletCtx,
  target: RefundTarget,
): string {
  const head = [
    `⚠️ **Подтверди возврат** ${walletLine(walletId, ctx)}`,
    '',
  ];
  const body =
    'refundAddress' in target
      ? [`Получатель: \`${target.refundAddress}\``, '']
      : [
          'Получатель: **адрес плательщика, который выберет платформа**.',
          '',
          'Что это значит:',
          '• показать адрес заранее невозможно — preview у платформы нет;',
          `• на Tron определяется подписант транзакции, а не отправитель токенов — ` +
            'им может оказаться кошелёк биржи, который клиенту не принадлежит;',
          '• после успеха платформа не сообщит, куда ушли деньги.',
          '',
        ];
  return [
    ...head,
    ...body,
    'Перевод **необратим**.',
    '',
    `[ACTION:✅ Подтвердить возврат #${walletId}]`,
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundAwaitingTotp(
  walletId: number,
  ttlSeconds: number,
): string {
  return [
    `🔐 **Подтверди возврат кошелька #${walletId}**`,
    '',
    `Введи 6-значный код из аутентификатора в течение ${ttlSeconds} секунд.`,
    '',
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundTotpRejected(
  walletId: number,
  ttlSeconds: number,
): string {
  return [
    `⚠️ **Код не принят** для возврата кошелька **#${walletId}**.`,
    '',
    'Часы расходятся или код истёк. Возьми свежий код и пришли в течение ' +
      `${ttlSeconds} секунд.`,
    '',
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundCancelled(): string {
  return [
    '[B:blue]❌ Возврат отменён.[/B]',
    'Ничего не отправлено. Начни заново кнопкой «💸 Вернуть» в списке кошельков.',
    '',
    OPERATOR_BUTTONS,
  ].join('\n');
}

export function formatRefundResult(
  result: OperatorWalletRefundResult,
  target: RefundTarget,
): string {
  const where =
    'refundAddress' in target
      ? `Получатель: \`${target.refundAddress}\``
      : 'Возврат ушёл плательщику, но **адрес получателя платформа не сообщает** — ' +
        'ни адреса, ни хэша транзакции в ответе нет. Если он нужен в вашей ' +
        'записи, восстанавливать придётся вручную по цепочке.';
  return [
    `[B:green]✅ Возврат выполнен[/B] для кошелька **#${result.wallet_id}**`,
    '',
    `Статус: \`${result.status}\``,
    where,
    '',
    OPERATOR_BUTTONS,
  ].join('\n');
}

/**
 * The double-payout gate. The wallet has a withdrawal record carrying a tx
 * hash or order id, meaning the client was already paid. Clearing the gate
 * is a deliberate, logged assertion by a human — the button is worded as a
 * claim, never as "retry", and the flag is never set automatically.
 */
export function formatRefundGate(
  walletId: number,
  ctx: WalletCtx,
  upstreamMessage: string,
): string {
  return [
    `⛔ **Возврат #${walletId} заблокирован**`,
    '',
    `\`${upstreamMessage}\``,
    '',
    'У кошелька есть запись о выплате клиенту с идентификатором. ' +
      'Возврат сейчас заплатит ему **дважды**.',
    '',
    'Прежде чем снимать гейт, проверь:',
    `• в обозревателе ${ctx.network} нет исходящей транзакции на \`${ctx.address}\` ` +
      `на ${ctx.amount} ${ctx.token};`,
    '• в бэкофисе нет успешного order id по этой выплате.',
    '',
    'Нажимая кнопку, ты утверждаешь, что сверил цепочку и выплаты не было. ' +
      'Попытка снять гейт **логируется** платформой отдельным событием ещё ' +
      'до обращения к бэкенду — она останется в журнале, даже если возврат ' +
      'затем упадёт.',
    '',
    `[ACTION:✅ Сверил, выплаты не было #${walletId}]`,
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

const FAILURE_HEADLINE: Record<RefundFailure['kind'], string> = {
  second_payout: '⛔ Возврат заблокирован гейтом двойной выплаты',
  insufficient_hot: '⚠️ На hot-кошельке не хватает средств',
  no_payout_path: '⛔ В этой сети нет исходящего hot-wallet',
  node_unavailable: '⚠️ Узел сети не отвечает',
  already_exists: '⛔ Возврат по этому кошельку уже существует',
  generic_business: '⚠️ Платформа отказала без деталей',
  transport: '⚠️ Похоже на транспортный сбой, а не на отказ платформы',
};

const FAILURE_ADVICE: Record<RefundFailure['kind'], string> = {
  second_payout: 'Сверь цепочку и сними гейт осознанно.',
  insufficient_hot:
    'Ничего не отправлено. Пополни hot-кошелёк этой сети и повтори.',
  no_payout_path: 'Обрабатывать вне сервиса — вручную.',
  node_unavailable: 'Ничего не отправлено. Повтор допустим, когда узел ответит.',
  already_exists:
    'Читай это как «первая попытка прошла», а не как новую ошибку. ' +
    'Сверь вручную, повторять не надо.',
  generic_business: 'Причина не указана. Повторять вслепую не стоит.',
  transport:
    'Так выглядят ответы промежуточного прокси и обрезанные тела. ' +
    'Отправлено или нет — неизвестно, поэтому повтора не предлагаю.',
};

export function formatRefundFailure(
  walletId: number,
  failure: RefundFailure,
): string {
  const lines = [
    `${FAILURE_HEADLINE[failure.kind]} — кошелёк **#${walletId}**`,
    '',
  ];
  if (failure.message) {
    lines.push(`\`${failure.message}\``, '');
  }
  lines.push(FAILURE_ADVICE[failure.kind], '');
  if (failure.retryable) {
    lines.push(`[ACTION:💸 Вернуть #${walletId}]`);
  }
  if (failure.kind === 'insufficient_hot') {
    lines.push('[ACTION:💰 Балансы mini-acquiring]');
  }
  lines.push('[ACTION:📋 Кошельки оператора]');
  return lines.join('\n');
}

/**
 * Timeout is never a proof that nothing was sent: refund is a synchronous
 * on-chain send and our client waits longer than the platform's own budget,
 * but a network hiccup on our side still leaves the outcome unknown.
 */
export function formatRefundTimeout(walletId: number): string {
  return [
    `⚠️ **Ответ по возврату #${walletId} не пришёл вовремя**`,
    '',
    'Это **не** значит, что ничего не отправлено — транзакция **могла** уже ' +
      'уйти в сеть.',
    '',
    'Не повторяй вслепую. Сверь цепочку; если решишь повторить вручную и ' +
      'получишь «refund operation already exists» — значит первая попытка прошла.',
    '',
    '[ACTION:📋 Кошельки оператора]',
  ].join('\n');
}

export function formatRefundInFlight(walletId: number): string {
  return [
    `⚠️ По кошельку **#${walletId}** уже идёт возврат.`,
    '',
    'Параллельные возвраты по одному кошельку запрещены: защита на стороне ' +
      'платформы — проверка перед действием, а не гарантия уникальности. ' +
      'Дождись результата первой попытки.',
    '',
    '[ACTION:📋 Кошельки оператора]',
  ].join('\n');
}
```

- [ ] **Step 4: Прогнать тесты, убедиться что проходят**

Run: `npx jest src/informer-bot/informer.formatters.spec.ts`
Expected: PASS, включая 16 новых тестов.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer.formatters.ts src/informer-bot/informer.formatters.spec.ts
git commit -m "feat(informer): карточки мастера возврата и разбор отказов"
```

---

## Task 7: Автомат мастера

**Files:**
- Create: `src/informer-bot/informer.refund-flow.ts`
- Test: `src/informer-bot/informer.refund-flow.spec.ts`

Автомат чистый: не ходит ни в Redis, ни в HTTP. На вход — текущее состояние и текст сообщения, на выход — следующее состояние (или `null` = очистить), сообщения для публикации и признак «пора звать API».

- [ ] **Step 1: Написать падающий тест**

Создать `src/informer-bot/informer.refund-flow.spec.ts`:

```ts
import { advanceRefundFlow, parseRefundEntry } from './informer.refund-flow';
import { PendingOp } from './informer.pending-state';

const CTX = {
  network: 'BSC',
  token: 'usdt',
  amount: '50',
  address: '0xcust',
};
const TRON_CTX = { ...CTX, network: 'TRON' };

describe('parseRefundEntry — вход в мастер', () => {
  it('распознаёт кнопку возврата с id', () => {
    expect(parseRefundEntry('💸 Вернуть #1611')).toBe(1611);
  });

  it('распознаёт без эмодзи и решётки', () => {
    expect(parseRefundEntry('вернуть 1611')).toBe(1611);
  });

  it('не путает с кнопкой повтора', () => {
    expect(parseRefundEntry('🔁 Повторить #1611')).toBeNull();
  });

  it('не срабатывает на отмене возврата', () => {
    expect(parseRefundEntry('❌ Отмена возврата')).toBeNull();
  });

  it('не срабатывает без числа', () => {
    expect(parseRefundEntry('вернуть')).toBeNull();
  });

  it('не перезапускает мастер с шага «вернуть плательщику»', () => {
    // Иначе нажатие внутри мастера сбросило бы его в начало и потеряло
    // накопленное состояние.
    expect(parseRefundEntry('👤 Вернуть плательщику #1611')).toBeNull();
  });
});

describe('advanceRefundFlow — переходы', () => {
  const method: PendingOp = {
    kind: 'refund',
    step: 'method',
    walletId: 1611,
    ctx: CTX,
  };

  it('method + «указать адрес» → address', () => {
    const r = advanceRefundFlow(method, '📮 Указать адрес #1611');
    expect(r.next).toMatchObject({ step: 'address', walletId: 1611 });
    expect(r.call).toBeUndefined();
  });

  it('method + «плательщику» → confirm с toPayer', () => {
    const r = advanceRefundFlow(
      { ...method, ctx: TRON_CTX },
      '👤 Вернуть плательщику #1611',
    );
    expect(r.next).toMatchObject({
      step: 'confirm',
      target: { refundToPayer: true },
    });
  });

  it('method + «плательщику» на сети без определения → остаётся, объясняет', () => {
    const r = advanceRefundFlow(method, '👤 Вернуть плательщику #1611');
    expect(r.next).toMatchObject({ step: 'method' });
    expect(r.messages.join('')).toContain('не определяется');
  });

  it('address + непустой текст → confirm с адресом', () => {
    const r = advanceRefundFlow(
      { ...method, step: 'address' },
      '  0xB1c4Ae4F0f8f  ',
    );
    expect(r.next).toMatchObject({
      step: 'confirm',
      target: { refundAddress: '0xB1c4Ae4F0f8f' },
    });
  });

  it('address + пробелы → остаётся на address', () => {
    const r = advanceRefundFlow({ ...method, step: 'address' }, '     ');
    expect(r.next).toMatchObject({ step: 'address' });
    expect(r.messages.join('')).toContain('Пустой адрес');
  });

  it('confirm + подтверждение → totp с verifiedAbsent=false', () => {
    const confirm: PendingOp = {
      kind: 'refund',
      step: 'confirm',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
    };
    const r = advanceRefundFlow(confirm, '✅ Подтвердить возврат #1611');
    expect(r.next).toMatchObject({ step: 'totp', verifiedAbsent: false });
  });

  it('totp + 6 цифр → сигнал звать API, состояние очищается', () => {
    const totp: PendingOp = {
      kind: 'refund',
      step: 'totp',
      walletId: 1611,
      ctx: CTX,
      target: { refundToPayer: true },
      verifiedAbsent: false,
    };
    const r = advanceRefundFlow(totp, '123456');
    expect(r.call).toEqual({
      walletId: 1611,
      target: { refundToPayer: true },
      totpCode: '123456',
      verifiedAbsent: false,
      ctx: CTX,
    });
    expect(r.next).toBeNull();
  });

  it('totp + не 6 цифр → остаётся, просит код', () => {
    const totp: PendingOp = {
      kind: 'refund',
      step: 'totp',
      walletId: 1611,
      ctx: CTX,
      target: { refundToPayer: true },
      verifiedAbsent: false,
    };
    const r = advanceRefundFlow(totp, 'ага сейчас');
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'totp' });
  });

  it('gate + «сверил» → totp с verifiedAbsent=true', () => {
    const gate: PendingOp = {
      kind: 'refund',
      step: 'gate',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
      upstreamMessage: 'refund would be a second payout',
    };
    const r = advanceRefundFlow(gate, '✅ Сверил, выплаты не было #1611');
    expect(r.next).toMatchObject({ step: 'totp', verifiedAbsent: true });
  });

  it('gate + 6 цифр НЕ запускает возврат в обход подтверждения', () => {
    const gate: PendingOp = {
      kind: 'refund',
      step: 'gate',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
      upstreamMessage: 'refund would be a second payout',
    };
    const r = advanceRefundFlow(gate, '123456');
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'gate' });
  });

  it('отмена из любого состояния очищает', () => {
    for (const step of ['method', 'address', 'confirm', 'totp', 'gate'] as const) {
      const state = {
        kind: 'refund',
        step,
        walletId: 1611,
        ctx: CTX,
        target: { refundAddress: '0xB1c4' },
        verifiedAbsent: false,
        upstreamMessage: 'x',
      } as PendingOp;
      const r = advanceRefundFlow(state, '❌ Отмена возврата');
      expect(r.next).toBeNull();
      expect(r.call).toBeUndefined();
      expect(r.messages.join('')).toContain('отменён');
    }
  });
});
```

- [ ] **Step 2: Прогнать тест, убедиться что падает**

Run: `npx jest src/informer-bot/informer.refund-flow.spec.ts`
Expected: FAIL — `Cannot find module './informer.refund-flow'`.

- [ ] **Step 3: Реализовать автомат**

Создать `src/informer-bot/informer.refund-flow.ts`:

```ts
import { PendingOp, PENDING_OP_TTL_SEC } from './informer.pending-state';
import { RefundTarget, WalletCtx } from './informer.types';
import {
  formatRefundAddressEmpty,
  formatRefundAddressPrompt,
  formatRefundAwaitingTotp,
  formatRefundCancelled,
  formatRefundConfirm,
  formatRefundGate,
  formatRefundMethodChoice,
  supportsPayerDetection,
} from './informer.formatters';

/** What the service should do after the transition. */
export interface RefundCall {
  walletId: number;
  ctx: WalletCtx;
  target: RefundTarget;
  totpCode: string;
  verifiedAbsent: boolean;
}

export interface FlowResult {
  /** Next pending state, or null to clear it. */
  next: PendingOp | null;
  /** Messages to publish, in order. */
  messages: string[];
  /** Present only when the terminal API call should fire now. */
  call?: RefundCall;
}

const TOTP_RE = /^\d{6}$/;

/**
 * Matches the refund entry button: "💸 Вернуть #1611" or a bare
 * "вернуть 1611". Returns null for anything else — importantly for
 * "❌ Отмена возврата", which contains "возврат" but must not re-enter the
 * wizard, and for the retry button, which shares the card.
 */
export function parseRefundEntry(content: string): number | null {
  const lower = content.trim().toLowerCase();
  if (lower.includes('отмена')) return null;
  const m = lower.match(/верн[уи]ть\s*#?(\d+)/);
  if (!m) return null;
  // "вернуть плательщику #1611" is an in-wizard step, not an entry point.
  if (lower.includes('плательщик')) return null;
  return parseInt(m[1], 10);
}

function isCancel(content: string): boolean {
  const lower = content.toLowerCase();
  return lower.includes('отмена возврата') || lower.includes('отмена ретрая');
}

/**
 * Pure transition. Never touches Redis or the network — the service does
 * both, using `next` and `call`. Keeping it pure is what makes the whole
 * table testable without mocks.
 */
export function advanceRefundFlow(
  state: PendingOp & { kind: 'refund' },
  content: string,
): FlowResult {
  const text = content.trim();
  const lower = text.toLowerCase();

  if (isCancel(text)) {
    return { next: null, messages: [formatRefundCancelled()] };
  }

  switch (state.step) {
    case 'method': {
      if (lower.includes('указать адрес')) {
        const next: PendingOp = { ...state, step: 'address' };
        return {
          next,
          messages: [formatRefundAddressPrompt(state.walletId, state.ctx)],
        };
      }
      if (lower.includes('плательщик')) {
        if (!supportsPayerDetection(state.ctx.network)) {
          return {
            next: state,
            messages: [
              `⚠️ В сети ${state.ctx.network} плательщик не определяется — ` +
                'платформа ответит 400. Нужен явный адрес.',
              formatRefundMethodChoice(state.walletId, state.ctx),
            ],
          };
        }
        const target: RefundTarget = { refundToPayer: true };
        return {
          next: { ...state, step: 'confirm', target },
          messages: [formatRefundConfirm(state.walletId, state.ctx, target)],
        };
      }
      return {
        next: state,
        messages: [formatRefundMethodChoice(state.walletId, state.ctx)],
      };
    }

    case 'address': {
      // The platform trims the address and treats an all-whitespace string
      // as empty — sending it would mean an implicit refund_to_payer, which
      // must never happen without the operator saying so.
      if (text === '') {
        return {
          next: state,
          messages: [formatRefundAddressEmpty(state.walletId)],
        };
      }
      const target: RefundTarget = { refundAddress: text };
      return {
        next: { ...state, step: 'confirm', target },
        messages: [formatRefundConfirm(state.walletId, state.ctx, target)],
      };
    }

    case 'confirm': {
      if (lower.includes('подтвердить возврат')) {
        return {
          next: { ...state, step: 'totp', verifiedAbsent: false },
          messages: [
            formatRefundAwaitingTotp(state.walletId, PENDING_OP_TTL_SEC),
          ],
        };
      }
      return {
        next: state,
        messages: [
          formatRefundConfirm(state.walletId, state.ctx, state.target),
        ],
      };
    }

    case 'totp': {
      if (!TOTP_RE.test(text)) {
        return {
          next: state,
          messages: [
            formatRefundAwaitingTotp(state.walletId, PENDING_OP_TTL_SEC),
          ],
        };
      }
      return {
        next: null,
        messages: [],
        call: {
          walletId: state.walletId,
          ctx: state.ctx,
          target: state.target,
          totpCode: text,
          verifiedAbsent: state.verifiedAbsent,
        },
      };
    }

    case 'gate': {
      // A bare TOTP must NOT fire the refund here: clearing the double-payout
      // gate is a separate, explicit assertion by the operator, and skipping
      // it would pay the client twice.
      if (lower.includes('сверил')) {
        return {
          next: { ...state, step: 'totp', verifiedAbsent: true },
          messages: [
            formatRefundAwaitingTotp(state.walletId, PENDING_OP_TTL_SEC),
          ],
        };
      }
      return {
        next: state,
        messages: [
          formatRefundGate(state.walletId, state.ctx, state.upstreamMessage),
        ],
      };
    }
  }
}
```

- [ ] **Step 4: Прогнать тесты, убедиться что проходят**

Run: `npx jest src/informer-bot/informer.refund-flow.spec.ts`
Expected: PASS, 17 тестов.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer.refund-flow.ts src/informer-bot/informer.refund-flow.spec.ts
git commit -m "feat(informer): автомат мастера возврата"
```

---

## Task 8: Миграция retry на единое состояние

**Files:**
- Modify: `src/informer-bot/informer-bot.service.ts:71-75,170-230,300-328`
- Test: `src/informer-bot/informer-bot.service.spec.ts`

Отдельная задача, чтобы регрессия по retry (если будет) вылезла до того, как сверху ляжет возврат.

- [ ] **Step 1: Обновить существующие тесты retry на новый ключ**

В `src/informer-bot/informer-bot.service.spec.ts` заменить **все** вхождения строки `informer:pending_totp:u1` на `informer:pending_op:u1` (строки 476, 477, 502, 503, 520, 583 и любые другие).

Затем дописать в конец файла:

```ts
describe('retry на едином pending-состоянии', () => {
  it('кладёт состояние с kind=retry', async () => {
    const m = makeMocks();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #1611');

    const raw = m.redis.store.get('informer:pending_op:u1');
    expect(JSON.parse(raw!)).toEqual({
      kind: 'retry',
      step: 'totp',
      walletId: 1611,
    });
  });

  it('кнопка возврата перетирает pending от retry — последняя кнопка выигрывает', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList = jest.fn(async () => ({
      items: [
        {
          wallet_id: 1620,
          created_at: '2026-08-24T17:02:11Z',
          withdraw_address: '0xcust',
          withdraw_network: 'TRON',
          withdraw_token: 'usdt',
          withdraw_amount: '50',
        },
      ],
      total: 1,
      page: 1,
      per_page: 50,
    }));
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #1611');
    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1620');

    const state = JSON.parse(m.redis.store.get('informer:pending_op:u1')!);
    expect(state.kind).toBe('refund');
    expect(state.walletId).toBe(1620);
  });

  it('6 цифр при retry-состоянии зовут retry, а не возврат', async () => {
    const m = makeMocks();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #1611');
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect(m.client.retryOperatorWallet).toHaveBeenCalledWith(1611, '123456');
  });
});
```

- [ ] **Step 2: Прогнать тесты, убедиться что падают**

Run: `npx jest src/informer-bot/informer-bot.service.spec.ts`
Expected: FAIL — сервис пишет в `informer:pending_totp:u1`, тесты ждут `informer:pending_op:u1`.

- [ ] **Step 3: Перевести сервис на `PendingStateStore`**

В `src/informer-bot/informer-bot.service.ts`:

1. Заменить строки 71–75 (константы `PENDING_TOTP_TTL_SEC` и `pendingTotpKey`) на импорт:

```ts
import {
  PendingOp,
  PendingStateStore,
  PENDING_OP_TTL_SEC,
} from './informer.pending-state';
```

(импорт положить к остальным импортам вверху файла, константы `PENDING_TOTP_TTL_SEC` / `pendingTotpKey` удалить целиком).

2. В конструкторе после присваивания зависимостей создать хранилище. Заменить закрывающую скобку конструктора (строка 90) так, чтобы тело появилось:

```ts
  private readonly pending: PendingStateStore;

  constructor(
    private readonly prisma: PrismaService,
    private readonly client: InformerClient,
    private readonly messenger: MessengerService,
    @Inject(forwardRef(() => MessengerGateway))
    private readonly gateway: MessengerGateway,
    private readonly rates: InformerRatesService,
    private readonly redis: RedisService,
  ) {
    this.pending = new PendingStateStore(this.redis);
  }
```

3. В ветке `case 'RETRY_OPERATOR_WALLET'` заменить вызов `this.redis.setEx(pendingTotpKey(userId), …)` на:

```ts
          await this.pending.save(userId, {
            kind: 'retry',
            step: 'totp',
            walletId,
          });
          md = formatRetryAwaitingTotp(walletId, PENDING_OP_TTL_SEC);
```

4. В ветке `case 'SUBMIT_TOTP'` заменить `await this.redis.del(pendingTotpKey(userId));` на `await this.pending.clear(userId);`, а re-arm внутри `catch (e instanceof InformerTotpError)` — на:

```ts
              await this.pending.save(userId, {
                kind: 'retry',
                step: 'totp',
                walletId,
              });
              md = formatRetryTotpRejected(walletId, PENDING_OP_TTL_SEC);
```

5. В ветке `case 'CANCEL_TOTP'` заменить `await this.redis.del(pendingTotpKey(userId));` на `await this.pending.clear(userId);`.

6. Заменить `parseActionWithPendingState` (строки 306–328) на:

```ts
  async parseActionWithPendingState(
    userId: string,
    content: string,
  ): Promise<ParsedAction | null> {
    const trimmed = content.trim();
    if (/^\d{6}$/.test(trimmed)) {
      const state = await this.pending.load(userId);
      if (state?.kind === 'retry') {
        return {
          code: 'SUBMIT_TOTP',
          walletId: state.walletId,
          totpCode: trimmed,
        };
      }
    }
    return this.parseAction(content);
  }
```

- [ ] **Step 4: Прогнать тесты, убедиться что проходят**

Run: `npx jest src/informer-bot/informer-bot.service.spec.ts`
Expected: PASS. Тест «кнопка возврата перетирает pending» пока **падает** — возврата ещё нет. Временно пометить его `it.skip` с комментарием `// снимается в Task 9`, остальные должны быть зелёные.

Run: `npx tsc --noEmit -p tsconfig.json`
Expected: без ошибок.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer-bot.service.ts src/informer-bot/informer-bot.service.spec.ts
git commit -m "refactor(informer): retry на едином pending-состоянии"
```

---

## Task 9: Подключение мастера возврата к сервису

**Files:**
- Modify: `src/informer-bot/informer-bot.service.ts`
- Test: `src/informer-bot/informer-bot.service.spec.ts`

- [ ] **Step 1: Написать падающий тест**

Снять `it.skip` с теста «кнопка возврата перетирает pending» из Task 8 и дописать в конец `src/informer-bot/informer-bot.service.spec.ts`:

```ts
describe('мастер возврата в сервисе', () => {
  const ITEM = {
    wallet_id: 1611,
    created_at: '2026-08-24T17:02:11Z',
    withdraw_address: '0xcust',
    withdraw_network: 'TRON',
    withdraw_token: 'usdt',
    withdraw_amount: '50',
  };

  function mocksWithWallet() {
    const m = makeMocks();
    m.client.getOperatorRequiredList = jest.fn(async () => ({
      items: [ITEM],
      total: 1,
      page: 1,
      per_page: 50,
    }));
    (m.client as any).refundOperatorWallet = jest.fn(async () => ({
      wallet_id: 1611,
      status: 'ok',
    }));
    (m.redis as any).setNxEx = jest.fn(async (k: string) => {
      if (m.redis.store.has(k)) return false;
      m.redis.store.set(k, '1');
      return true;
    });
    return m;
  }

  async function walkToTotp(svc: any, m: any) {
    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');
    await svc.handleUserMessage('u1', 'c1', '👤 Вернуть плательщику #1611');
    await svc.handleUserMessage('u1', 'c1', '✅ Подтвердить возврат #1611');
  }

  it('проходит мастер целиком и зовёт API', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect((m.client as any).refundOperatorWallet).toHaveBeenCalledWith(
      1611,
      { refundToPayer: true },
      '123456',
      false,
    );
    expect(m.published.join('')).toContain('Возврат выполнен');
  });

  it('ветка с адресом отправляет refundAddress', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');
    await svc.handleUserMessage('u1', 'c1', '📮 Указать адрес #1611');
    await svc.handleUserMessage('u1', 'c1', '0xB1c4Ae4F0f8f');
    await svc.handleUserMessage('u1', 'c1', '✅ Подтвердить возврат #1611');
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect((m.client as any).refundOperatorWallet).toHaveBeenCalledWith(
      1611,
      { refundAddress: '0xB1c4Ae4F0f8f' },
      '123456',
      false,
    );
  });

  it('502 second payout переводит в gate и НЕ повторяет сам', async () => {
    const m = mocksWithWallet();
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      throw new InformerUnavailableError(
        502,
        JSON.stringify({ message: 'refund would be a second payout' }),
      );
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect((m.client as any).refundOperatorWallet).toHaveBeenCalledTimes(1);
    const state = JSON.parse(m.redis.store.get('informer:pending_op:u1')!);
    expect(state.step).toBe('gate');
    expect(m.published.join('')).toContain('Сверил, выплаты не было');
  });

  it('снятие гейта отправляет withdrawal_verified_absent=true', async () => {
    const m = mocksWithWallet();
    let call = 0;
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      if (++call === 1) {
        throw new InformerUnavailableError(
          502,
          JSON.stringify({ message: 'refund would be a second payout' }),
        );
      }
      return { wallet_id: 1611, status: 'ok' };
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');
    await svc.handleUserMessage('u1', 'c1', '✅ Сверил, выплаты не было #1611');
    await svc.handleUserMessage('u1', 'c1', '654321');

    expect((m.client as any).refundOperatorWallet).toHaveBeenLastCalledWith(
      1611,
      { refundToPayer: true },
      '654321',
      true,
    );
  });

  it('403 пересоздаёт totp-шаг возврата, а не сбрасывает мастер', async () => {
    const m = mocksWithWallet();
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      throw new InformerTotpError('bad code');
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    const state = JSON.parse(m.redis.store.get('informer:pending_op:u1')!);
    expect(state).toMatchObject({ step: 'totp', verifiedAbsent: false });
    expect(m.published.join('')).toContain('Код не принят');
  });

  it('таймаут не предлагает повтор', async () => {
    const m = mocksWithWallet();
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      throw new InformerTimeoutError();
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    const out = m.published.join('');
    expect(out).toContain('могла');
    expect(out).not.toContain('[ACTION:💸 Вернуть #1611]');
  });

  it('блокировка по кошельку отклоняет параллельный возврат', async () => {
    const m = mocksWithWallet();
    m.redis.store.set('informer:refund_inflight:1611', '1');
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect((m.client as any).refundOperatorWallet).not.toHaveBeenCalled();
    expect(m.published.join('')).toContain('уже идёт возврат');
  });

  it('блокировка снимается после успеха', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect(m.redis.store.has('informer:refund_inflight:1611')).toBe(false);
  });

  it('блокировка снимается после ошибки', async () => {
    const m = mocksWithWallet();
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      throw new InformerTimeoutError();
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect(m.redis.store.has('informer:refund_inflight:1611')).toBe(false);
  });

  it('отмена очищает состояние без вызова API', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');
    await svc.handleUserMessage('u1', 'c1', '❌ Отмена возврата');

    expect(m.redis.store.has('informer:pending_op:u1')).toBe(false);
    expect((m.client as any).refundOperatorWallet).not.toHaveBeenCalled();
  });

  it('двойное нажатие кнопки возврата не дёргает список дважды', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');
    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');

    expect(m.client.getOperatorRequiredList).toHaveBeenCalledTimes(1);
  });

  it('кнопка возврата по неизвестному кошельку объясняет, а не падает', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #9999');

    expect(m.published.join('')).toContain('9999');
    expect(m.redis.store.has('informer:pending_op:u1')).toBe(false);
  });
});
```

Добавить в шапку файла импорты ошибок, если их там нет:

```ts
import {
  InformerTotpError,
  InformerTimeoutError,
  InformerUnavailableError,
} from './informer.types';
```

- [ ] **Step 2: Прогнать тесты, убедиться что падают**

Run: `npx jest src/informer-bot/informer-bot.service.spec.ts -t 'мастер возврата в сервисе'`
Expected: FAIL — бот отвечает подсказкой «понимаю только кнопки», состояние не создаётся.

- [ ] **Step 3: Реализовать в сервисе**

В `src/informer-bot/informer-bot.service.ts`:

1. Добавить импорты:

```ts
import { advanceRefundFlow, parseRefundEntry } from './informer.refund-flow';
import { classifyRefundFailure } from './informer.refund-errors';
import {
  formatRefundFailure,
  formatRefundGate,
  formatRefundInFlight,
  formatRefundMethodChoice,
  formatRefundResult,
  formatRefundTimeout,
  formatRefundTotpRejected,
} from './informer.formatters';
import { WalletCtx } from './informer.types';
```

2. Добавить константы рядом с `ANTI_FLOOD_MS`:

```ts
// Refund holds an on-chain send open for up to 45s. The lock outlives that
// with margin so a process death between request and release cannot wedge a
// wallet permanently.
const REFUND_LOCK_TTL_SEC = 120;
const refundLockKey = (walletId: number) =>
  `informer:refund_inflight:${walletId}`;
```

3. В `handleUserMessage` вставить диспетчеризацию мастера **после закрывающей скобки блока `try { await this.assertAccess(userId) } catch { … return; }`** и **до** строки `const parsed = await this.parseActionWithPendingState(...)`:

```ts
    // The refund wizard owns the conversation while it's pending: its steps
    // consume free text (address, TOTP) that the generic action parser would
    // otherwise misread. Entry button is checked first so a new refund can
    // always start, even mid-wizard.
    const refundEntry = parseRefundEntry(content);
    if (refundEntry != null) {
      await this.startRefundWizard(userId, conversationId, refundEntry);
      return;
    }
    const pending = await this.pending.load(userId);
    if (pending?.kind === 'refund') {
      await this.runRefundStep(userId, conversationId, pending, content);
      return;
    }
```

4. Добавить методы в класс (после `handleUserMessage`):

```ts
  /**
   * Entry point of the wizard. Wallet facts are captured now and carried
   * through every step, so the confirmation card describes the actual money
   * instead of a bare id.
   */
  private async startRefundWizard(
    userId: string,
    conversationId: string,
    walletId: number,
  ): Promise<void> {
    // Anti-flood keyed by wallet, mirroring the retry button: a double-tap
    // must not fire two list fetches, but refunds on two different wallets
    // in quick succession stay allowed.
    const flKey = `${userId}:REFUND_ENTRY:${walletId}`;
    if (Date.now() - (this.lastAction.get(flKey) ?? 0) < ANTI_FLOOD_MS) {
      this.logger.warn(`anti-flood throttle for ${flKey}`);
      return;
    }
    this.lastAction.set(flKey, Date.now());

    let ctx: WalletCtx | null = null;
    try {
      const list = await this.client.getOperatorRequiredList(1, 50);
      const item = list.items.find((i) => i.wallet_id === walletId);
      if (item) {
        ctx = {
          network: item.withdraw_network,
          token: item.withdraw_token,
          amount: item.withdraw_amount,
          address: item.withdraw_address,
        };
      }
    } catch (e) {
      await this.publishBotMessage(
        userId,
        conversationId,
        this.errorToMessage(e),
      );
      return;
    }

    if (!ctx) {
      await this.publishBotMessage(
        userId,
        conversationId,
        `⚠️ Кошелька **#${walletId}** нет в текущем списке — возможно, его уже ` +
          'обработали. Обнови список и попробуй снова.\n\n[ACTION:📋 Кошельки оператора]',
      );
      return;
    }

    await this.pending.save(userId, {
      kind: 'refund',
      step: 'method',
      walletId,
      ctx,
    });
    await this.publishBotMessage(
      userId,
      conversationId,
      formatRefundMethodChoice(walletId, ctx),
    );
  }

  private async runRefundStep(
    userId: string,
    conversationId: string,
    state: PendingOp & { kind: 'refund' },
    content: string,
  ): Promise<void> {
    const result = advanceRefundFlow(state, content);

    if (result.next) {
      await this.pending.save(userId, result.next);
    } else {
      await this.pending.clear(userId);
    }
    for (const m of result.messages) {
      await this.publishBotMessage(userId, conversationId, m);
    }
    if (!result.call) return;

    const { walletId, ctx, target, totpCode, verifiedAbsent } = result.call;

    // One refund in flight per wallet. Pending state is per-operator, but
    // several operators hold informerAccess, and the platform's own guard is
    // a check-before-act, not a uniqueness guarantee.
    const locked = await this.redis.setNxEx(
      refundLockKey(walletId),
      REFUND_LOCK_TTL_SEC,
      userId,
    );
    if (!locked) {
      await this.publishBotMessage(
        userId,
        conversationId,
        formatRefundInFlight(walletId),
      );
      return;
    }

    try {
      const refund = await this.client.refundOperatorWallet(
        walletId,
        target,
        totpCode,
        verifiedAbsent,
      );
      await this.publishBotMessage(
        userId,
        conversationId,
        formatRefundResult(refund, target),
      );
    } catch (e) {
      await this.handleRefundError(
        userId,
        conversationId,
        { walletId, ctx, target, verifiedAbsent },
        e,
      );
    } finally {
      await this.redis.del(refundLockKey(walletId));
    }
  }

  /**
   * Refund errors are handled separately from every other informer action:
   * a refund is irreversible, so nothing here ever retries on its own, and
   * a timeout is explicitly NOT reported as "nothing was sent".
   */
  private async handleRefundError(
    userId: string,
    conversationId: string,
    op: {
      walletId: number;
      ctx: WalletCtx;
      target: RefundTarget;
      verifiedAbsent: boolean;
    },
    e: unknown,
  ): Promise<void> {
    if (e instanceof InformerTotpError) {
      // Re-arm the same step so a fresh code can be submitted without
      // walking the wizard again. verifiedAbsent is preserved: the operator
      // already made that assertion and shouldn't repeat it.
      await this.pending.save(userId, {
        kind: 'refund',
        step: 'totp',
        walletId: op.walletId,
        ctx: op.ctx,
        target: op.target,
        verifiedAbsent: op.verifiedAbsent,
      });
      await this.publishBotMessage(
        userId,
        conversationId,
        formatRefundTotpRejected(op.walletId, PENDING_OP_TTL_SEC),
      );
      return;
    }

    if (e instanceof InformerTimeoutError) {
      await this.publishBotMessage(
        userId,
        conversationId,
        formatRefundTimeout(op.walletId),
      );
      return;
    }

    if (e instanceof InformerUnavailableError) {
      const failure = classifyRefundFailure(
        upstreamMessageFrom(e.upstreamBody, 500),
      );
      if (failure.kind === 'second_payout') {
        await this.pending.save(userId, {
          kind: 'refund',
          step: 'gate',
          walletId: op.walletId,
          ctx: op.ctx,
          target: op.target,
          upstreamMessage: failure.message,
        });
        await this.publishBotMessage(
          userId,
          conversationId,
          formatRefundGate(op.walletId, op.ctx, failure.message),
        );
        return;
      }
      await this.publishBotMessage(
        userId,
        conversationId,
        formatRefundFailure(op.walletId, failure),
      );
      return;
    }

    this.logger.error(
      `refund failed for #${op.walletId}: ${(e as Error)?.message || e}`,
    );
    await this.publishBotMessage(
      userId,
      conversationId,
      this.errorToMessage(e),
    );
  }
```

5. Убедиться, что `RefundTarget` и `upstreamMessageFrom` импортированы из `./informer.types` (`upstreamMessageFrom` там уже есть, `RefundTarget` добавить).

- [ ] **Step 4: Прогнать тесты, убедиться что проходят**

Run: `npx jest src/informer-bot/informer-bot.service.spec.ts`
Expected: PASS, включая 12 новых тестов и снятый со skip тест из Task 8.

Run: `npx jest src/informer-bot`
Expected: PASS, все наборы.

Run: `npx tsc --noEmit -p tsconfig.json`
Expected: без ошибок.

- [ ] **Step 5: Commit**

```bash
git add src/informer-bot/informer-bot.service.ts src/informer-bot/informer-bot.service.spec.ts
git commit -m "feat(informer): мастер возврата средств в чат-боте"
```

---

## Task 10: Полная проверка и сборка

**Files:** нет изменений, только проверки.

- [ ] **Step 1: Прогнать весь набор тестов бэкенда**

Run: `cd /Users/dmitry/Downloads/taler_id && npm test`
Expected: PASS. Если падают наборы вне `src/informer-bot/` — они падали и до наших правок; сверить с `git stash`-прогоном перед тем, как чинить.

- [ ] **Step 2: Собрать проект**

Run: `npm run build`
Expected: сборка без ошибок.

- [ ] **Step 3: Проверить, что мобилка не затронута**

Run: `git -C /Users/dmitry/Downloads/taler_id_mobile status --short`
Expected: пусто — рендерер generic, изменений в приложении не требуется.

- [ ] **Step 4: Финальный коммит, если что-то осталось незакоммиченным**

```bash
git status --short
```
Expected: пусто. Если нет — разобрать и закоммитить остаток.

---

## Что остаётся вне этого плана

Обе позиции — внешние зависимости, кода не требуют:

1. **TOTP-секрет для возврата.** Запросить у Володи (владелец admin-API) секрет, привязанный к нашему `X-Informer-Key`, и выяснить, тот же ли он, что уже работает для retry. Без него возврат отвечает `403 2fa not enrolled for this key`. Ни код, ни тесты от этого не зависят — проверять на живом стенде можно только после.
2. **Релиз платёжного бэкенда платформы.** До него список не отдаёт `last_error*` (карточки просто без блока причины, что и есть корректное поведение), а возврат без адреса попадёт в старый обработчик и вернёт `400`. Пять текстов `502` появятся только после релиза. Правок после релиза платформы не потребуется.

Выкатка обычная: DEV → TEST → PROD по `CLAUDE.md`. Новых переменных окружения нет.
