import { Injectable, Logger } from '@nestjs/common';
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

/** A `WalletSide` needs at least a non-empty `network` to be usable —
 * that's the one field every card and the payer-detection gate dereference
 * without a fallback. */
function isValidWalletSide(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const network = (value as Record<string, unknown>).network;
  return typeof network === 'string' && network.trim() !== '';
}

/**
 * `WalletCtx` used to be a flat `{network, token, amount, address}` built
 * from `withdraw_*` alone; it is now `{deposit, withdraw}`, each a nested
 * `WalletSide` (see informer.types.ts). A pending entry saved by the old
 * code — or surviving a partial deploy where the writer is new but a
 * reader is still old, or just a stale key nobody expired yet — has
 * `ctx.network` at the top level and `ctx.deposit` / `ctx.withdraw`
 * `undefined`. A shallow `typeof ctx === 'object'` check would accept that
 * shape and hand it to the wizard, which would then render `undefined` for
 * every field on the confirm card of an irreversible operation. Requiring
 * both nested sides, each with its own non-empty `network`, rejects the
 * old flat shape by construction.
 */
function isValidWalletCtx(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return isValidWalletSide(v.deposit) && isValidWalletSide(v.withdraw);
}

/**
 * Validates that a parsed value has exactly the fields its `step` needs.
 * Guards against a truncated write (e.g. Redis restart mid-`save`, or a
 * future bug that saves a partial object) surviving JSON.parse and reaching
 * the wizard as a well-typed `PendingOp` — the wizard would then dereference
 * a missing `target` at runtime on an irreversible refund. Treated the same
 * as corrupt JSON: caller drops the key and returns null.
 */
function isValidPendingOp(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  if (!KNOWN_KINDS.has(typeof v.kind === 'string' ? v.kind : '')) return false;

  if (v.kind === 'retry') {
    return v.step === 'totp' && typeof v.walletId === 'number';
  }

  // v.kind === 'refund'
  if (typeof v.walletId !== 'number') return false;
  if (!isValidWalletCtx(v.ctx)) return false;

  switch (v.step) {
    case 'method':
    case 'address':
      return true;
    case 'confirm':
      return v.target !== undefined;
    case 'totp':
      return v.target !== undefined && typeof v.verifiedAbsent === 'boolean';
    case 'gate':
      return v.target !== undefined && typeof v.upstreamMessage === 'string';
    default:
      return false;
  }
}

@Injectable()
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
      const parsed: unknown = JSON.parse(raw);
      if (!isValidPendingOp(parsed)) {
        throw new Error(
          `invalid pending state shape: ${JSON.stringify(parsed).slice(0, 200)}`,
        );
      }
      return parsed as PendingOp;
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
