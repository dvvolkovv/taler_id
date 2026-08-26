import { Injectable, Logger } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';
import { InformerClient } from './informer.client';
import {
  PendingOp,
  PendingStateStore,
  PENDING_OP_TTL_SEC,
} from './informer.pending-state';
import { advanceRefundFlow } from './informer.refund-flow';
import { classifyRefundFailure } from './informer.refund-errors';
import {
  formatRefundFailure,
  formatRefundGate,
  formatRefundInFlight,
  formatRefundMethodChoice,
  formatRefundResult,
  formatRefundTimeout,
  formatRefundTotpRejected,
} from './informer.refund.formatters';
import {
  InformerTotpError,
  InformerTimeoutError,
  InformerUnavailableError,
  RefundTarget,
  WalletCtx,
  upstreamMessageFrom,
} from './informer.types';

// Refund holds an on-chain send open for up to 45s. The lock outlives that
// with margin so a process death between request and release cannot wedge a
// wallet permanently.
const REFUND_LOCK_TTL_SEC = 120;
const refundLockKey = (walletId: number) =>
  `informer:refund_inflight:${walletId}`;

/**
 * Orchestrates the refund wizard: wallet lookup, the pure state machine,
 * the API call, the wallet-level lock and error handling.
 *
 * Returns messages instead of publishing them — publishing stays with the
 * dispatcher that already owns it, which keeps this class testable without
 * gateway or messenger mocks.
 */
@Injectable()
export class InformerRefundService {
  private readonly logger = new Logger(InformerRefundService.name);

  constructor(
    private readonly client: InformerClient,
    private readonly pending: PendingStateStore,
    private readonly redis: RedisService,
  ) {}

  /**
   * Entry point of the wizard. Wallet facts are captured now and carried
   * through every step, so the confirmation card describes the actual money
   * instead of a bare id.
   */
  async startWizard(userId: string, walletId: number): Promise<string[]> {
    let ctx: WalletCtx | null = null;
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

    if (!ctx) {
      return [
        `⚠️ Кошелька **#${walletId}** нет в текущем списке — возможно, его уже ` +
          'обработали. Обнови список и попробуй снова.\n\n[ACTION:📋 Кошельки оператора]',
      ];
    }

    await this.pending.save(userId, {
      kind: 'refund',
      step: 'method',
      walletId,
      ctx,
    });
    return [formatRefundMethodChoice(walletId, ctx)];
  }

  async runStep(
    userId: string,
    state: PendingOp & { kind: 'refund' },
    content: string,
  ): Promise<string[]> {
    const result = advanceRefundFlow(state, content);

    if (result.next) {
      await this.pending.save(userId, result.next);
    } else {
      await this.pending.clear(userId);
    }
    const messages = [...result.messages];
    if (!result.call) return messages;

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
      messages.push(formatRefundInFlight(walletId));
      return messages;
    }

    try {
      const refund = await this.client.refundOperatorWallet(
        walletId,
        target,
        totpCode,
        verifiedAbsent,
      );
      messages.push(formatRefundResult(refund, target));
    } catch (e) {
      messages.push(
        ...(await this.handleError(
          userId,
          { walletId, ctx, target, verifiedAbsent },
          e,
        )),
      );
    } finally {
      await this.redis.del(refundLockKey(walletId));
    }
    return messages;
  }

  /**
   * Refund errors are handled separately from every other informer action:
   * a refund is irreversible, so nothing here ever retries on its own, and
   * a timeout is explicitly NOT reported as "nothing was sent".
   */
  private async handleError(
    userId: string,
    op: {
      walletId: number;
      ctx: WalletCtx;
      target: RefundTarget;
      verifiedAbsent: boolean;
    },
    e: unknown,
  ): Promise<string[]> {
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
      return [formatRefundTotpRejected(op.walletId, PENDING_OP_TTL_SEC)];
    }

    if (e instanceof InformerTimeoutError) {
      return [formatRefundTimeout(op.walletId)];
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
        return [formatRefundGate(op.walletId, op.ctx, failure.message)];
      }
      return [formatRefundFailure(op.walletId, failure)];
    }

    this.logger.error(
      `refund failed for #${op.walletId}: ${(e as Error)?.message || (e as any)}`,
    );
    throw e; // unknown error — let the dispatcher render its generic message
  }
}
