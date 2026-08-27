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
  formatRefundRejectedBeforeSend,
  formatRefundResult,
  formatRefundTimeout,
  formatRefundTotpRejected,
  formatRefundUnknownError,
} from './informer.refund.formatters';
import {
  InformerAuthError,
  InformerBadRequestError,
  InformerError,
  InformerNonceStoreError,
  InformerNotConfiguredError,
  InformerOperatorInterventionError,
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
        // Optional on the type — platform guarantees them non-empty, but
        // an older stand or a rollback must still produce a renderable
        // (if gate-closed) wizard instead of `undefined` reaching a card.
        deposit: {
          network: item.deposit_network ?? '',
          token: item.deposit_token ?? '',
          amount: item.deposit_amount ?? '',
          address: item.deposit_address ?? '',
        },
        withdraw: {
          network: item.withdraw_network,
          token: item.withdraw_token,
          amount: item.withdraw_amount,
          address: item.withdraw_address,
        },
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
   * Human headline for each pre-send rejection shape. Kept apart from the
   * upstream detail (rendered separately by the caller) so the headline
   * always names the actual cause instead of a generic "rejected".
   */
  private rejectedBeforeSendHeadline(e: InformerError): string {
    if (e instanceof InformerAuthError) {
      return 'Платформа отвергла нашу подпись запроса — сообщи администратору';
    }
    if (e instanceof InformerBadRequestError) {
      return 'Платформа не приняла запрос на возврат';
    }
    if (e instanceof InformerNotConfiguredError) {
      return 'Возврат на этом стенде не настроен, либо кошелёк не найден';
    }
    if (e instanceof InformerOperatorInterventionError) {
      return 'Требуется вмешательство оператора';
    }
    // InformerNonceStoreError — transient infra issue on the platform's
    // side, still caught before any send.
    return 'Платформа временно не смогла обработать подписанный запрос';
  }

  /** `upstreamStatus=… upstreamBody=…`, or '' when the error carries none —
   * mirrors the logging shape `InformerBotService`'s outer catch uses for
   * every other action, so refund failures show up in pm2 logs with the
   * same detail a balance lookup would. */
  private upstreamDetail(status?: number, body?: string): string {
    return status != null
      ? ` upstreamStatus=${status} upstreamBody=${(body ?? '').slice(0, 300)}`
      : '';
  }

  /**
   * Refund errors are handled separately from every other informer action:
   * a refund is irreversible, so nothing here ever retries on its own, and
   * neither a timeout nor an unrecognised exception is ever reported as
   * "nothing was sent" — both fire while the send to the admin-API was
   * already in flight.
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
      this.logger.warn(
        `refund #${op.walletId} totp rejected:${this.upstreamDetail(e.upstreamStatus, e.upstreamBody)}`,
      );
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
      // Nothing to log beyond the wallet — a timeout carries no upstream
      // body — but this stays `error`, not `warn`: the outcome is unknown
      // and someone may need to dig into it later.
      this.logger.error(
        `refund #${op.walletId} timed out — outcome unknown, no retry offered`,
      );
      return [formatRefundTimeout(op.walletId)];
    }

    if (e instanceof InformerUnavailableError) {
      const failure = classifyRefundFailure(
        upstreamMessageFrom(e.upstreamBody, 500),
      );
      if (failure.kind === 'second_payout') {
        this.logger.warn(
          `refund #${op.walletId} blocked by second-payout gate:${this.upstreamDetail(e.upstreamStatus, e.upstreamBody)}`,
        );
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
      this.logger.warn(
        `refund #${op.walletId} rejected (${failure.kind}):${this.upstreamDetail(e.upstreamStatus, e.upstreamBody)}`,
      );
      return [formatRefundFailure(op.walletId, failure)];
    }

    // The admin-API rejected the request outright, before any send happened
    // — request validation, our own signing, a misconfigured stand, an
    // unknown wallet, a nonce-store hiccup, or a case that needs a human
    // (422, which already carries an actionable upstream message). Unlike
    // everything below, the outcome here is NOT in doubt: nothing left.
    // Must be checked BEFORE the final unknown-exception branch, or these
    // typed, pre-send rejections would be told to the operator as "the
    // transaction might have gone out" — a false alarm on an irreversible
    // operation.
    if (
      e instanceof InformerBadRequestError ||
      e instanceof InformerAuthError ||
      e instanceof InformerNotConfiguredError ||
      e instanceof InformerOperatorInterventionError ||
      e instanceof InformerNonceStoreError
    ) {
      this.logger.warn(
        `refund #${op.walletId} rejected before send (${e.name}):${this.upstreamDetail(e.upstreamStatus, e.upstreamBody)}`,
      );
      return [
        formatRefundRejectedBeforeSend(
          op.walletId,
          this.rejectedBeforeSendHeadline(e),
          upstreamMessageFrom(e.upstreamBody, 300),
        ),
      ];
    }

    // Unknown exception thrown WHILE the request to refundOperatorWallet was
    // in flight — never treated like startWizard's errors (which fail
    // before anything is sent) and never bubbled to the dispatcher's
    // generic errorToMessage(), which offers a retry button. That retry
    // would risk paying the client twice, exactly what the gate and the
    // `retryable` flags elsewhere in this flow exist to prevent.
    const detail = e instanceof Error ? e.message : String(e);
    this.logger.error(
      `refund #${op.walletId} failed with an unrecognised error mid-send: ${detail}`,
    );
    return [formatRefundUnknownError(op.walletId, detail)];
  }
}
