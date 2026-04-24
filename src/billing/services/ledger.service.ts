import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';
import type { MeteringGateway } from './metering.service';
import type { TxType, Prisma } from '@prisma/client';

/**
 * Double-entry ledger. All balance changes go through credit/debit/refund,
 * each wrapped in a $transaction with row-level locking on UserWallet (and
 * BillingTransaction for refunds) to serialize concurrent access.
 *
 * Relies on PostgreSQL's default READ COMMITTED isolation level — FOR UPDATE
 * acquires a row lock and the subsequent read sees the freshly committed
 * state. If the service is ever moved to RepeatableRead, concurrent debits
 * will produce serialization failures that callers must retry.
 */
@Injectable()
export class LedgerService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject('MESSENGER_GATEWAY') private readonly gateway: MeteringGateway,
  ) {}

  /**
   * Emit a billing_balance_changed event to every socket of this user after
   * a successful credit/debit/refund commit. Reads balance post-commit so
   * clients see the authoritative new value.
   */
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

  async credit(
    userId: string,
    amountPlanck: bigint,
    type: TxType,
    metadata?: Prisma.JsonObject,
    extras?: { sessionId?: string; featureKey?: string; chainTxHash?: string },
  ): Promise<{ id: string }> {
    if (amountPlanck <= 0n) throw new Error('credit amount must be > 0');

    const result = await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT 1 FROM "UserWallet" WHERE "userId" = ${userId} FOR UPDATE`;

      const wallet = await tx.userWallet.findUnique({ where: { userId } });
      if (!wallet) throw new NotFoundException(`no wallet for user ${userId}`);

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

    await this.emitBalance(userId, type, result.id);
    return result;
  }

  async debit(
    userId: string,
    amountPlanck: bigint,
    type: TxType,
    extras: { featureKey?: string; sessionId?: string; metadata?: Prisma.JsonObject } = {},
  ): Promise<{ id: string }> {
    if (amountPlanck <= 0n) throw new Error('debit amount must be > 0');

    const result = await this.prisma.$transaction(async (tx) => {
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

    await this.emitBalance(userId, type, result.id);
    return result;
  }

  async refund(originalTxId: string, reason: string): Promise<{ id: string }> {
    const result = await this.prisma.$transaction(async (tx) => {
      // Lock the original transaction row BEFORE reading status, to serialize concurrent refund attempts.
      // BillingTransaction.id is TEXT (cuid/uuid), so no ::uuid cast needed.
      await tx.$executeRaw`SELECT 1 FROM "BillingTransaction" WHERE id = ${originalTxId} FOR UPDATE`;
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

    // The inner $transaction returns the newly created REFUND row via tx.billingTransaction.create.
    // Its .userId matches the original owner — re-read outside the tx to fetch userId for the emit.
    const refundTx = await this.prisma.billingTransaction.findUnique({ where: { id: result.id } });
    if (refundTx) await this.emitBalance(refundTx.userId, 'REFUND', result.id);
    return result;
  }

  async getBalance(userId: string): Promise<bigint> {
    const w = await this.prisma.userWallet.findUnique({ where: { userId } });
    return w?.balancePlanck ?? 0n;
  }
}
