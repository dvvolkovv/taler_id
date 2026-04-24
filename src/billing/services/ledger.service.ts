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
