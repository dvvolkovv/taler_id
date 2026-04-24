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
    const enforced = cfg.billingEnforced;

    const toggle = await this.prisma.userFeatureToggle.findUnique({
      where: { userId_featureKey: { userId, featureKey } },
    });
    const toggleEnabled = toggle?.enabled ?? true;

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
