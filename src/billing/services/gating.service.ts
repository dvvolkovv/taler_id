import { Inject, Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { PricingService } from './pricing.service';
import { LedgerService } from './ledger.service';
import type { MeteringGateway } from './metering.service';
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
    @Inject('MESSENGER_GATEWAY') private readonly gateway: MeteringGateway,
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

    const session = await this.prisma.aiSession.create({
      data: {
        userId,
        featureKey,
        contextRef,
        status: 'active',
      },
      select: { id: true },
    });

    // Notify all of this user's sockets that an AI session just became active.
    // Mobile can use this to show a "session live" indicator or close any pre-session modal.
    this.gateway.emitToUser(userId, 'ai_session_started', {
      sessionId: session.id,
      featureKey,
    });

    return session;
  }

  async endSession(sessionId: string, reason: SessionTerminationReason): Promise<void> {
    const session = await this.prisma.aiSession.update({
      where: { id: sessionId },
      data: { status: reason, endedAt: new Date() },
    });

    // Only emit ai_session_terminated for non-completed ends. Normal completion
    // is handled by the client-initiated flow and needs no push.
    if (reason !== 'completed') {
      this.gateway.emitToUser(session.userId, 'ai_session_terminated', {
        sessionId,
        reason: reason === 'terminated_no_funds' ? 'no_funds' : 'failed',
        featureKey: session.featureKey,
      });
    }
  }
}
