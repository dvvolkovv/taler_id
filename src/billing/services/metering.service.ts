import { Inject, Injectable, Logger } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import { PrismaService } from '../../prisma/prisma.service';
import { PricingService } from './pricing.service';
import { LedgerService } from './ledger.service';
import { GatingService } from './gating.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';

export interface MeteringGateway {
  emitToUser(userId: string, event: string, payload: unknown): void;
}

// Minute-based features: cron debits elapsed time automatically.
// whisper_transcribe is NOT here — it's a one-shot post-call debit owned by the transcription service.
// web_search / meeting_summary are one-shot debits done by their owning service.
const MINUTE_BASED = new Set(['voice_assistant', 'ai_twin', 'outbound_call']);

@Injectable()
export class MeteringService {
  private readonly log = new Logger(MeteringService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly pricing: PricingService,
    private readonly ledger: LedgerService,
    private readonly gating: GatingService,
    @Inject('MESSENGER_GATEWAY') private readonly gateway: MeteringGateway,
  ) {}

  @Interval(10_000)
  async tick(): Promise<void> {
    const sessions = await this.prisma.aiSession.findMany({ where: { status: 'active' } });
    const cfg = await this.pricing.getConfig();

    for (const s of sessions) {
      if (!MINUTE_BASED.has(s.featureKey)) continue;

      const now = new Date();
      const elapsedMs = now.getTime() - new Date(s.lastMeteredAt).getTime();
      const elapsedMinutes = elapsedMs / 60_000;
      if (elapsedMinutes <= 0) continue;

      try {
        const cost = await this.pricing.calculatePlanckCost(s.featureKey, elapsedMinutes);
        await this.ledger.debit(s.userId, cost, 'SPEND', {
          featureKey: s.featureKey,
          sessionId: s.id,
          metadata: { unitsUsed: elapsedMinutes, reporter: 'backend-cron' },
        });
        await this.prisma.aiSession.update({
          where: { id: s.id },
          data: { lastMeteredAt: now, totalSpentPlanck: { increment: cost } },
        });
        await this.prisma.usageLog.create({
          data: {
            userId: s.userId,
            sessionId: s.id,
            featureKey: s.featureKey,
            unit: 'minute',
            units: elapsedMinutes.toFixed(4),
            reporter: 'backend',
          },
        });
        await this.checkLowBalanceWarning(s);
      } catch (err) {
        if (err instanceof InsufficientFundsException) {
          if (cfg.billingEnforced) {
            await this.gating.endSession(s.id, 'terminated_no_funds');
            this.gateway.emitToUser(s.userId, 'ai_session_terminated', {
              sessionId: s.id,
              reason: 'no_funds',
              featureKey: s.featureKey,
              contextRef: s.contextRef,
            });
          } else {
            this.log.warn(`[dry-run] would terminate ${s.id} for ${s.userId} — continuing`);
          }
        } else {
          this.log.error(`metering failed for session ${s.id}: ${String(err)}`);
        }
      }
    }
  }

  private async checkLowBalanceWarning(s: {
    id: string;
    userId: string;
    featureKey: string;
  }): Promise<void> {
    const [balance, minReserve] = await Promise.all([
      this.ledger.getBalance(s.userId),
      this.pricing.getMinReservePlanck(s.featureKey),
    ]);
    if (balance < minReserve * 3n && balance >= minReserve) {
      this.gateway.emitToUser(s.userId, 'billing_low_balance_warning', {
        sessionId: s.id,
        balancePlanck: balance.toString(),
        minReservePlanck: minReserve.toString(),
      });
    }
  }

  /**
   * Final adjustment reported by an agent (ai-twin, outbound-call) or client (voice_assistant).
   * If agent-reported total > cron-debited total, debit the difference.
   * If less, keep cron-debited amount (trust cron / never credit back).
   */
  async reportUsage(sessionId: string, totalUnits: number, reporter: string): Promise<void> {
    const s = await this.prisma.aiSession.findUnique({ where: { id: sessionId } });
    if (!s) throw new Error(`session ${sessionId} not found`);

    const totalExpected = await this.pricing.calculatePlanckCost(s.featureKey, totalUnits);
    const diff = totalExpected - s.totalSpentPlanck;

    await this.prisma.usageLog.create({
      data: {
        userId: s.userId,
        sessionId,
        featureKey: s.featureKey,
        unit: 'minute',
        units: totalUnits.toFixed(4),
        reporter,
      },
    });

    if (diff <= 0n) return;

    try {
      await this.ledger.debit(s.userId, diff, 'SPEND', {
        featureKey: s.featureKey,
        sessionId,
        metadata: { unitsUsed: totalUnits, reporter, adjustment: true },
      });
      await this.prisma.aiSession.update({
        where: { id: sessionId },
        data: { totalSpentPlanck: { increment: diff } },
      });
    } catch (err) {
      if (err instanceof InsufficientFundsException) {
        this.log.warn(`final adjustment for ${sessionId} skipped: insufficient funds`);
      } else {
        throw err;
      }
    }
  }

  async heartbeat(sessionId: string): Promise<void> {
    // Liveness only. Cron drives actual time-based billing.
    await this.prisma.aiSession.update({
      where: { id: sessionId },
      data: {},
    });
  }
}
