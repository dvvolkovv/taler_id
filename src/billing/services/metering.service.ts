import { Inject, Injectable, Logger, NotFoundException, GoneException } from '@nestjs/common';
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
  private readonly lowBalanceWarnedSessions = new Set<string>();

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
      const oldLastMeteredAt = new Date(s.lastMeteredAt);
      const elapsedMs = now.getTime() - oldLastMeteredAt.getTime();
      const elapsedMinutes = elapsedMs / 60_000;
      if (elapsedMinutes <= 0) continue;

      // Optimistic concurrency: claim this tick's elapsed window by atomically advancing
      // lastMeteredAt only if no other tick has already done so. updateMany returns { count }
      // with zero if the row's lastMeteredAt changed since our findMany.
      const claim = await this.prisma.aiSession.updateMany({
        where: { id: s.id, lastMeteredAt: oldLastMeteredAt, status: 'active' },
        data: { lastMeteredAt: now },
      });
      if (claim.count === 0) {
        // Another tick already metered this window — skip.
        continue;
      }

      try {
        const cost = await this.pricing.calculatePlanckCost(s.featureKey, elapsedMinutes);
        await this.ledger.debit(s.userId, cost, 'SPEND', {
          featureKey: s.featureKey,
          sessionId: s.id,
          metadata: { unitsUsed: elapsedMinutes, reporter: 'backend-cron' },
        });
        await this.prisma.aiSession.update({
          where: { id: s.id },
          data: { totalSpentPlanck: { increment: cost } },
        });

        // Separate try block — log failure must not leave audit gap while cost stays debited.
        try {
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
        } catch (logErr) {
          this.log.error(
            `usageLog.create failed for session ${s.id} (cost ${cost} already debited): ${String(logErr)}`,
          );
        }

        await this.checkLowBalanceWarning(s);
      } catch (err) {
        if (err instanceof InsufficientFundsException) {
          this.lowBalanceWarnedSessions.delete(s.id);
          if (cfg.billingEnforced) {
            await this.gating.endSession(s.id, 'terminated_no_funds');
            try {
              this.gateway.emitToUser(s.userId, 'ai_session_terminated', {
                sessionId: s.id,
                reason: 'no_funds',
                featureKey: s.featureKey,
                contextRef: s.contextRef,
              });
            } catch (err) {
              this.log.warn(
                `emitToUser ai_session_terminated failed for ${s.userId}: ${String(err)}`,
              );
            }
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

    const inWindow = balance < minReserve * 3n && balance >= minReserve;
    const wasWarned = this.lowBalanceWarnedSessions.has(s.id);

    if (inWindow && !wasWarned) {
      try {
        this.gateway.emitToUser(s.userId, 'billing_low_balance_warning', {
          sessionId: s.id,
          balancePlanck: balance.toString(),
          minReservePlanck: minReserve.toString(),
        });
      } catch (err) {
        this.log.warn(
          `emitToUser billing_low_balance_warning failed for ${s.userId}: ${String(err)}`,
        );
      }
      this.lowBalanceWarnedSessions.add(s.id);
    } else if (!inWindow) {
      // User topped up above 3× OR dropped below minReserve — clear so we can warn again
      // if they re-enter the window later in the same session.
      this.lowBalanceWarnedSessions.delete(s.id);
    }
  }

  /**
   * Final adjustment from an agent (ai-twin, outbound-call) or client (voice_assistant).
   *
   * Debits `totalExpected - session.totalSpentPlanck` if positive. Never credits back
   * if the agent reports less than cron already drained (trust cron as source of truth).
   *
   * Late adjustments after `status='completed'` are intentionally allowed to capture
   * crash-recovery reports — we do not guard on session status here.
   */
  async reportUsage(sessionId: string, totalUnits: number, reporter: string): Promise<void> {
    const s = await this.prisma.aiSession.findUnique({ where: { id: sessionId } });
    if (!s) throw new NotFoundException(`session ${sessionId} not found`);

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
    // Pure liveness check. We do NOT advance lastMeteredAt — that would skip billing
    // for the interval between the last cron tick and this heartbeat. We only verify
    // the session still exists and is active.
    const session = await this.prisma.aiSession.findUnique({
      where: { id: sessionId },
      select: { status: true },
    });
    if (!session) {
      throw new NotFoundException(`session ${sessionId} not found`);
    }
    if (session.status !== 'active') {
      // HTTP 410 Gone — session existed but is no longer usable. Client should stop heartbeating.
      throw new GoneException(`session ${sessionId} not active`);
    }
  }
}
