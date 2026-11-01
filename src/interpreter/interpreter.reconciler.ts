import { Injectable, Logger } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import type { InterpreterEndReason } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { InterpreterLivekitService } from './interpreter-livekit.service';
import { InterpreterService } from './interpreter.service';

// As long as the agent waits for a person who left. A room without the agent
// for that long means it was restarted or redeployed: it will not report.
const AGENT_LOST_AFTER_MS = 60_000;
// After a code expires the host can still ask for a new one this long.
const WAITING_GRACE_MS = 5 * 60_000;

const SESSION_FIELDS = {
  id: true,
  roomName: true,
  billingSessionId: true,
  startedAt: true,
  agentSeenAt: true,
} as const;

type ReconciledSession = {
  id: string;
  roomName: string;
  billingSessionId: string | null;
  startedAt: Date | null;
  agentSeenAt: Date | null;
};

/**
 * Ends the sessions nobody else will end: billing closed by metering (no
 * funds, the 2-hour cap), an agent gone without reporting (restart, deploy),
 * a QR nobody scanned. Every end goes through InterpreterService.close, the
 * same path as a hang-up. Runs on every app node; close() makes that safe.
 */
@Injectable()
export class InterpreterReconciler {
  private readonly log = new Logger(InterpreterReconciler.name);
  private running = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly livekit: InterpreterLivekitService,
    private readonly interpreter: InterpreterService,
  ) {}

  @Interval(10_000)
  async tick(): Promise<void> {
    // An SFU that answers slowly can make a pass outlast the interval.
    if (this.running) return;
    this.running = true;
    try {
      await this.runOnce();
    } finally {
      this.running = false;
    }
  }

  /** One pass. Never throws: each session is handled on its own. */
  async runOnce(now = new Date()): Promise<void> {
    await this.forEach(
      'active sessions',
      () =>
        this.prisma.interpreterSession.findMany({
          where: { status: 'ACTIVE' },
          select: SESSION_FIELDS,
        }),
      (s) => this.reconcileActive(s, now),
    );
    await this.forEach(
      'expired codes',
      () =>
        this.prisma.interpreterSession.findMany({
          where: {
            status: 'WAITING',
            codeExpiresAt: { lt: new Date(now.getTime() - WAITING_GRACE_MS) },
          },
          select: SESSION_FIELDS,
        }),
      (s) => this.interpreter.close(s, 'EXPIRED', { stopAgent: false }),
    );
  }

  private async reconcileActive(
    s: ReconciledSession,
    now: Date,
  ): Promise<void> {
    if (s.billingSessionId) {
      const billing = await this.prisma.aiSession.findUnique({
        where: { id: s.billingSessionId },
        select: { status: true },
      });
      if (billing?.status !== 'active') {
        await this.interpreter.close(s, endedByBilling(billing?.status), {
          stopAgent: true,
        });
        return;
      }
    }

    const present = await this.livekit.agentPresent(s.roomName);
    // LiveKit did not answer: nothing is known, so nothing is decided.
    if (present === null) return;
    if (present) {
      await this.prisma.interpreterSession.updateMany({
        where: { id: s.id, status: 'ACTIVE' },
        data: { agentSeenAt: now },
      });
      return;
    }
    const lastSeen = s.agentSeenAt ?? s.startedAt;
    if (lastSeen && now.getTime() - lastSeen.getTime() > AGENT_LOST_AFTER_MS) {
      // Stopped anyway: the agent may still hold the session while it
      // tries to get back into the room.
      await this.interpreter.close(s, 'AGENT_LOST', { stopAgent: true });
    }
  }

  private async forEach(
    what: string,
    load: () => Promise<ReconciledSession[]>,
    handle: (s: ReconciledSession) => Promise<void>,
  ): Promise<void> {
    let sessions: ReconciledSession[];
    try {
      sessions = await load();
    } catch (e) {
      this.log.warn(`loading ${what} failed: ${String(e)}`);
      return;
    }
    for (const s of sessions) {
      try {
        await handle(s);
      } catch (e) {
        this.log.warn(`session ${s.id}: reconciling failed: ${String(e)}`);
      }
    }
  }
}

function endedByBilling(status: string | undefined): InterpreterEndReason {
  if (status === 'terminated_no_funds') return 'NO_FUNDS';
  if (status === 'terminated_stale') return 'MAX_DURATION';
  // Ended some other way, or gone: the conversation cannot go on unbilled.
  return 'TRANSLATION_FAILED';
}
