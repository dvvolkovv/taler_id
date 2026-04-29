import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../../../prisma/prisma.service';
import { GroupCallStatus, GroupCallInviteStatus } from '@prisma/client';
import { GroupCallService } from '../group-call.service';

const LOBBY_STALE_MS = 5 * 60 * 1000; // 5 minutes
const ACTIVE_STALE_MS = 60 * 1000; // 1 minute (no JOINED present)

/**
 * Periodic safety net for zombie group calls. Runs every 5 minutes.
 *
 * Cases handled:
 * 1. LOBBY older than 5 minutes — host created the call but no invitee ever
 *    JOINED and ring-timeouts somehow didn't fire (Bull queue down, Redis
 *    blip, etc.). Force-end with reason 'timeout'.
 * 2. ACTIVE with zero recent JOINED for >1 minute — all participants
 *    disconnected without explicitly leaving (LiveKit grace expired but
 *    webhook didn't fire, or backend was down at the time). Force-end with
 *    reason 'all_left'.
 *
 * The runtime path is best-effort: errors are logged and swallowed so a
 * single transient DB or LiveKit failure doesn't kill the cron.
 *
 * Both checks query against indexed columns (`(status, startedAt)`,
 * `(userId, status)`); see Task 1 for index design.
 */
@Injectable()
export class GroupCallCleanupCron {
  private readonly logger = new Logger(GroupCallCleanupCron.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly service: GroupCallService,
  ) {}

  @Cron(CronExpression.EVERY_5_MINUTES)
  async cleanup(): Promise<void> {
    const now = Date.now();

    // 1. LOBBY rooms older than 5 minutes — kill them
    const lobbyCutoff = new Date(now - LOBBY_STALE_MS);
    const staleLobby = await this.prisma.groupCall.findMany({
      where: {
        status: GroupCallStatus.LOBBY,
        startedAt: { lt: lobbyCutoff },
      },
      select: { id: true },
    });
    for (const c of staleLobby) {
      await this.service.handleZombieEnd(c.id, 'timeout').catch((e: any) =>
        this.logger.warn(`zombie LOBBY end failed for ${c.id}: ${e?.message ?? e}`),
      );
    }

    // 2. ACTIVE rooms with no JOINED participant in the last 1 minute
    const activeCutoff = new Date(now - ACTIVE_STALE_MS);
    const activeStale = await this.prisma.groupCall.findMany({
      where: {
        status: GroupCallStatus.ACTIVE,
        invites: {
          none: {
            status: GroupCallInviteStatus.JOINED,
            joinedAt: { gt: activeCutoff },
          },
        },
      },
      select: { id: true },
    });
    for (const c of activeStale) {
      await this.service.handleZombieEnd(c.id, 'all_left').catch((e: any) =>
        this.logger.warn(`zombie ACTIVE end failed for ${c.id}: ${e?.message ?? e}`),
      );
    }

    if (staleLobby.length || activeStale.length) {
      this.logger.log(
        `Cleaned ${staleLobby.length} LOBBY + ${activeStale.length} ACTIVE zombies`,
      );
    }
  }
}
