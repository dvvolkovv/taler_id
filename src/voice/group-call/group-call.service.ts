import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../../prisma/prisma.service';
import { VoiceService } from '../voice.service';
import { GroupCallGateway } from './group-call.gateway';
import { ApnsService } from '../../common/apns.service';
import { FcmService } from '../../common/fcm.service';
import { GroupCallStatus, GroupCallInviteStatus } from '@prisma/client';

const MAX_PARTICIPANTS = 8;
const RING_TIMEOUT_SEC = 30;

/**
 * Orchestrates group voice calls (Phase 1).
 *
 * Phase 1 Task 4 implements only `createCall` — host creates a GroupCall in
 * LOBBY state, invitees get push + Socket.io fan-out, ring-timeout jobs are
 * scheduled in BullMQ (Redis-backed, survives backend restarts), and the
 * host receives a LiveKit token so the mobile UI can join the room
 * immediately. State transitions and the rest of the lifecycle live in
 * Tasks 5-9.
 */
@Injectable()
export class GroupCallService {
  private readonly logger = new Logger(GroupCallService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly voice: VoiceService,
    private readonly gateway: GroupCallGateway,
    @InjectQueue('group-call-timeouts') private readonly queue: Queue,
    private readonly apns: ApnsService,
    private readonly fcm: FcmService,
  ) {}

  async createCall(hostUserId: string, inviteeIds: string[]) {
    if (inviteeIds.length === 0) {
      throw new BadRequestException('inviteeIds is empty');
    }
    if (inviteeIds.length > MAX_PARTICIPANTS - 1) {
      throw new BadRequestException(
        `Cannot invite more than ${MAX_PARTICIPANTS - 1} participants (host + invitees must fit in ${MAX_PARTICIPANTS}-cap)`,
      );
    }
    if (inviteeIds.includes(hostUserId)) {
      throw new BadRequestException('host cannot self-invite');
    }
    const dedup = Array.from(new Set(inviteeIds));

    // Generate the GroupCall id up front so we can derive `livekitRoomName`
    // (`group-${id}`) for the unique-constrained column on first INSERT —
    // a two-step create+update would race against the unique constraint and
    // fail when two concurrent calls land with the same empty placeholder.
    const groupCallId = uuidv4();
    const livekitRoomName = `group-${groupCallId}`;

    const call = await this.prisma.$transaction(async (tx: any) => {
      const created = await tx.groupCall.create({
        data: {
          id: groupCallId,
          hostUserId,
          status: GroupCallStatus.LOBBY,
          livekitRoomName,
        },
      });
      await tx.groupCallInvite.createMany({
        data: dedup.map((uid) => ({
          groupCallId: created.id,
          userId: uid,
          invitedBy: hostUserId,
          status: GroupCallInviteStatus.CALLING,
        })),
      });
      return created;
    });

    const invites = await this.prisma.groupCallInvite.findMany({
      where: { groupCallId: call.id },
    });

    // Schedule per-invite ring-timeout jobs. BullMQ persists in Redis so
    // the timeouts survive a backend restart; jobId lets us cancel a
    // specific invite when the user accepts/declines (Task 6).
    for (const inv of invites) {
      await this.queue.add(
        'timeout-invite',
        { inviteId: inv.id },
        { delay: RING_TIMEOUT_SEC * 1000, jobId: `timeout-${inv.id}` },
      );
    }

    // Push + Socket.io fan-out. Push failures shouldn't fail the call —
    // Socket.io still reaches connected clients, and the bell rings on
    // reconnect via the active-call query (Task 5).
    const host = await this.prisma.user.findUnique({ where: { id: hostUserId } });
    for (const inv of invites) {
      this.apns
        .sendGroupCallInvite(inv.userId, {
          groupCallId: call.id,
          host: host as any,
          inviteeCount: invites.length,
          livekitRoomName: call.livekitRoomName,
        })
        .catch((e) => this.logger.warn(`APNs push failed for ${inv.userId}: ${e?.message ?? e}`));
      this.fcm
        .sendGroupCallInvite(inv.userId, {
          groupCallId: call.id,
          host: host as any,
          inviteeCount: invites.length,
        })
        .catch((e) => this.logger.warn(`FCM push failed for ${inv.userId}: ${e?.message ?? e}`));
      this.gateway.emitInvite(inv.userId, {
        groupCallId: call.id,
        host,
        invitees: invites,
      });
    }

    const { token, livekitWsUrl } = await this.voice.generateGroupCallToken(call.id, hostUserId);
    return {
      groupCall: { ...call, invites },
      livekitToken: token,
      livekitWsUrl,
    };
  }
}
