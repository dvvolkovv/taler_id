import {
  Inject,
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  Logger,
  forwardRef,
} from '@nestjs/common';
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

// NOTE: BullModule.forRoot() must be configured in AppModule before this queue
// can connect at runtime (Task 11 owns this wiring). Unit tests mock the queue.

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
    @Inject(forwardRef(() => VoiceService))
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

    // Issue the host's LiveKit token immediately after the DB write succeeds —
    // before ringing invitees. If token generation throws (env typo, signature
    // mismatch), we surface the error to the host without waking up callees
    // who would then ring against a call the host can't join.
    const { token, livekitWsUrl } = await this.voice.generateGroupCallToken(call.id, hostUserId);

    const invites = await this.prisma.groupCallInvite.findMany({
      where: { groupCallId: call.id },
    });

    // Pull only the public fields needed for push/Socket.io fan-out so we
    // don't leak password/refreshTokens/KYC fields into APNs/FCM payloads
    // (those land in carrier logs once Task 14 wires real delivery).
    // displayName/avatarUrl live on Profile, not User, so we read Profile
    // directly and synthesize displayName the same way voice.service.makeToken
    // does (`firstName lastName` with userId as fallback).
    const profile = await this.prisma.profile.findUnique({
      where: { userId: hostUserId },
      select: { firstName: true, lastName: true, avatarUrl: true },
    });
    const host: { id: string; displayName: string; avatarUrl?: string | null } = {
      id: hostUserId,
      displayName:
        `${profile?.firstName ?? ''} ${profile?.lastName ?? ''}`.trim() || hostUserId,
      avatarUrl: profile?.avatarUrl ?? null,
    };

    // Schedule per-invite ring-timeout jobs in parallel (each `queue.add` is
    // an awaited Redis round-trip; serialising them stalled the host's
    // response by N×RTT). BullMQ persists in Redis so the timeouts survive
    // a backend restart; jobId lets us cancel a specific invite when the
    // user accepts/declines (Task 6). Push + Socket.io fan-out is folded
    // into the same Promise.all iteration: APNs/FCM are fire-and-forget
    // (push failures shouldn't fail the call — Socket.io still reaches
    // connected clients, and the bell rings on reconnect via the
    // active-call query in Task 5), and `emitInvite` is sync.
    await Promise.all(
      invites.map(async (inv) => {
        await this.queue.add(
          'timeout-invite',
          { inviteId: inv.id },
          { delay: RING_TIMEOUT_SEC * 1000, jobId: `timeout-${inv.id}` },
        );
        this.apns
          .sendGroupCallInvite(inv.userId, {
            groupCallId: call.id,
            host,
            inviteeCount: invites.length,
            livekitRoomName: call.livekitRoomName,
          })
          .catch((e) => this.logger.warn(`APNs push failed for ${inv.userId}: ${e?.message ?? e}`));
        this.fcm
          .sendGroupCallInvite(inv.userId, {
            groupCallId: call.id,
            host,
            inviteeCount: invites.length,
          })
          .catch((e) => this.logger.warn(`FCM push failed for ${inv.userId}: ${e?.message ?? e}`));
        this.gateway.emitInvite(inv.userId, {
          groupCallId: call.id,
          host,
          invitees: invites,
        });
      }),
    );

    return {
      groupCall: { ...call, invites },
      livekitToken: token,
      livekitWsUrl,
    };
  }

  // The plan called for `host: { select: { id, displayName, avatarUrl } }`,
  // but the User model has neither column — `displayName`/`avatarUrl` live on
  // the Profile relation (`User.profile Profile?`). We therefore include the
  // `host` and each invite's `user` together with their `profile`, leaving
  // synthesis of `displayName` (firstName+lastName fallback to userId) to the
  // controller/gateway layer (Tasks 10, 17), which is the same convention the
  // existing `createCall` push-payload code already follows.
  async getActiveCallsForUser(userId: string) {
    return this.prisma.groupCall.findMany({
      where: {
        status: { in: [GroupCallStatus.LOBBY, GroupCallStatus.ACTIVE] },
        invites: {
          some: {
            userId,
            status: {
              in: [
                GroupCallInviteStatus.CALLING,
                GroupCallInviteStatus.JOINED,
                GroupCallInviteStatus.LEFT,
                GroupCallInviteStatus.DECLINED,
              ],
            },
          },
        },
      },
      include: {
        host: {
          select: {
            id: true,
            profile: { select: { firstName: true, lastName: true, avatarUrl: true } },
          },
        },
        invites: {
          include: {
            user: {
              select: {
                id: true,
                profile: { select: { firstName: true, lastName: true, avatarUrl: true } },
              },
            },
          },
        },
      },
      orderBy: { startedAt: 'desc' },
    });
  }

  async getCall(callId: string, userId: string) {
    const call = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: {
        host: {
          select: {
            id: true,
            profile: { select: { firstName: true, lastName: true, avatarUrl: true } },
          },
        },
        invites: {
          include: {
            user: {
              select: {
                id: true,
                profile: { select: { firstName: true, lastName: true, avatarUrl: true } },
              },
            },
          },
        },
      },
    });
    if (!call) throw new NotFoundException('GroupCall not found');
    const isHost = call.hostUserId === userId;
    const hasInvite = call.invites.some((i: any) => i.userId === userId);
    if (!isHost && !hasInvite) {
      throw new ForbiddenException('No access to this call');
    }
    return call;
  }
}
