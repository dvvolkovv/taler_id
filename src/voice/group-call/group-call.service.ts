import {
  Inject,
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  GoneException,
  ConflictException,
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

  /**
   * Invitee joins the call.
   *
   * - Validates the user actually has an invite (404/403/410 are distinguished
   *   so the mobile UI can show "call ended" vs "no permission").
   * - Idempotent: if the user already JOINED, we just re-issue a LiveKit
   *   token. This handles iOS CallKit reconnect-flicker where the same
   *   `joinCall` REST call lands twice in quick succession — without this we
   *   would skip the early-return and run the transaction with stale invite
   *   data. We intentionally do NOT touch the queue or fan-out events on the
   *   idempotent path so we don't double-emit `groupCallJoined` to peers.
   * - First-join transitions LOBBY→ACTIVE; subsequent joins leave the call
   *   ACTIVE alone. Both happen inside a single $transaction so a peer
   *   listing the call between writes never sees an invite=JOINED + call=LOBBY
   *   inconsistency (Phase 1 has no compensating reconciliation logic).
   * - The ring-timeout job is cancelled best-effort: if BullMQ already fired
   *   the timeout (race with NO_ANSWER), `queue.remove` either no-ops or
   *   throws "job not found"; we swallow either since the invite is now
   *   JOINED and the timeout job's effect (mark NO_ANSWER) is moot.
   */
  async joinCall(callId: string, userId: string) {
    const call = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    if (!call) throw new NotFoundException('GroupCall not found');
    if (call.status === GroupCallStatus.ENDED) {
      throw new GoneException('Call ended');
    }

    const invite = call.invites.find((i: any) => i.userId === userId);
    if (!invite) throw new ForbiddenException('No invite for this user');

    // Idempotent: if already JOINED, just re-issue the token without touching
    // DB / queue / gateway. See doc comment above for why.
    if (invite.status === GroupCallInviteStatus.JOINED) {
      const { token, livekitWsUrl } = await this.voice.generateGroupCallToken(call.id, userId);
      return { livekitToken: token, livekitWsUrl };
    }

    // Single-transaction state transition so concurrent readers can't observe
    // an inconsistent (invite=JOINED, call=LOBBY) snapshot.
    await this.prisma.$transaction(async (tx: any) => {
      await tx.groupCallInvite.update({
        where: { groupCallId_userId: { groupCallId: callId, userId } },
        data: {
          status: GroupCallInviteStatus.JOINED,
          joinedAt: new Date(),
          respondedAt: new Date(),
        },
      });
      if (call.status === GroupCallStatus.LOBBY) {
        await tx.groupCall.update({
          where: { id: callId },
          data: { status: GroupCallStatus.ACTIVE },
        });
      }
    });

    // Best-effort cancel of the ring-timeout job. If the timeout already fired
    // (BullMQ delivered the job to its worker before we got here), `remove`
    // either no-ops or throws — either is fine since the invite is JOINED now.
    // `Promise.resolve` wraps in case `queue.remove` returns void synchronously
    // (some BullMQ versions / the unit-test mock).
    await Promise.resolve(this.queue.remove(`timeout-${invite.id}`)).catch(() => {});

    // Issue the joiner's LiveKit token BEFORE the fan-out — parity with
    // `createCall` (Task 4). If token generation throws (env typo, signature
    // mismatch), peers haven't yet been told this user joined, so we don't
    // leave the call in a state where everyone sees "X joined" but X has no
    // token to actually connect to LiveKit.
    const { token, livekitWsUrl } = await this.voice.generateGroupCallToken(call.id, userId);

    // Refetch invites so the broadcast carries the post-update view (the
    // pre-update `call` still has the old CALLING status). emitStatus also
    // needs the up-to-date list to compute the participant audience.
    const refreshed = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    const participantIds = this.collectParticipantIds(refreshed!);
    this.gateway.emitStatus(participantIds, {
      groupCallId: callId,
      invites: refreshed!.invites,
    });
    this.gateway.emitJoined(participantIds, {
      groupCallId: callId,
      userId,
      joinedAt: new Date(),
    });

    return { livekitToken: token, livekitWsUrl };
  }

  /**
   * Invitee declines the call.
   *
   * - 404 / 403 / 409 / idempotent ordering matches `joinCall` (and the same
   *   pattern documented in Task 6): missing call → 404, no invite → 403,
   *   already JOINED → 409 (the iOS UI must call `/leave` instead, since
   *   declining a call you've already joined would leave the LiveKit session
   *   dangling and confuse peers who already see this user as a participant).
   * - Already-DECLINED is an early-return no-op so the iOS Push-extension
   *   "decline" button is safe to retry on flaky network without spamming
   *   `groupCallStatus` events to peers.
   * - The 410 (Gone) check that `joinCall` does is intentionally absent here:
   *   if the call has ENDED, the caller's invite will already be in a
   *   terminal state (TIMEOUT / LEFT / DECLINED — `endCall` doesn't mutate
   *   invites, but the invite was set to one of those before reaching ENDED),
   *   so the JOINED-check or idempotent-DECLINED branch handles it. Falling
   *   through to mutate a CALLING invite on an ENDED call would be benign
   *   (DB row updates fine), and the broadcast on stale call data is
   *   harmless because clients ignore status events for ENDED calls.
   * - Cancels the ring-timeout job best-effort (same swallowed-throw pattern
   *   as `joinCall`).
   * - After the broadcast, calls `endCallIfDeserted` to auto-end LOBBY calls
   *   where every invitee has now declined / timed out — this is the path
   *   that fires `voice.deleteRoom` to release the LiveKit room.
   */
  async declineCall(callId: string, userId: string) {
    const call = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    if (!call) throw new NotFoundException('GroupCall not found');

    const invite = call.invites.find((i: any) => i.userId === userId);
    if (!invite) throw new ForbiddenException('No invite for this user');
    if (invite.status === GroupCallInviteStatus.JOINED) {
      throw new ConflictException('Already joined; use /leave instead');
    }
    if (invite.status === GroupCallInviteStatus.DECLINED) return; // idempotent

    await this.prisma.groupCallInvite.update({
      where: { groupCallId_userId: { groupCallId: callId, userId } },
      data: {
        status: GroupCallInviteStatus.DECLINED,
        respondedAt: new Date(),
      },
    });

    // Cancel pending timeout (idempotent — fine if already gone).
    await Promise.resolve(this.queue.remove(`timeout-${invite.id}`)).catch(() => {});

    // Refetch and broadcast post-update view (call.invites is pre-update).
    const refreshed = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    const participantIds = this.collectParticipantIds(refreshed!);
    this.gateway.emitStatus(participantIds, {
      groupCallId: callId,
      invites: refreshed!.invites,
    });

    // Auto-end the call if everyone's gone (LOBBY: nobody answered; ACTIVE:
    // last participant left). Runs after the status broadcast so subscribers
    // first see the DECLINED transition, then the ENDED event — same UI flow
    // as a host-ended call.
    await this.endCallIfDeserted(refreshed!);
  }

  /**
   * Maybe-end-call helper: called after every state-changing operation
   * (decline, leave, kick — Tasks 7/8/9) to detect "all gone" terminal
   * conditions. Two variants:
   *
   * - LOBBY → end with reason `timeout` if no JOINED and no still-CALLING
   *   invitees (the host's createCall LOBBY had a chance, nobody picked up
   *   or everyone declined).
   * - ACTIVE → end with reason `all_left` if no JOINED invitees remain
   *   (everyone explicitly left after the call started).
   *
   * Does NOT cover `host_ended` (Task 8 calls `endCall` directly with that
   * reason). The two reason values here are derived solely from the
   * deserted-room state.
   */
  private async endCallIfDeserted(call: any): Promise<void> {
    if (
      call.status !== GroupCallStatus.LOBBY &&
      call.status !== GroupCallStatus.ACTIVE
    ) {
      return;
    }
    const anyJoined = call.invites.some(
      (i: any) => i.status === GroupCallInviteStatus.JOINED,
    );
    const anyCalling = call.invites.some(
      (i: any) => i.status === GroupCallInviteStatus.CALLING,
    );

    if (call.status === GroupCallStatus.LOBBY && !anyJoined && !anyCalling) {
      await this.endCall(call.id, 'timeout');
      return;
    }
    if (call.status === GroupCallStatus.ACTIVE && !anyJoined) {
      await this.endCall(call.id, 'all_left');
      return;
    }
  }

  /**
   * Atomically transition a GroupCall to ENDED, broadcast `groupCallEnded`,
   * and best-effort delete the LiveKit room.
   *
   * - The Prisma update is race-safe: the `where` clause filters on
   *   `status: { in: [LOBBY, ACTIVE] }`, so a concurrent caller (e.g. host
   *   pressing "End" at the same moment as the last invitee leaves) only
   *   wins once. Prisma 5 throws `P2025` (RecordNotFound) when zero rows
   *   match; we swallow that with `.catch(() => null)` and short-circuit so
   *   we never double-emit `groupCallEnded`.
   * - The audience for `emitEnded` is the FULL invitee list (DECLINED/LEFT/
   *   TIMEOUT included). Unlike status broadcasts (where we exclude
   *   opted-out users via `collectParticipantIds`), the call-ended event
   *   needs to reach those users so their UI can clear any stale "incoming
   *   call" sheet that may be lingering after a push-only delivery.
   * - LiveKit `deleteRoom` failure is non-fatal: the room may already be
   *   empty and auto-cleaned by LiveKit's `emptyTimeout`, or the LK server
   *   might be transiently down. We log a warning so ops can investigate
   *   if leaks accumulate, but the call is already ENDED in our DB so the
   *   user-facing flow is correct.
   */
  private async endCall(
    callId: string,
    reason: 'all_left' | 'timeout' | 'host_ended',
  ): Promise<void> {
    const updated = await this.prisma.groupCall
      .update({
        where: {
          id: callId,
          status: {
            in: [GroupCallStatus.LOBBY, GroupCallStatus.ACTIVE],
          } as any,
        } as any,
        data: {
          status: GroupCallStatus.ENDED,
          endedAt: new Date(),
          endedReason: reason,
        },
      })
      .catch(() => null); // already ENDED → P2025, no-op

    if (!updated) return;

    const allInvites = await this.prisma.groupCallInvite.findMany({
      where: { groupCallId: callId },
    });
    // DO NOT replace this with `collectParticipantIds(...)`. The end-of-call
    // event MUST reach DECLINED/LEFT/TIMEOUT invitees too — e.g. a user who
    // declined on phone A may still have a stale incoming-call sheet on phone B
    // (delivered via APNs but never reconciled by Socket.IO). Narrowing the
    // audience here will silently strand those sheets. See Task 7 review.
    const allUserIds = Array.from(
      new Set([updated.hostUserId, ...allInvites.map((i: any) => i.userId)]),
    );
    this.gateway.emitEnded(allUserIds, { groupCallId: callId, reason });

    // Best-effort LiveKit cleanup; the room may already be gone.
    await this.voice
      .deleteRoom(updated.livekitRoomName)
      .catch((e: any) =>
        this.logger.warn(`LiveKit deleteRoom failed: ${e?.message ?? e}`),
      );
  }

  /**
   * Recipients of group-call status broadcasts: host + everyone whose invite
   * is currently active (CALLING or JOINED). LEFT/DECLINED users are excluded
   * intentionally — they explicitly opted out and shouldn't keep receiving
   * presence churn. Reused by Tasks 7-9 (leave/end/kick).
   */
  private collectParticipantIds(call: any): string[] {
    const ids = new Set<string>([call.hostUserId]);
    for (const inv of call.invites) {
      if (
        inv.status === GroupCallInviteStatus.CALLING ||
        inv.status === GroupCallInviteStatus.JOINED
      ) {
        ids.add(inv.userId);
      }
    }
    return Array.from(ids);
  }
}
