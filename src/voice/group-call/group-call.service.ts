import {
  Inject,
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
  GoneException,
  ConflictException,
  HttpException,
  HttpStatus,
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
import { RedisService } from '../../redis/redis.service';
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
    private readonly redis: RedisService,
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
      include: {
        user: {
          select: {
            id: true,
            profile: { select: { firstName: true, lastName: true, avatarUrl: true } },
          },
        },
      },
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
    // Mirror the `host`/`invites[].user.profile` shape returned by getCall so
    // the mobile picker→lobby transition renders names instead of UUIDs.
    const callWithHost = {
      ...call,
      host: { id: hostUserId, profile },
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
      groupCall: { ...callWithHost, invites },
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
        // Host has no invite row — they're tracked via `hostUserId`. Include
        // both arms so the host sees their own call (e.g. after app kill, to
        // resume from the active-call banner).
        OR: [
          { hostUserId: userId },
          {
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
        ],
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
   * Participant (or host) leaves an active call.
   *
   * - 404 / 403 / idempotent / race-safe-ENDED ordering matches the rest of
   *   the lifecycle methods. Unlike `declineCall`, this method accepts a
   *   bare host (no invite row) — host has no `GroupCallInvite` since the
   *   schema models the host on `GroupCall.hostUserId` only.
   * - Idempotent on already-LEFT invites: re-tapping "leave" on a flaky
   *   network won't double-broadcast `groupCallLeft` to peers.
   * - Race-safe on already-ENDED calls: if `endCall` won concurrently
   *   (host-ended button + last-leaver simultaneously), this is a no-op
   *   instead of a confusing 409 error to the leaver.
   * - **Host transfer**: if the host leaves and at least one invitee is still
   *   JOINED, the host role is transferred to the next JOINED invitee sorted
   *   by `joinedAt` ascending (earliest joiner wins — closest to a "vice-host"
   *   semantic). The transfer happens inside the same `$transaction` as the
   *   invite update so peers never see an inconsistent (host-userId stale +
   *   invite=LEFT) snapshot. If no JOINED candidates remain, the host change
   *   is skipped and `endCallIfDeserted` will end the call with `all_left`.
   * - We deliberately do NOT touch the BullMQ queue here: leaving an ACTIVE
   *   call means the ring-timeout for this invite has already fired or been
   *   cancelled at JOIN time.
   * - Emits in order: `emitHostChanged` (if applicable) → `emitStatus`
   *   → `emitLeft`. The status broadcast carries the post-update invite
   *   list; clients can rebuild their participant grid from it without
   *   needing to merge the `emitLeft` event. Then `endCallIfDeserted` may
   *   fire `emitEnded` after.
   */
  async leaveCall(callId: string, userId: string): Promise<void> {
    const call = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    if (!call) throw new NotFoundException('GroupCall not found');
    if (call.status === GroupCallStatus.ENDED) return; // idempotent — call already over

    const isHost = call.hostUserId === userId;
    const invite = call.invites.find((i: any) => i.userId === userId);

    // Authorization: must be host OR have an invite.
    if (!isHost && !invite) {
      throw new ForbiddenException('Not a participant of this call');
    }

    // Idempotent: if invite already LEFT, no-op (host has no invite row, so
    // this branch is non-host-only by construction).
    if (invite && invite.status === GroupCallInviteStatus.LEFT) return;

    // Transaction: mark invite LEFT (if exists) + maybe transfer host. Wrapping
    // both writes guarantees peers can't observe (host=stale, invite=LEFT) or
    // (host=new, invite=JOINED) snapshots between the two updates.
    let newHostId: string | null = null;
    await this.prisma.$transaction(async (tx: any) => {
      if (invite) {
        await tx.groupCallInvite.update({
          where: { groupCallId_userId: { groupCallId: callId, userId } },
          data: { status: GroupCallInviteStatus.LEFT, leftAt: new Date() },
        });
      }

      if (isHost) {
        // Host transfer candidate: earliest JOINED invitee (joinedAt asc).
        // We exclude the leaving user defensively even though the host can't
        // have an invite row in the current schema — a future schema where
        // the host also has an invite row would otherwise self-transfer.
        const candidates = call.invites
          .filter(
            (i: any) =>
              i.status === GroupCallInviteStatus.JOINED &&
              i.userId !== userId &&
              i.joinedAt,
          )
          .sort((a: any, b: any) => a.joinedAt!.getTime() - b.joinedAt!.getTime());
        const next = candidates[0];
        if (next) {
          await tx.groupCall.update({
            where: { id: callId },
            data: { hostUserId: next.userId },
          });
          newHostId = next.userId;
        }
        // If no candidate, hostUserId stays — we'll end the call directly
        // below (after the transaction) since `endCallIfDeserted` no longer
        // auto-ends ACTIVE calls (we made that change so an invitee leaving
        // doesn't kick the host out — but host-leaves-alone IS a real desertion).
      }
    });

    // Refetch + broadcast the post-update view.
    const refreshed = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    const participantIds = this.collectParticipantIds(refreshed!);

    if (newHostId) {
      this.gateway.emitHostChanged(participantIds, {
        groupCallId: callId,
        newHostUserId: newHostId,
      });
    }
    this.gateway.emitStatus(participantIds, {
      groupCallId: callId,
      invites: refreshed!.invites,
    });
    this.gateway.emitLeft(participantIds, {
      groupCallId: callId,
      userId,
      leftAt: new Date(),
    });

    // Direct ACTIVE termination only when the host themselves left and no
    // JOINED candidate remained to take over. (`endCallIfDeserted` no longer
    // auto-ends ACTIVE — invitee-leave shouldn't kick host out.)
    if (
      isHost &&
      !newHostId &&
      refreshed!.status === GroupCallStatus.ACTIVE
    ) {
      await this.endCall(callId, 'all_left');
      return;
    }

    // Otherwise, only LOBBY can be auto-ended (timeout when everyone declined).
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
    if (call.status !== GroupCallStatus.LOBBY) {
      // ACTIVE auto-end is intentionally NOT handled here:
      // - When the host leaves last → leaveCall calls endCall('all_left') directly.
      // - When an invitee leaves and the host stays alone → the host can wait,
      //   invite more, or /end manually. Auto-ending here would kick the host
      //   out forcibly and clobber endedReason='host_ended' if the host was
      //   about to /end.
      // - Cron cleanup (Task 12) is the safety net for true ACTIVE zombies
      //   (>1min with no JOINED).
      return;
    }
    const anyJoined = call.invites.some(
      (i: any) => i.status === GroupCallInviteStatus.JOINED,
    );
    const anyCalling = call.invites.some(
      (i: any) => i.status === GroupCallInviteStatus.CALLING,
    );

    if (!anyJoined && !anyCalling) {
      // LOBBY exhausted (everyone declined/timed out before anyone joined).
      // Host is alone in an empty lobby — auto-end with 'timeout'.
      await this.endCall(call.id, 'timeout');
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
   * Public wrapper for `endCall`, used by `GroupCallCleanupCron` (Task 12) to
   * force-end zombie LOBBY/ACTIVE rows that have been stale beyond the cleanup
   * thresholds. The underlying `endCall` is already race-safe via its
   * `where: { status: { in: [LOBBY, ACTIVE] } }` filter, so concurrent ends
   * (e.g. last-leaver + cron tick) are harmless.
   */
  async handleZombieEnd(
    callId: string,
    reason: 'all_left' | 'timeout' | 'host_ended',
  ): Promise<void> {
    await this.endCall(callId, reason);
  }

  /**
   * LiveKit webhook callback for `participant_left`. Translates the LiveKit
   * event into a normal `leaveCall` so the GroupCall state machine handles it
   * uniformly (LEFT transition, host transfer, auto-end-deserted, etc.).
   *
   * Swallows 403/404 because: (a) a kicked user's `leaveCall` race-loses to
   * the kick path that already set LEFT (404 on the invite), (b) a stale
   * webhook for an already-ENDED call returns silently (handled inside
   * `leaveCall` itself, but keeping the swallow defensive is cheap), (c) the
   * host has no invite row so 403 fires if the leftBundle is the host who
   * already left. Rethrows other errors so they hit Sentry.
   */
  async handleLivekitParticipantLeft(
    callId: string,
    userId: string,
  ): Promise<void> {
    try {
      await this.leaveCall(callId, userId);
    } catch (e: any) {
      const status = e?.status ?? e?.getStatus?.();
      if (status === 403 || status === 404) return;
      throw e;
    }
  }

  /**
   * Host adds more invitees to an in-progress call.
   *
   * - 404 / 403 / 409 ordering matches the rest of the lifecycle methods.
   *   ENDED is rejected with 409 because there's no recovery path (the
   *   LiveKit room has been deleted by `endCall`); the iOS UI will never
   *   show the "invite more" button for an ENDED call, but a flaky network
   *   could race the user's tap against the ENDED transition.
   * - **Capacity**: counts host (1) + currently-active invites (JOINED OR
   *   CALLING). CALLING counts because pending-ring slots aren't free —
   *   if every still-CALLING invitee accepts after we add new ones, the
   *   room would otherwise overflow. We don't count LEFT/DECLINED/TIMEOUT
   *   since those users have already vacated their slot.
   * - **Deduplication**: any userId already JOINED/CALLING is silently
   *   skipped (idempotent). The host could re-tap an invitee whose ring
   *   is in flight, and we shouldn't double-create an invite row (would
   *   violate the `(groupCallId, userId)` unique constraint anyway). We
   *   also defensively skip the host's own id even though the schema has
   *   no host invite row, mirroring `createCall`'s self-invite guard.
   * - DB write + queue + push + Socket.io fan-out follow the same parallel
   *   `Promise.all` pattern as `createCall` for low latency, and emit a
   *   final `emitStatus` to existing participants so they see the new
   *   invitees appear in their participant grid in CALLING state.
   * - **Note**: this method does NOT use a $transaction around createMany.
   *   Unlike `createCall` (which atomically creates both the GroupCall and
   *   its first invites), here the GroupCall already exists and its state
   *   is unchanged. createMany is a single write — if it fails, no
   *   rollback is needed.
   */
  async inviteMore(callId: string, hostUserId: string, userIds: string[]) {
    const call = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    if (!call) throw new NotFoundException('GroupCall not found');
    if (call.hostUserId !== hostUserId) {
      throw new ForbiddenException('Only host can invite');
    }
    if (call.status === GroupCallStatus.ENDED) {
      throw new ConflictException('Call ended');
    }

    // Skip userIds that already have a JOINED or CALLING invite (no duplicates),
    // and the host's own id (defensive — schema has no host invite row, but
    // a future schema change shouldn't accidentally create one).
    const existingIds = new Set(
      call.invites
        .filter(
          (i: any) =>
            i.status === GroupCallInviteStatus.JOINED ||
            i.status === GroupCallInviteStatus.CALLING,
        )
        .map((i: any) => i.userId),
    );
    const newUserIds = userIds.filter(
      (id) => !existingIds.has(id) && id !== hostUserId,
    );

    // Capacity: occupied = host + JOINED + CALLING. CALLING counts because
    // the pending ring still holds a slot — if all current rings accept
    // after the new ones are added, the room could overflow.
    const occupied =
      1 /* host */ +
      call.invites.filter(
        (i: any) =>
          i.status === GroupCallInviteStatus.JOINED ||
          i.status === GroupCallInviteStatus.CALLING,
      ).length;
    if (occupied + newUserIds.length > MAX_PARTICIPANTS) {
      throw new ConflictException(
        `Capacity exceeded: ${MAX_PARTICIPANTS} max participants`,
      );
    }

    // Nothing to do? Still return a structured response so the controller
    // can give the client a deterministic shape.
    if (newUserIds.length === 0) return { added: 0 };

    await this.prisma.groupCallInvite.createMany({
      data: newUserIds.map((uid) => ({
        groupCallId: callId,
        userId: uid,
        invitedBy: hostUserId,
        status: GroupCallInviteStatus.CALLING,
      })),
    });

    // Refetch only the new invites so we know their auto-generated `id`s
    // (needed for the `timeout-${invite.id}` jobId). createMany doesn't
    // return rows in Prisma.
    const newInvites = await this.prisma.groupCallInvite.findMany({
      where: { groupCallId: callId, userId: { in: newUserIds } },
    });

    // Same Profile-based host payload as createCall — we keep this in sync
    // so iOS clients render the incoming-call sheet identically whether the
    // invite came from the initial createCall or a subsequent inviteMore.
    const profile = await this.prisma.profile.findUnique({
      where: { userId: hostUserId },
      select: { firstName: true, lastName: true, avatarUrl: true },
    });
    const host = {
      id: hostUserId,
      displayName:
        `${profile?.firstName ?? ''} ${profile?.lastName ?? ''}`.trim() ||
        hostUserId,
      avatarUrl: profile?.avatarUrl ?? null,
    };

    await Promise.all(
      newInvites.map(async (inv: any) => {
        await this.queue.add(
          'timeout-invite',
          { inviteId: inv.id },
          { delay: RING_TIMEOUT_SEC * 1000, jobId: `timeout-${inv.id}` },
        );
        this.apns
          .sendGroupCallInvite(inv.userId, {
            groupCallId: callId,
            host,
            inviteeCount: newInvites.length,
            livekitRoomName: call.livekitRoomName,
          })
          .catch((e) =>
            this.logger.warn(
              `APNs push failed for ${inv.userId}: ${e?.message ?? e}`,
            ),
          );
        this.fcm
          .sendGroupCallInvite(inv.userId, {
            groupCallId: callId,
            host,
            inviteeCount: newInvites.length,
          })
          .catch((e) =>
            this.logger.warn(
              `FCM push failed for ${inv.userId}: ${e?.message ?? e}`,
            ),
          );
        this.gateway.emitInvite(inv.userId, {
          groupCallId: callId,
          host,
          invitees: newInvites,
        });
      }),
    );

    // Refetch and broadcast the updated invite list to existing participants
    // (same pattern as joinCall/leaveCall) so their UIs add the new pending
    // tiles to the participant grid.
    const refreshed = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    const participantIds = this.collectParticipantIds(refreshed!);
    this.gateway.emitStatus(participantIds, {
      groupCallId: callId,
      invites: refreshed!.invites,
    });

    return { added: newUserIds.length };
  }

  /**
   * Host forcibly removes an invitee from the call.
   *
   * - 400 / 404 / 403 / idempotent ordering matches the lifecycle convention,
   *   with one wrinkle: `BadRequest` for self-kick is checked BEFORE the DB
   *   round-trip because it's a pure pre-condition — saves a query for an
   *   obviously broken request.
   * - **Authorization vs. existence**: we look up the call, verify host,
   *   then locate the target invite. Missing target → 404 (the host's UI
   *   would only show "kick" for a participant they can see; if the row
   *   is missing the host has stale state).
   * - **Idempotent**: target already LEFT → no-op early return so a flaky
   *   double-tap doesn't try to re-disconnect a phantom LiveKit participant
   *   or re-broadcast.
   * - **LiveKit removeParticipant is best-effort**: the kicked user may have
   *   already disconnected on their own, in which case LK either returns
   *   success or a benign error. We log but don't throw — the DB write
   *   (status=LEFT) is the source of truth, and LK's `departureTimeout`
   *   will reap stragglers.
   * - **Broadcast**: the kicked user gets a single-recipient `emitKicked`
   *   event so their UI can show a "you were removed" sheet (vs. the
   *   self-initiated leave UX). Other participants get the standard
   *   `emitStatus` so their grid drops the kicked user's tile.
   * - Calls `endCallIfDeserted` after to handle the (rare) case where
   *   kicking the last JOINED invitee leaves the host alone in an ACTIVE
   *   call — that should auto-end with `all_left`. (The host itself can't
   *   be kicked, so the host-only-remaining branch is the only path here.)
   */
  async kick(callId: string, hostUserId: string, targetUserId: string) {
    if (hostUserId === targetUserId) {
      throw new BadRequestException('Cannot kick host');
    }

    const call = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    if (!call) throw new NotFoundException('GroupCall not found');
    if (call.hostUserId !== hostUserId) {
      throw new ForbiddenException('Only host can kick');
    }

    const target = call.invites.find((i: any) => i.userId === targetUserId);
    if (!target) throw new NotFoundException('Target not in call');
    if (target.status === GroupCallInviteStatus.LEFT) return; // idempotent

    await this.prisma.groupCallInvite.update({
      where: {
        groupCallId_userId: { groupCallId: callId, userId: targetUserId },
      },
      data: { status: GroupCallInviteStatus.LEFT, leftAt: new Date() },
    });

    // Force LiveKit disconnect (best-effort — target may already be gone).
    await this.voice
      .removeParticipant(call.livekitRoomName, targetUserId)
      .catch((e: any) =>
        this.logger.warn(
          `LiveKit removeParticipant failed: ${e?.message ?? e}`,
        ),
      );

    // Single-recipient kicked event so the kicked client can show
    // a distinguishable "you were removed" sheet vs. the self-leave UX;
    // status broadcast updates everyone else's grid.
    this.gateway.emitKicked(targetUserId, {
      groupCallId: callId,
      by: hostUserId,
    });

    const refreshed = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    const participantIds = this.collectParticipantIds(refreshed!);
    this.gateway.emitStatus(participantIds, {
      groupCallId: callId,
      invites: refreshed!.invites,
    });

    // If kicking the last JOINED invitee leaves the host alone, auto-end
    // with `all_left`. Same desertion logic as decline/leave.
    await this.endCallIfDeserted(refreshed!);
  }

  /**
   * Host requests all JOINED participants to mute themselves.
   *
   * - **Peer-equal philosophy**: the host doesn't actually mute peers via
   *   LiveKit's `updateParticipant` track-publication API — we send a soft
   *   request via Socket.io and let each client's UI decide whether to
   *   comply. This keeps the host from being able to silently censor a
   *   participant (e.g., a hostile host muting a whistleblower mid-call)
   *   and surfaces the action as a notification on the muted client.
   * - **Rate limit**: 1 per 10s per call, enforced via Redis SET NX EX.
   *   Prevents a runaway host (or buggy client) from spamming the entire
   *   room with mute prompts. Returns 429 (TooManyRequests) on hit.
   * - **Audience**: only JOINED participants except the host. CALLING users
   *   aren't yet in the LiveKit room and have no media to mute, so sending
   *   them a mute request is meaningless and would just churn their UI.
   * - We explicitly do NOT pre-validate that there are any JOINED targets:
   *   a host muting an empty room is a no-op (the gateway emits to []),
   *   not an error. This lets the host pre-mute before everyone joins.
   */
  async muteAll(callId: string, hostUserId: string) {
    const call = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      include: { invites: true },
    });
    if (!call) throw new NotFoundException('GroupCall not found');
    if (call.hostUserId !== hostUserId) {
      throw new ForbiddenException('Only host can mute-all');
    }

    // Rate limit: 1 per 10s per call. Redis SET NX returns 'OK' if the key
    // was set, null if it already existed. The TTL self-cleans the key so
    // we don't need a sweeper. Per-call (not per-host) so a transferred
    // host can't immediately re-mute on top of the previous host's burst.
    const allowed = await this.redis
      .getClient()
      .set(`groupcall:mute-all:${callId}`, '1', 'EX', 10, 'NX');
    if (allowed !== 'OK') {
      throw new HttpException(
        'Rate limited: 1 mute-all per 10s',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // Soft-mute request to JOINED only (excluding host). CALLING users have
    // no media to mute yet — sending to them is noise.
    const targetIds = call.invites
      .filter(
        (i: any) =>
          i.status === GroupCallInviteStatus.JOINED && i.userId !== hostUserId,
      )
      .map((i: any) => i.userId);

    this.gateway.emitMuteRequest(targetIds, {
      groupCallId: callId,
      by: hostUserId,
    });
  }

  /**
   * Host explicitly ends the call for everyone.
   *
   * - 404 / 403 / idempotent ordering matches the rest of the lifecycle.
   * - Already-ENDED → silent no-op (idempotent), so a flaky double-tap on
   *   "End for all" doesn't error after the first click already won the
   *   ENDED transition.
   * - Delegates to the private `endCall` helper with reason `host_ended`,
   *   which atomically transitions ENDED, broadcasts `groupCallEnded` to
   *   the FULL invitee audience (DECLINED/LEFT/TIMEOUT included — see
   *   `endCall` doc on why narrowing strands stale incoming-call sheets),
   *   and best-effort deletes the LiveKit room.
   */
  async forceEnd(callId: string, hostUserId: string) {
    const call = await this.prisma.groupCall.findUnique({
      where: { id: callId },
    });
    if (!call) throw new NotFoundException('GroupCall not found');
    if (call.hostUserId !== hostUserId) {
      throw new ForbiddenException('Only host can end call');
    }
    if (call.status === GroupCallStatus.ENDED) return; // idempotent

    await this.endCall(callId, 'host_ended');
  }

  /**
   * Called by BullMQ when a `timeout-invite` job fires (30s after createCall/inviteMore).
   *
   * Idempotent: if the invite is no longer CALLING (JOINED/DECLINED/LEFT/TIMEOUT
   * already), this is a no-op. The job may have raced with a join/decline that
   * already cancelled it, or the job may have run twice via BullMQ retry — either
   * case is harmless.
   *
   * If the timeout was the last pending ring on a LOBBY call (no JOINED, no
   * remaining CALLING), `endCallIfDeserted` ends the call with reason `timeout`.
   */
  async handleInviteTimeout(inviteId: string): Promise<void> {
    const invite = await this.prisma.groupCallInvite.findUnique({
      where: { id: inviteId },
    });
    if (!invite) return;
    if (invite.status !== GroupCallInviteStatus.CALLING) return;

    await this.prisma.groupCallInvite.update({
      where: { id: inviteId },
      data: {
        status: GroupCallInviteStatus.TIMEOUT,
        respondedAt: new Date(),
      },
    });

    const refreshed = await this.prisma.groupCall.findUnique({
      where: { id: invite.groupCallId },
      include: { invites: true },
    });
    if (!refreshed) return;

    const participantIds = this.collectParticipantIds(refreshed);
    this.gateway.emitStatus(participantIds, {
      groupCallId: refreshed.id,
      invites: refreshed.invites,
    });

    await this.endCallIfDeserted(refreshed);
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
