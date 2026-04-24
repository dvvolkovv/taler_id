import {
  Inject,
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
  forwardRef,
} from '@nestjs/common';
import { AgentDispatchClient, RoomServiceClient } from 'livekit-server-sdk';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { GatingService } from '../billing/services/gating.service';
import { MeteringService } from '../billing/services/metering.service';
import { FEATURE_KEYS } from '../billing/constants/feature-keys';
import { InsufficientFundsException } from '../billing/exceptions/insufficient-funds.exception';
import { FeatureDisabledException } from '../billing/exceptions/feature-disabled.exception';

const LK_HOST = process.env.LIVEKIT_HOST || 'http://localhost:7880';
const LK_API_KEY = process.env.LIVEKIT_API_KEY || 'lkdevkey';
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || 'lkSecret2024TalerID';

// Name of the registered livekit-agents worker (see ~/ai-twin-agent/agent.py).
const AI_TWIN_AGENT_NAME = 'ai-twin-agent';

// Redis sorted set containing `<roomName>|<callerId>|<calleeId>` members scored
// by the unix-ms deadline at which the AI twin should offer to take the call.
const TIMER_ZSET_KEY = 'ai_twin:pending';

// Redis hash keyed by roomName storing per-call params (prompt, voiceId,
// callee/caller names). We need those when firing the offer / dispatch.
const TIMER_META_PREFIX = 'ai_twin:meta:';

// How often the poller wakes up to inspect the zset. Tight enough to give the
// user a snappy experience, loose enough to keep Redis traffic low.
const POLL_INTERVAL_MS = 1000;

type PendingPayload = {
  roomName: string;
  callerId: string;
  calleeId: string;
  conversationId?: string;
  prompt: string;
  voiceId: string;
  calleeName: string;
  callerName: string;
  timeoutSeconds: number;
};

/**
 * Encapsulates the AI voice twin fallback flow:
 *
 *   call_invite ──► schedulePending() ──► Redis zset
 *                                          │
 *                                          ▼ (poller every 1s)
 *                                  timeout reached?
 *                                          │
 *                                          ▼
 *   caller gets `call_ai_twin_offer` via Socket.io
 *                                          │
 *                                          ▼
 *   caller clicks "Yes" ──► `call_ai_twin_accepted`
 *                                          │
 *                                          ▼
 *                              dispatchAgent(roomName)
 *                                          │
 *                                          ▼
 *            LiveKit sends the job to the registered ai-twin worker
 *
 * The Socket.io emit itself lives in MessengerGateway because the Gateway owns
 * the Server instance. AiTwinService tells the Gateway *what* to emit via a
 * callback registered at startup.
 */
@Injectable()
export class AiTwinService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AiTwinService.name);
  private readonly dispatcher = new AgentDispatchClient(
    LK_HOST,
    LK_API_KEY,
    LK_API_SECRET,
  );
  private readonly rooms = new RoomServiceClient(
    LK_HOST,
    LK_API_KEY,
    LK_API_SECRET,
  );
  private pollTimer: NodeJS.Timeout | null = null;

  // Set by MessengerGateway during its onModuleInit so we can push events back
  // to the correct socket room. Kept as a callback to avoid a circular import
  // (Gateway already imports this service).
  private emitOffer: (
    calleeUserIdOfCaller: string,
    payload: {
      roomName: string;
      calleeId: string;
      calleeName: string;
      timeoutSeconds: number;
    },
  ) => void = () => {};

  private emitJoined: (
    targetUserId: string,
    payload: { roomName: string; calleeId: string },
  ) => void = () => {};

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    // forwardRef mirrors the cycle declared in MessengerModule — BillingModule
    // depends on MessengerModule for MESSENGER_GATEWAY, and AiTwinService
    // now depends back on BillingModule for gating/metering.
    @Inject(forwardRef(() => GatingService))
    private readonly gating: GatingService,
    @Inject(forwardRef(() => MeteringService))
    private readonly metering: MeteringService,
  ) {}

  registerEmitters(
    emitOffer: typeof this.emitOffer,
    emitJoined: typeof this.emitJoined,
  ) {
    this.emitOffer = emitOffer;
    this.emitJoined = emitJoined;
  }

  async onModuleInit() {
    this.pollTimer = setInterval(
      () => this.tick().catch((e) => this.logger.error('tick error', e)),
      POLL_INTERVAL_MS,
    );
    this.logger.log(`AiTwinService started (poll ${POLL_INTERVAL_MS}ms)`);
  }

  async onModuleDestroy() {
    if (this.pollTimer) clearInterval(this.pollTimer);
  }

  // ── Scheduling ────────────────────────────────────────────────────────

  /**
   * Called from `call_invite` handler for every (caller → callee) pair where
   * the callee has `aiTwinEnabled = true`. Records the deadline in Redis.
   */
  async schedulePending(input: PendingPayload): Promise<void> {
    const deadline = Date.now() + input.timeoutSeconds * 1000;
    const member = this.memberKey(input.roomName, input.callerId, input.calleeId);
    const meta = JSON.stringify(input);

    const client = this.redis.getClient();
    await client.zadd(TIMER_ZSET_KEY, deadline, member);
    // Meta lives long enough to outlive the deadline even if the poller is slow.
    await client.setex(
      TIMER_META_PREFIX + member,
      input.timeoutSeconds + 60,
      meta,
    );

    this.logger.log(
      `[schedulePending] room=${input.roomName} callee=${input.calleeId} deadline=+${input.timeoutSeconds}s`,
    );
  }

  /**
   * Called when the callee actually joined the room (`call_answered`) or when
   * the call ended (`call_ended`). Removes any pending timer for that call.
   */
  async cancelPending(roomName: string): Promise<void> {
    const client = this.redis.getClient();
    // We don't know caller/callee from the room alone, so scan the zset for
    // members starting with the room prefix. The set is small so this is fine.
    const prefix = roomName + '|';
    const members: string[] = await client.zrange(TIMER_ZSET_KEY, 0, -1);
    const toRemove = members.filter((m) => m.startsWith(prefix));
    if (toRemove.length) {
      await client.zrem(TIMER_ZSET_KEY, ...toRemove);
      for (const m of toRemove) {
        await client.del(TIMER_META_PREFIX + m);
      }
      this.logger.log(
        `[cancelPending] room=${roomName} removed=${toRemove.length}`,
      );
    }
  }

  // ── Polling ───────────────────────────────────────────────────────────

  private async tick(): Promise<void> {
    const now = Date.now();
    const client = this.redis.getClient();
    const expired: string[] = await client.zrangebyscore(
      TIMER_ZSET_KEY,
      '-inf',
      String(now),
    );
    if (!expired.length) return;

    for (const member of expired) {
      // Always remove first so a slow handler never double-fires.
      await client.zrem(TIMER_ZSET_KEY, member);

      const raw = await client.get(TIMER_META_PREFIX + member);
      await client.del(TIMER_META_PREFIX + member);
      if (!raw) continue;

      let payload: PendingPayload;
      try {
        payload = JSON.parse(raw);
      } catch {
        continue;
      }

      // Double-check the call is still active and the callee hasn't joined.
      const stillValid = await this.isCallStillPending(payload);
      if (!stillValid) {
        this.logger.log(
          `[tick] skip room=${payload.roomName} — no longer pending`,
        );
        continue;
      }

      this.logger.log(
        `[tick] offer AI twin for room=${payload.roomName} to caller=${payload.callerId}`,
      );
      this.emitOffer(payload.callerId, {
        roomName: payload.roomName,
        calleeId: payload.calleeId,
        calleeName: payload.calleeName,
        timeoutSeconds: payload.timeoutSeconds,
      });

      // The meta hash stays gone after del(). We need the prompt/voice for the
      // subsequent `acceptOffer` call, so stash a lightweight copy under a
      // different key with a generous TTL. The caller has a few minutes to
      // decide whether to say yes.
      await client.setex(
        `ai_twin:offered:${payload.roomName}`,
        300,
        JSON.stringify(payload),
      );
    }
  }

  private async isCallStillPending(p: PendingPayload): Promise<boolean> {
    // Caller must still be in the room.
    try {
      const participants = await this.rooms.listParticipants(p.roomName);
      const callerIn = participants.some((pt) => pt.identity === p.callerId);
      const calleeIn = participants.some((pt) => pt.identity === p.calleeId);
      if (!callerIn) return false;
      if (calleeIn) return false;
    } catch (e) {
      this.logger.warn(
        `[isCallStillPending] listParticipants failed: ${(e as Error).message}`,
      );
      // If LiveKit is flaky, fall back to CallLog truth.
    }
    try {
      const log = await this.prisma.callLog.findUnique({
        where: { roomName: p.roomName },
      });
      if (!log) return false;
      if (log.endedAt) return false;
      if (log.answeredAt) return false;
    } catch (_) {
      return false;
    }
    return true;
  }

  // ── Accept offer (called from Socket.io `call_ai_twin_accepted`) ──────

  /**
   * Dispatches the livekit-agents worker to the room and notifies the caller
   * that the agent is joining.
   */
  async acceptOffer(
    roomName: string,
    callerId: string,
  ): Promise<{ ok: boolean; reason?: string }> {
    const client = this.redis.getClient();
    const raw = await client.get(`ai_twin:offered:${roomName}`);
    if (!raw) {
      return { ok: false, reason: 'offer_expired' };
    }
    let payload: PendingPayload;
    try {
      payload = JSON.parse(raw);
    } catch {
      return { ok: false, reason: 'bad_payload' };
    }
    if (payload.callerId !== callerId) {
      return { ok: false, reason: 'not_caller' };
    }

    // Mark the call log so the call history shows who got AI-answered.
    try {
      await this.prisma.callLog.update({
        where: { roomName },
        data: { withAi: true, answeredAt: new Date() },
      });
    } catch (_) {}

    // Billing gate (Task 14): the twin owner (callee) pays — NOT the caller.
    // If the owner has no funds / has disabled the feature, we skip dispatch and
    // return 'unavailable'. The caller UI then falls back to the normal
    // "no twin" behaviour (keep ringing the human).
    let billingSessionId: string | null = null;
    try {
      const session = await this.gating.startSession(
        payload.calleeId,
        FEATURE_KEYS.AI_TWIN,
        roomName,
      );
      billingSessionId = session.id;
    } catch (err) {
      if (
        err instanceof InsufficientFundsException ||
        err instanceof FeatureDisabledException
      ) {
        this.logger.warn(
          `[acceptOffer] ai-twin not dispatched for callee=${payload.calleeId}: ${err.message}`,
        );
        // Drop the stash so we don't keep re-offering a twin that can't pay.
        await client.del(`ai_twin:offered:${roomName}`);
        return { ok: false, reason: 'unavailable' };
      }
      this.logger.error('[acceptOffer] gating.startSession failed', err);
      return { ok: false, reason: 'gating_failed' };
    }

    const metadata = JSON.stringify({
      voiceId: payload.voiceId,
      prompt: payload.prompt,
      calleeName: payload.calleeName,
      callerName: payload.callerName,
      calleeUserId: payload.calleeId,
      callerUserId: payload.callerId,
      billingSessionId,
    });

    try {
      await this.dispatcher.createDispatch(roomName, AI_TWIN_AGENT_NAME, {
        metadata,
      });
      this.logger.log(
        `[acceptOffer] dispatched ${AI_TWIN_AGENT_NAME} to room=${roomName} billingSession=${billingSessionId}`,
      );
    } catch (e) {
      this.logger.error('[acceptOffer] dispatch failed', e);
      // Clean up the billing session we just opened — otherwise the cron would
      // keep draining the owner's wallet for a call that never happened.
      await this.gating.endSession(billingSessionId, 'failed').catch(() => {});
      return { ok: false, reason: 'dispatch_failed' };
    }

    // Tell the caller UI to swap the header to "Name (AI twin)".
    this.emitJoined(payload.callerId, {
      roomName,
      calleeId: payload.calleeId,
    });

    // NOTE: we deliberately do NOT dismiss the callee's ringing banner.
    // The human owner should always be able to grab the call from their
    // AI twin by tapping "Answer" — handleCallAnswered on the backend
    // will call takeoverCall() to kick the agent out and let the human
    // take over. Suppressing the banner would remove that escape hatch.

    // Clean up the stash so duplicate clicks can't re-dispatch.
    await client.del(`ai_twin:offered:${roomName}`);

    return { ok: true };
  }

  /** Called when caller dismisses the offer ("Wait for human answer"). */
  async declineOffer(roomName: string): Promise<void> {
    await this.redis.getClient().del(`ai_twin:offered:${roomName}`);
  }

  /**
   * Called when the human callee (or anyone else) joins a room that already
   * has an AI twin agent in it. The agent should step aside — the human is
   * back. Finds any participant whose identity starts with "agent-" and kicks
   * them out of the room.
   */
  async takeoverCall(roomName: string): Promise<boolean> {
    try {
      const participants = await this.rooms.listParticipants(roomName);
      const agents = participants.filter(
        (p) => p.identity && p.identity.startsWith('agent-'),
      );
      if (agents.length === 0) return false;
      for (const agent of agents) {
        this.logger.log(
          `[takeoverCall] removing agent ${agent.identity} from room=${roomName}`,
        );
        await this.rooms.removeParticipant(roomName, agent.identity);
      }
      // Mark CallLog — the call transitioned from AI-answered to human-answered.
      try {
        await this.prisma.callLog.update({
          where: { roomName },
          data: { withAi: false },
        });
      } catch (_) {}

      // Close the billing session so the cron stops draining the owner's wallet.
      // The agent's callback would eventually reportUsage + endSession anyway,
      // but that can arrive seconds later — we want to stop the bleeding now.
      // We DO NOT reportUsage here because the agent still owns the authoritative
      // duration number; it'll send the final adjustment in its callback.
      try {
        const session = await this.prisma.aiSession.findFirst({
          where: {
            contextRef: roomName,
            featureKey: FEATURE_KEYS.AI_TWIN,
            status: 'active',
          },
          select: { id: true },
        });
        if (session) {
          await this.gating
            .endSession(session.id, 'completed')
            .catch(() => {});
        }
      } catch (e) {
        this.logger.warn(
          `[takeoverCall] endSession lookup failed for room=${roomName}: ${(e as Error).message}`,
        );
      }
      return true;
    } catch (e) {
      this.logger.warn(
        `[takeoverCall] failed for room=${roomName}: ${(e as Error).message}`,
      );
      return false;
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────

  private memberKey(roomName: string, callerId: string, calleeId: string) {
    return `${roomName}|${callerId}|${calleeId}`;
  }
}
