import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  GoneException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { InterpreterEndReason, InterpreterSession } from '@prisma/client';
import { randomUUID } from 'crypto';
import { FEATURE_KEYS } from '../billing/constants/feature-keys';
import { FeatureDisabledException } from '../billing/exceptions/feature-disabled.exception';
import { InsufficientFundsException } from '../billing/exceptions/insufficient-funds.exception';
import {
  GatingService,
  type SessionTerminationReason,
} from '../billing/services/gating.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { cosine } from '../voice-gate/cosine';
import type { AgentEndReason } from './dto/agent-ended.dto';
import { InterpreterAgentClient } from './interpreter-agent.client';
import {
  CODE_TTL_MS,
  generateCode,
  hashCode,
  normalizeCode,
} from './interpreter-code';
import {
  type EngineKind,
  INTERPRETER_LANGUAGES,
  engineFor,
  isSupportedLang,
} from './interpreter-languages';
import { InterpreterLivekitService } from './interpreter-livekit.service';
import { SAME_PRINT_COSINE, hasUsableVoicePrint } from './voice-print';

/** The JWT payload fields this module reads. */
export interface InterpreterUser {
  sub: string;
  session_id?: string;
}

export interface Directions {
  /** How the partner's speech reaches me. */
  toMe: EngineKind;
  /** How my speech reaches the partner. */
  fromMe: EngineKind;
}

export interface Partner {
  firstName: string | null;
  avatarUrl: string | null;
  lang: string;
}

/** What close() needs to clean up after a session. */
export type ClosableSession = Pick<
  InterpreterSession,
  'id' | 'roomName' | 'startedAt' | 'billingSessionId'
>;

const CLOSABLE = {
  id: true,
  roomName: true,
  startedAt: true,
  billingSessionId: true,
} as const;

// Enough for typos and rescans; with 40-bit codes living 5 minutes, nowhere
// near enough to guess one.
const JOIN_ATTEMPTS_PER_MINUTE = 10;

/** How an ending closes the host's billing; null where metering already closed it. */
const BILLING_END: Record<
  InterpreterEndReason,
  SessionTerminationReason | null
> = {
  HANGUP: 'completed',
  PARTNER_LEFT: 'completed',
  EXPIRED: 'completed',
  TRANSLATION_FAILED: 'failed',
  AGENT_LOST: 'failed',
  NO_FUNDS: null,
  MAX_DURATION: null,
};

const AGENT_END: Record<AgentEndReason, InterpreterEndReason> = {
  partner_left: 'PARTNER_LEFT',
  agent_lost: 'AGENT_LOST',
  translation_failed: 'TRANSLATION_FAILED',
};

/**
 * Face-to-face interpreter sessions: the host shows a QR, the guest scans it,
 * the agent translates each one's speech for the other. See
 * docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md.
 *
 * Voice prints go to the agent and nowhere else: not into responses, errors
 * or logs. Codes are stored as hashes only.
 */
@Injectable()
export class InterpreterService {
  private readonly log = new Logger(InterpreterService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly gating: GatingService,
    private readonly redis: RedisService,
    private readonly agent: InterpreterAgentClient,
    private readonly livekit: InterpreterLivekitService,
  ) {}

  languages(): {
    enabled: boolean;
    languages: ReadonlyArray<{ code: string; name: string }>;
  } {
    return { enabled: isEnabled(), languages: INTERPRETER_LANGUAGES };
  }

  /** The host's side: a waiting session, its room and a code for the QR. */
  async create(
    user: InterpreterUser,
    lang: string,
  ): Promise<{
    sessionId: string;
    code: string;
    expiresAt: Date;
    roomName: string;
    token: string;
    livekitWsUrl: string;
  }> {
    this.assertEnabled();
    if (!isSupportedLang(lang)) {
      throw new BadRequestException('unsupported_language');
    }
    const profile = await this.voiceProfile(user.sub);
    if (!profile || !hasUsableVoicePrint(profile.ownerEmbedding)) {
      throw new ConflictException('voice_print_required');
    }
    await this.assertNotInConversation(user.sub);
    // Refused here rather than when the guest is already scanning the code.
    // Billing itself opens only on join: waiting on the QR screen is free.
    await withBillingCodes(
      () => this.gating.assertCanStart(user.sub, FEATURE_KEYS.INTERPRETER),
      'insufficient_funds',
      'feature_disabled',
    );

    // Starting over replaces the QR on screen; the old one must stop working.
    await this.closeWaiting(user.sub);

    const roomName = `interp-${randomUUID()}`;
    try {
      await this.livekit.createRoom(roomName);
    } catch (e) {
      this.log.warn(`creating room ${roomName} failed: ${String(e)}`);
      throw new ServiceUnavailableException('interpreter_unavailable');
    }
    const code = generateCode();
    const expiresAt = new Date(Date.now() + CODE_TTL_MS);
    const session = await this.prisma.interpreterSession.create({
      data: {
        roomName,
        hostId: user.sub,
        hostLang: lang,
        codeHash: hashCode(code),
        codeExpiresAt: expiresAt,
      },
      select: { id: true },
    });
    const token = await this.livekit.issueToken({
      roomName,
      userId: user.sub,
      loginSessionId: user.session_id,
      lang,
      name: profile.firstName ?? undefined,
    });
    this.log.log(`session ${session.id} waiting in ${roomName} (${lang})`);
    return {
      sessionId: session.id,
      code,
      expiresAt,
      roomName,
      token,
      livekitWsUrl: this.livekit.wsUrl,
    };
  }

  /** A fresh code for the host's QR; the previous one stops working. */
  async newCode(
    userId: string,
    sessionId: string,
  ): Promise<{ code: string; expiresAt: Date }> {
    this.assertEnabled();
    const session = await this.prisma.interpreterSession.findUnique({
      where: { id: sessionId },
      select: { hostId: true, status: true },
    });
    if (!session || session.hostId !== userId) {
      throw new NotFoundException('session_not_found');
    }
    if (session.status !== 'WAITING') {
      throw new ConflictException('not_waiting');
    }
    const code = generateCode();
    const expiresAt = new Date(Date.now() + CODE_TTL_MS);
    // Conditional: a guest who joined in the meantime made it ACTIVE.
    const { count } = await this.prisma.interpreterSession.updateMany({
      where: { id: sessionId, status: 'WAITING' },
      data: { codeHash: hashCode(code), codeExpiresAt: expiresAt },
    });
    if (count === 0) throw new ConflictException('not_waiting');
    return { code, expiresAt };
  }

  /** The guest's side: opens the host's billing, claims the code, starts the agent. */
  async join(
    user: InterpreterUser,
    rawCode: string,
    lang: string,
  ): Promise<{
    sessionId: string;
    roomName: string;
    token: string;
    livekitWsUrl: string;
    partner: Partner;
    directions: Directions;
  }> {
    this.assertEnabled();
    await this.limitJoinAttempts(user.sub);
    const code = normalizeCode(rawCode);
    if (!code) throw new NotFoundException('code_not_found');
    const session = await this.prisma.interpreterSession.findUnique({
      where: { codeHash: hashCode(code) },
    });
    if (!session || session.status !== 'WAITING') {
      throw new NotFoundException('code_not_found');
    }
    if (
      !session.codeExpiresAt ||
      session.codeExpiresAt.getTime() <= Date.now()
    ) {
      throw new GoneException('code_expired');
    }
    if (session.hostId === user.sub) throw new ConflictException('own_code');
    if (!isSupportedLang(lang)) {
      throw new BadRequestException('unsupported_language');
    }
    if (lang === session.hostLang) {
      throw new BadRequestException('same_language');
    }
    const guest = await this.voiceProfile(user.sub);
    if (!guest || !hasUsableVoicePrint(guest.ownerEmbedding)) {
      throw new ConflictException('voice_print_required');
    }
    await this.assertNotInConversation(user.sub);
    // The agent refuses a pair without two usable prints, and by then billing is open.
    const host = await this.voiceProfile(session.hostId);
    if (!host || !hasUsableVoicePrint(host.ownerEmbedding)) {
      throw new ConflictException('host_voice_print_required');
    }
    // The agent refuses this pair too (same cosine, same threshold), but only
    // after step 1 below has opened the host's billing.
    if (
      cosine(host.ownerEmbedding, guest.ownerEmbedding) >= SAME_PRINT_COSINE
    ) {
      throw new ConflictException('same_voice_print');
    }
    // Minted up front: once billing is open, only the agent may still fail.
    const token = await this.livekit.issueToken({
      roomName: session.roomName,
      userId: user.sub,
      loginSessionId: user.session_id,
      lang,
      name: guest.firstName ?? undefined,
    });

    // 1. The host pays from the moment the guest is in. Refused, the session
    //    stays as it was and the code keeps working.
    const billing = await withBillingCodes(
      () =>
        this.gating.startSession(
          session.hostId,
          FEATURE_KEYS.INTERPRETER,
          session.id,
        ),
      'host_insufficient_funds',
      'host_feature_disabled',
    );

    // 2. Claim the code. Conditional, so of two guests scanning one code only
    //    one gets in, and a code the host replaced meanwhile no longer works.
    const now = new Date();
    let claimed = false;
    try {
      const { count } = await this.prisma.interpreterSession.updateMany({
        where: {
          id: session.id,
          status: 'WAITING',
          codeHash: session.codeHash,
        },
        data: {
          guestId: user.sub,
          guestLang: lang,
          billingSessionId: billing.id,
          status: 'ACTIVE',
          startedAt: now,
          // The agent is not in the room yet; this starts its 60 s to get there.
          agentSeenAt: now,
          codeHash: null,
          codeExpiresAt: null,
        },
      });
      claimed = count === 1;
    } finally {
      // Billing from step 1 must not outlive a claim that failed or threw.
      if (!claimed) {
        await this.attempt(`session ${session.id}: closing billing`, () =>
          this.gating.endSession(billing.id, 'failed'),
        );
      }
    }
    if (!claimed) throw new ConflictException('code_used');
    await this.closeWaiting(user.sub);

    // 3. Start the agent.
    try {
      await this.agent.start({
        sessionId: session.id,
        roomName: session.roomName,
        participants: [
          {
            userId: session.hostId,
            lang: session.hostLang,
            embedding: host.ownerEmbedding,
          },
          { userId: user.sub, lang, embedding: guest.ownerEmbedding },
        ],
      });
    } catch (e) {
      this.log.warn(`session ${session.id}: agent did not start: ${String(e)}`);
      await this.attempt(`session ${session.id}: closing`, () =>
        this.close(
          { ...session, billingSessionId: billing.id, startedAt: now },
          'TRANSLATION_FAILED',
          { stopAgent: true },
        ),
      );
      throw new ServiceUnavailableException('interpreter_unavailable');
    }

    this.log.log(`session ${session.id} active: ${session.hostLang}↔${lang}`);
    return {
      sessionId: session.id,
      roomName: session.roomName,
      token,
      livekitWsUrl: this.livekit.wsUrl,
      partner: {
        firstName: host.firstName,
        avatarUrl: host.avatarUrl,
        lang: session.hostLang,
      },
      directions: {
        toMe: engineFor(session.hostLang, lang),
        fromMe: engineFor(lang, session.hostLang),
      },
    };
  }

  /**
   * A participant's view of the session. The host learns about the guest from
   * LiveKit; this is the fallback, and the only source of why it ended. Not
   * behind the switch: turned off mid-conversation, it must still say why.
   */
  async get(
    userId: string,
    sessionId: string,
  ): Promise<{
    status: string;
    endReason: string | null;
    partner: Partner | null;
    directions: Directions | null;
    startedAt: Date | null;
  }> {
    const s = await this.participantSession(userId, sessionId);
    const status = s.status.toLowerCase();
    const endReason = s.endReason?.toLowerCase() ?? null;
    if (!s.guestId || !s.guestLang) {
      return {
        status,
        endReason,
        partner: null,
        directions: null,
        startedAt: s.startedAt,
      };
    }
    const iAmHost = s.hostId === userId;
    const myLang = iAmHost ? s.hostLang : s.guestLang;
    const partnerLang = iAmHost ? s.guestLang : s.hostLang;
    const profile = await this.prisma.profile.findUnique({
      where: { userId: iAmHost ? s.guestId : s.hostId },
      select: { firstName: true, avatarUrl: true },
    });
    return {
      status,
      endReason,
      partner: {
        firstName: profile?.firstName ?? null,
        avatarUrl: profile?.avatarUrl ?? null,
        lang: partnerLang,
      },
      directions: {
        toMe: engineFor(partnerLang, myLang),
        fromMe: engineFor(myLang, partnerLang),
      },
      startedAt: s.startedAt,
    };
  }

  /**
   * Either participant hangs up; repeating it changes nothing. Not behind the
   * switch: turning the feature off must not keep running sessions billing.
   */
  async end(userId: string, sessionId: string): Promise<{ status: 'ended' }> {
    const s = await this.participantSession(userId, sessionId);
    await this.close(s, 'HANGUP', { stopAgent: true });
    return { status: 'ended' };
  }

  /**
   * The agent stopped by itself. It retries after a network error or a 5xx,
   * so an unknown or already ended session is still answered ok. Not behind
   * the switch, for the same reason as end().
   */
  async agentEnded(
    sessionId: string,
    reason: AgentEndReason,
  ): Promise<{ ok: true }> {
    const s = await this.prisma.interpreterSession.findUnique({
      where: { id: sessionId },
      select: CLOSABLE,
    });
    // The agent is already gone: nothing to stop.
    if (s) await this.close(s, AGENT_END[reason], { stopAgent: false });
    return { ok: true };
  }

  /**
   * The agent's selftest: both engines' OpenAI sessions. Not behind the
   * switch: the post-deploy smoke runs it on TEST and PROD while it is off.
   */
  async selftest(): Promise<{ status: number; body: unknown }> {
    return this.agent.selftest();
  }

  /**
   * Ends a session. Only the call that moves it to ENDED cleans up, so a
   * hang-up racing the agent's report or the reconciler cleans up once. Each
   * cleanup step runs even when the one before it failed.
   *
   * @param opts.stopAgent false when the agent itself reported the end.
   */
  async close(
    session: ClosableSession,
    reason: InterpreterEndReason,
    opts: { stopAgent: boolean },
  ): Promise<void> {
    const { count } = await this.prisma.interpreterSession.updateMany({
      where: { id: session.id, status: { not: 'ENDED' } },
      data: {
        status: 'ENDED',
        endReason: reason,
        endedAt: new Date(),
        codeHash: null,
      },
    });
    if (count === 0) return;
    this.log.log(`session ${session.id} ended: ${reason}`);

    const ended = await this.asEnded(session);
    // startedAt is set only by the join that made the session ACTIVE.
    if (opts.stopAgent && ended.startedAt) {
      await this.attempt(`session ${ended.id}: stopping the agent`, () =>
        this.agent.stop(ended.roomName),
      );
    }
    const billingId = ended.billingSessionId;
    const billingEnd = BILLING_END[reason];
    if (billingId && billingEnd) {
      await this.attempt(`session ${ended.id}: closing billing`, () =>
        this.endBillingIfActive(billingId, billingEnd),
      );
    }
    await this.attempt(`session ${ended.id}: deleting the room`, () =>
      this.livekit.deleteRoom(ended.roomName),
    );
  }

  /**
   * The session as it ended, read after the transition. The caller's copy can
   * be stale: read while WAITING, it misses a guest who joined just before the
   * close landed — and that join opened billing.
   */
  private async asEnded(session: ClosableSession): Promise<ClosableSession> {
    try {
      const row = await this.prisma.interpreterSession.findUnique({
        where: { id: session.id },
        select: CLOSABLE,
      });
      return row ?? session;
    } catch (e) {
      this.log.warn(
        `session ${session.id}: re-reading it failed, cleaning up from the caller's copy: ${String(e)}`,
      );
      return session;
    }
  }

  /** Metering may have closed it already; endSession would overwrite that status. */
  private async endBillingIfActive(
    billingSessionId: string,
    reason: SessionTerminationReason,
  ): Promise<void> {
    const billing = await this.prisma.aiSession.findUnique({
      where: { id: billingSessionId },
      select: { status: true },
    });
    if (billing?.status === 'active') {
      await this.gating.endSession(billingSessionId, reason);
    }
  }

  /** Ends the QR sessions a person was showing. Never throws: it is cleanup. */
  private async closeWaiting(userId: string): Promise<void> {
    await this.attempt(`closing waiting sessions of ${userId}`, async () => {
      const waiting = await this.prisma.interpreterSession.findMany({
        where: { hostId: userId, status: 'WAITING' },
        select: CLOSABLE,
      });
      // stopAgent only matters if a guest joined one of them just now.
      for (const s of waiting) {
        await this.close(s, 'HANGUP', { stopAgent: true });
      }
    });
  }

  /** Runs one cleanup step; a failure is logged and the caller goes on. */
  private async attempt(
    what: string,
    step: () => Promise<unknown>,
  ): Promise<void> {
    try {
      await step();
    } catch (e) {
      this.log.error(`${what} failed: ${String(e)}`);
    }
  }

  private async participantSession(
    userId: string,
    sessionId: string,
  ): Promise<InterpreterSession> {
    const s = await this.prisma.interpreterSession.findUnique({
      where: { id: sessionId },
    });
    if (!s || (s.hostId !== userId && s.guestId !== userId)) {
      throw new NotFoundException('session_not_found');
    }
    return s;
  }

  /** One conversation at a time. A waiting QR does not count: it gets replaced. */
  private async assertNotInConversation(userId: string): Promise<void> {
    const active = await this.prisma.interpreterSession.findFirst({
      where: {
        status: 'ACTIVE',
        OR: [{ hostId: userId }, { guestId: userId }],
      },
      select: { id: true },
    });
    if (active) throw new ConflictException('already_in_session');
  }

  private voiceProfile(userId: string) {
    return this.prisma.profile.findUnique({
      where: { userId },
      select: { firstName: true, avatarUrl: true, ownerEmbedding: true },
    });
  }

  /** Per person, not per IP: @Throttle runs before the JWT is read. */
  private async limitJoinAttempts(userId: string): Promise<void> {
    const key = `interp:join:${userId}`;
    const attempts = await this.redis.incr(key);
    if (attempts === 1) await this.redis.expire(key, 60);
    if (attempts > JOIN_ATTEMPTS_PER_MINUTE) {
      throw new HttpException(
        { message: 'too_many_attempts' },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  private assertEnabled(): void {
    if (!isEnabled()) throw new ForbiddenException('interpreter_disabled');
  }
}

function isEnabled(): boolean {
  return process.env.INTERPRETER_ENABLED === 'true';
}

/**
 * Billing refuses with plain Errors, which would surface as 500s. Maps them to
 * this module's codes; the host_ variants tell the guest whose wallet it was.
 */
async function withBillingCodes<T>(
  call: () => Promise<T>,
  insufficientFunds: string,
  featureDisabled: string,
): Promise<T> {
  try {
    return await call();
  } catch (e) {
    if (e instanceof InsufficientFundsException) {
      throw new HttpException(
        { message: insufficientFunds },
        HttpStatus.PAYMENT_REQUIRED,
      );
    }
    if (e instanceof FeatureDisabledException) {
      throw new ForbiddenException(featureDisabled);
    }
    throw e;
  }
}
