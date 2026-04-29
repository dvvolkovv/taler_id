import { Injectable, Logger, NotFoundException, ForbiddenException } from "@nestjs/common";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { v4 as uuidv4 } from "uuid";
import * as crypto from "crypto";
import * as bcrypt from "bcrypt";
import { PrismaService } from "../prisma/prisma.service";

import { FileStorageService } from "../common/file-storage.service";
import { GatingService } from "../billing/services/gating.service";
import { MeteringService } from "../billing/services/metering.service";
import { LedgerService } from "../billing/services/ledger.service";
import { PricingService } from "../billing/services/pricing.service";
import { FEATURE_KEYS } from "../billing/constants/feature-keys";

const LK_HOST = process.env.LIVEKIT_HOST || "http://localhost:7880";
const LK_API_KEY = process.env.LIVEKIT_API_KEY || "lkdevkey";
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || "lkSecret2024TalerID";
const LK_WS_URL = process.env.LIVEKIT_WS_URL || "ws://localhost:7880";
const AI_AGENT_URL = process.env.AI_AGENT_URL || "http://localhost:3100";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const BASE_URL = process.env.BASE_URL || "https://id.taler.tirol";

@Injectable()
export class VoiceService {
  private readonly log = new Logger(VoiceService.name);
  private rooms = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET);

  constructor(
    private readonly prisma: PrismaService,
    private readonly fileStorage: FileStorageService,
    private readonly gating: GatingService,
    private readonly metering: MeteringService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
  ) {}

  async createRoom(initiatorId: string, withAi = false, userToken?: string, conversationId?: string) {
    const roomName = "call-" + uuidv4();
    await this.rooms.createRoom({ name: roomName, emptyTimeout: 300, departureTimeout: 60, maxParticipants: 10 });
    const token = await this.makeToken(roomName, initiatorId);
    try {
      await this.prisma.callLog.create({
        data: { roomName, initiatorId, participantIds: [initiatorId], withAi, conversationId },
      });
    } catch (_) {}
    // NOTE: the old livekit-ai-agent (gpt-realtime-mini) no longer auto-joins
    // person-to-person calls. It's still available for explicit scenarios
    // via its HTTP endpoint, but nothing in the clients currently asks for it
    // — and letting it auto-join collides with the new ai-twin-agent fallback.
    console.log(`[createRoom] room=${roomName} initiator=${initiatorId} withAi=${withAi} — auto-join suppressed`);
    return { roomName, token };
  }

  async joinRoom(roomName: string, userId: string) {
    try {
      const log = await this.prisma.callLog.findUnique({ where: { roomName } });
      if (log && !log.participantIds.includes(userId)) {
        await this.prisma.callLog.update({
          where: { roomName },
          data: { participantIds: { push: userId } },
        });
      }
    } catch (_) {}
    return { token: await this.makeToken(roomName, userId) };
  }

  /**
   * Issues a LiveKit access token for a group voice call. Group calls live in
   * rooms named `group-${groupCallId}` so the LiveKit webhook handler (Task 15)
   * can route room events to GroupCallService by prefix. Mirrors the 1-on-1
   * `makeToken` shape (roomJoin + canPublish/canSubscribe) and adds
   * canPublishData for in-room signaling. Returns the WS URL alongside the
   * token so callers don't need to know the LiveKit endpoint.
   */
  async generateGroupCallToken(
    groupCallId: string,
    userId: string,
  ): Promise<{ token: string; livekitWsUrl: string }> {
    const roomName = `group-${groupCallId}`;
    const at = new AccessToken(LK_API_KEY, LK_API_SECRET, {
      identity: userId,
      ttl: 60 * 60 * 4, // 4 hours
    });
    at.addGrant({
      room: roomName,
      roomJoin: true,
      canPublish: true,
      canSubscribe: true,
      canPublishData: true,
    });
    const token = await at.toJwt();
    return {
      token,
      livekitWsUrl: LK_WS_URL,
    };
  }

  async endCallLog(roomName: string): Promise<void> {
    try {
      const log = await this.prisma.callLog.findUnique({ where: { roomName } });
      if (!log || log.endedAt) return;
      const endedAt = new Date();
      // durationSec = talk time (from answeredAt), or 0 if never answered
      const durationSec = log.answeredAt
        ? Math.round((endedAt.getTime() - log.answeredAt.getTime()) / 1000)
        : 0;
      await this.prisma.callLog.update({
        where: { roomName },
        data: { endedAt, durationSec },
      });
    } catch (_) {}
    try {
      const pub = await this.prisma.publicRoom.findFirst({ where: { roomName } });
      if (pub && pub.type === "temporary" && pub.isActive) {
        await this.prisma.publicRoom.update({ where: { code: pub.code }, data: { isActive: false } });
      }
    } catch (_) {}
  }

  async getCallHistory(userId: string, page = 0, limit = 50) {
    const logs = await this.prisma.callLog.findMany({
      where: { participantIds: { has: userId } },
      orderBy: { startedAt: "desc" },
      skip: page * limit,
      take: limit,
      include: { meetingSummary: { select: { id: true, summary: true, recordingUrl: true } } },
    });
    const result = await Promise.all(logs.map(async (log) => {
      let otherIds = [...new Set(log.participantIds)].filter((id: string) => id !== userId);
      if (otherIds.length === 0 && log.conversationId) {
        const convParticipants = await this.prisma.conversationParticipant.findMany({
          where: { conversationId: log.conversationId, userId: { not: userId } },
          select: { userId: true },
        });
        otherIds = convParticipants.map((cp) => cp.userId);
      }
      const profiles = await this.prisma.profile.findMany({
        where: { userId: { in: otherIds } },
        select: { userId: true, firstName: true, lastName: true, avatarUrl: true },
      });
      const participants = profiles.map((p) => ({
        userId: p.userId,
        displayName: `${p.firstName ?? ""} ${p.lastName ?? ""}`.trim() || p.userId,
        avatarUrl: p.avatarUrl ?? undefined,
      }));
      return {
        id: log.id,
        roomName: log.roomName,
        conversationId: log.conversationId,
        isOutgoing: log.initiatorId === userId,
        isMissed: !log.answeredAt && log.endedAt != null && log.initiatorId !== userId,
        startedAt: log.startedAt,
        endedAt: log.endedAt,
        durationSec: log.durationSec,
        withAi: log.withAi,
        aiTwinSummary: log.aiTwinSummary ?? null,
        aiTwinTranscript: log.aiTwinTranscript ?? null,
        meetingSummary: log.meetingSummary ? { id: log.meetingSummary.id, summary: log.meetingSummary.summary, recordingUrl: log.meetingSummary.recordingUrl } : null,
        participants,
      };
    }));
    return result;
  }

  /**
   * Called by the Python ai-twin-agent after a call session ends. Stores the
   * full transcript + GPT-generated summary on the CallLog so the owner of
   * the twin can see what was said while they were away.
   */
  async saveAiTwinCallData(
    roomName: string,
    transcript: unknown,
    summary: string,
  ): Promise<void> {
    try {
      await this.prisma.callLog.update({
        where: { roomName },
        data: {
          aiTwinTranscript: transcript as any,
          aiTwinSummary: summary,
        },
      });
      console.log(
        `[saveAiTwinCallData] saved transcript+summary for room=${roomName}`,
      );
    } catch (e) {
      console.warn(
        `[saveAiTwinCallData] failed for room=${roomName}:`,
        (e as Error).message,
      );
    }
  }


  async getCallDetail(callId: string, userId: string) {
    const log = await this.prisma.callLog.findUnique({
      where: { id: callId },
      include: { meetingSummary: true },
    });
    if (!log) throw new Error("Call not found");
    if (!log.participantIds.includes(userId)) throw new Error("Access denied");
    const profiles = await this.prisma.profile.findMany({
      where: { userId: { in: log.participantIds } },
      select: { userId: true, firstName: true, lastName: true, avatarUrl: true },
    });
    const participants = profiles.map((p) => ({
      userId: p.userId,
      displayName: `${p.firstName ?? ""} ${p.lastName ?? ""}`.trim() || p.userId,
      avatarUrl: p.avatarUrl,
    }));
    return {
      id: log.id,
      roomName: log.roomName,
      conversationId: log.conversationId,
      isOutgoing: log.initiatorId === userId,
      startedAt: log.startedAt,
      endedAt: log.endedAt,
      durationSec: log.durationSec,
      withAi: log.withAi,
      aiTwinSummary: log.aiTwinSummary ?? null,
      aiTwinTranscript: log.aiTwinTranscript ?? null,
      participants,
      summary: log.meetingSummary ? {
        id: log.meetingSummary.id,
        summary: log.meetingSummary.summary,
        keyPoints: log.meetingSummary.keyPoints,
        actionItems: log.meetingSummary.actionItems,
        decisions: log.meetingSummary.decisions,
        transcript: log.meetingSummary.transcript,
        status: log.meetingSummary.status,
        recordingUrl: log.meetingSummary.recordingUrl,
      } : null,
    };
  }

  async createVoiceSession(userId: string) {
    if (!OPENAI_API_KEY) throw new Error("OPENAI_API_KEY not configured on server");

    // Billing pre-check: feature toggle + minReserve balance. Throws
    // FeatureDisabledException (→403) or InsufficientFundsException (→402),
    // mapped by BillingExceptionFilter on the controller.
    const billingSession = await this.gating.startSession(userId, FEATURE_KEYS.VOICE_ASSISTANT);

    try {
      const response = await fetch("https://api.openai.com/v1/realtime/sessions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "gpt-realtime-mini",
          voice: "marin",
          instructions: "Ты — голосовой ассистент Taler ID. Помогай пользователям с их цифровой идентификацией, статусом KYC-верификации и данными профиля. Будь краток и полезен. Отвечай на русском языке. Ты можешь использовать инструменты для чтения или обновления профиля пользователя.",
        }),
      });
      if (!response.ok) {
        const err = await response.text();
        throw new Error(`OpenAI session error ${response.status}: ${err}`);
      }
      const data = await response.json() as any;
      return {
        clientSecret: data.client_secret.value as string,
        billingSessionId: billingSession.id,
      };
    } catch (err) {
      // Roll back the billing session so we don't leak an 'active' AiSession
      // whose OpenAI counterpart never existed.
      await this.gating.endSession(billingSession.id, 'failed').catch(() => {});
      throw err;
    }
  }

  /**
   * Client-initiated close of a voice_assistant session. Reports the actual
   * duration (for final adjustment debit) and marks the AiSession completed.
   * Report failures are swallowed — MeteringService.tick (cron) has already
   * been draining the balance at ~1-minute granularity, so the final debit
   * is only an adjustment. Ending the session must always succeed.
   */
  async closeVoiceSession(
    userId: string,
    sessionId: string,
    durationSec: number,
  ): Promise<void> {
    const session = await this.prisma.aiSession.findUnique({
      where: { id: sessionId },
      select: { userId: true, status: true },
    });
    // Return 404 (not 403) to avoid revealing whether a sessionId exists.
    if (!session || session.userId !== userId) {
      throw new NotFoundException('session not found');
    }

    const safeDuration = Number.isFinite(durationSec) && durationSec > 0 ? durationSec : 0;
    const durationMin = safeDuration / 60;
    try {
      await this.metering.reportUsage(sessionId, durationMin, 'client');
    } catch {
      // Swallow report failure so session close always succeeds. Metering's cron
      // tick has already been draining at ~10-second granularity, so a swallowed
      // final report means at most ~10 seconds of under-billing drift, not lost billing.
    }
    await this.gating.endSession(sessionId, 'completed');
  }

  // ─── Public rooms ───

  async getOrCreatePersonalRoom(userId: string) {
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile) throw new NotFoundException("Profile not found");

    if (profile.personalRoomCode) {
      const existing = await this.prisma.publicRoom.findUnique({ where: { code: profile.personalRoomCode } });
      if (existing) {
        return { code: existing.code, link: `${BASE_URL}/room/${existing.code}` };
      }
    }

    const code = crypto.randomBytes(4).toString("hex");
    const roomName = "personal-" + userId.slice(0, 8) + "-" + code;
    await this.prisma.publicRoom.create({
      data: { code, roomName, creatorId: userId, title: "", type: "permanent" },
    });
    await this.prisma.profile.update({
      where: { userId },
      data: { personalRoomCode: code },
    });
    return { code, link: `${BASE_URL}/room/${code}` };
  }

  async createTemporaryRoom(userId: string, title?: string, password?: string) {
    const roomName = "tmp-" + uuidv4();
    const code = crypto.randomBytes(4).toString("hex");
    await this.rooms.createRoom({ name: roomName, emptyTimeout: 300, departureTimeout: 60, maxParticipants: 20 });
    const passwordHash = password ? await bcrypt.hash(password, 10) : null;
    await this.prisma.publicRoom.create({
      data: {
        code,
        roomName,
        creatorId: userId,
        title: title || "",
        type: "temporary",
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        ...(passwordHash ? { passwordHash } : {}),
      },
    });
    return { code, link: `${BASE_URL}/room/${code}` };
  }

  async deactivateTemporaryRoom(code: string, userId: string) {
    const room = await this.prisma.publicRoom.findUnique({ where: { code } });
    if (!room || room.type !== "temporary") throw new NotFoundException("Room not found");
    if (room.creatorId !== userId) throw new NotFoundException("Not your room");
    await this.prisma.publicRoom.update({ where: { code }, data: { isActive: false } });
  }

  async createPublicRoom(userId?: string, title?: string, password?: string) {
    const roomName = "pub-" + uuidv4();
    const code = crypto.randomBytes(4).toString("hex");
    await this.rooms.createRoom({ name: roomName, emptyTimeout: 600, departureTimeout: 120, maxParticipants: 20 });
    const passwordHash = password ? await bcrypt.hash(password, 10) : null;
    await this.prisma.publicRoom.create({
      data: {
        code,
        roomName,
        creatorId: userId ?? null,
        title: title || "",
        ...(passwordHash ? { passwordHash } : {}),
      },
    });
    return { code, roomName, link: `${BASE_URL}/room/${code}` };
  }

  async getPublicRoom(code: string) {
    const room = await this.prisma.publicRoom.findUnique({ where: { code } });
    if (!room || !room.isActive) throw new NotFoundException("Room not found");

    let creatorName: string | null = null;
    let creatorAvatar: string | null = null;
    if (room.creatorId) {
      const profile = await this.prisma.profile.findUnique({ where: { userId: room.creatorId } });
      if (profile) {
        creatorName = `${profile.firstName ?? ""} ${profile.lastName ?? ""}`.trim() || null;
        creatorAvatar = (profile as any).avatarUrl ?? null;
      }
    }

    return {
      code: room.code,
      title: room.title,
      roomName: room.roomName,
      isActive: room.isActive,
      requiresPassword: !!room.passwordHash,
      creatorName,
      creatorAvatar,
    };
  }

  async joinPublicRoom(code: string, guestName: string, password?: string) {
    const room = await this.prisma.publicRoom.findUnique({ where: { code } });
    if (!room || !room.isActive) throw new NotFoundException("Room not found");
    if (room.type === "temporary" && room.expiresAt && new Date() > room.expiresAt) {
      await this.prisma.publicRoom.update({ where: { code }, data: { isActive: false } });
      throw new NotFoundException("Room has expired");
    }
    if (room.passwordHash) {
      if (!password || !(await bcrypt.compare(password, room.passwordHash))) {
        throw new ForbiddenException("Invalid room password");
      }
    }
    try {
      const timeout = room.type === "permanent" ? 600 : 300;
      await this.rooms.createRoom({ name: room.roomName, emptyTimeout: timeout, departureTimeout: 120, maxParticipants: 20 });
    } catch (_) {}
    return { token: await this.makeGuestToken(room.roomName, guestName), roomName: room.roomName };
  }

  async joinPublicRoomAuth(code: string, userId: string, password?: string) {
    const room = await this.prisma.publicRoom.findUnique({ where: { code } });
    if (!room || !room.isActive) throw new NotFoundException("Room not found");
    if (room.type === "temporary" && room.expiresAt && new Date() > room.expiresAt) {
      await this.prisma.publicRoom.update({ where: { code }, data: { isActive: false } });
      throw new NotFoundException("Room has expired");
    }
    if (room.passwordHash) {
      if (!password || !(await bcrypt.compare(password, room.passwordHash))) {
        throw new ForbiddenException("Invalid room password");
      }
    }
    try {
      const timeout = room.type === "permanent" ? 600 : 300;
      await this.rooms.createRoom({ name: room.roomName, emptyTimeout: timeout, departureTimeout: 120, maxParticipants: 20 });
    } catch (_) {}
    return { token: await this.makeToken(room.roomName, userId), roomName: room.roomName };
  }

  private async makeGuestToken(room: string, displayName: string) {
    const identity = "guest-" + crypto.randomBytes(4).toString("hex");
    const at = new AccessToken(LK_API_KEY, LK_API_SECRET, { identity, name: displayName });
    at.addGrant({ roomJoin: true, room, canPublish: true, canSubscribe: true });
    return await at.toJwt();
  }

  private async makeToken(room: string, identity: string) {
    const profile = await this.prisma.profile.findUnique({ where: { userId: identity } });
    const displayName = profile
      ? `${profile.firstName ?? ""} ${profile.lastName ?? ""}`.trim() || identity
      : identity;
    const at = new AccessToken(LK_API_KEY, LK_API_SECRET, { identity, name: displayName });
    at.addGrant({ roomJoin: true, room, canPublish: true, canSubscribe: true });
    return await at.toJwt();
  }

  // ─── E2EE ───

  async disableE2EE(roomName: string) {
    try {
      await this.rooms.updateRoomMetadata(roomName, JSON.stringify({ e2ee_disabled: true }));
      return { ok: true };
    } catch (e) {
      console.error('Failed to update room metadata for E2EE disable:', e);
      return { ok: false, reason: (e as Error).message };
    }
  }

  // ─── Voice Translator ───

  async getTranslatorLanguages() {
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/languages');
      return await res.json();
    } catch (e) {
      // Fallback if agent is unavailable
      return [
        { code: 'ru', name: 'Русский' },
        { code: 'en', name: 'English' },
        { code: 'de', name: 'Deutsch' },
        { code: 'it', name: 'Italiano' },
      ];
    }
  }

  async startTranslator(roomName: string) {
    // Disable E2EE first — translator needs unencrypted audio
    await this.disableE2EE(roomName);

    // Clear any leftover lang metadata from previous translator sessions
    try {
      const participants = await this.rooms.listParticipants(roomName);
      for (const p of participants) {
        if (p.identity === 'voice-translator' || p.identity === 'ai-assistant' || p.identity === 'meeting-recorder') continue;
        try {
          const meta = p.metadata ? JSON.parse(p.metadata) : {};
          if (meta.lang) {
            // Remove lang/sourceLang so translator doesn't create unnecessary sessions
            delete meta.lang;
            delete meta.sourceLang;
            await this.rooms.updateParticipant(roomName, p.identity, {
              metadata: Object.keys(meta).length > 0 ? JSON.stringify(meta) : '',
            });
          }
        } catch (_) {}
      }
    } catch (_) {}

    try {
      const res = await fetch(AI_AGENT_URL + '/translator/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      const data = await res.json() as any;
      return { status: data.status || 'started' };
    } catch (e) {
      console.error('Failed to start translator:', e);
      throw new Error('Translator service unavailable');
    }
  }

  async stopTranslator(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      const data = await res.json() as any;
      return { status: data.status || 'stopped' };
    } catch (e) {
      console.error('Failed to stop translator:', e);
      throw new Error('Translator service unavailable');
    }
  }

  async setTranslatorLang(roomName: string, userId: string, lang: string, sourceLang?: string) {
    // Also set LiveKit participant metadata so translator can read lang from existing participants
    try {
      await this.rooms.updateParticipant(roomName, userId, { metadata: JSON.stringify({ lang, sourceLang: sourceLang || lang }) });
    } catch (e) {
      console.warn('Failed to update participant metadata:', (e as Error).message);
    }
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/set-lang', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName, userId, lang, sourceLang: sourceLang || lang }),
      });
      return await res.json();
    } catch (e) {
      return { ok: false, reason: 'Translator service unavailable' };
    }
  }

  async setTranslatorLangByIdentity(roomName: string, identity: string, lang: string) {
    // Same as setTranslatorLang but uses participant identity directly (for guests)
    try {
      await this.rooms.updateParticipant(roomName, identity, { metadata: JSON.stringify({ lang }) });
    } catch (e) {
      console.warn('Failed to update participant metadata:', (e as Error).message);
    }
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/set-lang', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName, userId: identity, lang }),
      });
      return await res.json();
    } catch (e) {
      return { ok: false, reason: 'Translator service unavailable' };
    }
  }

  async getTranslatorStatus(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/translator/status/' + roomName);
      return await res.json();
    } catch (e) {
      return { running: false };
    }
  }

  // ─── Meeting Recorder ───

  async startRecorder(roomName: string, withAi = true) {
    try {
      const res = await fetch(AI_AGENT_URL + '/record', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName, withAi }),
      });
      const data = await res.json() as any;
      return { status: data.status || 'started' };
    } catch (e) {
      console.error('Failed to start recorder:', e);
      throw new Error('Recorder service unavailable');
    }
  }

  async stopRecorder(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/stop-record', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      const data = await res.json() as any;
      return { status: data.status || 'stopping' };
    } catch (e) {
      console.error('Failed to stop recorder:', e);
      throw new Error('Recorder service unavailable');
    }
  }

  async getRecorderStatus(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/record-status/' + roomName);
      return await res.json();
    } catch (e) {
      return { recording: false };
    }
  }

  async saveMeetingSummary(data: {
    id?: string;
    roomName: string;
    transcript: string;
    summary: string;
    keyPoints: any;
    actionItems: any;
    decisions: any;
    participants: string[];
    participantIds?: string[];
    durationSec?: number;
    recordingUrl?: string;
    status?: string;
    participantTracks?: any;
  }) {
    // If id provided — update existing record (pending → done)
    if (data.id) {
      const updated = await this.prisma.meetingSummary.update({
        where: { id: data.id },
        data: {
          transcript: data.transcript,
          summary: data.summary,
          keyPoints: data.keyPoints,
          actionItems: data.actionItems,
          decisions: data.decisions,
          recordingUrl: data.recordingUrl ?? null,
          durationSec: data.durationSec ?? null,
          status: data.status ?? 'done',
          ...(data.participants && { participants: data.participants }),
          ...(data.participantIds && data.participantIds.length > 0 && { participantIds: data.participantIds }),
          ...(data.participantTracks && { participantTracks: data.participantTracks }),
        },
      });
      return { id: updated.id };
    }

    let callLogId: string | null = null;
    try {
      const log = await this.prisma.callLog.findUnique({ where: { roomName: data.roomName } });
      if (log) callLogId = log.id;
    } catch (_) {}

    const summary = await this.prisma.meetingSummary.create({
      data: {
        roomName: data.roomName,
        callLogId,
        transcript: data.transcript,
        summary: data.summary,
        keyPoints: data.keyPoints,
        actionItems: data.actionItems,
        decisions: data.decisions,
        participants: data.participants,
        participantIds: data.participantIds ?? [],
        durationSec: data.durationSec ?? null,
        recordingUrl: data.recordingUrl ?? null,
        status: data.status ?? 'done',
        ...(data.participantTracks && { participantTracks: data.participantTracks }),
      },
    });
    return { id: summary.id };
  }

  async getMeetingSummaries(userId: string, page = 0, limit = 20) {
    const logs = await this.prisma.callLog.findMany({
      where: { participantIds: { has: userId }, meetingSummary: { isNot: null } },
      orderBy: { startedAt: 'desc' },
      skip: page * limit,
      take: limit,
      include: { meetingSummary: true },
    });

    const publicSummaries = await this.prisma.meetingSummary.findMany({
      where: {
        callLogId: null,
        OR: [
          { participantIds: { has: userId } },
          { roomName: { startsWith: `personal-${userId.substring(0, 8)}` } },
        ],
      },
      orderBy: { createdAt: 'desc' },
      skip: page * limit,
      take: limit,
    });

    const fromLogs = logs
      .filter(l => l.meetingSummary)
      .map(l => ({
        id: l.meetingSummary!.id,
        roomName: l.roomName,
        summary: l.meetingSummary!.summary,
        participants: l.meetingSummary!.participants,
        durationSec: l.meetingSummary!.durationSec,
        actionItemsCount: Array.isArray(l.meetingSummary!.actionItems) ? (l.meetingSummary!.actionItems as any[]).length : 0,
        createdAt: l.meetingSummary!.createdAt,
        recordingUrl: l.meetingSummary!.recordingUrl,
        status: (l.meetingSummary as any).status ?? 'done',
      }));

    const fromPublic = publicSummaries.map(s => ({
      id: s.id,
      roomName: s.roomName,
      summary: s.summary,
      participants: s.participants,
      durationSec: s.durationSec,
      actionItemsCount: Array.isArray(s.actionItems) ? (s.actionItems as any[]).length : 0,
      createdAt: s.createdAt,
      recordingUrl: s.recordingUrl,
      status: (s as any).status ?? 'done',
    }));

    return [...fromLogs, ...fromPublic].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getMeetingRecordings(userId: string, page = 0, limit = 20) {
    const logs = await this.prisma.callLog.findMany({
      where: { participantIds: { has: userId }, meetingSummary: { isNot: null } },
      orderBy: { startedAt: 'desc' },
      skip: page * limit,
      take: limit,
      include: { meetingSummary: true },
    });

    const publicSummaries = await this.prisma.meetingSummary.findMany({
      where: {
        callLogId: null,
        recordingUrl: { not: null },
        OR: [
          { participantIds: { has: userId } },
          { roomName: { startsWith: `personal-${userId.substring(0, 8)}` } },
        ],
      },
      orderBy: { createdAt: 'desc' },
      skip: page * limit,
      take: limit,
    });

    const fromLogs = logs
      .filter(l => l.meetingSummary?.recordingUrl)
      .map(l => ({
        id: l.meetingSummary!.id,
        roomName: l.roomName,
        participants: l.meetingSummary!.participants,
        durationSec: l.meetingSummary!.durationSec,
        createdAt: l.meetingSummary!.createdAt,
        recordingUrl: l.meetingSummary!.recordingUrl!,
        status: (l.meetingSummary as any).status ?? 'done',
        hasTranscript: !!l.meetingSummary!.transcript && l.meetingSummary!.transcript.length > 0,
        hasSummary: !!l.meetingSummary!.summary && l.meetingSummary!.summary.length > 0,
      }));

    const fromPublic = publicSummaries.map(s => ({
      id: s.id,
      roomName: s.roomName,
      participants: s.participants,
      durationSec: s.durationSec,
      createdAt: s.createdAt,
      recordingUrl: s.recordingUrl!,
      status: (s as any).status ?? 'done',
      hasTranscript: !!s.transcript && s.transcript.length > 0,
      hasSummary: !!s.summary && s.summary.length > 0,
    }));

    return [...fromLogs, ...fromPublic].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getMeetingSummary(id: string) {
    const summary = await this.prisma.meetingSummary.findUnique({ where: { id } });
    if (!summary) throw new NotFoundException('Meeting summary not found');
    return summary;
  }

  async transcribeExistingRecording(userId: string, meetingId: string) {
    const meeting = await this.prisma.meetingSummary.findUnique({ where: { id: meetingId } });
    if (!meeting) throw new NotFoundException('Meeting not found');
    if (!meeting.recordingUrl) throw new Error('No recording URL');

    // Ownership: only a participant in the call can kick off transcription (and be billed).
    // If participantIds wasn't populated on legacy rows, skip the check rather than hard-fail —
    // the JWT guard already ensures an authenticated user.
    if (meeting.participantIds.length > 0 && !meeting.participantIds.includes(userId)) {
      throw new ForbiddenException('Not a participant of this meeting');
    }

    // Mark as processing
    await this.prisma.meetingSummary.update({
      where: { id: meetingId },
      data: { status: 'processing' },
    });

    // Download recording
    let audioBuffer: Buffer;
    const url = meeting.recordingUrl;

    if (url.includes('/messenger/files/download?key=')) {
      // S3 stored — read via FileStorageService
      const key = decodeURIComponent(url.split('key=')[1]);
      const { stream } = await this.fileStorage.getObject(key);
      const chunks: Buffer[] = [];
      for await (const chunk of stream) chunks.push(Buffer.from(chunk));
      audioBuffer = Buffer.concat(chunks);
    } else {
      // External URL — fetch
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Failed to download recording: ${res.status}`);
      audioBuffer = Buffer.from(await res.arrayBuffer());
    }

    // Check if we have per-participant tracks for speaker diarization
    const participantTracks = (meeting as any).participantTracks as Record<string, string> | null;
    const hasMultipleTracks = participantTracks && typeof participantTracks === 'object' && Object.keys(participantTracks).length > 1;

    // ─── Whisper billing pre-check + pre-debit ───
    // Whisper charges per audio-minute. For diarization we send each track (same length
    // as the call) separately, so billable minutes = numTracks × durationSec. For the
    // single-mixed path it's just durationSec. Fall back to 1 min if durationSec is null
    // on legacy rows — pricing rounds up and refunds on failure anyway.
    const baseDurationSec = meeting.durationSec && meeting.durationSec > 0 ? meeting.durationSec : 60;
    const trackCount = hasMultipleTracks ? Object.keys(participantTracks!).length : 1;
    const whisperMinutes = (baseDurationSec * trackCount) / 60;

    const whisperSession = await this.gating.startSession(userId, FEATURE_KEYS.WHISPER_TRANSCRIBE);
    const whisperCost = await this.pricing.calculatePlanckCost(
      FEATURE_KEYS.WHISPER_TRANSCRIBE,
      whisperMinutes,
    );

    let whisperTx: { id: string };
    try {
      whisperTx = await this.ledger.debit(userId, whisperCost, 'SPEND', {
        featureKey: FEATURE_KEYS.WHISPER_TRANSCRIBE,
        sessionId: whisperSession.id,
        metadata: { meetingId, durationMin: whisperMinutes, trackCount },
      });
    } catch (err) {
      // Debit failed (insufficient funds) before Whisper ran — mark the meeting
      // as failed so the UI doesn't show stale "processing" or misleading "done".
      await this.gating.endSession(whisperSession.id, 'failed').catch(() => {});
      await this.prisma.meetingSummary
        .update({ where: { id: meetingId }, data: { status: 'failed' } })
        .catch(() => {});
      throw err;
    }

    let transcript = '';

    try {
      if (hasMultipleTracks) {
        // Speaker diarization: transcribe each participant track separately and merge by timestamp
        console.log('[VOICE] Speaker diarization: transcribing', Object.keys(participantTracks).length, 'tracks separately');
        const allSegments: { start: number; end: number; text: string; speaker: string }[] = [];

        for (const [speakerName, trackUrl] of Object.entries(participantTracks)) {
          try {
            // Download individual track
            let trackBuffer: Buffer;
            if ((trackUrl as string).includes('/messenger/files/download?key=')) {
              const key = decodeURIComponent((trackUrl as string).split('key=')[1]);
              const { stream } = await this.fileStorage.getObject(key);
              const chunks: Buffer[] = [];
              for await (const chunk of stream) chunks.push(Buffer.from(chunk));
              trackBuffer = Buffer.concat(chunks);
            } else {
              const trackRes = await fetch(trackUrl as string);
              if (!trackRes.ok) { console.warn('[VOICE] Failed to download track for', speakerName); continue; }
              trackBuffer = Buffer.from(await trackRes.arrayBuffer());
            }

            // Transcribe this track
            const trackForm = new FormData();
            const trackBlob = new Blob([new Uint8Array(trackBuffer)], { type: 'audio/ogg' });
            trackForm.append('file', trackBlob, speakerName + '.ogg');
            trackForm.append('model', 'whisper-1');
            trackForm.append('response_format', 'verbose_json');
            trackForm.append('timestamp_granularities[]', 'segment');

            const trackWhisperRes = await fetch('https://api.openai.com/v1/audio/transcriptions', {
              method: 'POST',
              headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
              body: trackForm,
            });

            if (!trackWhisperRes.ok) {
              console.warn('[VOICE] Whisper error for track', speakerName, ':', trackWhisperRes.status);
              continue;
            }

            const trackData = await trackWhisperRes.json() as any;
            const segs = trackData.segments ?? [];
            for (const s of segs) {
              allSegments.push({ start: s.start, end: s.end, text: s.text.trim(), speaker: speakerName });
            }
            if (segs.length === 0 && trackData.text) {
              allSegments.push({ start: 0, end: 0, text: trackData.text.trim(), speaker: speakerName });
            }
          } catch (e) {
            console.warn('[VOICE] Error transcribing track for', speakerName, ':', (e as Error).message);
          }
        }

        // If every track failed (per-track catches swallow errors), we'd end up with
        // an empty transcript, skip GPT-4o, and silently mark the session completed —
        // leaving the user charged for N tracks × duration with nothing to show.
        // Throw so the outer catch refunds and marks the meeting failed.
        if (allSegments.length === 0) {
          throw new Error('diarization_all_tracks_failed: no transcript produced');
        }

        // Sort by timestamp and format
        allSegments.sort((a, b) => a.start - b.start);
        transcript = allSegments
          .map(s => {
            const mm = String(Math.floor(s.start / 60)).padStart(2, '0');
            const ss = String(Math.floor(s.start % 60)).padStart(2, '0');
            return `[${mm}:${ss}] ${s.speaker}: ${s.text}`;
          })
          .join('\n');
      } else {
        // Single mixed recording - transcribe without speaker info
        const formData = new FormData();
        const blob = new Blob([new Uint8Array(audioBuffer)], { type: 'audio/mpeg' });
        formData.append('file', blob, 'recording.mp3');
        formData.append('model', 'whisper-1');
        formData.append('response_format', 'verbose_json');
        formData.append('timestamp_granularities[]', 'segment');

        const whisperRes = await fetch('https://api.openai.com/v1/audio/transcriptions', {
          method: 'POST',
          headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
          body: formData,
        });

        if (!whisperRes.ok) {
          const errText = await whisperRes.text();
          throw new Error(`Whisper error ${whisperRes.status}: ${errText}`);
        }

        const whisperData = await whisperRes.json() as any;
        const segments = whisperData.segments ?? [];
        transcript = segments.length > 0
          ? segments.map((s: any) => {
              const mm = String(Math.floor(s.start / 60)).padStart(2, '0');
              const ss = String(Math.floor(s.start % 60)).padStart(2, '0');
              return `[${mm}:${ss}] ${s.text.trim()}`;
            }).join('\n')
          : whisperData.text?.trim() ?? '';
      }
      await this.gating.endSession(whisperSession.id, 'completed');
    } catch (err) {
      // Transcription failed — covers both the single-mixed path (Whisper HTTP error)
      // and the diarization path (all tracks failed → we throw above). Mark the
      // meeting as failed so UI stops showing "processing", refund the pre-debit,
      // and close the gating session.
      await this.prisma.meetingSummary
        .update({ where: { id: meetingId }, data: { status: 'failed' } })
        .catch(() => {});
      await this.ledger
        .refund(whisperTx.id, `whisper error: ${String(err).slice(0, 200)}`)
        .catch(() => {});
      await this.gating.endSession(whisperSession.id, 'failed').catch(() => {});
      throw err;
    }

    // ─── GPT-4o meeting summary (exact post-call debit from usage.total_tokens) ───
    let summary = { summary: '', keyPoints: [] as string[], actionItems: [] as any[], decisions: [] as string[] };
    if (transcript.length > 0) {
      const summarySession = await this.gating.startSession(userId, FEATURE_KEYS.MEETING_SUMMARY);

      try {
        const gptRes = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${OPENAI_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'gpt-4o',
            response_format: { type: 'json_object' },
            messages: [
              {
                role: 'system',
                content: `Ты — профессиональный ассистент для анализа деловых встреч. Внимательно проанализируй транскрипт и верни JSON с полями:
- "summary": структурированное резюме встречи (2-3 абзаца). Включи контекст встречи, основные обсуждённые темы и общий итог. Пиши на языке встречи.
- "keyPoints": массив ключевых моментов (строки). Каждый пункт должен быть конкретным и информативным — не общие фразы, а суть обсуждённого. Формат: "[Тема] — описание".
- "actionItems": массив задач, каждая: { "task": "конкретное описание задачи с ожидаемым результатом", "assignee": "имя ответственного или null", "deadline": "срок или null" }. Извлекай задачи из явных обещаний, договорённостей и поручений.
- "decisions": массив принятых решений (строки). Включай только явно согласованные решения, а не предложения или обсуждения.
Пиши резюме на том же языке, на котором проходила встреча. Если есть спикеры — указывай кто что сказал/предложил/решил.`,
              },
              { role: 'user', content: transcript },
            ],
            max_tokens: 4096,
          }),
        });

        if (gptRes.ok) {
          const gptData = await gptRes.json() as any;
          // Exact cost from actual token usage; fallback to 0 only if usage missing.
          const totalTokens = gptData.usage?.total_tokens ?? 0;
          const tokensK = totalTokens / 1000;
          const summaryCost = await this.pricing.calculatePlanckCost(
            FEATURE_KEYS.MEETING_SUMMARY,
            tokensK,
          );

          try {
            // Zero tokens happens only when GPT-4o returns an empty response (edge case,
            // already logged). Skipping the debit is intentional — don't charge for nothing.
            if (summaryCost > 0n) {
              await this.ledger.debit(userId, summaryCost, 'SPEND', {
                featureKey: FEATURE_KEYS.MEETING_SUMMARY,
                sessionId: summarySession.id,
                metadata: { meetingId, totalTokens },
              });
            }
          } catch (debitErr) {
            // Post-call debit failed (insufficient funds). We already spent money on GPT-4o.
            // Fail closed: mark session failed and throw — better to 500 than silently
            // give the user free summaries.
            this.log.error(
              `meeting_summary post-call debit failed for user=${userId} session=${summarySession.id}: ${String(debitErr)}`,
            );
            await this.gating.endSession(summarySession.id, 'failed').catch(() => {});
            throw debitErr;
          }

          try {
            summary = JSON.parse(gptData.choices[0].message.content);
          } catch {
            summary.summary = gptData.choices[0].message.content;
          }
          await this.gating.endSession(summarySession.id, 'completed');
        } else {
          // GPT-4o 4xx/5xx — no debit needed (we only bill on successful response),
          // but still close the session so cron doesn't sweep it as "active".
          await this.gating.endSession(summarySession.id, 'failed').catch(() => {});
        }
      } catch (err) {
        // OpenAI network error OR the inner debit-fail rethrow. Ensure session is closed.
        // endSession is idempotent on already-ended rows via Prisma where-clause match,
        // but we guard with catch-all to avoid double-close errors on the debit-fail path.
        await this.gating.endSession(summarySession.id, 'failed').catch(() => {});
        throw err;
      }
    }

    // Update meeting summary
    const updated = await this.prisma.meetingSummary.update({
      where: { id: meetingId },
      data: {
        transcript,
        summary: summary.summary || '',
        keyPoints: summary.keyPoints || [],
        actionItems: summary.actionItems || [],
        decisions: summary.decisions || [],
        status: 'done',
      },
    });

    return { id: updated.id, status: 'done' };
  }


  // ─── Hold Music ───

  async startHoldMusic(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/hold-music/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      return await res.json();
    } catch (e) {
      console.error('Failed to start hold music:', e);
      return { error: 'Hold music agent unavailable' };
    }
  }

  async stopHoldMusic(roomName: string) {
    try {
      const res = await fetch(AI_AGENT_URL + '/hold-music/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      return await res.json();
    } catch (e) {
      console.error('Failed to stop hold music:', e);
      return { error: 'Hold music agent unavailable' };
    }
  }

}
