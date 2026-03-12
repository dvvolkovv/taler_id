import * as fs from 'fs';
import { Injectable, NotFoundException, ForbiddenException } from "@nestjs/common";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { v4 as uuidv4 } from "uuid";
import * as crypto from "crypto";
import * as bcrypt from "bcrypt";
import { PrismaService } from "../prisma/prisma.service";

const LK_HOST = process.env.LIVEKIT_HOST || "http://localhost:7880";
const LK_API_KEY = process.env.LIVEKIT_API_KEY || "lkdevkey";
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || "lkSecret2024TalerID";
const AI_AGENT_URL = process.env.AI_AGENT_URL || "http://localhost:3100";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const BASE_URL = process.env.BASE_URL || "https://id.taler.tirol";

@Injectable()
export class VoiceService {
  private rooms = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET);

  constructor(private readonly prisma: PrismaService) {}

  async createRoom(initiatorId: string, withAi = true, userToken?: string, conversationId?: string) {
    const roomName = "call-" + uuidv4();
    await this.rooms.createRoom({ name: roomName, emptyTimeout: 300, departureTimeout: 60, maxParticipants: 10 });
    const token = await this.makeToken(roomName, initiatorId);
    try {
      await this.prisma.callLog.create({
        data: { roomName, initiatorId, participantIds: [initiatorId], withAi, conversationId },
      });
    } catch (_) {}
    if (withAi) {
      fetch(AI_AGENT_URL + "/join", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ roomName, userId: initiatorId, userToken }),
      }).catch((e) => console.warn("AI agent not available:", e.message));
    }
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

  async endCallLog(roomName: string): Promise<void> {
    try {
      const log = await this.prisma.callLog.findUnique({ where: { roomName } });
      if (!log || log.endedAt) return;
      const endedAt = new Date();
      const durationSec = Math.round((endedAt.getTime() - log.startedAt.getTime()) / 1000);
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
        select: { userId: true, firstName: true, lastName: true },
      });
      const participants = profiles.map((p) => ({
        userId: p.userId,
        displayName: `${p.firstName ?? ""} ${p.lastName ?? ""}`.trim() || p.userId,
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
        participants,
      };
    }));
    return result;
  }

  async createVoiceSession(userId: string) {
    if (!OPENAI_API_KEY) throw new Error("OPENAI_API_KEY not configured on server");
    const response = await fetch("https://api.openai.com/v1/realtime/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-realtime",
        voice: "marin",
        instructions: "Ты — голосовой ассистент Taler ID. Помогай пользователям с их цифровой идентификацией, статусом KYC-верификации и данными профиля. Будь краток и полезен. Отвечай на русском языке. Ты можешь использовать инструменты для чтения или обновления профиля пользователя.",
      }),
    });
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`OpenAI session error ${response.status}: ${err}`);
    }
    const data = await response.json() as any;
    return { clientSecret: data.client_secret.value as string };
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
      }));

    const fromPublic = publicSummaries.map(s => ({
      id: s.id,
      roomName: s.roomName,
      participants: s.participants,
      durationSec: s.durationSec,
      createdAt: s.createdAt,
      recordingUrl: s.recordingUrl!,
    }));

    return [...fromLogs, ...fromPublic].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getMeetingSummary(id: string) {
    const summary = await this.prisma.meetingSummary.findUnique({ where: { id } });
    if (!summary) throw new NotFoundException('Meeting summary not found');
    return summary;
  }

  async transcribeAudio(file: Express.Multer.File): Promise<{ text: string }> {
    if (!OPENAI_API_KEY) throw new Error('OPENAI_API_KEY not configured');
    const fileBuffer = fs.readFileSync(file.path);
    const blob = new Blob([fileBuffer], { type: file.mimetype || 'audio/m4a' });
    const form = new FormData();
    form.append('model', 'whisper-1');
    form.append('file', blob, file.originalname || 'audio.m4a');
    const response = await fetch('https://api.openai.com/v1/audio/transcriptions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
      body: form,
    });
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Whisper error ${response.status}: ${err}`);
    }
    const data = await response.json() as { text: string };
    try { fs.unlinkSync(file.path); } catch (_) {}
    return { text: data.text };
  }
}
