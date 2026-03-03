import { Injectable } from "@nestjs/common";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { v4 as uuidv4 } from "uuid";
import { PrismaService } from "../prisma/prisma.service";

const LK_HOST = process.env.LIVEKIT_HOST || "http://localhost:7880";
const LK_API_KEY = process.env.LIVEKIT_API_KEY || "lkdevkey";
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || "lkSecret2024TalerID";
const AI_AGENT_URL = process.env.AI_AGENT_URL || "http://localhost:3100";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";

@Injectable()
export class VoiceService {
  private rooms = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET);

  constructor(private readonly prisma: PrismaService) {}

  async createRoom(initiatorId: string, withAi = true, userToken?: string, conversationId?: string) {
    const roomName = "call-" + uuidv4();
    await this.rooms.createRoom({ name: roomName, emptyTimeout: 300, departureTimeout: 60, maxParticipants: 10 });
    const token = await this.makeToken(roomName, initiatorId);
    // Log call start
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
    // Log participant joining
    try {
      await this.prisma.callLog.updateMany({
        where: { roomName },
        data: { participantIds: { push: userId } },
      });
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
  }

  async getCallHistory(userId: string, page = 0, limit = 50) {
    const logs = await this.prisma.callLog.findMany({
      where: { participantIds: { has: userId } },
      orderBy: { startedAt: "desc" },
      skip: page * limit,
      take: limit,
    });
    // Enrich with participant display names
    const result = await Promise.all(logs.map(async (log) => {
      const otherIds = log.participantIds.filter((id: string) => id !== userId);
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
        model: "gpt-4o-realtime-preview-2024-12-17",
        voice: "alloy",
        instructions: "You are Taler ID voice assistant. Help users with their digital identity, KYC verification status, and profile data. Be concise and helpful. Respond in the language the user speaks. You can use tools to read or update the user profile.",
      }),
    });
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`OpenAI session error ${response.status}: ${err}`);
    }
    const data = await response.json() as any;
    return { clientSecret: data.client_secret.value as string };
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
}
