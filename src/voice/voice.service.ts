import { Injectable } from "@nestjs/common";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { v4 as uuidv4 } from "uuid";

const LK_HOST = process.env.LIVEKIT_HOST || "http://localhost:7880";
const LK_API_KEY = process.env.LIVEKIT_API_KEY || "lkdevkey";
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || "lkSecret2024TalerID";
const AI_AGENT_URL = process.env.AI_AGENT_URL || "http://localhost:3100";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";

@Injectable()
export class VoiceService {
  private rooms = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET);

  async createRoom(initiatorId: string, withAi = true, userToken?: string) {
    const roomName = "call-" + uuidv4();
    await this.rooms.createRoom({ name: roomName, emptyTimeout: 300, departureTimeout: 60, maxParticipants: 10 });
    const token = await this.makeToken(roomName, initiatorId);
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
    return { token: await this.makeToken(roomName, userId) };
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
    const at = new AccessToken(LK_API_KEY, LK_API_SECRET, { identity });
    at.addGrant({ roomJoin: true, room, canPublish: true, canSubscribe: true });
    return await at.toJwt();
  }
}
