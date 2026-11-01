import { Injectable, Logger } from '@nestjs/common';
import {
  AccessToken,
  RoomServiceClient,
  TrackSource,
} from 'livekit-server-sdk';
import { LK_API_KEY, LK_API_SECRET } from '../common/livekit-credentials';
import { makeParticipantIdentity } from '../common/participant-identity';

// Interpreter rooms live on the main SFU, the one the agent connects to.
const LK_HOST = process.env.LIVEKIT_HOST || 'http://localhost:7880';

/** The agent's identity in an interpreter room (livekit-agent/interpreter.js). */
export const AGENT_IDENTITY = 'voice-interpreter';

export interface InterpreterTokenRequest {
  roomName: string;
  userId: string;
  /** The JWT's session_id: one identity per device, as in calls. */
  loginSessionId?: string;
  lang: string;
  name?: string;
}

@Injectable()
export class InterpreterLivekitService {
  private readonly log = new Logger(InterpreterLivekitService.name);

  /** Creates and deletes rooms. */
  rooms = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET);

  /**
   * Asks whether the agent is in a room. The reconciler asks this of every
   * live conversation each 10 s; with the SDK's 60-second default timeout an
   * SFU that stopped answering would hold every tick for a minute per room.
   */
  presence = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET, {
    requestTimeout: 2,
  });

  get wsUrl(): string {
    return process.env.LIVEKIT_WS_URL || 'ws://localhost:7880';
  }

  async createRoom(roomName: string): Promise<void> {
    await this.rooms.createRoom({
      name: roomName,
      emptyTimeout: 300,
      // Kept open as long as the agent waits for someone to come back.
      departureTimeout: 60,
      // Two people, the agent, and a phone reconnecting before LiveKit has
      // dropped its previous connection.
      maxParticipants: 4,
    });
  }

  /**
   * Only a microphone and no data: whatever reaches the other phone comes
   * from the agent, never straight from this person.
   */
  issueToken(req: InterpreterTokenRequest): Promise<string> {
    const at = new AccessToken(LK_API_KEY, LK_API_SECRET, {
      identity: makeParticipantIdentity(req.userId, req.loginSessionId),
      name: req.name,
      metadata: JSON.stringify({ lang: req.lang }),
      ttl: '4h',
    });
    at.addGrant({
      roomJoin: true,
      room: req.roomName,
      canPublish: true,
      canPublishSources: [TrackSource.MICROPHONE],
      canSubscribe: true,
      canPublishData: false,
    });
    return at.toJwt();
  }

  /**
   * null when LiveKit did not answer. listParticipants resolves [] for a room
   * that is gone, so only a rejection is "unknown" — and nothing may be closed
   * because of an unknown.
   */
  async agentPresent(roomName: string): Promise<boolean | null> {
    try {
      const participants = await this.presence.listParticipants(roomName);
      return participants.some((p) => p.identity === AGENT_IDENTITY);
    } catch (e) {
      this.log.warn(`listParticipants(${roomName}) failed: ${String(e)}`);
      return null;
    }
  }

  /** Best effort: LiveKit closes an empty room by itself after departureTimeout. */
  async deleteRoom(roomName: string): Promise<void> {
    try {
      await this.rooms.deleteRoom(roomName);
    } catch (e) {
      this.log.warn(`deleteRoom(${roomName}) failed: ${String(e)}`);
    }
  }
}
