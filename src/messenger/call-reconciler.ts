import { Injectable, Logger } from '@nestjs/common';
import { Interval } from '@nestjs/schedule';
import { RoomServiceClient } from 'livekit-server-sdk';
import { LK_API_KEY, LK_API_SECRET } from '../common/livekit-credentials';
import { parseUserId } from '../common/participant-identity';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { MessengerGateway } from './messenger.gateway';

const LK_HOST = process.env.LIVEKIT_HOST || 'http://localhost:7880';
const LK_HOST_RU = process.env.LIVEKIT_HOST_RU || LK_HOST;

// How long a participant may be missing from the room before the call counts
// as over: longer than a reconnect (the app's own retries; LiveKit keeps a
// dropped participant listed while it tries to resume) and than an answered
// callee takes to connect — `answeredAt` is set when they ask for a token.
const ABSENT_GRACE_MS = 60_000;
// Older calls nobody closed are left as they are: whoever was in them is long
// gone, and ending them now would only stamp a made-up duration on them.
const LOOKBACK_MS = 12 * 60 * 60 * 1000;
const LOCK_KEY = 'call:reconcile:lock';
const LOCK_TTL_S = 10;
// Outlives the grace with room to spare; a call whose passes stop (no lock
// for a while) starts its clock over rather than ending on a stale mark.
const ABSENT_TTL_S = 300;

const absentKey = (roomName: string) => `call:absent:${roomName}`;

type OpenCall = {
  roomName: string;
  initiatorId: string;
  participantIds: string[];
  conversationId: string | null;
};

/** Who is in a call room, asked of the SFU the room lives on. */
@Injectable()
export class CallRoomProbe {
  // A short timeout: a pass asks about its calls one at a time, and an SFU
  // that doesn't answer must not hold the others up for the SDK's 60 s.
  private readonly rooms = new RoomServiceClient(
    LK_HOST,
    LK_API_KEY,
    LK_API_SECRET,
    { requestTimeout: 2 },
  );
  private readonly ruRooms = new RoomServiceClient(
    LK_HOST_RU,
    LK_API_KEY,
    LK_API_SECRET,
    { requestTimeout: 2 },
  );

  /** Identities in the room. LiveKit answers a room that doesn't exist with
   *  an empty list; a failure to answer at all throws. */
  async identities(roomName: string): Promise<string[]> {
    const client = roomName.startsWith('call-ru-') ? this.ruRooms : this.rooms;
    const participants = await client.listParticipants(roomName);
    return participants.map((p) => p.identity);
  }
}

/**
 * Ends the answered calls one side has left without saying so — their app
 * died, they lost network — so nothing sent call_ended. LiveKit webhooks are
 * off on every environment, so the server never hears about it otherwise,
 * the call stays open in CallLog, and the person still in the room keeps a
 * "return to call" banner for a call that is over. The end goes through
 * MessengerGateway.endCallFromHttp, the same path as a hang-up, on behalf of
 * the one who left.
 */
@Injectable()
export class CallReconciler {
  private readonly log = new Logger(CallReconciler.name);
  private running = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly probe: CallRoomProbe,
    private readonly gateway: MessengerGateway,
  ) {}

  @Interval(15_000)
  async tick(): Promise<void> {
    // An SFU that answers slowly can make a pass outlast the interval.
    if (this.running) return;
    this.running = true;
    try {
      await this.runOnce();
    } catch (e) {
      this.log.warn(`pass failed: ${String(e)}`);
    } finally {
      this.running = false;
    }
  }

  /** One pass. Each call is handled on its own: one failing doesn't stop the rest. */
  async runOnce(now = new Date()): Promise<void> {
    // One app node per pass: both would end the same call, and the second
    // end sends everyone call_ended again.
    if (!(await this.redis.setNxEx(LOCK_KEY, LOCK_TTL_S, '1'))) return;
    let calls: OpenCall[];
    try {
      calls = await this.prisma.callLog.findMany({
        where: {
          answeredAt: { not: null },
          endedAt: null,
          conversationId: { not: null },
          startedAt: { gt: new Date(now.getTime() - LOOKBACK_MS) },
        },
        select: {
          roomName: true,
          initiatorId: true,
          participantIds: true,
          conversationId: true,
        },
      });
    } catch (e) {
      this.log.warn(`loading open calls failed: ${String(e)}`);
      return;
    }
    for (const call of calls) {
      try {
        await this.reconcile(call, now);
      } catch (e) {
        this.log.warn(`${call.roomName}: ${String(e)}`);
      }
    }
  }

  private async reconcile(call: OpenCall, now: Date): Promise<void> {
    // Throws when LiveKit doesn't answer: that says nothing about who is in
    // the room, so the call is left exactly as it is.
    const identities = await this.probe.identities(call.roomName);
    const key = absentKey(call.roomName);
    const members = [...new Set([call.initiatorId, ...call.participantIds])];
    const present = new Set(identities.map(parseUserId));
    const absent = members.filter((id) => !present.has(id));
    const stuck =
      // One person left alone in the call. Nobody at all is nobody stuck:
      // when they left is unknown, and ending it would only be a guess.
      members.length - absent.length === 1 &&
      // The caller talking to the callee's AI twin — the callee being away is
      // the point of it.
      !identities.some((id) => id.startsWith('agent-'));
    if (!stuck) {
      await this.redis.del(key);
      return;
    }
    await this.redis.setNxEx(key, ABSENT_TTL_S, String(now.getTime()));
    const since = Number(await this.redis.get(key));
    if (!(now.getTime() - since >= ABSENT_GRACE_MS)) return;

    this.log.log(
      `${call.roomName}: ${absent.join(',')} gone for ${Math.round((now.getTime() - since) / 1000)} s — ending the call`,
    );
    await this.redis.del(key);
    await this.gateway.endCallFromHttp(
      absent[0],
      call.conversationId!,
      call.roomName,
    );
  }
}
