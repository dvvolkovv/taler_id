import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { PrismaService } from '../../prisma/prisma.service';
import { isApiAccessToken } from '../../common/utils/access-token.util';
import { LK_API_SECRET } from '../../common/livekit-credentials';

/**
 * Proves the caller is entitled to act on `:roomName` — and, on success,
 * records who: it sets `req.roomActor` to the caller's identity before
 * returning `true`, so routes gated by this guard can attribute or
 * rate-limit per sender (see the room chat write throttle in
 * VoiceService.sendRoomChatMessage).
 *
 * `roomActor` is an identifier *within the room*, not a stable reference to
 * a Taler ID user account, and its shape depends on which proof matched: on
 * the LiveKit-grant path it's whatever participant identity that token
 * carries — `guest-<id>`, an agent name like `meeting-recorder`, or
 * `<userId>#<deviceHash>` for a signed-in caller (see
 * common/participant-identity.ts) — and on the Taler ID token path it's the
 * bare userId, with no device suffix. The same human can show up under
 * different `roomActor` values across devices or proof types — don't treat
 * it as a userId without checking which path produced it.
 *
 * Recorder control used to be unauthenticated, on the assumption that the room
 * name is an unguessable secret. It is not a good one: personal rooms are named
 * `personal-<first 8 chars of userId>-<8 hex chars>`, and that code is handed to
 * every guest who ever opened the room's share link — so a one-time visitor
 * could silently start recording any later meeting held there.
 *
 * Two kinds of proof are accepted, because two different clients call these
 * routes:
 *  - a LiveKit access token whose grant names exactly this room (the web guest
 *    client at public/room.html already holds one to connect at all);
 *  - a Taler ID access token, provided the user is a participant of the call or
 *    owns the personal room (mirrors the ownership rule in transcribeMeeting).
 */
@Injectable()
export class RoomAccessGuard implements CanActivate {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest();
    const roomName: string | undefined = req.params?.roomName;
    if (!roomName) throw new ForbiddenException('room not specified');

    const auth = req.headers['authorization'];
    const token =
      typeof auth === 'string' && auth.startsWith('Bearer ')
        ? auth.slice(7)
        : undefined;
    if (!token) throw new UnauthorizedException('No token');

    // `roomActor` — кто именно пишет. Нужен потолку на запись в чате: без него
    // один зациклившийся клиент заглушил бы всю комнату.
    const lkSubject = this.livekitSubjectForRoom(token, roomName);
    if (lkSubject) {
      req.roomActor = lkSubject;
      return true;
    }

    const userId = await this.entitledUserId(token, roomName);
    if (userId) {
      req.roomActor = userId;
      return true;
    }

    throw new ForbiddenException('No access to this room');
  }

  /** A LiveKit grant is scoped to one room, so it proves presence in it.
   *  Returns the token subject, which identifies the sender (see the class
   *  doc for the shapes that can take).
   *
   *  The `'livekit'` fallback is not just a label: `canActivate` treats a
   *  falsy return as "no proof" and denies access, so a valid grant must
   *  never resolve to `null`/`''` here merely because the token happened
   *  not to carry a `sub` claim — that would turn a legitimate connection
   *  into a 403. Unreachable today (every place that mints a LiveKit token
   *  sets an identity, and livekit-server-sdk stores it as `sub`), but
   *  cheap insurance against a future minting path that forgets to. */
  private livekitSubjectForRoom(
    token: string,
    roomName: string,
  ): string | null {
    try {
      const payload = jwt.verify(token, LK_API_SECRET, {
        algorithms: ['HS256'],
      }) as jwt.JwtPayload & { video?: { room?: string } };
      if (payload?.video?.room !== roomName) return null;
      return typeof payload.sub === 'string' && payload.sub
        ? payload.sub
        : 'livekit';
    } catch {
      return null;
    }
  }

  private async entitledUserId(
    token: string,
    roomName: string,
  ): Promise<string | null> {
    let payload: any;
    try {
      const publicKeyPath =
        this.config.get<string>('jwt.publicKeyPath') ?? '';
      const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
      payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    } catch {
      return null;
    }
    if (!isApiAccessToken(payload)) return null;

    const userId: string = payload.sub;

    // Owner of the personal room, by naming convention.
    if (roomName.startsWith(`personal-${userId.substring(0, 8)}`)) {
      return userId;
    }

    // Rooms created via /voice/rooms/temporary and /rooms/public live in
    // PublicRoom, not CallLog — their creator owns them and must be able to
    // drive the recorder. Missing this locked the owner out of their own
    // temporary room (caught by the meeting-recording smoke suite).
    const publicRoom = await this.prisma.publicRoom.findFirst({
      where: { roomName, creatorId: userId },
      select: { id: true },
    });
    if (publicRoom) return userId;

    const log = await this.prisma.callLog.findUnique({ where: { roomName } });
    if (!log) return null;
    return log.participantIds.includes(userId) ? userId : null;
  }
}
