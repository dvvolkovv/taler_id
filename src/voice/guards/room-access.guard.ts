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
 * Proves the caller is entitled to act on `:roomName`.
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

    if (this.isLivekitTokenForRoom(token, roomName)) return true;
    if (await this.isEntitledUser(token, roomName)) return true;

    throw new ForbiddenException('No access to this room');
  }

  /** A LiveKit grant is scoped to one room, so it proves presence in it. */
  private isLivekitTokenForRoom(token: string, roomName: string): boolean {
    try {
      const payload = jwt.verify(token, LK_API_SECRET, {
        algorithms: ['HS256'],
      }) as jwt.JwtPayload & { video?: { room?: string } };
      return payload?.video?.room === roomName;
    } catch {
      return false;
    }
  }

  private async isEntitledUser(
    token: string,
    roomName: string,
  ): Promise<boolean> {
    let payload: any;
    try {
      const publicKeyPath =
        this.config.get<string>('jwt.publicKeyPath') ?? '';
      const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
      payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    } catch {
      return false;
    }
    if (!isApiAccessToken(payload)) return false;

    const userId: string = payload.sub;

    // Owner of the personal room, by naming convention.
    if (roomName.startsWith(`personal-${userId.substring(0, 8)}`)) return true;

    const log = await this.prisma.callLog.findUnique({ where: { roomName } });
    if (!log) return false;
    return log.participantIds.includes(userId);
  }
}
