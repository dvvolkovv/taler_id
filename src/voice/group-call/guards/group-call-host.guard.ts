import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';

/**
 * Host-only authorization guard for `GroupCallController` endpoints that
 * require host privileges (invite/kick/mute-all/end). Reads `:id` from the
 * route params and `req.user.id` (set by JwtAuthGuard upstream), then asks
 * Prisma whether the call's `hostUserId` matches.
 *
 * Layered AFTER `JwtAuthGuard` — `req.user` must exist by the time this guard runs.
 */
@Injectable()
export class GroupCallHostGuard implements CanActivate {
  constructor(private readonly prisma: PrismaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const userId = req.user?.sub;
    const callId = req.params.id;
    if (!userId || !callId) {
      throw new ForbiddenException();
    }
    const call = await this.prisma.groupCall.findUnique({
      where: { id: callId },
      select: { hostUserId: true },
    });
    if (!call || call.hostUserId !== userId) {
      throw new ForbiddenException('Host only');
    }
    return true;
  }
}
