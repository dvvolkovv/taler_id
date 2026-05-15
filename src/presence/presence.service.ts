import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { resolveUserIdOrUsername } from '../common/utils/user-id.util';

export interface PresenceResult {
  isOnline: boolean | null;
  lastSeenAt: string | null;
  hidden: boolean;
}

@Injectable()
export class PresenceService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
  ) {}

  async ping(userId: string): Promise<void> {
    await this.redis.setEx(`presence:online:${userId}`, 90, '1');
    // Atomic SET NX EX: only the first concurrent pinger acquires the DB-write
    // slot for the 60s throttle window; others early-return. Matches the idiom
    // used in group-call.service.ts.
    const acquired = await this.redis
      .getClient()
      .set(`presence:dbwrite:${userId}`, '1', 'EX', 60, 'NX');
    if (acquired !== 'OK') return;
    await this.prisma.profile.update({
      where: { userId },
      data: { lastSeenAt: new Date() },
    });
  }

  async getPresence(viewerId: string, targetIdOrUsername: string): Promise<PresenceResult> {
    // Accept either a userId (UUID) or a username — share-link deep-link
    // (https://id.taler.tirol/u/<username>) hits this endpoint with username.
    const targetUserId = await resolveUserIdOrUsername(this.prisma, targetIdOrUsername);
    if (!targetUserId) return { isOnline: null, lastSeenAt: null, hidden: true };

    const profile = await this.prisma.profile.findUnique({
      where: { userId: targetUserId },
      select: { lastSeenPrivacy: true, lastSeenAt: true },
    });
    if (!profile) return { isOnline: null, lastSeenAt: null, hidden: true };

    const isSelf = viewerId === targetUserId;
    if (!isSelf) {
      if (profile.lastSeenPrivacy === 'NOBODY') {
        return { isOnline: null, lastSeenAt: null, hidden: true };
      }
      if (profile.lastSeenPrivacy === 'CONTACTS') {
        const contact = await this.prisma.contactRequest.findFirst({
          where: {
            status: 'ACCEPTED',
            OR: [
              { senderId: viewerId, receiverId: targetUserId },
              { senderId: targetUserId, receiverId: viewerId },
            ],
          },
          select: { id: true },
        });
        if (!contact) return { isOnline: null, lastSeenAt: null, hidden: true };
      }
    }

    const online = await this.redis.getClient().exists(`presence:online:${targetUserId}`);
    return {
      isOnline: online === 1,
      lastSeenAt: profile.lastSeenAt ? profile.lastSeenAt.toISOString() : null,
      hidden: false,
    };
  }
}
