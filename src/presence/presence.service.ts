import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';

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
    const throttleKey = `presence:dbwrite:${userId}`;
    const throttled = await this.redis.get(throttleKey);
    if (throttled) return;
    await this.redis.setEx(throttleKey, 60, '1');
    await this.prisma.profile.update({
      where: { userId },
      data: { lastSeenAt: new Date() },
    });
  }

  async getPresence(viewerId: string, targetUserId: string): Promise<PresenceResult> {
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
