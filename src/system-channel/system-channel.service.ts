import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { MessengerService } from '../messenger/messenger.service';
import {
  SYSTEM_USER_EMAIL,
  SYSTEM_USERNAME,
  SYSTEM_CHANNEL_NAME,
} from './system-channel.constants';

export { SYSTEM_USER_EMAIL, SYSTEM_USERNAME, SYSTEM_CHANNEL_NAME };

@Injectable()
export class SystemChannelService implements OnApplicationBootstrap {
  private readonly logger = new Logger(SystemChannelService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly gateway: MessengerGateway,
    private readonly messenger: MessengerService,
  ) {}

  async onApplicationBootstrap() {
    try {
      await this.ensureSeeded();
      // autopostLatestRelease() will be added in Task 5 — not called yet
    } catch (e) {
      this.logger.error(
        `System channel seed failed: ${(e as Error).message}`,
      );
    }
  }

  async ensureSeeded(): Promise<{ userId: string; channelId: string }> {
    // 1. Ensure system user exists
    let sysUser = await this.prisma.user.findUnique({
      where: { email: SYSTEM_USER_EMAIL },
    });
    if (!sysUser) {
      sysUser = await this.prisma.user.create({
        data: {
          email: SYSTEM_USER_EMAIL,
          username: SYSTEM_USERNAME,
          // Random hex instead of a real bcrypt hash — bcrypt.compare always
          // returns false, making login impossible for this system account.
          passwordHash: crypto.randomBytes(32).toString('hex'),
          profile: { create: { firstName: 'Taler ID', lastName: '' } },
          kycRecord: { create: {} },
        },
      });
    }

    // 2. Ensure system channel exists
    let channel = await this.prisma.conversation.findFirst({
      where: { isSystem: true },
    });
    if (!channel) {
      channel = await this.prisma.conversation.create({
        data: {
          type: 'CHANNEL',
          isSystem: true,
          name: SYSTEM_CHANNEL_NAME,
          participants: {
            create: { userId: sysUser.id, role: 'OWNER' },
          },
        },
      });
    }

    // 3. Backfill all users as SUBSCRIBER in batches (idempotent via skipDuplicates)
    const BATCH = 500;
    let cursor: string | undefined;
    for (;;) {
      const users = await this.prisma.user.findMany({
        take: BATCH,
        ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        orderBy: { id: 'asc' },
        select: { id: true },
      });
      if (users.length === 0) break;
      await this.prisma.conversationParticipant.createMany({
        data: users.map((u) => ({
          conversationId: channel!.id,
          userId: u.id,
          role: 'SUBSCRIBER',
        })),
        skipDuplicates: true,
      });
      cursor = users[users.length - 1].id;
      if (users.length < BATCH) break;
    }

    return { userId: sysUser.id, channelId: channel.id };
  }

  async subscribeUser(userId: string): Promise<void> {
    const channels = await this.prisma.conversation.findMany({
      where: { isSystem: true },
      select: { id: true },
    });
    if (channels.length === 0) return;
    await this.prisma.conversationParticipant.createMany({
      data: channels.map((c) => ({ conversationId: c.id, userId, role: 'SUBSCRIBER' })),
      skipDuplicates: true,
    });
  }
}
