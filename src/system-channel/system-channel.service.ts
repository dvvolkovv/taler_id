import { Injectable, Logger, NotFoundException, OnApplicationBootstrap } from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { MessengerService } from '../messenger/messenger.service';
import { RedisService } from '../redis/redis.service';
import {
  SYSTEM_USER_EMAIL,
  SYSTEM_USERNAME,
  SYSTEM_CHANNEL_NAME,
} from './system-channel.constants';
import { APP_RELEASES } from '../app-releases';

export { SYSTEM_USER_EMAIL, SYSTEM_USERNAME, SYSTEM_CHANNEL_NAME };

@Injectable()
export class SystemChannelService implements OnApplicationBootstrap {
  private readonly logger = new Logger(SystemChannelService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly gateway: MessengerGateway,
    private readonly messenger: MessengerService,
    private readonly redis: RedisService,
  ) {}

  onApplicationBootstrap() {
    // Fire-and-forget: fan-out релизного поста (FCM сотням юзеров) не должен
    // блокировать app.listen() — на DEV задержал старт на ~10с (2026-07-24)
    void this.seedInBackground();
  }

  private async seedInBackground() {
    try {
      await this.ensureSeeded();
      await this.autopostLatestRelease();
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
    // Логотип раздаётся самим бэкендом (public/brand), у каждого окружения свой URL.
    // app-icon-dark.png — тот же арт, что в иконках приложения (512px копия
    // assets/app_icon_dark.png из мобильного репо)
    const avatarUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/brand/app-icon-dark.png`;
    let channel = await this.prisma.conversation.findFirst({
      where: { isSystem: true },
    });
    if (!channel) {
      channel = await this.prisma.conversation.create({
        data: {
          type: 'CHANNEL',
          isSystem: true,
          name: SYSTEM_CHANNEL_NAME,
          avatarUrl,
          participants: {
            create: { userId: sysUser.id, role: 'OWNER' },
          },
        },
      });
    } else if (channel.avatarUrl !== avatarUrl) {
      // seed приводит аватар к каноничному (в т.ч. перезапись старого логотипа)
      channel = await this.prisma.conversation.update({
        where: { id: channel.id },
        data: { avatarUrl },
      });
    }

    // 3. Backfill all users as SUBSCRIBER in batches (idempotent via skipDuplicates)
    const BATCH = 500;
    let cursor: string | undefined;
    for (;;) {
      const users = await this.prisma.user.findMany({
        // Удалённые (deletedAt) аккаунты не подписываем — иначе рестарт
        // бэкенда возвращал в канал тысячи вычищенных тест-юзеров.
        where: { deletedAt: null },
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

  async autopostLatestRelease(): Promise<void> {
    const latest = APP_RELEASES[0];
    if (!latest) return;
    const channel = await this.prisma.conversation.findFirst({
      where: { isSystem: true },
    });
    const sysUser = await this.prisma.user.findUnique({
      where: { email: SYSTEM_USER_EMAIL },
    });
    if (!channel || !sysUser) return;

    // Advisory lock: prevents both PROD app-nodes from posting the same
    // release simultaneously on bootstrap. TTL of 5 min is the window;
    // version-idempotency check below still protects after TTL expiry.
    const lockKey = `system-channel:autopost:${latest.version}`;
    const acquired = await this.redis.getClient().set(lockKey, '1', 'EX', 300, 'NX');
    if (acquired !== 'OK') {
      this.logger.log(`Autopost ${latest.version}: lock held by another node, skipping`);
      return;
    }

    const lastPost = await this.prisma.message.findFirst({
      where: {
        conversationId: channel.id,
        metadata: { path: ['newsType'], equals: 'release' },
      },
      orderBy: { sentAt: 'desc' },
    });
    if ((lastPost?.metadata as any)?.version === latest.version) return;
    const content = `🚀 Taler ID ${latest.version}\n\n${latest.notes_ru}\n\n— EN —\n\n${latest.notes_en}`;
    await this.post(channel.id, sysUser.id, content, {
      newsType: 'release',
      version: latest.version,
    });
    this.logger.log(`Release ${latest.version} posted to system channel`);
  }

  private async post(
    channelId: string,
    senderId: string,
    content: string,
    metadata: Record<string, any>,
  ): Promise<{ messageId: string }> {
    const msg = await this.messenger.createMessage(
      channelId,
      senderId,
      content,
      undefined,
      undefined,
      undefined,
      metadata,
    );
    const full = await this.messenger.getMessageById(msg.id);
    if (full) {
      try {
        await this.gateway.deliverNewMessage(
          // reactions: [] — свежее сообщение, реакций ещё нет
          { ...full, senderName: 'Taler ID', reactions: [] },
          senderId,
          channelId,
          { senderName: 'Taler ID', systemPost: true },
        );
      } catch (e) {
        // Пост сохранён; доставка best-effort — сбой рассылки не должен
        // помечать seed как failed (PROD 2026-07-24, fetchSockets timeout)
        this.logger.warn(`system post delivery failed: ${(e as Error).message}`);
      }
    }
    return { messageId: msg.id };
  }

  async postNews(dto: {
    type: 'news' | 'critical';
    text_ru: string;
    text_en?: string;
    minVersion?: string;
  }): Promise<{ messageId: string }> {
    const channel = await this.prisma.conversation.findFirst({ where: { isSystem: true } });
    const sysUser = await this.prisma.user.findUnique({ where: { email: SYSTEM_USER_EMAIL } });
    if (!channel || !sysUser) throw new NotFoundException('System channel is not seeded');
    const content = dto.text_en
      ? `${dto.text_ru}\n\n— EN —\n\n${dto.text_en}`
      : dto.text_ru;
    return this.post(channel.id, sysUser.id, content, {
      newsType: dto.type,
      ...(dto.minVersion ? { minVersion: dto.minVersion } : {}),
    });
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
