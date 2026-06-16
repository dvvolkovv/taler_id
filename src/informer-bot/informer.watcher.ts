import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { InformerClient } from './informer.client';
import { InformerBotService } from './informer-bot.service';
import {
  formatNewOperatorWalletAlert,
  formatDowntimeAlert,
} from './informer.formatters';
import {
  InformerAuthError,
  InformerNotConfiguredError,
} from './informer.types';

const ADVISORY_LOCK_ID = 87349126;
const BOOTSTRAP_KEY = 'informer:bootstrapped';
const BOOTSTRAP_TTL_SEC = 60 * 60 * 24 * 30; // 30 days
const DOWNTIME_THRESHOLD = 3;
const SEEN_RETENTION_DAYS = 30;

@Injectable()
export class InformerWatcher {
  private readonly logger = new Logger(InformerWatcher.name);
  private consecutiveFailures = 0;
  private downtimeAnnounced = false;
  private fatalError = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly client: InformerClient,
    private readonly service: InformerBotService,
    private readonly redis: RedisService,
  ) {}

  @Cron(CronExpression.EVERY_5_MINUTES)
  async tick(): Promise<void> {
    if (process.env.INFORMER_WATCHER_ENABLED === 'false') return;
    if (this.fatalError) return;
    let locked = false;
    try {
      const r = (await this.prisma.$queryRawUnsafe(
        `SELECT pg_try_advisory_lock(${ADVISORY_LOCK_ID}) as locked`,
      )) as { locked: boolean }[];
      locked = r?.[0]?.locked === true;
      if (!locked) return;
      await this.tickForTest();
    } finally {
      if (locked) {
        await this.prisma
          .$queryRawUnsafe(`SELECT pg_advisory_unlock(${ADVISORY_LOCK_ID})`)
          .catch(() => {});
      }
    }
  }

  async tickForTest(): Promise<{ newCount: number; bootstrapped: boolean }> {
    let list;
    try {
      list = await this.client.getOperatorRequiredList(1, 500);
      this.consecutiveFailures = 0;
      this.downtimeAnnounced = false;
    } catch (e) {
      if (
        e instanceof InformerAuthError ||
        e instanceof InformerNotConfiguredError
      ) {
        this.logger.error(`fatal informer error: ${(e as Error).message}`);
        this.fatalError = true;
        return { newCount: 0, bootstrapped: false };
      }
      this.consecutiveFailures += 1;
      this.logger.warn(
        `transient informer error (${this.consecutiveFailures}): ${(e as Error).message}`,
      );
      if (
        this.consecutiveFailures >= DOWNTIME_THRESHOLD &&
        !this.downtimeAnnounced
      ) {
        await this.broadcastToAll(formatDowntimeAlert());
        this.downtimeAnnounced = true;
      }
      return { newCount: 0, bootstrapped: false };
    }

    const bootstrapped = await this.redis.get(BOOTSTRAP_KEY);
    if (!bootstrapped) {
      for (const item of list.items) {
        await this.prisma.informerSeenWallet
          .create({
            data: {
              address: item.withdraw_address,
              network: item.withdraw_network,
              token: item.withdraw_token,
              amount: item.withdraw_amount,
            },
          })
          .catch(() => {});
      }
      await this.redis.setEx(BOOTSTRAP_KEY, BOOTSTRAP_TTL_SEC, '1');
      this.logger.log(`bootstrap: seeded ${list.items.length} seen wallets`);
      return { newCount: 0, bootstrapped: true };
    }

    let newCount = 0;
    for (const item of list.items) {
      const seen = await this.prisma.informerSeenWallet.findUnique({
        where: {
          address_network_token: {
            address: item.withdraw_address,
            network: item.withdraw_network,
            token: item.withdraw_token,
          },
        },
      });
      if (seen) continue;
      await this.prisma.informerSeenWallet
        .create({
          data: {
            address: item.withdraw_address,
            network: item.withdraw_network,
            token: item.withdraw_token,
            amount: item.withdraw_amount,
          },
        })
        .catch(() => {});
      newCount += 1;
      const alert = formatNewOperatorWalletAlert(item);
      await this.broadcastToAll(alert);
    }
    return { newCount, bootstrapped: false };
  }

  private async broadcastToAll(content: string): Promise<void> {
    const userIds = await this.service.listWhitelistedUserIds();
    for (const userId of userIds) {
      try {
        const convId = await this.service.getOrCreateChat(userId);
        await this.service.publishBotMessage(userId, convId, content);
      } catch (e) {
        this.logger.warn(
          `failed to deliver informer alert to ${userId}: ${(e as Error).message}`,
        );
      }
    }
  }

  @Cron('0 4 * * *')
  async cleanupOldSeenWallets(): Promise<void> {
    const cutoff = new Date(Date.now() - SEEN_RETENTION_DAYS * 86400 * 1000);
    const r = await this.prisma.informerSeenWallet.deleteMany({
      where: { firstSeenAt: { lt: cutoff } },
    });
    this.logger.log(`cleanup: removed ${r.count} stale seen wallets`);
  }
}
