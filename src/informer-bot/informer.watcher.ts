import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import BigNumber from 'bignumber.js';
import { randomUUID } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { InformerClient } from './informer.client';
import { InformerBotService } from './informer-bot.service';
import {
  formatNewOperatorWalletAlert,
  formatDowntimeAlert,
  formatInformerConfigAlert,
  formatInformerRecovered,
  formatRefillDigest,
} from './informer.formatters';
import {
  InformerAuthError,
  InformerError,
  InformerNotConfiguredError,
  RefillDeficit,
} from './informer.types';

const BOOTSTRAP_KEY = 'informer:bootstrapped';
const BOOTSTRAP_TTL_SEC = 60 * 60 * 24 * 30; // 30 days
const DOWNTIME_THRESHOLD = 3;
const SEEN_RETENTION_DAYS = 30;

// One tick at a time across app nodes. Expires before the next cron fire, so
// a process that dies holding it costs at most one tick.
const TICK_LOCK_KEY = 'informer:watcher_tick';
const TICK_LOCK_TTL_SEC = 4 * 60;
// Consecutive failed list fetches, counted across nodes: whichever node wins
// the lock runs the tick, so a per-process counter could never reach the
// threshold on PROD.
const FAILURES_KEY = 'informer:watcher_failures';
const FAILURES_TTL_SEC = 60 * 60;
// An auth or "not configured" error won't pass in five minutes, but must not
// stop the watcher until a restart either (2026-11-16): pause, then retry.
const BACKOFF_KEY = 'informer:watcher_backoff';
const CONFIG_ERROR_BACKOFF_SEC = 30 * 60;
// Set while an announced incident lasts; outlives the daily reminder, so a
// recovery right after a reminder lapsed is still announced.
const INCIDENT_KEY = 'informer:incident';
const INCIDENT_TTL_SEC = 7 * 24 * 60 * 60;
const INCIDENT_REMINDED_PREFIX = 'informer:incident_reminded:';
const INCIDENT_REMIND_SEC = 24 * 60 * 60;
// Heartbeat: wall-clock ms of the last tick that reached the upstream list
// (bootstrap counts). Read by GET /informer-bot/health for external monitoring
// — the watcher is otherwise silent on success, so a silent stall (process
// wedged, lock never released, upstream quietly 5xx) was invisible until now.
const LAST_OK_TICK_KEY = 'informer:last_ok_tick';
const LAST_OK_TICK_TTL_SEC = 7 * 24 * 60 * 60;

type IncidentKind = 'auth' | 'not_configured' | 'unavailable';
const INCIDENT_KINDS: IncidentKind[] = [
  'auth',
  'not_configured',
  'unavailable',
];

const STAGE_INTERVALS = [
  { from: 0, after: 0, nextStage: 1 }, // initial → STAGE 1
  { from: 1, after: 30 * 60, nextStage: 2 }, // +30 min → STAGE 2
  { from: 2, after: 60 * 60, nextStage: 3 }, // +60 min → STAGE 3
  // stage 3 → silence
];

@Injectable()
export class InformerWatcher {
  private readonly logger = new Logger(InformerWatcher.name);
  private readonly SAFETY_MARGIN_PCT = new BigNumber('0.10');

  constructor(
    private readonly prisma: PrismaService,
    private readonly client: InformerClient,
    private readonly service: InformerBotService,
    private readonly redis: RedisService,
  ) {}

  @Cron(CronExpression.EVERY_5_MINUTES)
  async tick(): Promise<void> {
    if (process.env.INFORMER_WATCHER_ENABLED === 'false') return;
    if (await this.redis.get(BACKOFF_KEY)) return;
    // Not pg_try_advisory_lock: Prisma ran the lock and the unlock on
    // different pooled connections, so the unlock missed and the lock stayed
    // on an idle connection, quietly skipping later ticks (2026-11-16).
    const token = randomUUID();
    if (!(await this.redis.setNxEx(TICK_LOCK_KEY, TICK_LOCK_TTL_SEC, token))) {
      return;
    }
    try {
      const { ok } = await this.tickForTest();
      // The refill check needs the same wallet list that just failed.
      if (!ok) return;
      // Heartbeat for /informer-bot/health: a successful upstream fetch.
      await this.redis
        .setEx(LAST_OK_TICK_KEY, LAST_OK_TICK_TTL_SEC, String(Date.now()))
        .catch(() => {});
      try {
        await this.tickRefillForTest();
      } catch (e) {
        this.logger.warn(
          `tickRefillForTest failed: ${(e as Error).message}`,
        );
      }
    } finally {
      await this.redis.delIfEquals(TICK_LOCK_KEY, token).catch(() => {});
    }
  }

  async tickForTest(): Promise<{
    ok: boolean;
    newCount: number;
    bootstrapped: boolean;
  }> {
    let list;
    try {
      list = await this.client.getOperatorRequiredList(1, 500);
    } catch (e) {
      await this.onListFailure(e);
      return { ok: false, newCount: 0, bootstrapped: false };
    }
    await this.closeIncident();

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
      return { ok: true, newCount: 0, bootstrapped: true };
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
    return { ok: true, newCount, bootstrapped: false };
  }

  private async onListFailure(e: unknown): Promise<void> {
    const status =
      e instanceof InformerError && e.upstreamStatus != null
        ? ` upstreamStatus=${e.upstreamStatus}`
        : '';
    if (
      e instanceof InformerAuthError ||
      e instanceof InformerNotConfiguredError
    ) {
      const kind = e instanceof InformerAuthError ? 'auth' : 'not_configured';
      this.logger.error(
        `informer ${kind} error, next check in ${CONFIG_ERROR_BACKOFF_SEC / 60} min: ${e.message}${status}`,
      );
      await this.redis.setEx(BACKOFF_KEY, CONFIG_ERROR_BACKOFF_SEC, kind);
      await this.reportIncident(kind, formatInformerConfigAlert(kind));
      return;
    }
    const failures = await this.redis.incr(FAILURES_KEY);
    await this.redis.expire(FAILURES_KEY, FAILURES_TTL_SEC);
    this.logger.warn(
      `transient informer error (${failures}): ${(e as Error).message}${status}`,
    );
    if (failures >= DOWNTIME_THRESHOLD) {
      await this.reportIncident('unavailable', formatDowntimeAlert());
    }
  }

  /** Tells every operator once per incident kind, again daily while it lasts. */
  private async reportIncident(
    kind: IncidentKind,
    content: string,
  ): Promise<void> {
    await this.redis.setEx(INCIDENT_KEY, INCIDENT_TTL_SEC, kind);
    const due = await this.redis.setNxEx(
      INCIDENT_REMINDED_PREFIX + kind,
      INCIDENT_REMIND_SEC,
      '1',
    );
    if (due) await this.broadcastToAll(content);
  }

  private async closeIncident(): Promise<void> {
    await this.redis.del(FAILURES_KEY);
    if (!(await this.redis.get(INCIDENT_KEY))) return;
    await this.redis.del(INCIDENT_KEY);
    for (const kind of INCIDENT_KINDS) {
      await this.redis.del(INCIDENT_REMINDED_PREFIX + kind);
    }
    this.logger.log('informer answers again, incident closed');
    await this.broadcastToAll(formatInformerRecovered());
  }

  async computeRefillDeficits(): Promise<RefillDeficit[]> {
    const operatorList = await this.client.getOperatorRequiredList(1, 500);

    // Group pending withdrawals by (network, token)
    const pending = new Map<
      string,
      { network: string; token: string; total: BigNumber }
    >();
    for (const item of operatorList.items) {
      const key = `${item.withdraw_network}::${item.withdraw_token}`;
      const cur = pending.get(key) ?? {
        network: item.withdraw_network,
        token: item.withdraw_token,
        total: new BigNumber(0),
      };
      cur.total = cur.total.plus(new BigNumber(item.withdraw_amount));
      pending.set(key, cur);
    }

    if (pending.size === 0) return [];

    const balances = await this.client.getMiniAcquiringBalances();
    const out: RefillDeficit[] = [];

    for (const { network, token, total: pendingTotal } of pending.values()) {
      const chain = balances.chains.find((c) => c.chain === network);
      if (!chain || !Array.isArray(chain.roles)) continue;
      const hot = chain.roles.find(
        (r) => r.role === 'hot_wallet' && !r.error,
      );
      if (!hot || !Array.isArray(hot.balances)) continue;
      const bal = hot.balances.find((b) => b.asset === token && !b.error);
      if (!bal) continue;

      const hotBalance = new BigNumber(bal.balance);
      const available = hotBalance.times(
        new BigNumber(1).minus(this.SAFETY_MARGIN_PCT),
      );
      const deficit = pendingTotal.minus(available);
      if (deficit.lte(0)) continue;

      out.push({
        chain: network,
        token,
        hotAddress: hot.address,
        hotBalance: hotBalance.toFixed(),
        pendingTotal: pendingTotal.toFixed(),
        availableForWithdrawal: available.toFixed(),
        deficit: deficit.toFixed(),
      });
    }

    return out;
  }

  async tickRefillForTest(): Promise<{ usersNotified: number }> {
    const deficits = await this.computeRefillDeficits();
    const userIds = await this.service.listWhitelistedUserIds();
    let notified = 0;

    for (const userId of userIds) {
      const cfg = await this.prisma.informerAlertConfig.findUnique({
        where: { userId },
      });
      const enabled = cfg?.enabled ?? true;
      const snoozed = (cfg?.snoozedUntil ?? new Date(0)) > new Date();
      const stage = cfg?.lastDigestStage ?? 0;
      const lastAt = cfg?.lastDigestAt ?? null;

      if (deficits.length === 0) {
        if (stage !== 0 || lastAt !== null) {
          await this.upsertConfig(userId, {
            lastDigestStage: 0,
            lastDigestAt: null,
          });
        }
        continue;
      }

      if (!enabled || snoozed) continue;

      const rule = STAGE_INTERVALS.find((r) => r.from === stage);
      if (!rule) continue; // already at stage 3, silent
      const elapsedSec = lastAt
        ? (Date.now() - lastAt.getTime()) / 1000
        : Number.POSITIVE_INFINITY;
      if (elapsedSec < rule.after) continue;

      const md = formatRefillDigest(deficits, rule.nextStage as 1 | 2 | 3);
      const convId = await this.service.getOrCreateChat(userId);
      await this.service.publishBotMessage(userId, convId, md);
      await this.upsertConfig(userId, {
        lastDigestStage: rule.nextStage,
        lastDigestAt: new Date(),
      });
      notified++;
    }

    return { usersNotified: notified };
  }

  private async upsertConfig(
    userId: string,
    patch: { lastDigestStage?: number; lastDigestAt?: Date | null },
  ): Promise<void> {
    await this.prisma.informerAlertConfig.upsert({
      where: { userId },
      update: patch,
      create: { userId, ...patch },
    });
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

  /**
   * Health snapshot for external monitoring (GET /informer-bot/health). Pure
   * Redis reads, no upstream call, so it is cheap to poll. `lastOkTickAgeSec`
   * is how long ago the watcher last reached the admin-API list; null or a
   * value well over the 5-min cadence means the watcher has not completed a
   * successful fetch (wedged, in backoff, or disabled). `backoff`/`incident`
   * expose an already-detected, already-announced outage and its kind.
   */
  async getHealth(): Promise<{
    watcherEnabled: boolean;
    lastOkTickAgeSec: number | null;
    backoff: string | null;
    incident: string | null;
  }> {
    const watcherEnabled = process.env.INFORMER_WATCHER_ENABLED !== 'false';
    const raw = await this.redis.get(LAST_OK_TICK_KEY);
    const lastOkTickAgeSec =
      raw != null && raw !== ''
        ? Math.max(0, Math.round((Date.now() - Number(raw)) / 1000))
        : null;
    const backoff = await this.redis.get(BACKOFF_KEY);
    const incident = await this.redis.get(INCIDENT_KEY);
    return { watcherEnabled, lastOkTickAgeSec, backoff, incident };
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
