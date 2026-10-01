import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import type { ConvType } from '@prisma/client';
import axios from 'axios';
import { Queue } from 'bullmq';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { decryptWebhookSecret } from './partner-secrets.util';
import { PartnerRegistryService } from './partner-registry.service';
import {
  buildMessageCreatedEvent,
  MessageCreatedInput,
  signWebhook,
  WEBHOOK_MAX_ATTEMPTS,
  WebhookEvent,
} from './partner-webhook-events';
import { isPartnerConversationType, PARTNER_WEBHOOK_QUEUE } from './partner.constants';

/** Что шлюз мессенджера делает с планом: ставит событие получателю, если нужно. */
export interface PartnerFanOut {
  /** Никогда не бросает и не ждёт: доставка сообщения от вебхука не зависит. */
  enqueue(recipientUserId: string, input: MessageCreatedInput): void;
}

export interface DeliveryResult {
  eventId: string;
  type: string;
  attempt: number;
  delivered: boolean;
  status: number | null;
  error: string | null;
  durationMs: number;
  at: string;
}

const DELIVERY_TIMEOUT_MS = 5_000;
const DELIVERY_LOG_MAX = 1_000;
const logKey = (partnerId: string) => `partner:webhook:log:${partnerId}`;

@Injectable()
export class PartnerWebhooksService {
  private readonly logger = new Logger(PartnerWebhooksService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly registry: PartnerRegistryService,
    private readonly redis: RedisService,
    @InjectQueue(PARTNER_WEBHOOK_QUEUE) private readonly queue: Queue,
  ) {}

  /**
   * Готовит рассылку по одному сообщению. null — вебхуки здесь не нужны:
   * API выключен, системный пост, не личный чат и не группа, или среди
   * участников нет никого с действующей связкой у партнёра с вебхуком.
   * Тип беседы — от вызывающего (шлюз мессенджера его уже знает из своего
   * fan-out), а не повторным запросом в базу. Сама беседа читается только
   * ради названия группы, и только после того, как нашлись связки: иначе
   * каждое сообщение в любой личный чат или группу стоило бы запрос в
   * Postgres впустую, пока не нашёлся ни один партнёр с вебхуком.
   * Связки всех участников — одним запросом: пошаговые запросы по участникам
   * уже роняли рассылку по системному каналу на PROD (2026-07-24).
   */
  async planFanOut(args: {
    conversationId: string;
    participantIds: string[];
    senderId: string;
    systemPost: boolean;
    conversationType: ConvType | string | null;
  }): Promise<PartnerFanOut | null> {
    if (process.env.PARTNER_API_ENABLED !== 'true' || args.systemPost) return null;
    const conversationType = args.conversationType ?? '';
    if (!isPartnerConversationType(conversationType)) return null;
    try {
      const links = await this.prisma.partnerLink.findMany({
        where: {
          userId: { in: args.participantIds },
          status: 'ACTIVE',
          partner: { enabled: true, webhookUrl: { not: null } },
        },
        select: { userId: true, externalId: true, partnerId: true },
      });
      if (links.length === 0) return null;
      let title: string | null = null;
      if (conversationType === 'GROUP') {
        const conv = await this.prisma.conversation.findUnique({
          where: { id: args.conversationId },
          select: { name: true },
        });
        title = conv?.name ?? null;
      }
      const conversation = { id: args.conversationId, type: conversationType, title };
      return {
        enqueue: (recipientUserId, input) => {
          try {
            if (recipientUserId === args.senderId) return;
            for (const link of links) {
              if (link.userId !== recipientUserId) continue;
              const senderLink = links.find((l) => l.userId === args.senderId && l.partnerId === link.partnerId);
              const event = buildMessageCreatedEvent({
                recipient: link,
                senderExternalId: senderLink?.externalId ?? null,
                conversation,
                input,
              });
              this.enqueueEvent(link.partnerId, event).catch((e) =>
                this.logger.warn(`enqueue ${event.id} failed: ${(e as Error).message}`),
              );
            }
          } catch (e) {
            // Обещание интерфейса PartnerFanOut — «никогда не бросает»: в
            // Task 34 этот вызов стоит прямо перед getFcmTokens внутри
            // per-recipient try шлюза, и падение здесь стоило бы человеку
            // его обычного TalerID-пуша.
            this.logger.warn(`enqueue to ${recipientUserId} failed: ${(e as Error).message}`);
          }
        },
      };
    } catch (e) {
      this.logger.warn(`planFanOut failed for ${args.conversationId}: ${(e as Error).message}`);
      return null;
    }
  }

  async enqueueEvent(partnerId: string, event: WebhookEvent): Promise<void> {
    await this.queue.add(
      'deliver',
      { partnerId, event },
      {
        // BullMQ не принимает «:» в своих id. Один и тот же id не встанет в
        // очередь дважды, пока задача хранится.
        jobId: `${partnerId}_${event.id}`,
        attempts: WEBHOOK_MAX_ATTEMPTS,
        backoff: { type: 'custom' },
        // Превью сообщений, имена и названия групп не должны висеть в Redis
        // неделями — хвост очереди ограничен и по возрасту, не только по count.
        removeOnComplete: { age: 3600, count: 1000 },
        removeOnFail: { age: 86400, count: 1000 },
      },
    );
  }

  /**
   * Одна попытка: подписать, отправить, записать в журнал. Не бросает —
   * решение о повторе принимает воркер очереди по полю delivered.
   *
   * Оба переключателя ниже должны останавливать уже стоящие в очереди
   * события и их повторы немедленно, а не через ~1.5 ч (все 6 шагов
   * backoff): иначе выключение партнёра или всего партнёрского API не
   * видно сразу.
   */
  async deliver(partnerId: string, event: WebhookEvent, attempt = 1): Promise<DeliveryResult> {
    if (process.env.PARTNER_API_ENABLED !== 'true') {
      this.logger.debug(`webhook ${event.id} to ${partnerId} dropped: partner API is off`);
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered: false, status: null, error: 'webhook_not_configured', durationMs: 0,
      });
    }
    const partner = await this.registry.findById(partnerId);
    if (!partner?.enabled || !partner.webhookUrl || !partner.webhookSecretEnc) {
      this.logger.debug(`webhook ${event.id} to ${partnerId} dropped: partner disabled or webhook not configured`);
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered: false, status: null, error: 'webhook_not_configured', durationMs: 0,
      });
    }
    const body = JSON.stringify(event);
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signWebhook(decryptWebhookSecret(partner.webhookSecretEnc), timestamp, body);
    const started = Date.now();
    try {
      const res = await axios.post(partner.webhookUrl, body, {
        headers: {
          'Content-Type': 'application/json',
          'X-TalerID-Event': event.type,
          'X-TalerID-Delivery': event.id,
          'X-TalerID-Signature': signature,
        },
        timeout: DELIVERY_TIMEOUT_MS,
        maxRedirects: 0,
        validateStatus: () => true,
      });
      const delivered = res.status >= 200 && res.status < 300;
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered, status: res.status, error: delivered ? null : `http_${res.status}`,
        durationMs: Date.now() - started,
      });
    } catch (e) {
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered: false, status: null, error: (e as Error).message.slice(0, 200),
        durationMs: Date.now() - started,
      });
    }
  }

  /** Последние попытки доставки, новые сначала. */
  async recentDeliveries(partnerId: string, limit: number): Promise<DeliveryResult[]> {
    const count = Math.min(Math.max(Math.floor(limit) || 50, 1), 200);
    const rows = await this.redis.getClient().lrange(logKey(partnerId), 0, count - 1);
    return rows.map((row) => JSON.parse(row) as DeliveryResult);
  }

  private async record(partnerId: string, result: Omit<DeliveryResult, 'at'>): Promise<DeliveryResult> {
    const entry: DeliveryResult = { ...result, at: new Date().toISOString() };
    try {
      const client = this.redis.getClient();
      await client.lpush(logKey(partnerId), JSON.stringify(entry));
      await client.ltrim(logKey(partnerId), 0, DELIVERY_LOG_MAX - 1);
    } catch (e) {
      this.logger.warn(`webhook log write failed for ${partnerId}: ${(e as Error).message}`);
    }
    return entry;
  }
}
