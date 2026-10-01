import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import type { ConvType } from '@prisma/client';
import { Queue } from 'bullmq';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { PartnerRegistryService } from './partner-registry.service';
import {
  buildMessageCreatedEvent,
  MessageCreatedInput,
  WEBHOOK_MAX_ATTEMPTS,
  WebhookEvent,
} from './partner-webhook-events';
import { isPartnerConversationType, PARTNER_WEBHOOK_QUEUE } from './partner.constants';

/** Что шлюз мессенджера делает с планом: ставит событие получателю, если нужно. */
export interface PartnerFanOut {
  /** Никогда не бросает и не ждёт: доставка сообщения от вебхука не зависит. */
  enqueue(recipientUserId: string, input: MessageCreatedInput): void;
}

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
}
