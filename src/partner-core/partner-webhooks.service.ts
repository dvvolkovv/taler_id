import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
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
   * Связки всех участников — одним запросом: пошаговые запросы по участникам
   * уже роняли рассылку по системному каналу на PROD (2026-07-24).
   */
  async planFanOut(args: {
    conversationId: string;
    participantIds: string[];
    senderId: string;
    systemPost: boolean;
  }): Promise<PartnerFanOut | null> {
    if (process.env.PARTNER_API_ENABLED !== 'true' || args.systemPost) return null;
    try {
      const conv = await this.prisma.conversation.findUnique({
        where: { id: args.conversationId },
        select: { type: true, name: true },
      });
      if (!conv || !isPartnerConversationType(conv.type)) return null;
      const links = await this.prisma.partnerLink.findMany({
        where: {
          userId: { in: args.participantIds },
          status: 'ACTIVE',
          partner: { enabled: true, webhookUrl: { not: null } },
        },
        select: { userId: true, externalId: true, partnerId: true },
      });
      if (links.length === 0) return null;
      const conversation = {
        id: args.conversationId,
        type: conv.type,
        title: conv.type === 'GROUP' ? (conv.name ?? null) : null,
      };
      return {
        enqueue: (recipientUserId, input) => {
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
        removeOnComplete: 1000,
        removeOnFail: 1000,
      },
    );
  }
}
