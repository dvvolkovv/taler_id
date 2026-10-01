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

/** Ровно то, что хранится в журнале Redis и что отдаёт GET webhooks/deliveries партнёру. */
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

/**
 * То, что deliver() отдаёт напрямую своему вызывающему (воркеру очереди) —
 * плюс slug партнёра для его предупреждающей строки на финальный провал
 * (мониторинг простоя). В журнал (и в deliveries() партнёру) slug не
 * попадает — никто за пределами воркера его не документирует и не ждёт.
 */
export interface DeliveryAttempt extends DeliveryResult {
  partnerSlug: string | null;
}

const DELIVERY_TIMEOUT_MS = 5_000;
// Партнёр может ответить чем угодно — нам важен только статус. Предел на
// размер ответа и text вместо auto-parse не дают случайному гигабайтному
// телу раздуть память воркера (инцидент: 150 МБ ответа → RSS 172→687 МБ).
const DELIVERY_RESPONSE_MAX_BYTES = 64 * 1024;
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
        // BullMQ 5 only age-sweeps a finished set when ANOTHER job finishes
        // into it — a lone final-failed job (with its message preview) could
        // sit in Redis forever otherwise. The journal (recentDeliveries) is
        // the durable attempt record; jobId dedup only needs to cover jobs
        // still in flight, so removing immediately on either outcome is safe.
        removeOnComplete: true,
        removeOnFail: true,
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
  async deliver(
    partnerId: string,
    event: WebhookEvent,
    attempt = 1,
    // Простой параметр метода, а не поле конструктора/DI-токен: deliver()
    // уже и так вызывается напрямую в спеках (без Nest-контейнера), и тесту
    // на реальный сервер нужен короткий дедлайн, не дожидаясь настоящих 5 с.
    deliveryTimeoutMs: number = DELIVERY_TIMEOUT_MS,
  ): Promise<DeliveryAttempt> {
    if (process.env.PARTNER_API_ENABLED !== 'true') {
      this.logger.debug(`webhook ${event.id} to ${partnerId} dropped: partner API is off`);
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered: false, status: null, error: 'webhook_not_configured', durationMs: 0, partnerSlug: null,
      });
    }
    const partner = await this.registry.findById(partnerId);
    if (!partner?.enabled || !partner.webhookUrl || !partner.webhookSecretEnc) {
      this.logger.debug(`webhook ${event.id} to ${partnerId} dropped: partner disabled or webhook not configured`);
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered: false, status: null, error: 'webhook_not_configured', durationMs: 0,
        partnerSlug: partner?.slug ?? null,
      });
    }
    // Связку могли отозвать уже после того, как событие встало в очередь
    // (ретраи растянуты до ~1.5 ч) — слать (и тем более повторять) вебхук про
    // уже отвязанного человека смысла нет. Применимо только к message.created:
    // у ping нет конкретного получателя.
    if (event.type === 'message.created') {
      const recipientUserId = (event as { recipient?: { talerUserId?: string } }).recipient?.talerUserId;
      if (recipientUserId) {
        const link = await this.prisma.partnerLink.findUnique({
          where: { partnerId_userId: { partnerId, userId: recipientUserId } },
          select: { status: true },
        });
        if (!link || link.status !== 'ACTIVE') {
          this.logger.debug(`webhook ${event.id} to ${partnerId} dropped: link_not_active`);
          return this.record(partnerId, {
            eventId: event.id, type: event.type, attempt,
            delivered: false, status: null, error: 'link_not_active', durationMs: 0, partnerSlug: partner.slug,
          });
        }
      }
    }
    let secret: string;
    try {
      secret = decryptWebhookSecret(partner.webhookSecretEnc);
    } catch {
      // Секрет шифруется общим для ноды PARTNER_SECRETS_KEY — рассинхрон
      // ключа на одной ноде не должен ронять доставку без следа в журнале
      // (и не должен светить ни секрет, ни тело в логе). Ретраится: другая
      // нода с верным ключом может доставить.
      this.logger.warn(`webhook secret undecryptable for partner ${partner.slug} (${partnerId})`);
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered: false, status: null, error: 'secret_unreadable', durationMs: 0, partnerSlug: partner.slug,
      });
    }
    const body = JSON.stringify(event);
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signWebhook(secret, timestamp, body);
    const started = Date.now();
    // Общий дедлайн на весь запрос — не только на паузы между байтами.
    // axios' собственный `timeout` сбрасывается на каждый пришедший байт,
    // поэтому ответ по байту в секунду держал воркер все 5 с и всё равно
    // отчитывался как "доставлено" (инцидент: 20 таких подряд заняли все
    // воркеры на обеих нодах). Держим сигнал в переменной: по нему и узнаём,
    // ЧТО оборвало запрос — дедлайн или что-то другое (см. catch ниже).
    const deadline = AbortSignal.timeout(deliveryTimeoutMs);
    try {
      const res = await axios.post(partner.webhookUrl, body, {
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'TalerID-Webhooks/1',
          'X-TalerID-Event': event.type,
          'X-TalerID-Delivery': event.id,
          'X-TalerID-Signature': signature,
        },
        signal: deadline,
        maxRedirects: 0,
        maxContentLength: DELIVERY_RESPONSE_MAX_BYTES,
        responseType: 'text',
        validateStatus: () => true,
      });
      const delivered = res.status >= 200 && res.status < 300;
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered, status: res.status, error: delivered ? null : `http_${res.status}`,
        durationMs: Date.now() - started, partnerSlug: partner.slug,
      });
    } catch (e) {
      const message = (e as { message?: string })?.message ?? '';
      // Короткий детерминированный код вместо произвольного текста ошибки —
      // по нему и журнал читается глазами, и мониторинг может агрегировать.
      //
      // Не судим по имени/коду ошибки: axios заворачивает обрыв по
      // AbortSignal в CanceledError (имя не 'TimeoutError', а сообщение —
      // просто "canceled"), поэтому единственный надёжный признак именно
      // НАШЕГО дедлайна — то, что сам signal реально сработал (deadline.aborted).
      // А ERR_BAD_RESPONSE бывает не только при превышении maxContentLength:
      // "Request stream has been aborted" (приёмник оборвал соединение
      // посреди тела) — тот же код, но это не превышение лимита; отличаем по
      // тексту, который для maxContentLength детерминированный.
      const error = deadline.aborted
        ? 'timeout'
        : message.startsWith('maxContentLength')
          ? 'response_too_large'
          : (message || 'unknown_error').slice(0, 200);
      return this.record(partnerId, {
        eventId: event.id, type: event.type, attempt,
        delivered: false, status: null, error, durationMs: Date.now() - started, partnerSlug: partner.slug,
      });
    }
  }

  /** Последние попытки доставки, новые сначала. */
  async recentDeliveries(partnerId: string, limit: number): Promise<DeliveryResult[]> {
    const count = Math.min(Math.max(Math.floor(limit) || 50, 1), 200);
    const rows = await this.redis.getClient().lrange(logKey(partnerId), 0, count - 1);
    return rows.map((row) => JSON.parse(row) as DeliveryResult);
  }

  private async record(
    partnerId: string,
    result: Omit<DeliveryAttempt, 'at'>,
  ): Promise<DeliveryAttempt> {
    const { partnerSlug, ...journaled } = result;
    const entry: DeliveryResult = { ...journaled, at: new Date().toISOString() };
    try {
      const client = this.redis.getClient();
      // partnerSlug нарочно не входит в entry — он только для предупреждения
      // воркера в памяти, в журнале (и в deliveries() партнёру) его не будет.
      await client.lpush(logKey(partnerId), JSON.stringify(entry));
      await client.ltrim(logKey(partnerId), 0, DELIVERY_LOG_MAX - 1);
    } catch (e) {
      this.logger.warn(`webhook log write failed for ${partnerId}: ${(e as Error).message}`);
    }
    return { ...entry, partnerSlug };
  }
}
