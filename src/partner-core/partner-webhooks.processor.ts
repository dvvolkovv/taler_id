import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { partnerWebhookBackoff, WebhookEvent } from './partner-webhook-events';
import { PARTNER_WEBHOOK_QUEUE } from './partner.constants';
import { PartnerWebhooksService } from './partner-webhooks.service';

/** Коды deliver(), которые означают «решение принято, повторять не надо» — не обязательно успех (см. link_not_active), просто не исключение. */
const DROPPED_WITHOUT_RETRY = new Set(['webhook_not_configured', 'link_not_active']);

/**
 * Воркер `partner-webhooks`. Работает на каждой ноде, очередь общая в Redis.
 * Неудача → исключение → BullMQ повторяет по partnerWebhookBackoff; после
 * последней попытки событие остаётся в журнале доставок и больше не шлётся.
 */
@Processor(PARTNER_WEBHOOK_QUEUE, {
  concurrency: 10,
  settings: { backoffStrategy: (attemptsMade: number) => partnerWebhookBackoff(attemptsMade) },
})
export class PartnerWebhooksProcessor extends WorkerHost {
  private readonly logger = new Logger(PartnerWebhooksProcessor.name);

  constructor(private readonly webhooks: PartnerWebhooksService) {
    super();
  }

  async process(job: Job<{ partnerId: string; event: WebhookEvent }>): Promise<void> {
    if (job.name !== 'deliver') {
      this.logger.warn(`Unknown job name '${job.name}' on ${PARTNER_WEBHOOK_QUEUE}`);
      return;
    }
    const attempt = job.attemptsMade + 1;
    const result = await this.webhooks.deliver(job.data.partnerId, job.data.event, attempt);
    if (result.delivered || (result.error && DROPPED_WITHOUT_RETRY.has(result.error))) return;
    // Последняя попытка перед тем, как BullMQ сдастся окончательно — отдельная
    // warn-строка для мониторинга простоя партнёра (только slug/id события/код
    // ошибки, без тела и секрета): свой failed-статус в Redis недолговечен
    // (removeOnFail: true) и сам по себе не алертит никого.
    const maxAttempts = job.opts?.attempts;
    if (typeof maxAttempts === 'number' && attempt >= maxAttempts) {
      this.logger.warn(
        `webhook delivery permanently failed: partner=${result.partnerSlug ?? job.data.partnerId} event=${job.data.event.id} error=${result.error}`,
      );
    }
    throw new Error(`webhook ${job.data.event.id} to ${job.data.partnerId}: ${result.error}`);
  }
}
