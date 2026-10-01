import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { partnerWebhookBackoff, WebhookEvent } from './partner-webhook-events';
import { PARTNER_WEBHOOK_QUEUE } from './partner.constants';
import { PartnerWebhooksService } from './partner-webhooks.service';

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
    const result = await this.webhooks.deliver(job.data.partnerId, job.data.event, job.attemptsMade + 1);
    // Партнёр снял вебхук — повторять некуда.
    if (!result.delivered && result.error !== 'webhook_not_configured') {
      throw new Error(`webhook ${job.data.event.id} to ${job.data.partnerId}: ${result.error}`);
    }
  }
}
