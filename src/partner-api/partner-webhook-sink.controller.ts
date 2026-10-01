import { Body, Controller, Headers, HttpCode, NotFoundException, Param, Post } from '@nestjs/common';
import { PartnerRegistryService } from '../partner-core/partner-registry.service';
import { PartnerWebhookSinkStore } from './partner-webhook-sink.store';

/**
 * Тестовый приёмник вебхуков для e2e-набора: вебхук тестового партнёра `e2e`
 * указывает сюда, набор забирает событие через GET /partner/v1/_sink/events и
 * сверяет подпись. Работает только при PARTNER_WEBHOOK_SINK=true (DEV/TEST);
 * на PROD переменная не задаётся, и здесь 404.
 */
@Controller('partner/v1/_sink')
export class PartnerWebhookSinkController {
  constructor(
    private readonly registry: PartnerRegistryService,
    private readonly store: PartnerWebhookSinkStore,
  ) {}

  @Post(':slug')
  @HttpCode(200)
  async receive(
    @Param('slug') slug: string,
    @Headers() headers: Record<string, string>,
    @Body() body: unknown,
  ): Promise<{ ok: true }> {
    if (!PartnerWebhookSinkStore.enabled()) throw new NotFoundException();
    if (!(await this.registry.findBySlug(slug))) throw new NotFoundException();
    await this.store.push(slug, {
      receivedAt: new Date().toISOString(),
      event: headers['x-talerid-event'] ?? null,
      delivery: headers['x-talerid-delivery'] ?? null,
      signature: headers['x-talerid-signature'] ?? null,
      // Тело уже разобрано JSON-парсером Nest. JSON.stringify возвращает ровно
      // ту строку, что подписывалась: отправитель сериализует простой объект.
      body: JSON.stringify(body),
    });
    return { ok: true };
  }
}
