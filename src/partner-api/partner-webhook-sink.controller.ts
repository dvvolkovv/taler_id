import { Controller, Headers, HttpCode, NotFoundException, Param, PayloadTooLargeException, Post, Req } from '@nestjs/common';
import { PartnerRegistryService } from '../partner-core/partner-registry.service';
import { decryptWebhookSecret } from '../partner-core/partner-secrets.util';
import { verifyWebhookSignature } from '../partner-core/partner-webhook-events';
import { PartnerWebhookSinkStore } from './partner-webhook-sink.store';

/** Как kyc.controller.ts: только то, что нужно здесь — захваченные main.ts сырые байты тела. */
interface RawBodyRequest {
  rawBody?: Buffer;
}

const SINK_BODY_MAX_BYTES = 64 * 1024;

/**
 * Тестовый приёмник вебхуков для e2e-набора: вебхук тестового партнёра `e2e`
 * указывает сюда, набор забирает событие через GET /partner/v1/_sink/events и
 * сверяет подпись. Работает только при PARTNER_WEBHOOK_SINK=true (DEV/TEST);
 * на PROD переменная не задаётся, и здесь 404.
 *
 * Без ключа партнёра это открытый HTTP-эндпоинт (его зовёт наш же исходящий
 * отправитель, у которого ключа нет) — поэтому подлинность проверяется тут
 * же, тем же X-TalerID-Signature над сырыми байтами тела (req.rawBody), что и
 * в deliver(); иначе любой мог бы анонимно забивать Redis и подсовывать e2e
 * набору чужие события. Любой отказ — 404, без разбивки на 401/403: партнёру
 * тестового приёмника незачем знать, что здесь вообще проверяется подпись.
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
    @Req() req: RawBodyRequest,
  ): Promise<{ ok: true }> {
    if (!PartnerWebhookSinkStore.enabled()) throw new NotFoundException();
    const partner = await this.registry.findBySlug(slug);
    if (!partner?.webhookSecretEnc) throw new NotFoundException();
    const rawBody = req.rawBody ?? Buffer.alloc(0);
    const bodyText = rawBody.toString('utf8');
    let secret: string;
    try {
      secret = decryptWebhookSecret(partner.webhookSecretEnc);
    } catch {
      throw new NotFoundException();
    }
    if (!verifyWebhookSignature(secret, headers['x-talerid-signature'], bodyText)) {
      throw new NotFoundException();
    }
    // Подпись проверена до предела размера: партнёр с верным секретом не
    // должен узнавать из кода ответа, что тело ограничено по размеру — тело
    // просто не сохранится.
    if (rawBody.byteLength > SINK_BODY_MAX_BYTES) throw new PayloadTooLargeException();
    await this.store.push(slug, {
      receivedAt: new Date().toISOString(),
      event: headers['x-talerid-event'] ?? null,
      delivery: headers['x-talerid-delivery'] ?? null,
      signature: headers['x-talerid-signature'] ?? null,
      // Сырые байты, а не JSON.stringify(распарсенного тела): повторная
      // сериализация не гарантированно воспроизводит то, что подписывалось
      // (да и теперь по этим самым байтам только что сверялась подпись).
      body: bodyText,
    });
    return { ok: true };
  }
}
