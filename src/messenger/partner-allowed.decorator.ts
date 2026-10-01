import { SetMetadata } from '@nestjs/common';

export const PARTNER_ALLOWED_KEY = 'partnerAllowed';

export interface PartnerAllowedOptions {
  /** Параметр маршрута с id беседы: беседа не того типа закрыта для партнёра. */
  conversationParam?: string;
  /** Параметр маршрута с id сообщения: то же по беседе этого сообщения. */
  messageParam?: string;
}

/**
 * Открывает обработчик мессенджера для партнёрского токена. Без декоратора
 * партнёр получает 403 — новые ручки закрыты для партнёров, пока их не откроют.
 */
export const PartnerAllowed = (options: PartnerAllowedOptions = {}) =>
  SetMetadata(PARTNER_ALLOWED_KEY, options);
