import type { ConvType } from '@prisma/client';

/**
 * Партнёрский API мессенджера: общие константы.
 * Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 */

/** Scope токенов партнёра. Мессенджер принимает его вместо токена входа TalerID. */
export const MESSENGER_SCOPE = 'messenger';

/** Какие беседы видит и может трогать партнёрский токен. */
export const PARTNER_CONVERSATION_TYPES = ['DIRECT', 'GROUP'] as const satisfies readonly ConvType[];

export function isPartnerConversationType(type: string | null | undefined): boolean {
  return (PARTNER_CONVERSATION_TYPES as readonly string[]).includes(type ?? '');
}

/** Совпадает с ttl.AccessToken в oidc-provider.factory.ts. */
export const PARTNER_ACCESS_TOKEN_TTL_SECONDS = 900;

export const PARTNER_WEBHOOK_QUEUE = 'partner-webhooks';

/** Текст отказа, когда партнёрский токен пришёл туда, куда ему нельзя. */
export const PARTNER_FORBIDDEN = 'not_available_for_partner';

/** Комната Socket.IO со всеми сокетами одного гранта: так отзыв рвёт их разом. */
export function partnerGrantRoom(grantId: string): string {
  return `pgrant:${grantId}`;
}

/** Кто стоит за партнёрским токеном. */
export interface PartnerPrincipal {
  userId: string;
  partnerId: string;
  partnerSlug: string;
  grantId: string;
  /** Когда токен истекает, unix-секунды. */
  expiresAt: number;
}

/** Пришёл ли запрос мессенджера по партнёрскому токену (см. MessengerAuthGuard). */
export function isPartnerCaller(user: unknown): user is { sub: string; partner: PartnerPrincipal } {
  return !!(user as { partner?: unknown } | null | undefined)?.partner;
}
