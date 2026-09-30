import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { decryptSecret, encryptSecret } from '../mail/mail-crypto';

/**
 * Мастер-ключ партнёрских секретов: 64 hex-символа (`openssl rand -hex 32`).
 * На всех нодах окружения он обязан совпадать — секрет вебхука, зашифрованный
 * на одной ноде, расшифровывает воркер очереди на любой другой.
 */
function masterKey(): Buffer {
  const hex = process.env.PARTNER_SECRETS_KEY ?? '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('PARTNER_SECRETS_KEY must be 64 hex chars (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
}

/** Отдельный подключ на каждое назначение: один ключ не служит и шифром, и HMAC. */
function derive(label: string): Buffer {
  return createHmac('sha256', masterKey()).update(label).digest();
}

export function generateWebhookSecret(): string {
  return `whsec_${randomBytes(32).toString('base64url')}`;
}

export function encryptWebhookSecret(secret: string): string {
  return encryptSecret(secret, derive('webhook-secret').toString('hex'));
}

export function decryptWebhookSecret(payload: string): string {
  return decryptSecret(payload, derive('webhook-secret').toString('hex'));
}

/** Код привязки храним только как HMAC, привязанный к конкретной связке. */
export function hashLinkCode(linkId: string, code: string): string {
  return createHmac('sha256', derive('link-code')).update(`${linkId}:${code}`).digest('hex');
}

export function linkCodeMatches(linkId: string, code: string, storedHash: string): boolean {
  const a = Buffer.from(hashLinkCode(linkId, code), 'hex');
  const b = Buffer.from(storedHash ?? '', 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
