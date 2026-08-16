import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Заголовок алгоритма → имя для crypto. Значения такие же, как у Sumsub:
 * поставщик присылает их в `x-payload-digest-alg`.
 */
const ALGORITHMS: Record<string, string> = {
  HMAC_SHA1_HEX: 'sha1',
  HMAC_SHA256_HEX: 'sha256',
  HMAC_SHA512_HEX: 'sha512',
};

/**
 * Если заголовка алгоритма нет, определяем его по длине шестнадцатеричного
 * дайджеста — она однозначна: 40 символов SHA-1, 64 SHA-256, 128 SHA-512.
 */
const BY_LENGTH: Record<number, string> = {
  40: 'sha1',
  64: 'sha256',
  128: 'sha512',
};

/**
 * Проверка подписи входящего колбэка KYC.
 *
 * Раньше алгоритм был жёстко зашит на SHA-256, а welid подписывает SHA-1 и
 * заголовка с алгоритмом не присылает вовсе — из-за этого **каждый** колбэк
 * отбивался с «Invalid webhook signature», и статусы верификации до нас не
 * доезжали.
 *
 * Заголовку доверяем в первую очередь: если он говорит SHA-256, а подпись
 * сделана SHA-1, это не «надо подобрать», а несовпадение.
 *
 * Сравнение постоянное по времени: `!==` на строках выходит на первом
 * различающемся символе и подсказывает, сколько угадано.
 */
export function verifyWebhookSignature(
  body: Buffer,
  signature: string | undefined | null,
  algorithmHeader: string | undefined | null,
  secret: string,
): boolean {
  if (!secret) return false;
  if (typeof signature !== 'string' || !/^[0-9a-fA-F]+$/.test(signature)) {
    return false;
  }

  let algorithm: string | undefined;
  if (algorithmHeader) {
    algorithm = ALGORITHMS[algorithmHeader.toUpperCase()];
    // Незнакомый алгоритм — отказ, а не молчаливый подбор.
    if (!algorithm) return false;
  } else {
    algorithm = BY_LENGTH[signature.length];
    if (!algorithm) return false;
  }

  const expected = createHmac(algorithm, secret).update(body).digest('hex');
  const received = signature.toLowerCase();
  if (received.length !== expected.length) return false;

  return timingSafeEqual(
    Buffer.from(received, 'utf8'),
    Buffer.from(expected, 'utf8'),
  );
}
