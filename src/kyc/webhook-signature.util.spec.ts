import { createHmac } from 'crypto';
import { verifyWebhookSignature } from './webhook-signature.util';

const SECRET = 'shared-secret';
const BODY = Buffer.from('{"applicantId":"abc","type":"applicantReviewed"}');

const sign = (alg: string) =>
  createHmac(alg, SECRET).update(BODY).digest('hex');

describe('verifyWebhookSignature', () => {
  it('accepts SHA-1, which is what welid actually sends', () => {
    // Реальный вызов из welid приходил с 40-символьным дайджестом и без
    // заголовка алгоритма; мы считали SHA-256 и отбивали каждый колбэк.
    const sig = sign('sha1');
    expect(sig).toHaveLength(40);
    expect(verifyWebhookSignature(BODY, sig, undefined, SECRET)).toBe(true);
  });

  it('accepts SHA-256', () => {
    expect(verifyWebhookSignature(BODY, sign('sha256'), undefined, SECRET)).toBe(true);
  });

  it('accepts SHA-512', () => {
    expect(verifyWebhookSignature(BODY, sign('sha512'), undefined, SECRET)).toBe(true);
  });

  it('honours the algorithm header when it is present', () => {
    expect(verifyWebhookSignature(BODY, sign('sha1'), 'HMAC_SHA1_HEX', SECRET)).toBe(true);
    expect(verifyWebhookSignature(BODY, sign('sha256'), 'HMAC_SHA256_HEX', SECRET)).toBe(true);
    expect(verifyWebhookSignature(BODY, sign('sha512'), 'HMAC_SHA512_HEX', SECRET)).toBe(true);
  });

  it('rejects a digest signed with a different algorithm than declared', () => {
    // Заголовок говорит одно, подпись сделана другим — доверяем заголовку.
    expect(verifyWebhookSignature(BODY, sign('sha1'), 'HMAC_SHA256_HEX', SECRET)).toBe(false);
  });

  it('rejects a wrong secret', () => {
    const foreign = createHmac('sha1', 'not-our-secret').update(BODY).digest('hex');
    expect(verifyWebhookSignature(BODY, foreign, undefined, SECRET)).toBe(false);
  });

  it('rejects a tampered body', () => {
    const sig = sign('sha1');
    const tampered = Buffer.from('{"applicantId":"abc","type":"applicantApproved"}');
    expect(verifyWebhookSignature(tampered, sig, undefined, SECRET)).toBe(false);
  });

  it('rejects a missing or malformed signature', () => {
    expect(verifyWebhookSignature(BODY, '', undefined, SECRET)).toBe(false);
    expect(verifyWebhookSignature(BODY, undefined as any, undefined, SECRET)).toBe(false);
    expect(verifyWebhookSignature(BODY, 'не-hex', undefined, SECRET)).toBe(false);
  });

  it('rejects a digest of unknown length when no header says otherwise', () => {
    // Длина — единственная подсказка без заголовка; чужая длина = чужой формат.
    expect(verifyWebhookSignature(BODY, 'ab12', undefined, SECRET)).toBe(false);
  });

  it('refuses to verify without a secret', () => {
    expect(verifyWebhookSignature(BODY, sign('sha1'), undefined, '')).toBe(false);
  });

  it('ignores the case of the hex digest', () => {
    expect(verifyWebhookSignature(BODY, sign('sha1').toUpperCase(), undefined, SECRET)).toBe(true);
  });

  it('rejects an unsupported algorithm header instead of guessing', () => {
    expect(verifyWebhookSignature(BODY, sign('sha1'), 'HMAC_MD5_HEX', SECRET)).toBe(false);
  });
});
