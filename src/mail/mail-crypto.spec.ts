import { encryptSecret, decryptSecret } from './mail-crypto';

const KEY = 'a'.repeat(64); // 32 bytes hex

describe('mail-crypto', () => {
  it('roundtrips a secret', () => {
    const enc = encryptSecret('S3cret-Пароль!', KEY);
    expect(enc).not.toContain('S3cret');
    expect(decryptSecret(enc, KEY)).toBe('S3cret-Пароль!');
  });

  it('produces different ciphertext each time (random IV)', () => {
    expect(encryptSecret('x', KEY)).not.toBe(encryptSecret('x', KEY));
  });

  it('fails on wrong key', () => {
    const enc = encryptSecret('x', KEY);
    expect(() => decryptSecret(enc, 'b'.repeat(64))).toThrow();
  });

  it('fails on tampered payload', () => {
    const enc = encryptSecret('x', KEY);
    const buf = Buffer.from(enc, 'base64');
    buf[buf.length - 1] ^= 0xff;
    expect(() => decryptSecret(buf.toString('base64'), KEY)).toThrow();
  });
});
