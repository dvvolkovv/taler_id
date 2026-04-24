import { encrypt, decrypt } from './encryption';

const SECRET = 'unit-test-secret-32chars-xxxxxxxxxxxx';

describe('encryption', () => {
  it('round-trips plaintext through encrypt → decrypt', () => {
    const plain = 'correct horse battery staple twelve words of mnemonic yeah';
    const ct = encrypt(plain, SECRET);
    expect(ct).not.toContain(plain);
    expect(decrypt(ct, SECRET)).toBe(plain);
  });

  it('produces different ciphertext for identical plaintexts (per-record salt)', () => {
    const plain = 'same plaintext';
    const ct1 = encrypt(plain, SECRET);
    const ct2 = encrypt(plain, SECRET);
    expect(ct1).not.toBe(ct2);
    expect(decrypt(ct1, SECRET)).toBe(plain);
    expect(decrypt(ct2, SECRET)).toBe(plain);
  });

  it('decrypt throws on wrong secret', () => {
    const ct = encrypt('hello', SECRET);
    expect(() => decrypt(ct, 'different-secret-of-sufficient-length-xxxxxx')).toThrow();
  });

  it('decrypt throws on tampered ciphertext (GCM integrity)', () => {
    const ct = encrypt('hello', SECRET);
    const buf = Buffer.from(ct, 'base64');
    // Flip a byte in the ciphertext portion (after version+salt+iv+tag = 1+16+12+16 = 45)
    buf[46] ^= 0xff;
    const tampered = buf.toString('base64');
    expect(() => decrypt(tampered, SECRET)).toThrow();
  });

  it('decrypt throws on truncated input', () => {
    expect(() => decrypt('aGVsbG8=', SECRET)).toThrow(/too short/);
  });

  it('decrypt throws on unsupported version byte', () => {
    const ct = encrypt('hello', SECRET);
    const buf = Buffer.from(ct, 'base64');
    buf[0] = 99; // unsupported version
    expect(() => decrypt(buf.toString('base64'), SECRET)).toThrow(/unsupported encryption version/);
  });
});
