import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const ALG = 'aes-256-gcm';
const IV_LEN = 12;
const SALT_LEN = 16;
const TAG_LEN = 16;

function keyFromSecret(secret: string, salt: Buffer): Buffer {
  return scryptSync(secret, salt, 32);
}

export function encrypt(plaintext: string, secret: string): string {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = keyFromSecret(secret, salt);
  const cipher = createCipheriv(ALG, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, enc]).toString('base64');
}

export function decrypt(ciphertextB64: string, secret: string): string {
  const buf = Buffer.from(ciphertextB64, 'base64');
  const salt = buf.subarray(0, SALT_LEN);
  const iv = buf.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const tag = buf.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const enc = buf.subarray(SALT_LEN + IV_LEN + TAG_LEN);
  const key = keyFromSecret(secret, salt);
  const decipher = createDecipheriv(ALG, key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString('utf8');
}
