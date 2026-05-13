import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'crypto';

const ALG = 'aes-256-gcm';
const IV_LEN = 12;
const SALT_LEN = 16;
const TAG_LEN = 16;
const VERSION_LEN = 1;

// Version byte identifies the KDF+cipher parameter set. To rotate, add a new
// version and a branch in `deriveKey`. Never reuse a version number.
const CURRENT_VERSION = 1;

// scrypt N/r/p pinned so defaults can change without breaking stored ciphertexts.
// N=16384 ≈ 16 MB memory, adequate for 2026 at per-request scale.
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function deriveKey(secret: string, salt: Buffer, version: number): Buffer {
  if (version !== CURRENT_VERSION) {
    throw new Error(`unsupported encryption version ${version}`);
  }
  return scryptSync(secret, salt, 32, SCRYPT_PARAMS);
}

export function encrypt(plaintext: string, secret: string): string {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = deriveKey(secret, salt, CURRENT_VERSION);
  const cipher = createCipheriv(ALG, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const version = Buffer.from([CURRENT_VERSION]);
  return Buffer.concat([version, salt, iv, tag, enc]).toString('base64');
}

export function decrypt(ciphertextB64: string, secret: string): string {
  const buf = Buffer.from(ciphertextB64, 'base64');
  if (buf.length < VERSION_LEN + SALT_LEN + IV_LEN + TAG_LEN) {
    throw new Error('ciphertext too short');
  }
  const version = buf[0];
  const salt = buf.subarray(VERSION_LEN, VERSION_LEN + SALT_LEN);
  const iv = buf.subarray(
    VERSION_LEN + SALT_LEN,
    VERSION_LEN + SALT_LEN + IV_LEN,
  );
  const tag = buf.subarray(
    VERSION_LEN + SALT_LEN + IV_LEN,
    VERSION_LEN + SALT_LEN + IV_LEN + TAG_LEN,
  );
  const enc = buf.subarray(VERSION_LEN + SALT_LEN + IV_LEN + TAG_LEN);
  const key = deriveKey(secret, salt, version);
  const decipher = createDecipheriv(ALG, key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString('utf8');
}
