import { createHash, randomInt } from 'crypto';

/**
 * The one-time code in the host's QR (talerid://interp/<code>). Base32 without
 * I, O, 0 and 1, so it can also be read off the screen and typed. Eight
 * characters are 40 bits: with a 5-minute life, one use and a per-user limit
 * on join attempts, guessing a live code is out of reach.
 */
export const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const CODE_LENGTH = 8;
export const CODE_TTL_MS = 5 * 60_000;

const CODE_SHAPE = new RegExp(`^[${CODE_ALPHABET}]{${CODE_LENGTH}}$`);

export function generateCode(): string {
  let code = '';
  for (let i = 0; i < CODE_LENGTH; i++) {
    code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  }
  return code;
}

/** The code as generated, or null if the input cannot be one. */
export function normalizeCode(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const code = raw.toUpperCase().replace(/[\s-]/g, '');
  return CODE_SHAPE.test(code) ? code : null;
}

/** Only the hash is stored: a leaked row must not let anyone join. */
export function hashCode(code: string): string {
  return createHash('sha256').update(code).digest('hex');
}
