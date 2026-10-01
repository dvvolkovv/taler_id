import { createHash, randomBytes, timingSafeEqual } from 'crypto';

const KEY_PREFIX = 'tidp_';
const SLUG_RE = /^[a-z0-9-]{2,32}$/;
/** 32 случайных байта в base64url — 43 символа; меньше 32 точно не наш ключ. */
const MIN_SECRET_LENGTH = 32;

export function isValidPartnerSlug(slug: string): boolean {
  return SLUG_RE.test(slug);
}

/**
 * Новый ключ партнёра: `tidp_<slug>_<256 бит в base64url>`. Показывается один
 * раз при выпуске, в БД остаётся только хэш. В slug нет подчёркиваний, поэтому
 * первое подчёркивание после префикса однозначно отделяет его от секрета.
 */
export function generatePartnerKey(slug: string): string {
  if (!isValidPartnerSlug(slug))
    throw new Error(`invalid partner slug: ${slug}`);
  return `${KEY_PREFIX}${slug}_${randomBytes(32).toString('base64url')}`;
}

/** Достаёт slug из ключа. null — ключ не нашего формата. */
export function parsePartnerKey(key: string): { slug: string } | null {
  if (typeof key !== 'string' || !key.startsWith(KEY_PREFIX)) return null;
  const rest = key.slice(KEY_PREFIX.length);
  const sep = rest.indexOf('_');
  if (sep <= 0) return null;
  const slug = rest.slice(0, sep);
  const secret = rest.slice(sep + 1);
  if (!isValidPartnerSlug(slug) || secret.length < MIN_SECRET_LENGTH)
    return null;
  return { slug };
}

export function hashPartnerKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

/** Сверка за постоянное время: хэши одной длины по построению. */
export function partnerKeyMatches(key: string, storedHash: string): boolean {
  const a = Buffer.from(hashPartnerKey(key), 'hex');
  const b = Buffer.from(storedHash ?? '', 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
