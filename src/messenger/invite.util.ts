import { randomBytes } from 'crypto';

/** Длина кода в байтах до кодирования; 12 байт → 16 символов base64url. */
const CODE_BYTES = 12;

const MIN_USERNAME = 5;
const MAX_USERNAME = 32;

/**
 * Имена, которые нельзя отдавать беседам: они заняты маршрутами и служебными
 * страницами, и ссылка `/@admin` вела бы не туда, куда человек думает.
 */
const RESERVED = new Set([
  'admin', 'api', 'app', 'auth', 'billing', 'help', 'invite', 'invites',
  'login', 'mail', 'me', 'oauth', 'profile', 'room', 'settings', 'support',
  'system', 'taler', 'talerid', 'ui', 'voice', 'well-known',
]);

/**
 * Приводит публичное имя беседы к каноническому виду или отвергает его.
 *
 * Регистр опускается: иначе `@News` и `@news` — две разные беседы, и ссылка
 * ведёт не туда, куда человек набрал. Начинаться имя должно с буквы — так его
 * не спутать с идентификатором и не сломать разбор упоминаний.
 */
export function normalizePublicUsername(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.trim().replace(/^@/, '').toLowerCase();
  if (trimmed.length < MIN_USERNAME || trimmed.length > MAX_USERNAME) return null;
  if (!/^[a-z][a-z0-9_]*$/.test(trimmed)) return null;
  if (RESERVED.has(trimmed)) return null;
  return trimmed;
}

/**
 * Код приглашения.
 *
 * Криптостойкий и непредсказуемый: он единственное, что отделяет беседу от
 * посторонних, поэтому счётчики и метки времени тут не годятся.
 */
export function generateInviteCode(): string {
  return randomBytes(CODE_BYTES).toString('base64url');
}

export interface InviteState {
  revokedAt: Date | null;
  expiresAt: Date | null;
  maxUses: number | null;
  uses: number;
}

/**
 * Причина, по которой приглашением нельзя воспользоваться, либо null.
 *
 * Отдельная функция, потому что проверять это приходится дважды — при показе
 * превью и при самом вступлении, — и разъехавшиеся правила означали бы
 * «ссылка выглядит рабочей, а вступить нельзя».
 */
export function inviteUnusable(
  invite: InviteState,
  now: Date = new Date(),
): 'revoked' | 'expired' | 'exhausted' | null {
  if (invite.revokedAt) return 'revoked';
  if (invite.expiresAt && invite.expiresAt.getTime() <= now.getTime()) return 'expired';
  if (invite.maxUses !== null && invite.uses >= invite.maxUses) return 'exhausted';
  return null;
}
