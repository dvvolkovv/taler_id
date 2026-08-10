import { isIP } from 'net';

/** Потолок длины ссылки: всё длиннее — почти наверняка не ссылка на страницу. */
const MAX_URL_LENGTH = 2048;

/**
 * Приводит ссылку к виду, пригодному для запроса и для ключа кэша, либо
 * возвращает null, если ходить по ней нельзя.
 *
 * Отсекается всё, кроме http/https: `file://` прочитал бы диск сервера,
 * `data:` и `javascript:` вообще не адреса ресурсов. Логин с паролем в URL
 * запрещён — это способ показать один хост, а сходить на другой.
 *
 * Якорь отбрасывается: он не влияет на ответ сервера, а кэш из-за него дробился
 * бы на десяток записей об одной странице.
 */
export function normalizePreviewUrl(raw: string | null | undefined): string | null {
  if (!raw || raw.length > MAX_URL_LENGTH) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (u.username || u.password) return null;
  u.hash = '';
  const out = u.toString();
  return out.length > MAX_URL_LENGTH ? null : out;
}

/**
 * Адрес, по которому серверу ходить нельзя.
 *
 * Превью строится по ссылке из чужого сообщения, то есть цель выбирает кто
 * угодно. Без этой проверки любой участник заставил бы бэкенд постучаться во
 * внутреннюю сеть — в базу, в Redis, в метаданные облака (169.254.169.254) или
 * в соседнюю ноду VPC.
 *
 * Проверять надо именно разрешённый IP, а не имя хоста: имя может резолвиться
 * во что угодно, и перепроверять придётся после каждого редиректа.
 */
export function isPrivateAddress(address: string): boolean {
  const kind = isIP(address);
  if (kind === 4) return isPrivateV4(address);
  if (kind === 6) return isPrivateV6(address);
  // Не адрес — считаем небезопасным: звать сюда с именем хоста нельзя.
  return true;
}

function isPrivateV4(address: string): boolean {
  const parts = address.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return true;
  const [a, b] = parts;
  if (a === 0) return true; // «этот» хост
  if (a === 10) return true; // RFC1918
  if (a === 127) return true; // loopback целиком, не только 127.0.0.1
  if (a === 169 && b === 254) return true; // link-local + метаданные облака
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
  if (a === 192 && b === 168) return true; // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 192 && b === 0) return true; // 192.0.0.0/24 и 192.0.2.0/24
  if (a >= 224) return true; // multicast и зарезервированное, включая 255.255.255.255
  return false;
}

function isPrivateV6(address: string): boolean {
  const lower = address.toLowerCase();
  // IPv4-mapped (::ffff:10.0.0.1) — иначе проверка обходится в одну строку.
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateV4(mapped[1]);
  if (lower === '::' || lower === '::1') return true;
  if (lower.startsWith('fe80')) return true; // link-local
  if (/^f[cd]/.test(lower)) return true; // unique-local fc00::/7
  if (lower.startsWith('ff')) return true; // multicast
  return false;
}
