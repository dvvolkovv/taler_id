const LOCALPART_RE = /^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$/;

const RESERVED = new Set([
  'admin', 'administrator', 'postmaster', 'abuse', 'noreply', 'no-reply',
  'support', 'root', 'security', 'hostmaster', 'webmaster', 'info',
  'billing', 'sales', 'help', 'mail', 'mailer-daemon', 'taler', 'talerid',
  'contact', 'legal', 'privacy', 'team', 'official', 'notifications',
]);

export function normalizeLocalpart(raw: string): string {
  return raw.trim().toLowerCase();
}

/** null = ок; 'INVALID' | 'RESERVED' = причина отказа */
export function validateLocalpart(localpart: string): 'INVALID' | 'RESERVED' | null {
  if (!LOCALPART_RE.test(localpart) || localpart.includes('..')) return 'INVALID';
  if (RESERVED.has(localpart)) return 'RESERVED';
  return null;
}
