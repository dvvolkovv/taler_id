const INLINE_SAFE_PREFIXES = ['image/', 'video/', 'audio/'];
const INLINE_SAFE_MIMES = new Set(['application/pdf', 'text/plain']);
// Types that can execute script in the browser even though they match a safe prefix
const FORBIDDEN_INLINE_MIMES = new Set(['image/svg+xml']);

export function isInlineSafeMime(mime: string | undefined | null): boolean {
  if (!mime) return false;
  const m = mime.toLowerCase().split(';')[0].trim();
  if (FORBIDDEN_INLINE_MIMES.has(m)) return false;
  if (INLINE_SAFE_MIMES.has(m)) return true;
  return INLINE_SAFE_PREFIXES.some((p) => m.startsWith(p));
}

const ALLOWED_DOWNLOAD_PREFIXES = [
  'files/',
  'thumbs/',
  'recordings/',
  'backgrounds/',
];

export function isAllowedDownloadKey(key: string): boolean {
  if (key.includes('..')) return false;
  return ALLOWED_DOWNLOAD_PREFIXES.some((p) => key.startsWith(p));
}

export function attachmentFilenameFromKey(key: string): string {
  const base = key.split('/').pop() ?? 'file';
  const safe = base.replace(/[^\w.\-]/g, '_');
  return safe || 'file';
}
