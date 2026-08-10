import { isPrivateAddress, normalizePreviewUrl } from './link-preview.guard';

describe('normalizePreviewUrl', () => {
  it('accepts a plain https url', () => {
    expect(normalizePreviewUrl('https://example.com/a')).toBe('https://example.com/a');
  });

  it('accepts http', () => {
    expect(normalizePreviewUrl('http://example.com')).toBe('http://example.com/');
  });

  it('rejects anything that is not http(s)', () => {
    // file:// прочитал бы диск сервера, gopher:// и прочее — лишние протоколы.
    expect(normalizePreviewUrl('file:///etc/passwd')).toBeNull();
    expect(normalizePreviewUrl('ftp://example.com')).toBeNull();
    expect(normalizePreviewUrl('javascript:alert(1)')).toBeNull();
    expect(normalizePreviewUrl('data:text/html,<h1>hi')).toBeNull();
  });

  it('rejects a url with credentials', () => {
    // user:pass@host — способ подсунуть один хост, а сходить на другой.
    expect(normalizePreviewUrl('https://user:pass@example.com')).toBeNull();
  });

  it('rejects garbage', () => {
    expect(normalizePreviewUrl('not a url')).toBeNull();
    expect(normalizePreviewUrl('')).toBeNull();
    expect(normalizePreviewUrl(null as any)).toBeNull();
  });

  it('drops the fragment so the cache does not split on anchors', () => {
    expect(normalizePreviewUrl('https://example.com/a#section')).toBe('https://example.com/a');
  });

  it('rejects an absurdly long url instead of storing it', () => {
    expect(normalizePreviewUrl('https://example.com/' + 'a'.repeat(3000))).toBeNull();
  });
});

describe('isPrivateAddress', () => {
  it('blocks loopback', () => {
    expect(isPrivateAddress('127.0.0.1')).toBe(true);
    expect(isPrivateAddress('127.13.37.1')).toBe(true);
    expect(isPrivateAddress('::1')).toBe(true);
  });

  it('blocks the RFC1918 ranges', () => {
    expect(isPrivateAddress('10.0.0.1')).toBe(true);
    expect(isPrivateAddress('192.168.1.1')).toBe(true);
    expect(isPrivateAddress('172.16.0.1')).toBe(true);
    expect(isPrivateAddress('172.31.255.255')).toBe(true);
  });

  it('lets the rest of 172.x through', () => {
    // 172.32.0.0 уже публичный — граница диапазона живая, её легко перепутать.
    expect(isPrivateAddress('172.32.0.1')).toBe(false);
    expect(isPrivateAddress('172.15.0.1')).toBe(false);
  });

  it('blocks link-local and cloud metadata', () => {
    // 169.254.169.254 — метаданные облака, классическая цель SSRF.
    expect(isPrivateAddress('169.254.169.254')).toBe(true);
  });

  it('blocks the VPC range this project actually uses', () => {
    // DO VPC 10.130.0.0/20 — попадает в 10/8, но проверить стоит явно.
    expect(isPrivateAddress('10.130.0.13')).toBe(true);
  });

  it('blocks CGNAT, 0.0.0.0 and broadcast', () => {
    expect(isPrivateAddress('100.64.0.1')).toBe(true);
    expect(isPrivateAddress('0.0.0.0')).toBe(true);
    expect(isPrivateAddress('255.255.255.255')).toBe(true);
  });

  it('blocks IPv6 unique-local and link-local', () => {
    expect(isPrivateAddress('fd00::1')).toBe(true);
    expect(isPrivateAddress('fe80::1')).toBe(true);
  });

  it('blocks IPv4-mapped IPv6 pointing at a private address', () => {
    // ::ffff:127.0.0.1 — обход проверки, если смотреть только на строку.
    expect(isPrivateAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateAddress('::ffff:10.0.0.1')).toBe(true);
  });

  it('lets public addresses through', () => {
    expect(isPrivateAddress('93.184.216.34')).toBe(false);
    expect(isPrivateAddress('2606:2800:220:1:248:1893:25c8:1946')).toBe(false);
  });
});
