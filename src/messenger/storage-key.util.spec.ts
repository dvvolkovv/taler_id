import { storageKeyFromUrl } from './storage-key.util';

describe('storageKeyFromUrl', () => {
  it('extracts the key from a download url', () => {
    expect(
      storageKeyFromUrl(
        'https://staging.id.taler.tirol/messenger/files/download?key=voice%2Fabc.m4a',
      ),
    ).toBe('voice/abc.m4a');
  });

  it('works regardless of the host', () => {
    // Один и тот же файл на DEV, TEST и PROD отдаётся с разных доменов.
    expect(
      storageKeyFromUrl('https://api.talerid.io/messenger/files/download?key=a.m4a'),
    ).toBe('a.m4a');
  });

  it('ignores a url that is not a download link', () => {
    expect(storageKeyFromUrl('https://example.com/some/file.m4a')).toBeNull();
    expect(storageKeyFromUrl('https://staging.id.taler.tirol/messenger/files')).toBeNull();
  });

  it('ignores a download link without a key', () => {
    expect(storageKeyFromUrl('https://x.test/messenger/files/download')).toBeNull();
  });

  it('refuses a key trying to climb out of the bucket', () => {
    expect(
      storageKeyFromUrl('https://x.test/messenger/files/download?key=..%2F..%2Fetc%2Fpasswd'),
    ).toBeNull();
  });

  it('survives garbage', () => {
    expect(storageKeyFromUrl('not a url')).toBeNull();
    expect(storageKeyFromUrl(null)).toBeNull();
    expect(storageKeyFromUrl(undefined)).toBeNull();
  });
});
