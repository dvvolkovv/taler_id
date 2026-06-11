import {
  isInlineSafeMime,
  isAllowedDownloadKey,
  attachmentFilenameFromKey,
} from './safe-mime';

describe('isInlineSafeMime', () => {
  it('allows common media types inline', () => {
    expect(isInlineSafeMime('image/jpeg')).toBe(true);
    expect(isInlineSafeMime('image/png')).toBe(true);
    expect(isInlineSafeMime('video/mp4')).toBe(true);
    expect(isInlineSafeMime('audio/mpeg')).toBe(true);
    expect(isInlineSafeMime('application/pdf')).toBe(true);
    expect(isInlineSafeMime('text/plain')).toBe(true);
    expect(isInlineSafeMime('text/plain; charset=utf-8')).toBe(true);
    expect(isInlineSafeMime('IMAGE/JPEG')).toBe(true);
  });

  it('rejects script-capable types', () => {
    expect(isInlineSafeMime('text/html')).toBe(false);
    expect(isInlineSafeMime('image/svg+xml')).toBe(false);
    expect(isInlineSafeMime('application/xhtml+xml')).toBe(false);
    expect(isInlineSafeMime('text/xml')).toBe(false);
    expect(isInlineSafeMime('application/javascript')).toBe(false);
  });

  it('rejects unknown/empty types', () => {
    expect(isInlineSafeMime('application/octet-stream')).toBe(false);
    expect(isInlineSafeMime('application/zip')).toBe(false);
    expect(isInlineSafeMime('')).toBe(false);
    expect(isInlineSafeMime(undefined)).toBe(false);
    expect(isInlineSafeMime(null)).toBe(false);
  });
});

describe('isAllowedDownloadKey', () => {
  it('allows known prefixes', () => {
    expect(isAllowedDownloadKey('files/abc.png')).toBe(true);
    expect(isAllowedDownloadKey('thumbs/abc_s.webp')).toBe(true);
    expect(isAllowedDownloadKey('recordings/123-rec.mp3')).toBe(true);
    expect(isAllowedDownloadKey('backgrounds/u1/abc.jpg')).toBe(true);
  });

  it('rejects other prefixes and traversal', () => {
    expect(isAllowedDownloadKey('documents/passport.jpg')).toBe(false);
    expect(isAllowedDownloadKey('files/../documents/passport.jpg')).toBe(
      false,
    );
    expect(isAllowedDownloadKey('/files/abc.png')).toBe(false);
    expect(isAllowedDownloadKey('')).toBe(false);
  });
});

describe('attachmentFilenameFromKey', () => {
  it('returns sanitized basename', () => {
    expect(attachmentFilenameFromKey('files/abc-123.pdf')).toBe('abc-123.pdf');
    expect(attachmentFilenameFromKey('files/we"ird\r\nname.txt')).toBe(
      'we_ird__name.txt',
    );
    expect(attachmentFilenameFromKey('files/')).toBe('file');
  });
});
