import { createHash } from 'crypto';
import {
  CODE_ALPHABET,
  CODE_LENGTH,
  CODE_TTL_MS,
  generateCode,
  hashCode,
  normalizeCode,
} from './interpreter-code';

describe('interpreter code', () => {
  it('is 8 characters of base32 without look-alikes, alive for 5 minutes', () => {
    expect(CODE_ALPHABET).toBe('ABCDEFGHJKLMNPQRSTUVWXYZ23456789');
    expect(CODE_LENGTH).toBe(8);
    expect(CODE_TTL_MS).toBe(300_000);
  });

  it('generates codes from the alphabet only, and not the same code twice', () => {
    const codes = Array.from({ length: 500 }, () => generateCode());
    for (const code of codes) expect(code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/);
    expect(new Set(codes).size).toBe(codes.length);
  });

  it('normalizes what a person types: case, spaces and dashes', () => {
    expect(normalizeCode('abcd-efgh')).toBe('ABCDEFGH');
    expect(normalizeCode(' AB CD EF 23 ')).toBe('ABCDEF23');
  });

  it('takes what a phone puts in place of a dash or a space', () => {
    for (const sep of [
      '\u2010', // hyphen
      '\u2011', // non-breaking hyphen
      '\u2013', // en dash: iOS smart punctuation
      '\u2014', // em dash: iOS smart punctuation, '--'
      '\u2212', // minus sign
      '\u00A0', // no-break space
      '\u200B', // zero-width space from a paste
    ]) {
      expect(normalizeCode(`ABCD${sep}EFGH`)).toBe('ABCDEFGH');
    }
    expect(normalizeCode('\uFEFFABCDEFGH')).toBe('ABCDEFGH'); // BOM
  });

  it('folds full-width letters and digits from a CJK keyboard', () => {
    expect(normalizeCode('\uFF41\uFF42\uFF43\uFF44EFG\uFF12')).toBe('ABCDEFG2');
  });

  it('refuses anything that cannot be a code', () => {
    for (const raw of [
      'ABCDEFG', // too short
      'ABCDEFGH2', // too long
      'ABCDEFGI', // I is not in the alphabet
      'ABCDEFG0', // nor is 0
      'ABCD_EFG',
      '',
      42,
      null,
      undefined,
    ]) {
      expect(normalizeCode(raw)).toBeNull();
    }
  });

  it('hashes a code as sha256 hex, so only the hash is stored', () => {
    expect(hashCode('ABCDEFGH')).toBe(
      createHash('sha256').update('ABCDEFGH').digest('hex'),
    );
    expect(hashCode('ABCDEFGH')).not.toContain('ABCDEFGH');
  });
});
