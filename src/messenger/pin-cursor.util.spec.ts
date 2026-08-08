import { parseUpToCursor } from './pin-cursor.util';

describe('parseUpToCursor', () => {
  it('returns undefined when the field is absent', () => {
    expect(parseUpToCursor(undefined)).toBeUndefined();
  });

  it('returns undefined for null and empty string', () => {
    expect(parseUpToCursor(null as any)).toBeUndefined();
    expect(parseUpToCursor('')).toBeUndefined();
  });

  it('parses a valid ISO timestamp into a Date', () => {
    const out = parseUpToCursor('2026-08-06T12:00:00.000Z');
    expect(out).toBeInstanceOf(Date);
    expect(out!.toISOString()).toBe('2026-08-06T12:00:00.000Z');
  });

  it('returns undefined for garbage instead of an Invalid Date', () => {
    expect(parseUpToCursor('not-a-date')).toBeUndefined();
    expect(parseUpToCursor('{}')).toBeUndefined();
  });

  it('ignores non-string input', () => {
    expect(parseUpToCursor(123 as any)).toBeUndefined();
    expect(parseUpToCursor({} as any)).toBeUndefined();
  });
});
