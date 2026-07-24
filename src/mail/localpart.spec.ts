import { normalizeLocalpart, validateLocalpart } from './localpart';

describe('localpart', () => {
  it('normalizes to lowercase and trims', () => {
    expect(normalizeLocalpart('  Vasya.Pupkin ')).toBe('vasya.pupkin');
  });

  it.each(['vasya', 'v.p-2026', 'a1b', 'john_doe'])('accepts %s', (lp) => {
    expect(validateLocalpart(lp)).toBeNull();
  });

  it.each([
    ['ab', 'слишком короткий (<3)'],
    ['a'.repeat(65), 'слишком длинный'],
    ['.vasya', 'точка в начале'],
    ['vasya.', 'точка в конце'],
    ['va..sya', 'двойная точка'],
    ['вася', 'не-ASCII'],
    ['va sya', 'пробел'],
    ['va@sya', 'спецсимвол'],
  ])('rejects %s (%s)', (lp) => {
    expect(validateLocalpart(lp)).toBe('INVALID');
  });

  it.each(['admin', 'postmaster', 'abuse', 'noreply', 'root', 'support', 'talerid'])(
    'blocks reserved %s',
    (lp) => {
      expect(validateLocalpart(lp)).toBe('RESERVED');
    },
  );
});
