import { BadRequestException } from '@nestjs/common';
import { assertExternalId } from './external-id.util';

describe('assertExternalId', () => {
  it.each(['cm1abc', 'e2e-a-lx9', 'org:42', 'a.b_c', 'a.b', '.a', 'a..b'])(
    'accepts %p',
    (value: string) => {
      expect(assertExternalId(value)).toBe(value);
    },
  );

  it.each([
    '',
    'has space',
    'x'.repeat(129),
    'кирилиця',
    'a/b',
    '.',
    '..',
    '...',
  ])('rejects %p', (value: string) => {
    expect(() => assertExternalId(value)).toThrow(BadRequestException);
  });
});
