import 'reflect-metadata';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { PartnerApi } from './partner-api.decorator';
import { PartnerKeyGuard } from './partner-key.guard';
import { PartnerRateLimitGuard } from './partner-rate-limit.guard';

@PartnerApi()
class Dummy {}

describe('PartnerApi', () => {
  it('applies PartnerKeyGuard then PartnerRateLimitGuard, in that order', () => {
    expect(Reflect.getMetadata(GUARDS_METADATA, Dummy)).toEqual([
      PartnerKeyGuard,
      PartnerRateLimitGuard,
    ]);
  });

  it.each(['short', 'medium', 'long'])(
    'skips the named %s throttle',
    (name: string) => {
      expect(Reflect.getMetadata('THROTTLER:SKIP' + name, Dummy)).toBe(true);
    },
  );
});
