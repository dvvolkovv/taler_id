import { PartnerRateLimitGuard } from './partner-rate-limit.guard';

function ctx(req: any) {
  return {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as any;
}

describe('PartnerRateLimitGuard', () => {
  const now = new Date('2026-10-01T10:00:15Z');
  const minute = Math.floor(now.getTime() / 60_000);
  let redis: any;
  let reflector: any;
  let guard: PartnerRateLimitGuard;

  beforeEach(() => {
    jest.useFakeTimers({ now });
    redis = { incr: jest.fn().mockResolvedValue(1), expire: jest.fn().mockResolvedValue(undefined) };
    reflector = { getAllAndOverride: jest.fn().mockReturnValue(undefined) };
    guard = new PartnerRateLimitGuard(reflector, redis);
  });
  afterEach(() => jest.useRealTimers());

  it('counts per partner, bucket and minute', async () => {
    await expect(guard.canActivate(ctx({ partner: { id: 'p1' } }))).resolves.toBe(true);
    expect(redis.incr).toHaveBeenCalledWith(`partner:rl:p1:default:${minute}`);
    expect(redis.expire).toHaveBeenCalledWith(`partner:rl:p1:default:${minute}`, 120);
  });

  it('lets the token bucket through up to 600 a minute', async () => {
    reflector.getAllAndOverride.mockReturnValue('token');
    redis.incr.mockResolvedValue(600);
    await expect(guard.canActivate(ctx({ partner: { id: 'p1' } }))).resolves.toBe(true);
    expect(redis.incr).toHaveBeenCalledWith(`partner:rl:p1:token:${minute}`);
    redis.incr.mockResolvedValue(601);
    const err = await guard.canActivate(ctx({ partner: { id: 'p1' } })).catch((e) => e);
    expect(err.getStatus()).toBe(429);
  });

  it('answers 429 with retryAfter above 120 a minute on ordinary routes', async () => {
    redis.incr.mockResolvedValue(121);
    const err = await guard.canActivate(ctx({ partner: { id: 'p1' } })).catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({ message: 'rate_limited', retryAfter: 45 });
  });
});
