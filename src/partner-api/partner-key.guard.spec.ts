import { HttpException, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { generatePartnerKey, hashPartnerKey } from '../partner-core/partner-key.util';
import { PARTNER_AUTH_FAILURES_PER_MINUTE, PartnerKeyGuard } from './partner-key.guard';

function ctx(req: any, res: any = { setHeader: jest.fn() }) {
  return { switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }) } as any;
}

/** Считающий счётчик в памяти — тот же контракт, что incrementCounter видит от живого Redis. */
function fakeRedis(): any {
  const counts = new Map<string, number>();
  const getClient = jest.fn(() => ({
    multi: () => {
      let currentKey = '';
      const chain: any = {
        incr: (key: string) => {
          currentKey = key;
          return chain;
        },
        expire: () => chain,
        exec: async () => {
          const next = (counts.get(currentKey) ?? 0) + 1;
          counts.set(currentKey, next);
          return [
            [null, next],
            [null, 'OK'],
          ];
        },
      };
      return chain;
    },
  }));
  return { getClient };
}

/** Redis, у которого любая команда отказывает — имитация недоступности. */
function downRedis(): any {
  const getClient = jest.fn(() => ({
    multi: () => {
      const chain: any = {
        incr: () => chain,
        expire: () => chain,
        exec: () => Promise.reject(new Error('down')),
      };
      return chain;
    },
  }));
  return { getClient };
}

const saved = process.env.PARTNER_API_ENABLED;

describe('PartnerKeyGuard', () => {
  const key = generatePartnerKey('nadi');
  const partner = { id: 'p1', slug: 'nadi', keyHash: hashPartnerKey(key), enabled: true, ipAllowlist: [] as string[] };
  const request = (over: any = {}) => ({ headers: { authorization: `Bearer ${key}` }, ip: '1.2.3.4', ...over });
  let registry: any;
  let redis: any;
  let guard: PartnerKeyGuard;

  beforeEach(() => {
    process.env.PARTNER_API_ENABLED = 'true';
    registry = { findBySlug: jest.fn().mockResolvedValue(partner) };
    redis = fakeRedis();
    guard = new PartnerKeyGuard(registry, redis);
  });
  afterAll(() => {
    if (saved === undefined) delete process.env.PARTNER_API_ENABLED;
    else process.env.PARTNER_API_ENABLED = saved;
  });
  afterEach(() => jest.useRealTimers());

  it('attaches the partner for a valid key and never touches Redis on success', async () => {
    const req: any = request();
    await expect(guard.canActivate(ctx(req))).resolves.toBe(true);
    expect(req.partner).toBe(partner);
    expect(registry.findBySlug).toHaveBeenCalledWith('nadi');
    expect(redis.getClient).not.toHaveBeenCalled();
  });

  it('403 partner_api_disabled while the partner API is switched off, before looking at the key', async () => {
    process.env.PARTNER_API_ENABLED = 'false';
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow('partner_api_disabled');
    expect(registry.findBySlug).not.toHaveBeenCalled();
  });

  it('403 partner_api_disabled when the switch is unset entirely, not just falsy', async () => {
    delete process.env.PARTNER_API_ENABLED;
    try {
      await expect(guard.canActivate(ctx(request()))).rejects.toThrow('partner_api_disabled');
      expect(registry.findBySlug).not.toHaveBeenCalled();
    } finally {
      process.env.PARTNER_API_ENABLED = 'true';
    }
  });

  it.each([undefined, 'Bearer', `Basic ${key}`, `Bearer tidp_nadi_${'x'.repeat(43)}`])(
    '401 invalid_partner_key for authorization %p',
    async (authorization: string | undefined) => {
      await expect(guard.canActivate(ctx(request({ headers: { authorization } })))).rejects.toThrow(
        'invalid_partner_key',
      );
    },
  );

  it('401 invalid_partner_key for an unknown partner', async () => {
    registry.findBySlug.mockResolvedValue(null);
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow('invalid_partner_key');
  });

  it('403 partner_disabled for a disabled partner with a valid key', async () => {
    registry.findBySlug.mockResolvedValue({ ...partner, enabled: false });
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow('partner_disabled');
  });

  it('disabled partner + wrong key → 401 invalid_partner_key (key is checked before enabled)', async () => {
    registry.findBySlug.mockResolvedValue({ ...partner, enabled: false });
    const wrongKey = generatePartnerKey('nadi');
    await expect(
      guard.canActivate(ctx(request({ headers: { authorization: `Bearer ${wrongKey}` } }))),
    ).rejects.toThrow('invalid_partner_key');
  });

  it('checks the IP allowlist, ignoring the ::ffff: prefix', async () => {
    registry.findBySlug.mockResolvedValue({ ...partner, ipAllowlist: ['165.227.141.149'] });
    await expect(guard.canActivate(ctx(request({ ip: '::ffff:165.227.141.149' })))).resolves.toBe(true);
    await expect(guard.canActivate(ctx(request({ ip: '8.8.8.8' })))).rejects.toThrow('ip_not_allowed');
  });

  it('wrong key from a non-allowlisted IP → 401 invalid_partner_key (key is checked before IP)', async () => {
    registry.findBySlug.mockResolvedValue({ ...partner, ipAllowlist: ['1.2.3.4'] });
    const wrongKey = generatePartnerKey('nadi');
    await expect(
      guard.canActivate(ctx(request({ ip: '9.9.9.9', headers: { authorization: `Bearer ${wrongKey}` } }))),
    ).rejects.toThrow('invalid_partner_key');
  });

  it(`pins the threshold exactly: the ${PARTNER_AUTH_FAILURES_PER_MINUTE}th auth failure from the same IP is still 401, the ${PARTNER_AUTH_FAILURES_PER_MINUTE + 1}th becomes 429`, async () => {
    const now = new Date('2026-10-01T10:00:15Z');
    jest.useFakeTimers({ now });
    registry.findBySlug.mockResolvedValue(null);
    const res = { setHeader: jest.fn() };
    for (let i = 0; i < PARTNER_AUTH_FAILURES_PER_MINUTE - 1; i++) {
      await guard.canActivate(ctx(request(), res)).catch((e: unknown) => e);
    }
    // count is now 30: `>` must still let this one through as the original 401, not 429 (a `>=` bug would flip it).
    const thirtieth = await guard.canActivate(ctx(request(), res)).catch((e: unknown) => e);
    expect(thirtieth).toBeInstanceOf(UnauthorizedException);
    expect(thirtieth.message).toBe('invalid_partner_key');

    // count is now 31: the first request over the threshold.
    const thirtyFirst = await guard.canActivate(ctx(request(), res)).catch((e: unknown) => e);
    expect(thirtyFirst).toBeInstanceOf(HttpException);
    expect(thirtyFirst.getStatus()).toBe(429);
    expect(thirtyFirst.getResponse()).toEqual({ message: 'too_many_auth_failures', retryAfter: 45 });
    expect(res.setHeader).toHaveBeenCalledWith('Retry-After', '45');
  });

  it('falls back to the original 401 when the auth-failure counter is unavailable', async () => {
    registry.findBySlug.mockResolvedValue(null);
    guard = new PartnerKeyGuard(registry, downRedis());
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow('invalid_partner_key');
  });

  it('propagates a registry outage untouched, without counting it against the IP', async () => {
    registry.findBySlug.mockRejectedValue(new ServiceUnavailableException('partner registry unavailable'));
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow(ServiceUnavailableException);
    expect(redis.getClient).not.toHaveBeenCalled();
  });
});
