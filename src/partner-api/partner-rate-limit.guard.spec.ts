import { Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PartnerRateBucket, PartnerRateLimitGuard } from './partner-rate-limit.guard';

@PartnerRateBucket('default')
class DummyController {
  @PartnerRateBucket('token')
  tokenMethod() {
    /* noop */
  }
  plainMethod() {
    /* noop */
  }
}

function ctx(req: any, res: any, handler: (...args: any[]) => unknown, cls: unknown = DummyController) {
  return {
    switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
    getHandler: () => handler,
    getClass: () => cls,
  } as any;
}

/** Считающий счётчик в памяти — тот же контракт, что incrementCounter видит от живого Redis. */
function fakeRedis() {
  const counts = new Map<string, number>();
  const incr = jest.fn();
  const getClient = jest.fn(() => ({
    multi: () => {
      let currentKey = '';
      const chain: any = {
        incr: (key: string) => {
          currentKey = key;
          incr(key);
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
  return { redis: { getClient } as any, incr };
}

/** Redis, у которого любая команда виснет отказом — имитация недоступности. */
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

describe('PartnerRateLimitGuard', () => {
  const now = new Date('2026-10-01T10:00:15Z');
  const minute = Math.floor(now.getTime() / 60_000);

  beforeEach(() => jest.useFakeTimers({ now }));
  afterEach(() => jest.useRealTimers());

  it('a method-level bucket wins over the class-level bucket', async () => {
    const { redis, incr } = fakeRedis();
    const guard = new PartnerRateLimitGuard(new Reflector(), redis);
    await expect(
      guard.canActivate(
        ctx({ partner: { id: 'p1' } }, { setHeader: jest.fn() }, DummyController.prototype.tokenMethod),
      ),
    ).resolves.toBe(true);
    expect(incr).toHaveBeenCalledWith(`partner:rl:p1:token:${minute}`);
  });

  it('an undecorated method falls back to the class-level bucket', async () => {
    const { redis, incr } = fakeRedis();
    const guard = new PartnerRateLimitGuard(new Reflector(), redis);
    await expect(
      guard.canActivate(
        ctx({ partner: { id: 'p1' } }, { setHeader: jest.fn() }, DummyController.prototype.plainMethod),
      ),
    ).resolves.toBe(true);
    expect(incr).toHaveBeenCalledWith(`partner:rl:p1:default:${minute}`);
  });

  it('answers 429 with rate_limited and sets Retry-After once the bucket is exceeded', async () => {
    const redis: any = {
      getClient: () => ({
        multi: () => {
          const chain: any = {
            incr: () => chain,
            expire: () => chain,
            exec: () =>
              Promise.resolve([
                [null, 121],
                [null, 'OK'],
              ]),
          };
          return chain;
        },
      }),
    };
    const res = { setHeader: jest.fn() };
    const guard = new PartnerRateLimitGuard(new Reflector(), redis);
    const err = await guard
      .canActivate(ctx({ partner: { id: 'p1' } }, res, DummyController.prototype.plainMethod))
      .catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({ message: 'rate_limited', retryAfter: 45 });
    expect(res.setHeader).toHaveBeenCalledWith('Retry-After', '45');
  });

  it('fails open when Redis is unavailable, warning only once within a minute', async () => {
    const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined as any);
    const guard = new PartnerRateLimitGuard(new Reflector(), downRedis());
    const req = { partner: { id: 'p1' } };
    await expect(
      guard.canActivate(ctx(req, { setHeader: jest.fn() }, DummyController.prototype.plainMethod)),
    ).resolves.toBe(true);
    await expect(
      guard.canActivate(ctx(req, { setHeader: jest.fn() }, DummyController.prototype.plainMethod)),
    ).resolves.toBe(true);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    warnSpy.mockRestore();
  });

  it('throws when req.partner is missing (guard order violated)', async () => {
    const guard = new PartnerRateLimitGuard(new Reflector(), {} as any);
    await expect(
      guard.canActivate(ctx({}, { setHeader: jest.fn() }, DummyController.prototype.plainMethod)),
    ).rejects.toThrow('PartnerRateLimitGuard must run after PartnerKeyGuard');
  });
});
