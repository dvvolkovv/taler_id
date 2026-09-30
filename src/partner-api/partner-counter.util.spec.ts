import { HttpException } from '@nestjs/common';
import {
  currentMinute,
  incrementCounter,
  PARTNER_COUNTER_TIMEOUT_MS,
  throwTooManyRequests,
} from './partner-counter.util';

/** Имитация ioredis multi().incr().expire().exec() с управляемым результатом exec(). */
function fakeRedis(exec: () => Promise<any>) {
  const chain: any = {};
  chain.incr = jest.fn(() => chain);
  chain.expire = jest.fn(() => chain);
  chain.exec = exec;
  return { redis: { getClient: () => ({ multi: () => chain }) } as any, incr: chain.incr, expire: chain.expire };
}

describe('currentMinute', () => {
  it('computes the minute bucket and the seconds left in it', () => {
    const nowMs = new Date('2026-10-01T10:00:15Z').getTime();
    expect(currentMinute(nowMs)).toEqual({ minute: Math.floor(nowMs / 60_000), retryAfter: 45 });
  });
});

describe('incrementCounter', () => {
  afterEach(() => jest.useRealTimers());

  it('returns the INCR value and queues EXPIRE with the given TTL on a healthy Redis', async () => {
    const { redis, expire } = fakeRedis(() =>
      Promise.resolve([
        [null, 5],
        [null, 'OK'],
      ]),
    );
    await expect(incrementCounter(redis, 'k', 60)).resolves.toBe(5);
    expect(expire).toHaveBeenCalledWith('k', 60);
  });

  it('returns null when exec() rejects (e.g. EXECABORT against a read-only replica right after failover)', async () => {
    const { redis } = fakeRedis(() =>
      Promise.reject(new Error('EXECABORT Transaction discarded because of previous errors.')),
    );
    await expect(incrementCounter(redis, 'k', 60)).resolves.toBeNull();
  });

  it('returns null when the command times out (dead Redis hangs ~10.5s by default)', async () => {
    const { redis } = fakeRedis(() => new Promise(() => {})); // never resolves
    await expect(incrementCounter(redis, 'k', 60, 5)).resolves.toBeNull();
  });

  it('returns null when exec() itself resolves to null', async () => {
    const { redis } = fakeRedis(() => Promise.resolve(null));
    await expect(incrementCounter(redis, 'k', 60)).resolves.toBeNull();
  });

  it('returns null when a queued command carries its own error (e.g. INCR against a non-numeric value)', async () => {
    const { redis } = fakeRedis(() =>
      Promise.resolve([
        [new Error('ERR value is not an integer or out of range'), null],
        [null, 'OK'],
      ]),
    );
    await expect(incrementCounter(redis, 'k', 60)).resolves.toBeNull();
  });

  it('never throws even when the Redis client itself throws synchronously', async () => {
    const redis: any = {
      getClient: () => {
        throw new Error('client not ready');
      },
    };
    await expect(incrementCounter(redis, 'k', 60)).resolves.toBeNull();
  });

  it('without an explicit timeoutMs, stays pending at 249ms and resolves null at 250ms (PARTNER_COUNTER_TIMEOUT_MS)', async () => {
    jest.useFakeTimers();
    const { redis } = fakeRedis(() => new Promise(() => {})); // never resolves
    let settled = false;
    const promise = incrementCounter(redis, 'k', 60).then((value) => {
      settled = true;
      return value;
    });
    await jest.advanceTimersByTimeAsync(PARTNER_COUNTER_TIMEOUT_MS - 1);
    expect(settled).toBe(false);
    await jest.advanceTimersByTimeAsync(1);
    await expect(promise).resolves.toBeNull();
    expect(settled).toBe(true);
  });
});

describe('throwTooManyRequests', () => {
  it('sets Retry-After and throws a 429 with the message and retryAfter', () => {
    const res = { setHeader: jest.fn() };
    let caught: any;
    try {
      throwTooManyRequests(res, 'rate_limited', 45);
    } catch (e) {
      caught = e;
    }
    expect(res.setHeader).toHaveBeenCalledWith('Retry-After', '45');
    expect(caught).toBeInstanceOf(HttpException);
    expect(caught.getStatus()).toBe(429);
    expect(caught.getResponse()).toEqual({ message: 'rate_limited', retryAfter: 45 });
  });
});
