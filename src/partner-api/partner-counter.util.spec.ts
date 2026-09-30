import { HttpException } from '@nestjs/common';
import {
  currentMinute,
  incrementCounter,
  PARTNER_COUNTER_TIMEOUT_MS,
  throwTooManyRequests,
} from './partner-counter.util';

/** Имитация ioredis multi().incr().expire().exec() с управляемым результатом exec(). */
function fakeRedis(exec: () => Promise<any>): any {
  const chain: any = {};
  chain.incr = jest.fn(() => chain);
  chain.expire = jest.fn(() => chain);
  chain.exec = exec;
  return { getClient: () => ({ multi: () => chain }) };
}

describe('currentMinute', () => {
  it('computes the minute bucket and the seconds left in it', () => {
    const nowMs = new Date('2026-10-01T10:00:15Z').getTime();
    expect(currentMinute(nowMs)).toEqual({ minute: Math.floor(nowMs / 60_000), retryAfter: 45 });
  });
});

describe('incrementCounter', () => {
  it('returns the INCR value on a healthy Redis', async () => {
    const redis = fakeRedis(() =>
      Promise.resolve([
        [null, 5],
        [null, 'OK'],
      ]),
    );
    await expect(incrementCounter(redis, 'k', 60)).resolves.toBe(5);
  });

  it('returns null when Redis rejects', async () => {
    const redis = fakeRedis(() => Promise.reject(new Error('ECONNREFUSED')));
    await expect(incrementCounter(redis, 'k', 60)).resolves.toBeNull();
  });

  it('returns null when the command times out (dead Redis hangs ~10.5s by default)', async () => {
    const redis = fakeRedis(() => new Promise(() => {})); // never resolves
    await expect(incrementCounter(redis, 'k', 60, 5)).resolves.toBeNull();
  });

  it('returns null when exec() itself resolves to null', async () => {
    const redis = fakeRedis(() => Promise.resolve(null));
    await expect(incrementCounter(redis, 'k', 60)).resolves.toBeNull();
  });

  it('returns null when the INCR entry carries an error (e.g. READONLY right after failover)', async () => {
    const redis = fakeRedis(() =>
      Promise.resolve([
        [new Error('READONLY'), null],
        [null, 'OK'],
      ]),
    );
    await expect(incrementCounter(redis, 'k', 60)).resolves.toBeNull();
  });

  it('defaults the timeout to PARTNER_COUNTER_TIMEOUT_MS', () => {
    expect(PARTNER_COUNTER_TIMEOUT_MS).toBe(250);
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
