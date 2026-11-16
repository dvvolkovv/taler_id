const mockEval = jest.fn();
jest.mock('ioredis', () =>
  jest.fn().mockImplementation(() => ({ on: jest.fn(), eval: mockEval })),
);

import { RedisService } from './redis.service';

describe('RedisService.delIfEquals', () => {
  const redis = new RedisService({ get: () => undefined } as any);

  beforeEach(() => mockEval.mockReset());

  it('compares and deletes in one server-side script', async () => {
    mockEval.mockResolvedValueOnce(1);

    await expect(redis.delIfEquals('lock', 'token-a')).resolves.toBe(true);

    const [script, numKeys, key, value] = mockEval.mock.calls[0];
    expect(script).toContain("redis.call('get', KEYS[1]) == ARGV[1]");
    expect(script).toContain("redis.call('del', KEYS[1])");
    expect([numKeys, key, value]).toEqual([1, 'lock', 'token-a']);
  });

  it('returns false when the key holds another value', async () => {
    mockEval.mockResolvedValueOnce(0);

    await expect(redis.delIfEquals('lock', 'token-a')).resolves.toBe(false);
  });
});
