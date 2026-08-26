import {
  PendingOp,
  PendingStateStore,
  PENDING_OP_TTL_SEC,
  pendingOpKey,
} from './informer.pending-state';

function makeRedisStub() {
  const store = new Map<string, string>();
  return {
    store,
    get: jest.fn(async (k: string) => store.get(k) ?? null),
    setEx: jest.fn(async (k: string, _ttl: number, v: string) => {
      store.set(k, v);
    }),
    del: jest.fn(async (k: string) => {
      store.delete(k);
    }),
  };
}

const CTX = {
  network: 'BSC',
  token: 'usdt',
  amount: '50',
  address: '0xcust',
};

describe('PendingStateStore', () => {
  it('кладёт состояние под ключ пользователя с TTL', async () => {
    const redis = makeRedisStub();
    const store = new PendingStateStore(redis as any);
    const op: PendingOp = { kind: 'retry', step: 'totp', walletId: 1611 };

    await store.save('u1', op);

    expect(redis.setEx).toHaveBeenCalledWith(
      'informer:pending_op:u1',
      PENDING_OP_TTL_SEC,
      JSON.stringify(op),
    );
  });

  it('читает обратно ровно то, что положили', async () => {
    const redis = makeRedisStub();
    const store = new PendingStateStore(redis as any);
    const op: PendingOp = {
      kind: 'refund',
      step: 'confirm',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
    };

    await store.save('u1', op);
    expect(await store.load('u1')).toEqual(op);
  });

  it('отдаёт null когда состояния нет', async () => {
    const store = new PendingStateStore(makeRedisStub() as any);
    expect(await store.load('nobody')).toBeNull();
  });

  it('отдаёт null и чистит ключ на битом JSON', async () => {
    const redis = makeRedisStub();
    redis.store.set('informer:pending_op:u1', '{not json');
    const store = new PendingStateStore(redis as any);

    expect(await store.load('u1')).toBeNull();
    expect(redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
  });

  it('отдаёт null и чистит ключ на неизвестном kind', async () => {
    const redis = makeRedisStub();
    redis.store.set(
      'informer:pending_op:u1',
      JSON.stringify({ kind: 'teleport', step: 'totp', walletId: 1 }),
    );
    const store = new PendingStateStore(redis as any);

    expect(await store.load('u1')).toBeNull();
    expect(redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
  });

  it('clear удаляет ключ', async () => {
    const redis = makeRedisStub();
    const store = new PendingStateStore(redis as any);
    await store.save('u1', { kind: 'retry', step: 'totp', walletId: 7 });

    await store.clear('u1');

    expect(await store.load('u1')).toBeNull();
    expect(redis.store.has('informer:pending_op:u1')).toBe(false);
  });

  it('новое состояние перетирает предыдущее — последняя кнопка выигрывает', async () => {
    const redis = makeRedisStub();
    const store = new PendingStateStore(redis as any);

    await store.save('u1', { kind: 'retry', step: 'totp', walletId: 1611 });
    await store.save('u1', {
      kind: 'refund',
      step: 'method',
      walletId: 1620,
      ctx: CTX,
    });

    const loaded = await store.load('u1');
    expect(loaded).toEqual({
      kind: 'refund',
      step: 'method',
      walletId: 1620,
      ctx: CTX,
    });
  });

  it('pendingOpKey строит ключ из userId', () => {
    expect(pendingOpKey('abc')).toBe('informer:pending_op:abc');
  });

  it('отдаёт null и чистит ключ на confirm без target', async () => {
    const redis = makeRedisStub();
    redis.store.set(
      'informer:pending_op:u1',
      JSON.stringify({
        kind: 'refund',
        step: 'confirm',
        walletId: 1611,
        ctx: CTX,
      }),
    );
    const store = new PendingStateStore(redis as any);

    expect(await store.load('u1')).toBeNull();
    expect(redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
  });

  it('отдаёт null и чистит ключ на totp без verifiedAbsent', async () => {
    const redis = makeRedisStub();
    redis.store.set(
      'informer:pending_op:u1',
      JSON.stringify({
        kind: 'refund',
        step: 'totp',
        walletId: 1611,
        ctx: CTX,
        target: { refundAddress: '0xB1c4' },
      }),
    );
    const store = new PendingStateStore(redis as any);

    expect(await store.load('u1')).toBeNull();
    expect(redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
  });

  it('отдаёт null и чистит ключ на gate без upstreamMessage', async () => {
    const redis = makeRedisStub();
    redis.store.set(
      'informer:pending_op:u1',
      JSON.stringify({
        kind: 'refund',
        step: 'gate',
        walletId: 1611,
        ctx: CTX,
        target: { refundAddress: '0xB1c4' },
      }),
    );
    const store = new PendingStateStore(redis as any);

    expect(await store.load('u1')).toBeNull();
    expect(redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
  });

  it('отдаёт null и чистит ключ на неизвестном step', async () => {
    const redis = makeRedisStub();
    redis.store.set(
      'informer:pending_op:u1',
      JSON.stringify({
        kind: 'refund',
        step: 'нет_такого',
        walletId: 1611,
        ctx: CTX,
      }),
    );
    const store = new PendingStateStore(redis as any);

    expect(await store.load('u1')).toBeNull();
    expect(redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
  });

  it('round-trip для refund/totp переживает verifiedAbsent: false', async () => {
    const redis = makeRedisStub();
    const store = new PendingStateStore(redis as any);
    const op: PendingOp = {
      kind: 'refund',
      step: 'totp',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
      verifiedAbsent: false,
    };

    await store.save('u1', op);

    expect(await store.load('u1')).toEqual(op);
  });
});
