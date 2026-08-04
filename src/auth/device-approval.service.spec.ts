import { DeviceApprovalService } from './device-approval.service';

function makeRedis() {
  const store = new Map<string, string>();
  const counters = new Map<string, number>();
  const sets: Record<string, Set<string>> = {};
  return {
    store,
    counters,
    sets,
    get: jest.fn(async (k: string) => store.get(k) ?? null),
    setEx: jest.fn(async (k: string, _t: number, v: string) => {
      store.set(k, v);
    }),
    del: jest.fn(async (k: string) => {
      store.delete(k);
    }),
    incr: jest.fn(async (k: string) => {
      const n = (counters.get(k) ?? 0) + 1;
      counters.set(k, n);
      return n;
    }),
    expire: jest.fn(async () => undefined),
    getClient: () => ({
      getdel: jest.fn(async (k: string) => {
        const v = store.get(k) ?? null;
        store.delete(k);
        return v;
      }),
      sadd: jest.fn(async (k: string, v: string) => {
        (sets[k] ??= new Set()).add(v);
        return 1;
      }),
      srem: jest.fn(async (k: string, v: string) => {
        sets[k]?.delete(v);
        return 1;
      }),
      smembers: jest.fn(async (k: string) => [...(sets[k] ?? [])]),
    }),
  };
}

function makePrisma() {
  return {
    session: {
      findMany: jest.fn().mockResolvedValue([
        { id: 's-old', fcmToken: 'tok-old', deviceId: 'dev-old' },
      ]),
    },
    trustedDevice: {
      upsert: jest.fn().mockResolvedValue({}),
      findFirst: jest.fn().mockResolvedValue(null),
      count: jest.fn().mockResolvedValue(0),
    },
    auditLog: { create: jest.fn().mockResolvedValue({}) },
  };
}

describe('DeviceApprovalService.createPending', () => {
  let service: DeviceApprovalService;
  let prisma: any;
  let redis: any;
  let fcm: any;

  beforeEach(() => {
    redis = makeRedis();
    prisma = makePrisma();
    fcm = { sendDeviceApprovalRequest: jest.fn().mockResolvedValue(undefined) };
    service = new DeviceApprovalService(
      prisma as any,
      redis as any,
      fcm as any,
      { sendOtp: jest.fn() } as any,
    );
  });

  it('returns a token, and pushes to every other live session', async () => {
    const result = await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });

    expect(result.approvalToken).toEqual(expect.any(String));
    expect(result.approverCount).toBe(1);
    expect(fcm.sendDeviceApprovalRequest).toHaveBeenCalledWith(
      'tok-old',
      expect.objectContaining({
        approvalId: expect.any(String),
        deviceInfo: 'Pixel',
      }),
    );
  });

  it('never pushes the secret token — only the public approval id', async () => {
    await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });

    const pushed = JSON.stringify(
      fcm.sendDeviceApprovalRequest.mock.calls[0][1],
    );
    const stored = [...redis.store.keys()].find((k: string) =>
      k.startsWith('device_approval:'),
    )!;
    const secret = stored.replace('device_approval:', '');
    expect(pushed).not.toContain(secret);
  });

  it('excludes the device that is trying to sign in from the approvers', async () => {
    await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });

    expect(prisma.session.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ NOT: { deviceId: 'dev-new' } }),
      }),
    );
  });

  it('refuses once the hourly ceiling is reached', async () => {
    redis.counters.set('device_approval_rate:u1', 10);
    await expect(
      service.createPending({
        userId: 'u1',
        deviceId: 'dev-new',
        deviceInfo: 'Pixel',
        ip: '1.2.3.4',
        email: 'a@b.c',
      }),
    ).rejects.toThrow(/too many/i);
  });

  it('reports that email is unavailable for an account without one', async () => {
    const result = await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: null,
    });

    expect(result.emailAvailable).toBe(false);
  });
});

describe('DeviceApprovalService approve/reject', () => {
  let service: DeviceApprovalService;
  let prisma: any;
  let redis: any;

  const seed = async () => {
    const r = await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });
    const record = JSON.parse(
      redis.store.get(`device_approval:${r.approvalToken}`)!,
    );
    return { token: r.approvalToken, approvalId: record.approvalId };
  };

  beforeEach(() => {
    redis = makeRedis();
    prisma = makePrisma();
    prisma.session.findMany.mockResolvedValue([]);
    service = new DeviceApprovalService(
      prisma as any,
      redis as any,
      { sendDeviceApprovalRequest: jest.fn() } as any,
      { sendOtp: jest.fn() } as any,
    );
  });

  it('marks the record approved and trusts the device right away', async () => {
    const { token, approvalId } = await seed();
    await service.approve('u1', approvalId);

    expect(
      JSON.parse(redis.store.get(`device_approval:${token}`)!).status,
    ).toBe('approved');
    expect(prisma.trustedDevice.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { userId_deviceId: { userId: 'u1', deviceId: 'dev-new' } },
      }),
    );
  });

  it("refuses to approve another user's pending login", async () => {
    const { approvalId } = await seed();
    await expect(service.approve('someone-else', approvalId)).rejects.toThrow(
      /not found/i,
    );
    expect(prisma.trustedDevice.upsert).not.toHaveBeenCalled();
  });

  it('rejection is terminal — the record cannot then be approved', async () => {
    const { token, approvalId } = await seed();
    await service.reject('u1', approvalId);

    expect(
      JSON.parse(redis.store.get(`device_approval:${token}`)!).status,
    ).toBe('rejected');
    await expect(service.approve('u1', approvalId)).rejects.toThrow(/rejected/i);
  });

  it('an unknown approval id is not found rather than silently accepted', async () => {
    await expect(service.approve('u1', 'no-such-id')).rejects.toThrow(
      /not found/i,
    );
  });
});

describe('DeviceApprovalService.claim', () => {
  let service: DeviceApprovalService;
  let prisma: any;
  let redis: any;

  const seed = async () => {
    const r = await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });
    const record = JSON.parse(
      redis.store.get(`device_approval:${r.approvalToken}`)!,
    );
    return { token: r.approvalToken, approvalId: record.approvalId };
  };

  beforeEach(() => {
    redis = makeRedis();
    prisma = makePrisma();
    prisma.session.findMany.mockResolvedValue([]);
    service = new DeviceApprovalService(
      prisma as any,
      redis as any,
      { sendDeviceApprovalRequest: jest.fn() } as any,
      { sendOtp: jest.fn() } as any,
    );
  });

  it('hands the approved record over exactly once', async () => {
    const { token, approvalId } = await seed();
    await service.approve('u1', approvalId);

    const first = await service.claim(token);
    expect(first.status).toBe('approved');
    expect(first.record?.deviceId).toBe('dev-new');

    // Второй опрос не должен породить вторую сессию на тот же вход.
    const second = await service.claim(token);
    expect(second.status).toBe('claimed');
    expect(second.record).toBeUndefined();
  });

  it('reports pending while nobody has answered', async () => {
    const { token } = await seed();
    expect((await service.claim(token)).status).toBe('pending');
  });

  it('reports expired for an unknown token', async () => {
    expect((await service.claim('nope')).status).toBe('expired');
  });

  it('reports rejected and clears the record', async () => {
    const { token, approvalId } = await seed();
    await service.reject('u1', approvalId);

    expect((await service.claim(token)).status).toBe('rejected');
    expect(redis.store.has(`device_approval:${token}`)).toBe(false);
  });

  it('frees the approval id so it cannot be replayed after the claim', async () => {
    const { token, approvalId } = await seed();
    await service.approve('u1', approvalId);
    await service.claim(token);

    expect(redis.store.has(`device_approval_id:${approvalId}`)).toBe(false);
  });
});

// Единственный путь для человека, у которого одно устройство или до остальных
// не доходят пуши. Без него фича превращается в способ потерять свой аккаунт.
describe('DeviceApprovalService email fallback', () => {
  let service: DeviceApprovalService;
  let prisma: any;
  let redis: any;
  let email: any;

  const seed = async () => {
    const r = await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });
    return { token: r.approvalToken };
  };

  beforeEach(() => {
    redis = makeRedis();
    prisma = makePrisma();
    prisma.session.findMany.mockResolvedValue([]);
    email = { sendOtp: jest.fn().mockResolvedValue(undefined) };
    service = new DeviceApprovalService(
      prisma as any,
      redis as any,
      { sendDeviceApprovalRequest: jest.fn() } as any,
      email as any,
    );
  });

  it('sends a six-digit code to the account address', async () => {
    const { token } = await seed();
    await service.sendEmailCode(token, 'a@b.c');

    expect(email.sendOtp).toHaveBeenCalledWith(
      'a@b.c',
      expect.stringMatching(/^\d{6}$/),
      expect.any(String),
    );
  });

  it('refuses a second send inside the cooldown', async () => {
    const { token } = await seed();
    await service.sendEmailCode(token, 'a@b.c');
    await expect(service.sendEmailCode(token, 'a@b.c')).rejects.toThrow(/wait/i);
  });

  it('a correct code approves the login and trusts the device', async () => {
    const { token } = await seed();
    await service.sendEmailCode(token, 'a@b.c');
    const code = redis.store.get(`device_approval_code:${token}`)!;

    await service.verifyEmailCode(token, code);

    expect(
      JSON.parse(redis.store.get(`device_approval:${token}`)!).status,
    ).toBe('approved');
    expect(prisma.trustedDevice.upsert).toHaveBeenCalled();
  });

  it('burns the request after five wrong codes', async () => {
    const { token } = await seed();
    await service.sendEmailCode(token, 'a@b.c');

    for (let i = 0; i < 4; i++) {
      await expect(service.verifyEmailCode(token, '000000')).rejects.toThrow(
        /invalid/i,
      );
    }
    await expect(service.verifyEmailCode(token, '000000')).rejects.toThrow(
      /again/i,
    );
    expect(redis.store.has(`device_approval:${token}`)).toBe(false);
  });

  it('will not send a code for an already-resolved request', async () => {
    const { token } = await seed();
    const record = JSON.parse(redis.store.get(`device_approval:${token}`)!);
    await service.reject('u1', record.approvalId);

    await expect(service.sendEmailCode(token, 'a@b.c')).rejects.toThrow(
      /resolved/i,
    );
  });
});

describe('DeviceApprovalService.gateDecision', () => {
  let service: DeviceApprovalService;
  let prisma: any;

  beforeEach(() => {
    prisma = makePrisma();
    service = new DeviceApprovalService(
      prisma as any,
      makeRedis() as any,
      { sendDeviceApprovalRequest: jest.fn() } as any,
      { sendOtp: jest.fn() } as any,
    );
  });

  it('lets a legacy client through — no device id, no gate', async () => {
    prisma.trustedDevice.count.mockResolvedValue(3);
    expect(await service.gateDecision('u1', undefined, true)).toBe('allow');
  });

  it('lets the very first device through — there would be nothing to ask', async () => {
    prisma.trustedDevice.count.mockResolvedValue(0);
    prisma.trustedDevice.findFirst.mockResolvedValue(null);
    expect(await service.gateDecision('u1', 'dev-1', true)).toBe('allow');
  });

  it('lets a known device through', async () => {
    prisma.trustedDevice.count.mockResolvedValue(2);
    prisma.trustedDevice.findFirst.mockResolvedValue({
      id: 't1',
      revokedAt: null,
    });
    expect(await service.gateDecision('u1', 'dev-1', true)).toBe('allow');
  });

  it('gates an unknown device when the toggle is on', async () => {
    prisma.trustedDevice.count.mockResolvedValue(2);
    prisma.trustedDevice.findFirst.mockResolvedValue(null);
    expect(await service.gateDecision('u1', 'dev-new', true)).toBe('approve');
  });

  it('does not gate when the user has the toggle off', async () => {
    prisma.trustedDevice.count.mockResolvedValue(2);
    prisma.trustedDevice.findFirst.mockResolvedValue(null);
    expect(await service.gateDecision('u1', 'dev-new', false)).toBe('allow');
  });

  it('only counts devices that are not revoked — revoking must mean something', async () => {
    prisma.trustedDevice.count.mockResolvedValue(2);
    prisma.trustedDevice.findFirst.mockResolvedValue(null);
    await service.gateDecision('u1', 'dev-old', true);

    expect(prisma.trustedDevice.findFirst).toHaveBeenCalledWith({
      where: { userId: 'u1', deviceId: 'dev-old', revokedAt: null },
    });
    expect(prisma.trustedDevice.count).toHaveBeenCalledWith({
      where: { userId: 'u1', revokedAt: null },
    });
  });
});

describe('DeviceApprovalService.listPending', () => {
  let service: DeviceApprovalService;
  let redis: any;

  const seed = async () => {
    const r = await service.createPending({
      userId: 'u1',
      deviceId: 'dev-new',
      deviceInfo: 'Pixel',
      ip: '1.2.3.4',
      email: 'a@b.c',
    });
    const record = JSON.parse(
      redis.store.get(`device_approval:${r.approvalToken}`)!,
    );
    return { token: r.approvalToken, approvalId: record.approvalId };
  };

  beforeEach(() => {
    redis = makeRedis();
    const prisma = makePrisma();
    prisma.session.findMany.mockResolvedValue([]);
    service = new DeviceApprovalService(
      prisma as any,
      redis as any,
      { sendDeviceApprovalRequest: jest.fn() } as any,
      { sendOtp: jest.fn() } as any,
    );
  });

  it('lists a pending request with its device details', async () => {
    const { approvalId } = await seed();

    const pending = await service.listPending('u1');

    expect(pending).toHaveLength(1);
    expect(pending[0].approvalId).toBe(approvalId);
    expect(pending[0].deviceInfo).toBe('Pixel');
  });

  it('never leaks the secret token into the listing', async () => {
    const { token } = await seed();

    const pending = await service.listPending('u1');

    expect(JSON.stringify(pending)).not.toContain(token);
  });

  it('drops a resolved request from the index', async () => {
    const { approvalId } = await seed();
    await service.approve('u1', approvalId);

    expect(await service.listPending('u1')).toHaveLength(0);
  });

  it('prunes entries whose record has expired', async () => {
    const { token, approvalId } = await seed();
    redis.store.delete(`device_approval:${token}`);

    expect(await service.listPending('u1')).toHaveLength(0);
    expect(redis.sets['device_approval_pending:u1'].has(approvalId)).toBe(false);
  });

  it('shows nothing for a user with no pending requests', async () => {
    expect(await service.listPending('nobody')).toEqual([]);
  });
});
