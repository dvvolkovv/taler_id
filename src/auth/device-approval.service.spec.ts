import { DeviceApprovalService } from './device-approval.service';

function makeRedis() {
  const store = new Map<string, string>();
  const counters = new Map<string, number>();
  return {
    store,
    counters,
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
