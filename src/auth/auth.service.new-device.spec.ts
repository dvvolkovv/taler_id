import * as bcrypt from 'bcrypt';

jest.mock('otplib', () => ({
  generateSecret: jest.fn(() => 'SECRET'),
  generateURI: jest.fn(() => 'otpauth://totp/test'),
  verify: jest.fn(async () => ({ valid: true })),
}));

// The constructor reads the JWT key files.
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn().mockReturnValue('mock-key-content'),
}));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { AuthService } = require('./auth.service');

describe('AuthService device identity', () => {
  let service: any;
  let prisma: any;
  let redis: any;
  let deviceApproval: any;

  beforeEach(async () => {
    const passwordHash = await bcrypt.hash('pw', 4);

    prisma = {
      user: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'u1',
          email: 'a@b.c',
          passwordHash,
          totpSecret: null,
        }),
        findUnique: jest.fn().mockResolvedValue({ id: 'u1', email: 'a@b.c' }),
      },
      session: {
        create: jest.fn(async ({ data }: any) => ({ id: 's1', ...data })),
      },
      kycRecord: { findUnique: jest.fn().mockResolvedValue(null) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
      profile: {
        findUnique: jest.fn().mockResolvedValue({ newDeviceApproval: false }),
      },
    };

    redis = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn(),
      setEx: jest.fn(),
      del: jest.fn(),
      incr: jest.fn().mockResolvedValue(1),
      expire: jest.fn(),
    };

    deviceApproval = {
      gateDecision: jest.fn().mockResolvedValue('allow'),
      touch: jest.fn().mockResolvedValue(undefined),
      createPending: jest.fn(),
    };

    service = new AuthService(
      prisma,
      { sign: jest.fn(() => 'jwt') },
      { get: jest.fn(() => undefined) },
      redis,
      { sendOtp: jest.fn() },
      { subscribeUser: jest.fn() },
      deviceApproval,
    );
  });

  it('stamps the session with the device id the client sent', async () => {
    await service.login(
      { email: 'a@b.c', password: 'pw' },
      '1.2.3.4',
      'UA',
      'dev-abc',
    );

    expect(prisma.session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ deviceId: 'dev-abc' }),
      }),
    );
  });

  it('leaves the column null for a client that sends no device id', async () => {
    await service.login({ email: 'a@b.c', password: 'pw' }, '1.2.3.4', 'UA');

    expect(prisma.session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ deviceId: null }),
      }),
    );
  });
});
