import { UnauthorizedException } from '@nestjs/common';

jest.mock('otplib', () => ({
  generateSecret: jest.fn(() => 'SECRET'),
  generateURI: jest.fn(() => 'otpauth://totp/test'),
  verify: jest.fn(async () => ({ valid: false })),
}));

jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn().mockReturnValue('mock-key-content'),
}));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { AuthService } = require('./auth.service');

// Regression cover for the 2026-07-27 audit finding: rotation did GET then DEL
// (racy), never noticed a replayed token, and ignored Session.expiresAt.
describe('AuthService.refreshTokens rotation', () => {
  let service: any;
  let prisma: any;
  let store: Map<string, string>;
  let redisClient: any;

  const SESSION_ID = 'session-1';
  const future = () => new Date(Date.now() + 86_400_000);

  beforeEach(() => {
    store = new Map();

    redisClient = {
      // Atomic claim, as Redis GETDEL is.
      getdel: jest.fn(async (k: string) => {
        const v = store.get(k) ?? null;
        store.delete(k);
        return v;
      }),
    };

    const redis = {
      get: jest.fn(async (k: string) => store.get(k) ?? null),
      setEx: jest.fn(async (k: string, _t: number, v: string) => {
        store.set(k, v);
      }),
      del: jest.fn(async (k: string) => void store.delete(k)),
      getClient: () => redisClient,
    };

    prisma = {
      session: {
        findUnique: jest.fn().mockResolvedValue({
          id: SESSION_ID,
          userId: 'user-1',
          isRevoked: false,
          expiresAt: future(),
          user: { id: 'user-1', email: 'u@e.com', kycRecord: null },
        }),
        update: jest.fn().mockResolvedValue({}),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      kycRecord: { findUnique: jest.fn().mockResolvedValue(null) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };

    service = new AuthService(
      prisma,
      { sign: jest.fn(() => 'signed-token'), verify: jest.fn() },
      { get: jest.fn().mockReturnValue(4) },
      redis,
      { send: jest.fn() },
      { ensureMembership: jest.fn() },
    );

    store.set('refresh:token-1', SESSION_ID);
  });

  it('issues a new pair for a valid token', async () => {
    const res = await service.refreshTokens('token-1', '1.2.3.4', 'agent');
    expect(res.accessToken).toBe('signed-token');
    expect(typeof res.refreshToken).toBe('string');
  });

  it('claims the token atomically, so a concurrent retry finds nothing', async () => {
    await service.refreshTokens('token-1', '1.2.3.4', 'agent');
    expect(redisClient.getdel).toHaveBeenCalledWith('refresh:token-1');
    expect(store.has('refresh:token-1')).toBe(false);
  });

  it('revokes the session when a spent token is replayed', async () => {
    await service.refreshTokens('token-1', '1.2.3.4', 'agent');

    await expect(
      service.refreshTokens('token-1', '5.6.7.8', 'thief'),
    ).rejects.toThrow(/reuse detected/);

    expect(prisma.session.updateMany).toHaveBeenCalledWith({
      where: { id: SESSION_ID, isRevoked: false },
      data: { isRevoked: true },
    });
  });

  it('reports an unknown token plainly, without revoking anything', async () => {
    await expect(
      service.refreshTokens('never-existed', '1.2.3.4', 'agent'),
    ).rejects.toThrow(/Invalid or expired refresh token/);

    expect(prisma.session.updateMany).not.toHaveBeenCalled();
  });

  it('refuses a session past its expiry', async () => {
    prisma.session.findUnique.mockResolvedValue({
      id: SESSION_ID,
      userId: 'user-1',
      isRevoked: false,
      expiresAt: new Date(Date.now() - 1000),
      user: { id: 'user-1', email: 'u@e.com', kycRecord: null },
    });

    await expect(
      service.refreshTokens('token-1', '1.2.3.4', 'agent'),
    ).rejects.toThrow(/Session expired/);
  });

  it('refuses a revoked session', async () => {
    prisma.session.findUnique.mockResolvedValue({
      id: SESSION_ID,
      userId: 'user-1',
      isRevoked: true,
      expiresAt: future(),
      user: { id: 'user-1', email: 'u@e.com', kycRecord: null },
    });

    await expect(
      service.refreshTokens('token-1', '1.2.3.4', 'agent'),
    ).rejects.toThrow(UnauthorizedException);
  });
});
