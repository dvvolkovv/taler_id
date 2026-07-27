import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

// otplib pulls in @noble/* ESM that jest's transformIgnorePatterns does not
// cover, and these cases never need a real TOTP: every code here is wrong on
// purpose, so the counter is what is under test.
jest.mock('otplib', () => ({
  generateSecret: jest.fn(() => 'SECRET'),
  generateURI: jest.fn(() => 'otpauth://totp/test'),
  verify: jest.fn(async () => ({ valid: false })),
}));

// The constructor reads the JWT key files.
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn().mockReturnValue('mock-key-content'),
}));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { AuthService } = require('./auth.service');

// Regression cover for two 2026-07-27 audit findings:
//  - changing or resetting a password left every other session (and its 30-day
//    refresh token) usable, so it did not evict an intruder;
//  - a 2FA challenge survived unlimited wrong codes for its full 5 minutes.
describe('AuthService credential-change side effects', () => {
  let service: any;
  let prisma: any;
  let redis: any;
  let store: Map<string, string>;
  let counters: Map<string, number>;

  const USER_ID = 'user-1';

  beforeEach(async () => {
    store = new Map();
    counters = new Map();

    redis = {
      get: jest.fn(async (k: string) => store.get(k) ?? null),
      set: jest.fn(async (k: string, v: string) => void store.set(k, v)),
      setEx: jest.fn(async (k: string, _t: number, v: string) => {
        store.set(k, v);
      }),
      del: jest.fn(async (k: string) => {
        store.delete(k);
        counters.delete(k);
      }),
      incr: jest.fn(async (k: string) => {
        const n = (counters.get(k) ?? 0) + 1;
        counters.set(k, n);
        return n;
      }),
      expire: jest.fn(async () => undefined),
    };

    const passwordHash = await bcrypt.hash('current-password', 4);
    prisma = {
      user: {
        findUnique: jest.fn().mockResolvedValue({
          id: USER_ID,
          email: 'user@example.com',
          passwordHash,
          totpSecret: { secret: 'SECRET', verified: true },
        }),
        update: jest.fn().mockResolvedValue({}),
      },
      session: { updateMany: jest.fn().mockResolvedValue({ count: 3 }) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };

    // (prisma, jwtService, configService, redis, emailService, systemChannel)
    service = new AuthService(
      prisma,
      { sign: jest.fn(() => 'token'), verify: jest.fn() },
      { get: jest.fn().mockReturnValue(4) },
      redis,
      { send: jest.fn() },
      { ensureMembership: jest.fn() },
    );
  });

  describe('changePassword', () => {
    it('revokes the other sessions but keeps the caller signed in', async () => {
      await service.changePassword(
        USER_ID,
        'current-password',
        'new-password',
        '1.2.3.4',
        'agent',
        'session-current',
      );

      expect(prisma.session.updateMany).toHaveBeenCalledWith({
        where: {
          userId: USER_ID,
          isRevoked: false,
          id: { not: 'session-current' },
        },
        data: { isRevoked: true },
      });
    });

    it('revokes every session when the caller session is unknown', async () => {
      await service.changePassword(
        USER_ID,
        'current-password',
        'new-password',
        '1.2.3.4',
        'agent',
      );

      expect(prisma.session.updateMany).toHaveBeenCalledWith({
        where: { userId: USER_ID, isRevoked: false },
        data: { isRevoked: true },
      });
    });

    it('does not revoke anything when the current password is wrong', async () => {
      await expect(
        service.changePassword(
          USER_ID,
          'wrong-password',
          'new-password',
          '1.2.3.4',
          'agent',
          'session-current',
        ),
      ).rejects.toThrow(UnauthorizedException);

      expect(prisma.session.updateMany).not.toHaveBeenCalled();
      expect(prisma.user.update).not.toHaveBeenCalled();
    });
  });

  describe('verify2fa', () => {
    const CHALLENGE = 'challenge-1';

    beforeEach(() => {
      store.set(`2fa_challenge:${CHALLENGE}`, USER_ID);
    });

    it('discards the challenge after five wrong codes', async () => {
      for (let i = 0; i < 4; i++) {
        await expect(
          service.verify2fa(CHALLENGE, '000000', '1.2.3.4', 'agent'),
        ).rejects.toThrow('Invalid 2FA code');
      }

      // Fifth miss burns it...
      await expect(
        service.verify2fa(CHALLENGE, '000000', '1.2.3.4', 'agent'),
      ).rejects.toThrow(/sign in again/);

      // ...so the challenge no longer resolves to a user at all.
      await expect(
        service.verify2fa(CHALLENGE, '000000', '1.2.3.4', 'agent'),
      ).rejects.toThrow(/Invalid or expired challenge/);
    });

    it('rejects an unknown challenge token outright', async () => {
      await expect(
        service.verify2fa('no-such-challenge', '000000', '1.2.3.4', 'agent'),
      ).rejects.toThrow(/Invalid or expired challenge/);
    });
  });
});
