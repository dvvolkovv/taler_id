// Mock ESM modules that cannot be loaded in Jest (same pattern as auth.service.spec.ts)
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn().mockReturnValue('mock-key-content'),
}));

jest.mock('otplib', () => ({
  generateSecret: jest.fn(),
  generateURI: jest.fn(),
  verify: jest.fn(),
}));

jest.mock('qrcode', () => ({
  toDataURL: jest.fn(),
}));

import { AuthService } from './auth.service';

/**
 * Если партнёр (nadi) завёл аккаунт на адрес, который на деле не проверил,
 * настоящий владелец ящика получает аккаунт через «забыли пароль» — но не
 * должен делить его с чужим человеком у партнёра. Первый пароль на таком
 * аккаунте (passwordHash null → не-null) обязан отозвать все его партнёрские
 * связки. Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 */
describe('AuthService.resetPassword — revokes partner links on first password', () => {
  function makeService(
    opts: {
      user?: any;
      revokeAllForUser?: jest.Mock;
    } = {},
  ) {
    const user = opts.user ?? {
      id: 'u1',
      email: 'ivan@example.com',
      passwordHash: null,
      createdByPartnerId: 'p1',
    };
    const prisma: any = {
      user: {
        findUnique: jest.fn().mockResolvedValue(user),
        update: jest
          .fn()
          .mockResolvedValue({ ...user, passwordHash: 'new-hash' }),
      },
      session: { updateMany: jest.fn().mockResolvedValue({ count: 0 }) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };
    const jwtService: any = {
      verify: jest
        .fn()
        .mockReturnValue({ purpose: 'password_reset', email: user.email }),
    };
    const configService: any = { get: jest.fn().mockReturnValue(4) };
    const partnerLinks: any = {
      revokeAllForUser: opts.revokeAllForUser ?? jest.fn().mockResolvedValue(0),
    };
    const service = Object.create(AuthService.prototype) as AuthService;
    (service as any).prisma = prisma;
    (service as any).jwtService = jwtService;
    (service as any).configService = configService;
    (service as any).partnerLinks = partnerLinks;
    (service as any).publicKey = 'pub';
    (service as any).logger = {
      error: jest.fn(),
      warn: jest.fn(),
      log: jest.fn(),
    };
    return { service, prisma, jwtService, configService, partnerLinks };
  }

  it('revokes every partner link when a partner-managed account (no password yet) sets its first password', async () => {
    const { service, partnerLinks } = makeService();
    await expect(service.resetPassword('tok', 'NewPass123!')).resolves.toEqual({
      reset: true,
    });
    expect(partnerLinks.revokeAllForUser).toHaveBeenCalledWith('u1');
  });

  it('does not revoke anything for an account that already had a password', async () => {
    const { service, partnerLinks } = makeService({
      user: {
        id: 'u2',
        email: 'ivan@example.com',
        passwordHash: 'already-set',
        createdByPartnerId: 'p1',
      },
    });
    await service.resetPassword('tok', 'NewPass123!');
    expect(partnerLinks.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('does not revoke anything for an account no partner ever created', async () => {
    const { service, partnerLinks } = makeService({
      user: {
        id: 'u3',
        email: 'ivan@example.com',
        passwordHash: null,
        createdByPartnerId: null,
      },
    });
    await service.resetPassword('tok', 'NewPass123!');
    expect(partnerLinks.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('still resets the password and returns success when revocation fails (logged, not thrown)', async () => {
    const { service, prisma } = makeService({
      revokeAllForUser: jest.fn().mockRejectedValue(new Error('redis down')),
    });
    const errorSpy = jest.spyOn((service as any).logger, 'error');
    await expect(service.resetPassword('tok', 'NewPass123!')).resolves.toEqual({
      reset: true,
    });
    expect(errorSpy).toHaveBeenCalled();
    expect(prisma.user.update).toHaveBeenCalled();
  });

  it('revokes links only after the new password has actually been saved', async () => {
    const { service, partnerLinks, prisma } = makeService();
    await service.resetPassword('tok', 'NewPass123!');
    expect(prisma.user.update.mock.invocationCallOrder[0]).toBeLessThan(
      partnerLinks.revokeAllForUser.mock.invocationCallOrder[0],
    );
  });
});
