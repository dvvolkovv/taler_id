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
      partnerLink: { updateMany: jest.fn().mockResolvedValue({ count: 1 }) },
      session: { updateMany: jest.fn().mockResolvedValue({ count: 0 }) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };
    // Мок транзакции просто выполняет колбэк на том же prisma — настоящий
    // откат при ошибке внутри проверяет e2e-набор на реальной базе, не этот мок.
    prisma.$transaction = jest.fn((fn: any) => fn(prisma));
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

  it('marks non-REVOKED partner links REVOKED with revokedAt, in the SAME transaction as the password write, keeping grantId for revokeAllForUser to finish', async () => {
    const { service, prisma } = makeService();
    await service.resetPassword('tok', 'NewPass123!');
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith({
      where: { userId: 'u1', status: { not: 'REVOKED' } },
      data: { status: 'REVOKED', revokedAt: expect.any(Date) },
    });
    // grantId не упомянут вовсе — его отзыв (Redis/OIDC) остаётся за
    // revokeAllForUser, у этой записи нет доступа к стороне, которая не
    // откатывается вместе с транзакцией.
    const call = (prisma.partnerLink.updateMany as jest.Mock).mock.calls[0][0];
    expect(call.data).not.toHaveProperty('grantId');
  });

  it('does not touch partner links for an account that already had a password', async () => {
    const { service, prisma } = makeService({
      user: {
        id: 'u2',
        email: 'ivan@example.com',
        passwordHash: 'already-set',
        createdByPartnerId: 'p1',
      },
    });
    await service.resetPassword('tok', 'NewPass123!');
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
  });

  it('does not touch partner links for an account no partner ever created', async () => {
    const { service, prisma } = makeService({
      user: {
        id: 'u3',
        email: 'ivan@example.com',
        passwordHash: null,
        createdByPartnerId: null,
      },
    });
    await service.resetPassword('tok', 'NewPass123!');
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
  });

  it('commits the password+link-status transaction before calling revokeAllForUser (grant teardown is best-effort afterward)', async () => {
    const { service, prisma, partnerLinks } = makeService();
    await service.resetPassword('tok', 'NewPass123!');
    expect(prisma.$transaction.mock.invocationCallOrder[0]).toBeLessThan(
      partnerLinks.revokeAllForUser.mock.invocationCallOrder[0],
    );
  });
});
