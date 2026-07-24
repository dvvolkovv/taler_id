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
import { SYSTEM_USER_EMAIL } from '../system-channel/system-channel.constants';

describe('AuthService.forgotPassword — system account guard', () => {
  function makeService() {
    const prisma = { user: { findUnique: jest.fn() } } as any;
    const emailService = { sendOtp: jest.fn() } as any;
    const redis = { get: jest.fn(), setEx: jest.fn(), del: jest.fn() } as any;
    const service = Object.create(AuthService.prototype) as AuthService;
    (service as any).prisma = prisma;
    (service as any).emailService = emailService;
    (service as any).redis = redis;
    return { service, prisma, emailService, redis };
  }

  it('returns { sent: true } for system account WITHOUT querying prisma or sending email', async () => {
    const { service, prisma, emailService } = makeService();

    const result = await service.forgotPassword(SYSTEM_USER_EMAIL);

    expect(result).toEqual({ sent: true });
    expect(prisma.user.findUnique).not.toHaveBeenCalled();
    expect(emailService.sendOtp).not.toHaveBeenCalled();
  });

  it('returns { sent: true } for system account even with mixed-case input', async () => {
    const { service, prisma, emailService } = makeService();

    const result = await service.forgotPassword('System@TalerId.IO');

    expect(result).toEqual({ sent: true });
    expect(prisma.user.findUnique).not.toHaveBeenCalled();
    expect(emailService.sendOtp).not.toHaveBeenCalled();
  });

  it('does NOT short-circuit for a regular unknown email (prisma called, no email sent)', async () => {
    const { service, prisma, emailService } = makeService();
    prisma.user.findUnique.mockResolvedValue(null);

    const result = await service.forgotPassword('nobody@example.com');

    expect(result).toEqual({ sent: true });
    expect(prisma.user.findUnique).toHaveBeenCalledTimes(1);
    expect(emailService.sendOtp).not.toHaveBeenCalled();
  });
});
