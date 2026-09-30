import { BadRequestException } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { PartnerApiController } from './partner-api.controller';
import { PartnerKeyGuard } from './partner-key.guard';
import { PartnerRateLimitGuard } from './partner-rate-limit.guard';

describe('PartnerApiController', () => {
  const partner: any = { id: 'p1', slug: 'nadi' };
  const req: any = { partner, ip: '1.2.3.4' };
  let users: any;
  let codes: any;
  let contacts: any;
  let controller: PartnerApiController;

  beforeEach(() => {
    users = { provision: jest.fn(), getUser: jest.fn(), patchUser: jest.fn(), deleteUser: jest.fn(), issueToken: jest.fn() };
    codes = { send: jest.fn(), verify: jest.fn() };
    contacts = { put: jest.fn(), remove: jest.fn() };
    controller = new PartnerApiController(users, codes, contacts);
  });

  it('passes deleteAccount=true through and validates the externalId', async () => {
    await controller.deleteUser(req, 'm-1', 'true');
    expect(users.deleteUser).toHaveBeenCalledWith(partner, 'm-1', true, '1.2.3.4');
    await controller.deleteUser(req, 'm-1', undefined);
    expect(users.deleteUser).toHaveBeenLastCalledWith(partner, 'm-1', false, '1.2.3.4');
    expect(() => controller.getUser(req, 'bad id')).toThrow(BadRequestException);
  });

  it('hands the six-digit code to the code service', () => {
    controller.verifyLinkCode(req, 'm-1', { code: '123456' });
    expect(codes.verify).toHaveBeenCalledWith(partner, 'm-1', '123456', '1.2.3.4');
  });

  it('is guarded by the partner key and limit instead of the global per-IP throttler', () => {
    expect(Reflect.getMetadata(GUARDS_METADATA, PartnerApiController)).toEqual([
      PartnerKeyGuard,
      PartnerRateLimitGuard,
    ]);
    for (const name of ['short', 'medium', 'long']) {
      expect(Reflect.getMetadata(`THROTTLER:SKIP${name}`, PartnerApiController)).toBe(true);
    }
  });
});
