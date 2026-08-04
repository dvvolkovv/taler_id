import { TrustedDeviceService } from './trusted-device.service';

describe('TrustedDeviceService', () => {
  let service: TrustedDeviceService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      trustedDevice: {
        findMany: jest.fn().mockResolvedValue([
          { id: 't1', deviceId: 'dev-1', deviceInfo: 'Pixel', label: null },
          { id: 't2', deviceId: 'dev-2', deviceInfo: 'iPhone', label: null },
        ]),
        findFirst: jest.fn().mockResolvedValue({ id: 't1', deviceId: 'dev-1' }),
        update: jest.fn().mockResolvedValue({}),
      },
      session: { updateMany: jest.fn().mockResolvedValue({ count: 2 }) },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };
    service = new TrustedDeviceService(prisma as any);
  });

  it('marks the current device in the list', async () => {
    const list = await service.list('u1', 'dev-1');

    expect(list[0].isCurrent).toBe(true);
    expect(list[1].isCurrent).toBe(false);
  });

  it('marks nothing current for a client that sends no device id', async () => {
    const list = await service.list('u1', undefined);

    expect(list.every((d) => !d.isCurrent)).toBe(true);
  });

  it('hides revoked devices from the list', async () => {
    await service.list('u1', 'dev-1');

    expect(prisma.trustedDevice.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { userId: 'u1', revokedAt: null },
      }),
    );
  });

  it('revoking a device also kills its live sessions', async () => {
    await service.revoke('u1', 't1', '1.2.3.4', 'UA');

    expect(prisma.trustedDevice.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: { revokedAt: expect.any(Date) } }),
    );
    expect(prisma.session.updateMany).toHaveBeenCalledWith({
      where: { userId: 'u1', deviceId: 'dev-1', isRevoked: false },
      data: { isRevoked: true },
    });
  });

  it('refuses to revoke a device belonging to somebody else', async () => {
    prisma.trustedDevice.findFirst.mockResolvedValue(null);

    await expect(service.revoke('u2', 't1', '', '')).rejects.toThrow(
      /not found/i,
    );
    expect(prisma.session.updateMany).not.toHaveBeenCalled();
  });
});
