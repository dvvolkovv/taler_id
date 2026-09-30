import { PartnerAuditService } from './partner-audit.service';

describe('PartnerAuditService', () => {
  it('writes a PARTNER_* audit row with the partner and externalId', async () => {
    const prisma: any = { auditLog: { create: jest.fn().mockResolvedValue({}) } };
    await new PartnerAuditService(prisma).log({ id: 'p1', slug: 'nadi' }, 'USER_CREATED', {
      externalId: 'm-1',
      userId: 'u1',
      ip: '1.2.3.4',
      meta: { otherUserId: 'u2' },
    });
    expect(prisma.auditLog.create).toHaveBeenCalledWith({
      data: {
        userId: 'u1',
        action: 'PARTNER_USER_CREATED',
        ipAddress: '1.2.3.4',
        meta: { partner: 'nadi', externalId: 'm-1', otherUserId: 'u2' },
      },
    });
  });

  it('never fails the request because of the audit log', async () => {
    const prisma: any = { auditLog: { create: jest.fn().mockRejectedValue(new Error('db down')) } };
    await expect(
      new PartnerAuditService(prisma).log({ id: 'p1', slug: 'nadi' }, 'LINK_REVOKED', {}),
    ).resolves.toBeUndefined();
  });

  it('meta cannot overwrite the partner slug or externalId', async () => {
    const prisma: any = { auditLog: { create: jest.fn().mockResolvedValue({}) } };
    await new PartnerAuditService(prisma).log({ id: 'p1', slug: 'nadi' }, 'USER_CREATED', {
      externalId: 'm-1',
      meta: { partner: 'evil', externalId: 'evil', extra: 1 },
    });
    expect(prisma.auditLog.create).toHaveBeenCalledWith({
      data: {
        userId: null,
        action: 'PARTNER_USER_CREATED',
        ipAddress: null,
        meta: { extra: 1, partner: 'nadi', externalId: 'm-1' },
      },
    });
  });
});
