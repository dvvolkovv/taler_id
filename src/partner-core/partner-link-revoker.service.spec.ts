import { PartnerLinkRevokerService } from './partner-link-revoker.service';
import { PartnerRealtimeService } from './partner-realtime.service';

describe('PartnerRealtimeService', () => {
  it('does nothing until the gateway registers', async () => {
    await expect(new PartnerRealtimeService().disconnectGrant('g1')).resolves.toBeUndefined();
  });

  it('calls the registered disconnector and swallows its errors', async () => {
    const realtime = new PartnerRealtimeService();
    const fn = jest.fn().mockRejectedValue(new Error('boom'));
    realtime.registerDisconnector(fn);
    await expect(realtime.disconnectGrant('g1')).resolves.toBeUndefined();
    expect(fn).toHaveBeenCalledWith('g1');
  });
});

describe('PartnerLinkRevokerService', () => {
  let prisma: any;
  let tokens: any;
  let realtime: any;
  let revoker: PartnerLinkRevokerService;

  beforeEach(() => {
    prisma = { partnerLink: { update: jest.fn().mockResolvedValue({}), findMany: jest.fn() } };
    tokens = { revokeGrant: jest.fn().mockResolvedValue(undefined) };
    realtime = { disconnectGrant: jest.fn().mockResolvedValue(undefined) };
    revoker = new PartnerLinkRevokerService(prisma, tokens, realtime);
  });

  it('revokes the link, its tokens and its sockets', async () => {
    await revoker.revokeLink({ id: 'l1', grantId: 'g1' });
    expect(prisma.partnerLink.update).toHaveBeenCalledWith({
      where: { id: 'l1' },
      data: expect.objectContaining({ status: 'REVOKED', grantId: null, codeHash: null }),
    });
    expect(tokens.revokeGrant).toHaveBeenCalledWith('g1');
    expect(realtime.disconnectGrant).toHaveBeenCalledWith('g1');
  });

  it('skips tokens and sockets for a link that never had a grant', async () => {
    await revoker.revokeLink({ id: 'l1', grantId: null });
    expect(tokens.revokeGrant).not.toHaveBeenCalled();
    expect(realtime.disconnectGrant).not.toHaveBeenCalled();
  });

  it('revokes every live link of a user', async () => {
    prisma.partnerLink.findMany.mockResolvedValue([
      { id: 'l1', grantId: 'g1' },
      { id: 'l2', grantId: null },
    ]);
    await expect(revoker.revokeAllForUser('u1')).resolves.toBe(2);
    expect(prisma.partnerLink.findMany).toHaveBeenCalledWith({
      where: { userId: 'u1', status: { not: 'REVOKED' } },
      select: { id: true, grantId: true },
    });
    expect(prisma.partnerLink.update).toHaveBeenCalledTimes(2);
  });
});
