import { Logger } from '@nestjs/common';
import { PartnerLinkRevokerService } from './partner-link-revoker.service';
import { PartnerRealtimeService } from './partner-realtime.service';

describe('PartnerRealtimeService', () => {
  let warn: jest.SpyInstance;

  beforeEach(() => {
    warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
  });
  afterEach(() => warn.mockRestore());

  it('warns that sockets stay open while no gateway is registered', async () => {
    await expect(new PartnerRealtimeService().disconnectLink('p1', 'u1')).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('p1:u1 were not disconnected'));
  });

  it('calls the registered disconnector with the link', async () => {
    const realtime = new PartnerRealtimeService();
    const fn = jest.fn();
    realtime.registerDisconnector(fn);
    await realtime.disconnectLink('p1', 'u1');
    expect(fn).toHaveBeenCalledWith('p1', 'u1');
    expect(warn).not.toHaveBeenCalled();
  });

  it('swallows and logs a failing disconnector', async () => {
    const realtime = new PartnerRealtimeService();
    const fn = jest.fn().mockRejectedValue(new Error('boom'));
    realtime.registerDisconnector(fn);
    await expect(realtime.disconnectLink('p1', 'u1')).resolves.toBeUndefined();
    expect(fn).toHaveBeenCalledWith('p1', 'u1');
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('boom'));
  });
});

describe('PartnerLinkRevokerService', () => {
  let prisma: any;
  let tokens: any;
  let realtime: any;
  let revoker: PartnerLinkRevokerService;

  beforeEach(() => {
    prisma = {
      partnerLink: {
        update: jest.fn().mockResolvedValue({ grantId: 'g-db', partnerId: 'p1', userId: 'u1', revokedAt: null }),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        findMany: jest.fn(),
      },
    };
    tokens = { revokeGrant: jest.fn().mockResolvedValue(undefined) };
    realtime = { disconnectLink: jest.fn().mockResolvedValue(undefined) };
    revoker = new PartnerLinkRevokerService(prisma, tokens, realtime);
  });

  it('flips the link to REVOKED keeping its grant, and reads the grant from that same row', async () => {
    await revoker.revokeLink({ id: 'l1', grantId: 'g-stale' } as any);
    expect(prisma.partnerLink.update).toHaveBeenCalledWith({
      where: { id: 'l1' },
      data: {
        status: 'REVOKED',
        codeHash: null,
        codeExpiresAt: null,
        codeAttempts: 0,
      },
      select: { grantId: true, partnerId: true, userId: true, revokedAt: true },
    });
    expect(tokens.revokeGrant).toHaveBeenCalledTimes(1);
    expect(tokens.revokeGrant).toHaveBeenCalledWith('g-db');
  });

  it('clears the grant only after revoking it, and only if the row still holds it', async () => {
    await revoker.revokeLink({ id: 'l1' });
    expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith({
      where: { id: 'l1', grantId: 'g-db' },
      data: { grantId: null },
    });
    expect(tokens.revokeGrant.mock.invocationCallOrder[0]).toBeLessThan(
      prisma.partnerLink.updateMany.mock.invocationCallOrder[0],
    );
  });

  it('disconnects the link room after the tokens are gone', async () => {
    await revoker.revokeLink({ id: 'l1' });
    expect(realtime.disconnectLink).toHaveBeenCalledWith('p1', 'u1');
    expect(tokens.revokeGrant.mock.invocationCallOrder[0]).toBeLessThan(
      realtime.disconnectLink.mock.invocationCallOrder[0],
    );
  });

  it('keeps the grant on the link when revoking it fails, so a retry can finish', async () => {
    tokens.revokeGrant.mockRejectedValue(new Error('redis down'));
    await expect(revoker.revokeLink({ id: 'l1' })).rejects.toThrow('redis down');
    expect(prisma.partnerLink.update).toHaveBeenCalledTimes(1);
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
    expect(realtime.disconnectLink).not.toHaveBeenCalled();
  });

  it('still disconnects sockets of a link that has no grant', async () => {
    prisma.partnerLink.update.mockResolvedValue({ grantId: null, partnerId: 'p1', userId: 'u1', revokedAt: null });
    await revoker.revokeLink({ id: 'l1' });
    expect(tokens.revokeGrant).not.toHaveBeenCalled();
    expect(realtime.disconnectLink).toHaveBeenCalledWith('p1', 'u1');
  });

  it('sets revokedAt via the guarded updateMany on first revocation', async () => {
    prisma.partnerLink.update.mockResolvedValue({ grantId: null, partnerId: 'p1', userId: 'u1', revokedAt: null });
    await revoker.revokeLink({ id: 'l1' });
    expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith({
      where: { id: 'l1', status: 'REVOKED', revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
  });

  it('does not rewrite revokedAt when completing an already-revoked row', async () => {
    const firstRevokedAt = new Date('2026-01-01T00:00:00Z');
    prisma.partnerLink.update.mockResolvedValue({
      grantId: 'g-db',
      partnerId: 'p1',
      userId: 'u1',
      revokedAt: firstRevokedAt,
    });
    await revoker.revokeLink({ id: 'l1' });
    // The grant is still cleared (that's the "unfinished revocation" this row represents)...
    expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith({
      where: { id: 'l1', grantId: 'g-db' },
      data: { grantId: null },
    });
    // ...but revokedAt is never touched a second time.
    const revokedAtWrites = prisma.partnerLink.updateMany.mock.calls.filter(([args]: any[]) => 'revokedAt' in args.data);
    expect(revokedAtWrites).toHaveLength(0);
  });

  describe('revokeAllForUser', () => {
    it('revokes every live link of a user and every revoked one still holding a grant', async () => {
      prisma.partnerLink.findMany.mockResolvedValue([{ id: 'l1' }, { id: 'l2' }]);
      await expect(revoker.revokeAllForUser('u1')).resolves.toBe(2);
      expect(prisma.partnerLink.findMany).toHaveBeenCalledWith({
        where: { userId: 'u1', OR: [{ status: { not: 'REVOKED' } }, { grantId: { not: null } }] },
        select: { id: true },
      });
      expect(prisma.partnerLink.update.mock.calls.map(([args]: any[]) => args.where)).toEqual([
        { id: 'l1' },
        { id: 'l2' },
      ]);
    });

    it('goes on after a failed link and reports every failure at the end', async () => {
      prisma.partnerLink.findMany.mockResolvedValue([{ id: 'l1' }, { id: 'l2' }, { id: 'l3' }]);
      tokens.revokeGrant
        .mockRejectedValueOnce(new Error('redis down'))
        .mockResolvedValueOnce(undefined)
        .mockRejectedValueOnce(new Error('timeout'));

      const err = await revoker.revokeAllForUser('u1').catch((e: Error) => e);

      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('partner link revocation failed: l1: redis down; l3: timeout');
      expect(prisma.partnerLink.update).toHaveBeenCalledTimes(3);
      expect(realtime.disconnectLink).toHaveBeenCalledTimes(1);
    });

    it('returns 0 when there is nothing to revoke', async () => {
      prisma.partnerLink.findMany.mockResolvedValue([]);
      await expect(revoker.revokeAllForUser('u1')).resolves.toBe(0);
      expect(prisma.partnerLink.update).not.toHaveBeenCalled();
    });
  });
});
