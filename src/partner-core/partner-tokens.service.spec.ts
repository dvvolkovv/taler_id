import { ServiceUnavailableException } from '@nestjs/common';
import { PartnerTokensService } from './partner-tokens.service';

function makeProvider() {
  const grants: any[] = [];
  const Grant: any = jest.fn().mockImplementation((args: any) => {
    const grant = { args, addOIDCScope: jest.fn(), save: jest.fn().mockResolvedValue('grant-new') };
    grants.push(grant);
    return grant;
  });
  Grant.find = jest.fn();
  const AccessToken: any = jest.fn().mockImplementation((args: any) => ({
    args,
    save: jest.fn().mockResolvedValue('at-opaque'),
  }));
  AccessToken.find = jest.fn();
  AccessToken.adapter = { revokeByGrantId: jest.fn().mockResolvedValue(undefined) };
  const Client = { find: jest.fn().mockResolvedValue({ clientId: 'nadi-partner' }) };
  return { provider: { Grant, AccessToken, Client } as any, grants };
}

const partner: any = { id: 'p1', slug: 'nadi', oauthClientId: 'nadi-partner', enabled: true };
const saved = process.env.PARTNER_API_ENABLED;

describe('PartnerTokensService', () => {
  let provider: any;
  let grants: any[];
  let prisma: any;
  let registry: any;
  let service: PartnerTokensService;

  beforeEach(() => {
    process.env.PARTNER_API_ENABLED = 'true';
    ({ provider, grants } = makeProvider());
    prisma = { partnerLink: { update: jest.fn().mockResolvedValue({}) } };
    registry = { findByClientId: jest.fn().mockResolvedValue(partner) };
    service = new PartnerTokensService(provider, prisma, registry);
  });
  afterAll(() => {
    if (saved === undefined) delete process.env.PARTNER_API_ENABLED;
    else process.env.PARTNER_API_ENABLED = saved;
  });

  describe('issueAccessToken', () => {
    it('reuses a live grant', async () => {
      provider.Grant.find.mockResolvedValue({ jti: 'grant-1' });
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(res).toEqual({ accessToken: 'at-opaque', expiresIn: 900, grantId: 'grant-1' });
      expect(provider.Grant).not.toHaveBeenCalled();
      expect(provider.AccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ accountId: 'u1', grantId: 'grant-1', scope: 'messenger' }),
      );
      expect(prisma.partnerLink.update).not.toHaveBeenCalled();
    });

    it('creates and stores a new grant when the old one expired', async () => {
      provider.Grant.find.mockResolvedValue(undefined);
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-old' }, partner);
      expect(res.grantId).toBe('grant-new');
      expect(grants[0].args).toEqual({ accountId: 'u1', clientId: 'nadi-partner' });
      expect(grants[0].addOIDCScope).toHaveBeenCalledWith('messenger');
      expect(prisma.partnerLink.update).toHaveBeenCalledWith({ where: { id: 'l1' }, data: { grantId: 'grant-new' } });
    });

    it('creates a grant for a link that never had one', async () => {
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: null }, partner);
      expect(provider.Grant.find).not.toHaveBeenCalled();
      expect(res.grantId).toBe('grant-new');
    });

    it('reports the TTL the provider actually gave the token', async () => {
      provider.Grant.find.mockResolvedValue({ jti: 'grant-1' });
      provider.AccessToken.mockImplementationOnce((args: any) => ({
        args,
        expiration: 600,
        save: jest.fn().mockResolvedValue('at-short'),
      }));
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(res).toEqual({ accessToken: 'at-short', expiresIn: 600, grantId: 'grant-1' });
    });
  });

  describe('revokeGrant', () => {
    it('revokes the tokens and destroys the grant', async () => {
      const destroy = jest.fn();
      provider.Grant.find.mockResolvedValue({ destroy });
      await service.revokeGrant('grant-1');
      expect(provider.AccessToken.adapter.revokeByGrantId).toHaveBeenCalledWith('grant-1');
      expect(destroy).toHaveBeenCalled();
    });
  });

  describe('verify', () => {
    const token = {
      accountId: 'u1',
      clientId: 'nadi-partner',
      grantId: 'grant-1',
      scope: 'messenger',
      exp: 1_900_000_000,
      isExpired: false,
    };

    it('returns the principal for a live messenger token of an enabled partner', async () => {
      provider.AccessToken.find.mockResolvedValue(token);
      await expect(service.verify('opaque')).resolves.toEqual({
        userId: 'u1',
        partnerId: 'p1',
        partnerSlug: 'nadi',
        grantId: 'grant-1',
        expiresAt: 1_900_000_000,
      });
    });

    it.each([
      ['an unknown token', undefined],
      ['an expired token', { ...token, isExpired: true }],
      ['a token without the messenger scope', { ...token, scope: 'openid mcp:calendar' }],
      ['a token without a grant', { ...token, grantId: undefined }],
    ])('returns null for %s', async (_name: string, found: any) => {
      provider.AccessToken.find.mockResolvedValue(found);
      await expect(service.verify('opaque')).resolves.toBeNull();
    });

    it('returns null when the client is not a partner or the partner is off', async () => {
      provider.AccessToken.find.mockResolvedValue(token);
      registry.findByClientId.mockResolvedValueOnce(null);
      await expect(service.verify('opaque')).resolves.toBeNull();
      registry.findByClientId.mockResolvedValueOnce({ ...partner, enabled: false });
      await expect(service.verify('opaque')).resolves.toBeNull();
    });

    it('is off entirely while PARTNER_API_ENABLED is not true', async () => {
      process.env.PARTNER_API_ENABLED = 'false';
      await expect(service.verify('opaque')).resolves.toBeNull();
      expect(provider.AccessToken.find).not.toHaveBeenCalled();
    });

    it('maps a token store failure to 503, not to "invalid token"', async () => {
      provider.AccessToken.find.mockRejectedValue(new Error('redis down'));
      await expect(service.verify('opaque')).rejects.toThrow(ServiceUnavailableException);
    });
  });
});
