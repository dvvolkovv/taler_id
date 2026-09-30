import { ConflictException, ServiceUnavailableException } from '@nestjs/common';
import { PartnerTokensService } from './partner-tokens.service';
import { PARTNER_TOKEN_GTY } from './partner.constants';

const NOW = Math.floor(new Date('2026-10-01T10:00:00Z').getTime() / 1000);
const DAY = 24 * 3600;

/** Живой грант oidc-provider в том виде, в каком его отдаёт Grant.find. */
const liveGrant = (over: Record<string, unknown> = {}) => ({
  jti: 'grant-1',
  accountId: 'u1',
  clientId: 'nadi-partner',
  exp: NOW + 30 * DAY,
  ...over,
});

function makeProvider() {
  const grants: any[] = [];
  const Grant: any = jest.fn().mockImplementation((args: any) => {
    const id = grants.length === 0 ? 'grant-new' : `grant-new-${grants.length + 1}`;
    const grant = { args, addOIDCScope: jest.fn(), save: jest.fn().mockResolvedValue(id) };
    grants.push(grant);
    return grant;
  });
  Grant.find = jest.fn();
  Grant.adapter = { destroy: jest.fn().mockResolvedValue(undefined) };
  const tokens: any[] = [];
  const AccessToken: any = jest.fn().mockImplementation((args: any) => {
    const at = {
      args,
      expiresIn: undefined as number | undefined,
      // как у BaseToken: ttl.AccessToken провайдера, пока токену не задали свой срок
      get expiration(): number {
        return this.expiresIn ?? 900;
      },
      save: jest.fn().mockResolvedValue('at-opaque'),
    };
    tokens.push(at);
    return at;
  });
  AccessToken.find = jest.fn();
  AccessToken.revokeByGrantId = jest.fn().mockResolvedValue(undefined);
  const Client = { find: jest.fn().mockResolvedValue({ clientId: 'nadi-partner' }) };
  return { provider: { Grant, AccessToken, Client } as any, grants, tokens };
}

const partner: any = { id: 'p1', slug: 'nadi', oauthClientId: 'nadi-partner', enabled: true };
const saved = process.env.PARTNER_API_ENABLED;

describe('PartnerTokensService', () => {
  let provider: any;
  let grants: any[];
  let tokens: any[];
  let prisma: any;
  let registry: any;
  let service: PartnerTokensService;

  beforeEach(() => {
    jest.useFakeTimers({ now: NOW * 1000 });
    process.env.PARTNER_API_ENABLED = 'true';
    ({ provider, grants, tokens } = makeProvider());
    prisma = {
      partnerLink: {
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        findUnique: jest.fn(),
      },
    };
    registry = { findByClientId: jest.fn().mockResolvedValue(partner) };
    service = new PartnerTokensService(provider, prisma, registry);
  });
  afterEach(() => jest.useRealTimers());
  afterAll(() => {
    if (saved === undefined) delete process.env.PARTNER_API_ENABLED;
    else process.env.PARTNER_API_ENABLED = saved;
  });

  describe('issueAccessToken', () => {
    it('reuses a live grant of the same user and client', async () => {
      provider.Grant.find.mockResolvedValue(liveGrant());
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(res).toEqual({ accessToken: 'at-opaque', expiresIn: 900, grantId: 'grant-1' });
      expect(provider.Grant.find).toHaveBeenCalledWith('grant-1');
      expect(provider.Grant).not.toHaveBeenCalled();
      expect(provider.AccessToken).toHaveBeenCalledWith({
        accountId: 'u1',
        client: { clientId: 'nadi-partner' },
        grantId: 'grant-1',
        scope: 'messenger',
        gty: PARTNER_TOKEN_GTY,
      });
      expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
    });

    it('creates and stores a new grant when the old one expired', async () => {
      provider.Grant.find.mockResolvedValue(undefined);
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-old' }, partner);
      expect(res).toEqual({ accessToken: 'at-opaque', expiresIn: 900, grantId: 'grant-new' });
      expect(grants[0].args).toEqual({ accountId: 'u1', clientId: 'nadi-partner' });
      expect(grants[0].addOIDCScope).toHaveBeenCalledWith('messenger');
      expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith({
        where: { id: 'l1', status: 'ACTIVE', grantId: 'grant-old' },
        data: { grantId: 'grant-new' },
      });
      expect(provider.AccessToken).toHaveBeenCalledWith(expect.objectContaining({ grantId: 'grant-new' }));
    });

    it('creates a grant for a link that never had one, destroying nothing', async () => {
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: null }, partner);
      expect(provider.Grant.find).not.toHaveBeenCalled();
      expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith({
        where: { id: 'l1', status: 'ACTIVE', grantId: null },
        data: { grantId: 'grant-new' },
      });
      expect(res.grantId).toBe('grant-new');
      expect(provider.Grant.adapter.destroy).not.toHaveBeenCalled();
    });

    it.each([
      ['vanished', undefined],
      ['nearly expired', liveGrant({ exp: NOW + 30 })],
      ["another user's", liveGrant({ accountId: 'u2' })],
      ["another client's", liveGrant({ clientId: 'acme-partner' })],
    ])('destroys the replaced %s grant once the swap succeeded', async (_name: string, found: any) => {
      provider.Grant.find.mockResolvedValue(found);
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(res.grantId).toBe('grant-new');
      expect(provider.Grant.adapter.destroy.mock.calls).toEqual([['grant-1']]);
      expect(prisma.partnerLink.updateMany.mock.invocationCallOrder[0]).toBeLessThan(
        provider.Grant.adapter.destroy.mock.invocationCallOrder[0],
      );
    });

    it('leaves the old grant alone when the swap is lost: it is up to the winner', async () => {
      provider.Grant.find
        .mockResolvedValueOnce(liveGrant({ exp: NOW + 30 })) // grant-1: меньше минуты — меняем
        .mockResolvedValueOnce(liveGrant({ jti: 'grant-2' })); // победитель уже поставил grant-2
      prisma.partnerLink.updateMany.mockResolvedValueOnce({ count: 0 });
      prisma.partnerLink.findUnique.mockResolvedValue({ userId: 'u1', grantId: 'grant-2', status: 'ACTIVE' });

      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);

      expect(res.grantId).toBe('grant-2');
      // уничтожен только свой свежий грант — ни grant-1, ни grant-2 победителя
      expect(provider.Grant.adapter.destroy.mock.calls).toEqual([['grant-new']]);
    });

    it.each([
      ['another user', { accountId: 'u2' }],
      ['another client', { clientId: 'acme-partner' }],
    ])('replaces, not reuses, a live grant of %s', async (_name: string, over: Record<string, unknown>) => {
      provider.Grant.find.mockResolvedValue(liveGrant(over));
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(res.grantId).toBe('grant-new');
      expect(grants[0].args).toEqual({ accountId: 'u1', clientId: 'nadi-partner' });
      expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith({
        where: { id: 'l1', status: 'ACTIVE', grantId: 'grant-1' },
        data: { grantId: 'grant-new' },
      });
      expect(provider.AccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ accountId: 'u1', grantId: 'grant-new' }),
      );
    });

    it('caps the token to the remaining life of the reused grant', async () => {
      provider.Grant.find.mockResolvedValue(liveGrant({ exp: NOW + 300 }));
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(tokens[0].expiresIn).toBe(300);
      expect(tokens[0].save).toHaveBeenCalled();
      expect(res).toEqual({ accessToken: 'at-opaque', expiresIn: 300, grantId: 'grant-1' });
    });

    it('still reuses a grant with exactly a minute left', async () => {
      provider.Grant.find.mockResolvedValue(liveGrant({ exp: NOW + 60 }));
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(provider.Grant).not.toHaveBeenCalled();
      expect(res).toEqual({ accessToken: 'at-opaque', expiresIn: 60, grantId: 'grant-1' });
    });

    it('replaces a grant with less than a minute left instead of issuing a token that dies with it', async () => {
      provider.Grant.find.mockResolvedValue(liveGrant({ exp: NOW + 59 }));
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(res).toEqual({ accessToken: 'at-opaque', expiresIn: 900, grantId: 'grant-new' });
      expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 'l1', status: 'ACTIVE', grantId: 'grant-1' } }),
      );
    });

    it('reports the TTL the provider actually gave the token', async () => {
      provider.Grant.find.mockResolvedValue(liveGrant());
      provider.AccessToken.mockImplementationOnce((args: any) => ({
        args,
        expiration: 600,
        save: jest.fn().mockResolvedValue('at-short'),
      }));
      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner);
      expect(res).toEqual({ accessToken: 'at-short', expiresIn: 600, grantId: 'grant-1' });
    });

    it('on a lost compare-and-swap destroys its grant and retries once on the current one', async () => {
      prisma.partnerLink.updateMany.mockResolvedValueOnce({ count: 0 });
      prisma.partnerLink.findUnique.mockResolvedValue({ userId: 'u1', grantId: 'grant-2', status: 'ACTIVE' });
      provider.Grant.find.mockResolvedValue(liveGrant({ jti: 'grant-2' }));

      const res = await service.issueAccessToken({ id: 'l1', userId: 'u1', grantId: null }, partner);

      expect(provider.Grant.adapter.destroy).toHaveBeenCalledWith('grant-new');
      expect(prisma.partnerLink.findUnique).toHaveBeenCalledWith({
        where: { id: 'l1' },
        select: { userId: true, grantId: true, status: true },
      });
      expect(provider.Grant.find).toHaveBeenCalledWith('grant-2');
      expect(provider.Grant).toHaveBeenCalledTimes(1);
      expect(prisma.partnerLink.updateMany).toHaveBeenCalledTimes(1);
      expect(provider.AccessToken).toHaveBeenCalledTimes(1);
      expect(provider.AccessToken).toHaveBeenCalledWith(
        expect.objectContaining({ accountId: 'u1', grantId: 'grant-2' }),
      );
      expect(res).toEqual({ accessToken: 'at-opaque', expiresIn: 900, grantId: 'grant-2' });
    });

    it('gives up with 409 link_changed when the compare-and-swap is lost twice', async () => {
      // третья попытка выиграла бы — но её быть не должно
      prisma.partnerLink.updateMany
        .mockResolvedValueOnce({ count: 0 })
        .mockResolvedValueOnce({ count: 0 })
        .mockResolvedValue({ count: 1 });
      prisma.partnerLink.findUnique.mockResolvedValue({ userId: 'u1', grantId: 'grant-2', status: 'ACTIVE' });
      provider.Grant.find.mockResolvedValue(undefined);

      const err = await service
        .issueAccessToken({ id: 'l1', userId: 'u1', grantId: null }, partner)
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(ConflictException);
      expect((err as ConflictException).message).toBe('link_changed');
      expect(provider.Grant.adapter.destroy.mock.calls).toEqual([['grant-new'], ['grant-new-2']]);
      expect(prisma.partnerLink.findUnique).toHaveBeenCalledTimes(1);
      expect(provider.AccessToken).not.toHaveBeenCalled();
    });

    it.each([
      ['revoked', { userId: 'u1', grantId: null, status: 'REVOKED' }],
      ['gone', null],
    ])('answers 409 link_not_active when the link is %s by the time of the swap', async (_name, current) => {
      provider.Grant.find.mockResolvedValue(liveGrant({ exp: NOW + 30 }));
      prisma.partnerLink.updateMany.mockResolvedValue({ count: 0 });
      prisma.partnerLink.findUnique.mockResolvedValue(current);

      const err = await service
        .issueAccessToken({ id: 'l1', userId: 'u1', grantId: 'grant-1' }, partner)
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(ConflictException);
      expect((err as ConflictException).message).toBe('link_not_active');
      // grant-1 гасит сам отзыв; выпуск уничтожает только свой свежий грант
      expect(provider.Grant.adapter.destroy.mock.calls).toEqual([['grant-new']]);
      expect(provider.AccessToken).not.toHaveBeenCalled();
    });
  });

  describe('revokeGrant', () => {
    it('destroys the grant first, then cleans up its tokens', async () => {
      await service.revokeGrant('grant-1');
      const destroy = provider.Grant.adapter.destroy;
      const cleanup = provider.AccessToken.revokeByGrantId;
      expect(destroy).toHaveBeenCalledWith('grant-1');
      expect(cleanup).toHaveBeenCalledWith('grant-1');
      expect(destroy.mock.invocationCallOrder[0]).toBeLessThan(cleanup.mock.invocationCallOrder[0]);
    });

    it('lets a store failure through so the caller keeps the link for a retry', async () => {
      provider.Grant.adapter.destroy.mockRejectedValue(new Error('redis down'));
      await expect(service.revokeGrant('grant-1')).rejects.toThrow('redis down');
      expect(provider.AccessToken.revokeByGrantId).not.toHaveBeenCalled();
    });
  });

  describe('verify', () => {
    const value = 'a'.repeat(43);
    const token = {
      accountId: 'u1',
      clientId: 'nadi-partner',
      grantId: 'grant-1',
      scope: 'messenger',
      gty: PARTNER_TOKEN_GTY,
      exp: 1_900_000_000,
      isExpired: false,
    };
    const grant = { accountId: 'u1', clientId: 'nadi-partner' };

    it('returns the principal for a live messenger token of an enabled partner', async () => {
      provider.AccessToken.find.mockResolvedValue(token);
      provider.Grant.find.mockResolvedValue(grant);
      await expect(service.verify(value)).resolves.toEqual({
        userId: 'u1',
        partnerId: 'p1',
        partnerSlug: 'nadi',
        grantId: 'grant-1',
        expiresAt: 1_900_000_000,
      });
      expect(provider.AccessToken.find).toHaveBeenCalledWith(value);
      expect(provider.Grant.find).toHaveBeenCalledWith('grant-1');
    });

    it.each([
      ['an unknown token', undefined, grant],
      ['an expired token', { ...token, isExpired: true }, grant],
      ['a token without the messenger scope', { ...token, scope: 'openid mcp:calendar' }, grant],
      ['a token without a grant', { ...token, grantId: undefined }, grant],
      ['a token not issued by the partner API', { ...token, gty: 'authorization_code' }, grant],
      ['a token whose grant is gone', token, undefined],
      ['a token whose grant belongs to another user', token, { ...grant, accountId: 'u2' }],
      ['a token whose grant belongs to another client', token, { ...grant, clientId: 'acme-partner' }],
    ])('returns null for %s', async (_name: string, found: any, foundGrant: any) => {
      provider.AccessToken.find.mockResolvedValue(found);
      provider.Grant.find.mockResolvedValue(foundGrant);
      await expect(service.verify(value)).resolves.toBeNull();
    });

    it.each([
      ['an empty string', ''],
      ['a TalerID app JWT', 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2lnbmF0dXJl'],
      ['a 42-char value', 'a'.repeat(42)],
      ['a 44-char value', 'a'.repeat(44)],
      ['43 chars outside base64url', `${'a'.repeat(42)}.`],
      ['a missing value', undefined],
    ])('returns null for %s without touching the token store', async (_name: string, bad: any) => {
      await expect(service.verify(bad)).resolves.toBeNull();
      expect(provider.AccessToken.find).not.toHaveBeenCalled();
      expect(provider.Grant.find).not.toHaveBeenCalled();
    });

    it('returns null when the client is not a partner or the partner is off', async () => {
      provider.AccessToken.find.mockResolvedValue(token);
      provider.Grant.find.mockResolvedValue(grant);
      registry.findByClientId.mockResolvedValueOnce(null);
      await expect(service.verify(value)).resolves.toBeNull();
      registry.findByClientId.mockResolvedValueOnce({ ...partner, enabled: false });
      await expect(service.verify(value)).resolves.toBeNull();
    });

    it('is off entirely while PARTNER_API_ENABLED is not true', async () => {
      process.env.PARTNER_API_ENABLED = 'false';
      await expect(service.verify(value)).resolves.toBeNull();
      expect(provider.AccessToken.find).not.toHaveBeenCalled();
    });

    it('maps a token store failure to 503, not to "invalid token"', async () => {
      provider.AccessToken.find.mockRejectedValue(new Error('redis down'));
      await expect(service.verify(value)).rejects.toThrow(ServiceUnavailableException);
    });

    it('maps a grant lookup failure to 503 as well', async () => {
      provider.AccessToken.find.mockResolvedValue(token);
      provider.Grant.find.mockRejectedValue(new Error('redis down'));
      await expect(service.verify(value)).rejects.toThrow(ServiceUnavailableException);
    });
  });
});
