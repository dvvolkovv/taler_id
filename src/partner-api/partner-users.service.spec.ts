import { ConflictException } from '@nestjs/common';
import { PartnerUsersService, profileLanguage } from './partner-users.service';

const partner: any = { id: 'p1', slug: 'nadi', name: 'Nadi' };
const dto: any = {
  externalId: 'm-1',
  email: ' Ivan@Example.COM ',
  firstName: 'Іван',
  lastName: 'Петренко',
  locale: 'uk',
};
const liveUser = { id: 'u1', deletedAt: null, passwordHash: null };

function make() {
  const prisma: any = {
    partnerLink: {
      findUnique: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({}),
      update: jest.fn().mockResolvedValue({}),
      delete: jest.fn().mockResolvedValue({}),
    },
    user: {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({ id: 'u-new' }),
    },
    profile: { upsert: jest.fn().mockResolvedValue({}) },
    conversationParticipant: { deleteMany: jest.fn().mockResolvedValue({ count: 1 }) },
  };
  const tokens: any = { issueAccessToken: jest.fn(), revokeGrant: jest.fn() };
  const revoker: any = { revokeLink: jest.fn().mockResolvedValue(undefined) };
  const systemChannel: any = { subscribeUser: jest.fn().mockResolvedValue(undefined) };
  const profiles: any = { deleteAccount: jest.fn().mockResolvedValue({ success: true }) };
  const audit: any = { log: jest.fn().mockResolvedValue(undefined) };
  const service = new PartnerUsersService(prisma, tokens, revoker, systemChannel, profiles, audit);
  return { service, prisma, tokens, revoker, systemChannel, profiles, audit };
}

/** findUnique отвечает по форме where: связка по externalId или по пользователю. */
function links(prisma: any, byExternal: any, byUser: any = null) {
  prisma.partnerLink.findUnique.mockImplementation(({ where }: any) =>
    Promise.resolve(where.partnerId_externalId ? byExternal : where.partnerId_userId ? byUser : null),
  );
}

describe('PartnerUsersService.provision', () => {
  it('creates an account for a new email and links it as ACTIVE', async () => {
    const { service, prisma, systemChannel, audit } = make();
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u-new',
      created: true,
    });
    expect(prisma.user.findFirst).toHaveBeenCalledWith({
      where: { email: { equals: 'ivan@example.com', mode: 'insensitive' }, deletedAt: null },
      select: { id: true, passwordHash: true },
    });
    expect(prisma.user.create).toHaveBeenCalledWith({
      data: {
        email: 'ivan@example.com',
        emailVerified: true,
        profile: { create: { firstName: 'Іван', lastName: 'Петренко', language: 'en' } },
        kycRecord: { create: {} },
      },
      select: { id: true },
    });
    expect(systemChannel.subscribeUser).toHaveBeenCalledWith('u-new');
    expect(prisma.partnerLink.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        partnerId: 'p1',
        externalId: 'm-1',
        userId: 'u-new',
        status: 'ACTIVE',
        createdAccount: true,
      }),
    });
    expect(audit.log).toHaveBeenCalledWith(
      partner,
      'USER_CREATED',
      expect.objectContaining({ externalId: 'm-1', userId: 'u-new' }),
    );
  });

  it('is idempotent for an ACTIVE link', async () => {
    const { service, prisma } = make();
    links(prisma, { id: 'l1', userId: 'u1', status: 'ACTIVE', createdAccount: true, user: liveUser });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'active', talerUserId: 'u1', created: false });
    expect(prisma.user.findFirst).not.toHaveBeenCalled();
  });

  it('keeps a PENDING link pending', async () => {
    const { service, prisma } = make();
    links(prisma, { id: 'l1', userId: 'u1', status: 'PENDING', createdAccount: false, user: liveUser });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'confirmation_required', talerUserId: null });
  });

  it('asks for confirmation when the email already belongs to someone', async () => {
    const { service, prisma } = make();
    prisma.user.findFirst.mockResolvedValue({ id: 'u-existing', passwordHash: 'hash' });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'confirmation_required', talerUserId: null });
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.partnerLink.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ userId: 'u-existing', status: 'PENDING', createdAccount: false }),
    });
  });

  it('refuses when that account is linked under another externalId', async () => {
    const { service, prisma } = make();
    prisma.user.findFirst.mockResolvedValue({ id: 'u-existing', passwordHash: null });
    links(prisma, null, { id: 'l-other', userId: 'u-existing', externalId: 'm-0', status: 'ACTIVE', createdAccount: true });
    await expect(service.provision(partner, dto)).rejects.toThrow(ConflictException);
  });

  it('replaces a revoked link held under another externalId', async () => {
    const { service, prisma } = make();
    prisma.user.findFirst.mockResolvedValue({ id: 'u-existing', passwordHash: null });
    links(prisma, null, { id: 'l-other', userId: 'u-existing', externalId: 'm-0', status: 'REVOKED', createdAccount: true });
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u-existing',
      created: false,
    });
    expect(prisma.partnerLink.delete).toHaveBeenCalledWith({ where: { id: 'l-other' } });
  });

  it('reactivates its own managed account without a code', async () => {
    const { service, prisma } = make();
    const revoked = { id: 'l1', userId: 'u1', externalId: 'm-1', status: 'REVOKED', createdAccount: true, grantId: null, user: liveUser };
    links(prisma, revoked, revoked);
    prisma.user.findFirst.mockResolvedValue({ id: 'u1', passwordHash: null });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'active', talerUserId: 'u1', created: false });
    expect(prisma.partnerLink.update).toHaveBeenCalledWith({
      where: { id: 'l1' },
      data: expect.objectContaining({ status: 'ACTIVE', revokedAt: null }),
    });
  });

  it('asks for a code again once the person has set a TalerID password', async () => {
    const { service, prisma } = make();
    const revoked = {
      id: 'l1', userId: 'u1', externalId: 'm-1', status: 'REVOKED', createdAccount: true, grantId: null,
      user: { ...liveUser, passwordHash: 'set' },
    };
    links(prisma, revoked, revoked);
    prisma.user.findFirst.mockResolvedValue({ id: 'u1', passwordHash: 'set' });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'confirmation_required', talerUserId: null });
  });

  it('revokes a link whose account was deleted and starts over', async () => {
    const { service, prisma, revoker } = make();
    const stale = {
      id: 'l1', userId: 'u-dead', externalId: 'm-1', status: 'ACTIVE', createdAccount: true, grantId: 'g1',
      user: { id: 'u-dead', deletedAt: new Date(), passwordHash: null },
    };
    links(prisma, stale);
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'active', talerUserId: 'u-new', created: true });
    expect(revoker.revokeLink).toHaveBeenCalledWith(stale);
    expect(prisma.partnerLink.update).toHaveBeenCalledWith({
      where: { id: 'l1' },
      data: expect.objectContaining({ userId: 'u-new', status: 'ACTIVE' }),
    });
  });

  it('finishes an unfinished revocation before reusing the link row', async () => {
    const { service, prisma, revoker } = make();
    const unfinished = { id: 'l1', userId: 'u1', externalId: 'm-1', status: 'REVOKED', createdAccount: true, grantId: 'g-old', user: liveUser };
    links(prisma, unfinished, unfinished);
    prisma.user.findFirst.mockResolvedValue({ id: 'u1', passwordHash: null });
    await service.provision(partner, dto);
    expect(revoker.revokeLink).toHaveBeenCalledWith(unfinished);
  });

  it('finishes the revocation of a stale link under another externalId before deleting it', async () => {
    const { service, prisma, revoker } = make();
    prisma.user.findFirst.mockResolvedValue({ id: 'u-existing', passwordHash: null });
    const other = { id: 'l-other', userId: 'u-existing', externalId: 'm-0', status: 'REVOKED', createdAccount: true, grantId: 'g-old' };
    links(prisma, null, other);
    await service.provision(partner, dto);
    expect(revoker.revokeLink).toHaveBeenCalledWith(other);
    expect(prisma.partnerLink.delete).toHaveBeenCalledWith({ where: { id: 'l-other' } });
  });

  it('retries once on a unique-constraint race', async () => {
    const { service, prisma } = make();
    prisma.user.create.mockRejectedValueOnce(Object.assign(new Error('dup'), { code: 'P2002' }));
    prisma.user.findFirst.mockResolvedValueOnce(null).mockResolvedValueOnce({ id: 'u-raced', passwordHash: 'x' });
    await expect(service.provision(partner, dto)).resolves.toEqual({ status: 'confirmation_required', talerUserId: null });
  });
});

describe('profileLanguage', () => {
  it.each([
    ['ru', 'ru'],
    ['ru-UA', 'ru'],
    ['en', 'en'],
    ['uk', 'en'],
    [undefined, 'en'],
  ])('%p → %p', (input: string | undefined, out: string) => {
    expect(profileLanguage(input)).toBe(out);
  });
});
