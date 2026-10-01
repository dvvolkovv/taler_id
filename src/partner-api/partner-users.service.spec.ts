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
// Партнёр p1 завёл этот аккаунт: пароля нет, аккаунт жив — «управляемый».
const liveUser = {
  id: 'u1',
  email: 'ivan@example.com',
  deletedAt: null,
  passwordHash: null,
  createdByPartnerId: 'p1',
};

function make() {
  const prisma: any = {
    partnerLink: {
      findUnique: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({}),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
    user: {
      create: jest.fn().mockResolvedValue({ id: 'u-new' }),
    },
    profile: { upsert: jest.fn().mockResolvedValue({}) },
    conversationParticipant: {
      deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
    // Владелец почты теперь ищется точным SQL (lower(email)=lower(...)), а не findFirst.
    $queryRaw: jest.fn().mockResolvedValue([]),
  };
  // Мок транзакции просто выполняет колбэк на том же prisma — настоящий откат
  // при ошибке внутри проверяет e2e-набор на реальной базе, не этот мок.
  prisma.$transaction = jest.fn((fn: any) => fn(prisma));
  const tokens: any = { issueAccessToken: jest.fn(), revokeGrant: jest.fn() };
  const revoker: any = { revokeLink: jest.fn().mockResolvedValue(undefined) };
  const systemChannel: any = {
    subscribeUser: jest.fn().mockResolvedValue(undefined),
  };
  const profiles: any = {
    deleteAccount: jest.fn().mockResolvedValue({ success: true }),
  };
  const audit: any = { log: jest.fn().mockResolvedValue(undefined) };
  const service = new PartnerUsersService(
    prisma,
    tokens,
    revoker,
    systemChannel,
    profiles,
    audit,
  );
  return { service, prisma, tokens, revoker, systemChannel, profiles, audit };
}

/** findUnique отвечает по форме where: связка по externalId или по пользователю. */
function links(prisma: any, byExternal: any, byUser: any = null) {
  prisma.partnerLink.findUnique.mockImplementation(({ where }: any) =>
    Promise.resolve(
      where.partnerId_externalId
        ? byExternal
        : where.partnerId_userId
          ? byUser
          : null,
    ),
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
    expect(prisma.$queryRaw).toHaveBeenCalledTimes(1);
    expect(prisma.user.create).toHaveBeenCalledWith({
      data: {
        email: 'ivan@example.com',
        emailVerified: true,
        createdByPartnerId: 'p1',
        profile: {
          create: { firstName: 'Іван', lastName: 'Петренко', language: 'en' },
        },
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
    links(prisma, { id: 'l1', userId: 'u1', status: 'ACTIVE', user: liveUser });
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u1',
      created: false,
    });
    expect(prisma.$queryRaw).not.toHaveBeenCalled();
    // Ничего не пишем: живая связка отвечает без единой записи в базу.
    expect(prisma.partnerLink.create).not.toHaveBeenCalled();
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
    expect(prisma.partnerLink.deleteMany).not.toHaveBeenCalled();
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('keeps a PENDING link pending', async () => {
    const { service, prisma } = make();
    links(prisma, {
      id: 'l1',
      userId: 'u1',
      status: 'PENDING',
      user: liveUser,
    });
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'confirmation_required',
      talerUserId: null,
    });
    expect(prisma.$queryRaw).not.toHaveBeenCalled();
    expect(prisma.partnerLink.create).not.toHaveBeenCalled();
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
    expect(prisma.partnerLink.deleteMany).not.toHaveBeenCalled();
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('asks for confirmation when the email already belongs to someone', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-existing',
        passwordHash: 'hash',
        deletedAt: null,
        createdByPartnerId: null,
      },
    ]);
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'confirmation_required',
      talerUserId: null,
    });
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.partnerLink.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        userId: 'u-existing',
        status: 'PENDING',
      }),
    });
  });

  it('refuses when that account is linked under another externalId', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-existing',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: null,
      },
    ]);
    links(prisma, null, {
      id: 'l-other',
      userId: 'u-existing',
      externalId: 'm-0',
      status: 'ACTIVE',
    });
    await expect(service.provision(partner, dto)).rejects.toThrow(
      ConflictException,
    );
  });

  it('replaces a revoked link held under another externalId', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-existing',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: 'p1',
      },
    ]);
    links(prisma, null, {
      id: 'l-other',
      userId: 'u-existing',
      externalId: 'm-0',
      status: 'REVOKED',
      grantId: null,
    });
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u-existing',
      created: false,
    });
    expect(prisma.partnerLink.deleteMany).toHaveBeenCalledWith({
      where: { id: 'l-other', status: 'REVOKED', grantId: null },
    });
  });

  it('reactivates its own managed account without a code', async () => {
    const { service, prisma } = make();
    const revoked = {
      id: 'l1',
      userId: 'u1',
      externalId: 'm-1',
      status: 'REVOKED',
      grantId: null,
      user: liveUser,
    };
    links(prisma, revoked, revoked);
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u1',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: 'p1',
      },
    ]);
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u1',
      created: false,
    });
    expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith({
      where: { id: 'l1', userId: 'u1', status: 'REVOKED', grantId: null },
      data: expect.objectContaining({ status: 'ACTIVE', revokedAt: null }),
    });
  });

  it('asks for a code again once the person has set a TalerID password', async () => {
    const { service, prisma } = make();
    const revoked = {
      id: 'l1',
      userId: 'u1',
      externalId: 'm-1',
      status: 'REVOKED',
      grantId: null,
      user: { ...liveUser, passwordHash: 'set' },
    };
    links(prisma, revoked, revoked);
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u1',
        passwordHash: 'set',
        deletedAt: null,
        createdByPartnerId: 'p1',
      },
    ]);
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'confirmation_required',
      talerUserId: null,
    });
  });

  it('revokes a link whose account was deleted and starts over', async () => {
    const { service, prisma, revoker } = make();
    const stale = {
      id: 'l1',
      userId: 'u-dead',
      externalId: 'm-1',
      status: 'ACTIVE',
      grantId: 'g1',
      user: {
        id: 'u-dead',
        email: 'dead@old.com',
        deletedAt: new Date(),
        passwordHash: null,
        createdByPartnerId: 'p1',
      },
    };
    links(prisma, stale);
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u-new',
      created: true,
    });
    expect(revoker.revokeLink).toHaveBeenCalledWith(stale);
    expect(prisma.partnerLink.updateMany).toHaveBeenCalledWith({
      where: { id: 'l1', userId: 'u-dead', status: 'REVOKED', grantId: null },
      data: expect.objectContaining({ userId: 'u-new', status: 'ACTIVE' }),
    });
  });

  it('finishes an unfinished revocation before reusing the link row', async () => {
    const { service, prisma, revoker } = make();
    const unfinished = {
      id: 'l1',
      userId: 'u1',
      externalId: 'm-1',
      status: 'REVOKED',
      grantId: 'g-old',
      user: liveUser,
    };
    links(prisma, unfinished, unfinished);
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u1',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: 'p1',
      },
    ]);
    await service.provision(partner, dto);
    expect(revoker.revokeLink).toHaveBeenCalledWith(unfinished);
    // Отзыв должен успеть закончиться до того, как строку переиспользуют:
    // иначе updateMany состязался бы с ещё идущим revokeLink за тот же грант.
    expect(revoker.revokeLink.mock.invocationCallOrder[0]).toBeLessThan(
      prisma.partnerLink.updateMany.mock.invocationCallOrder[0],
    );
  });

  it('finishes the revocation of a stale link under another externalId before deleting it', async () => {
    const { service, prisma, revoker } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-existing',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: null,
      },
    ]);
    const other = {
      id: 'l-other',
      userId: 'u-existing',
      externalId: 'm-0',
      status: 'REVOKED',
      grantId: 'g-old',
    };
    links(prisma, null, other);
    await service.provision(partner, dto);
    expect(revoker.revokeLink).toHaveBeenCalledWith(other);
    expect(prisma.partnerLink.deleteMany).toHaveBeenCalledWith({
      where: { id: 'l-other', status: 'REVOKED', grantId: null },
    });
  });

  it('retries once on a unique-constraint race and picks up the concurrent write', async () => {
    const { service, prisma } = make();
    const concurrent = {
      id: 'l1',
      userId: 'u-raced',
      status: 'ACTIVE',
      grantId: null,
      user: {
        id: 'u-raced',
        email: 'ivan@example.com',
        deletedAt: null,
        passwordHash: null,
        createdByPartnerId: 'p1',
      },
    };
    prisma.partnerLink.findUnique
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(concurrent);
    prisma.partnerLink.create.mockRejectedValueOnce(
      Object.assign(new Error('dup'), { code: 'P2002' }),
    );
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u-raced',
      created: false,
    });
    // Аккаунт, созданный в первой (проигранной) попытке, второй раз не создаётся —
    // вторая попытка подхватывает уже активную связку конкурента.
    expect(prisma.user.create).toHaveBeenCalledTimes(1);
  });

  it('looks up the owner by exact case-insensitive match, not a SQL LIKE pattern', async () => {
    const { service, prisma } = make();
    const patternDto = { ...dto, email: 'ivan_petrenko%@example.com' };
    await service.provision(partner, patternDto);
    expect(prisma.$queryRaw).toHaveBeenCalledTimes(1);
    const [strings, ...values] = prisma.$queryRaw.mock.calls[0];
    expect(strings.join('')).toContain('lower("email") = lower(');
    // Regular equals + mode:'insensitive' compiles to ILIKE on Postgres, and `_`/`%`
    // in the address would work as wildcards there. Здесь значение просто bind-параметр.
    expect(values).toEqual(['ivan_petrenko%@example.com']);
  });

  it('refuses to provision over an admin-blocked account and leaves it alone', async () => {
    const { service, prisma } = make();
    // AdminService.deleteUser блокирует через deletedAt, почту не обнуляет —
    // второй аккаунт на тот же адрес завести нельзя.
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-blocked',
        passwordHash: null,
        deletedAt: new Date(),
        createdByPartnerId: null,
      },
    ]);
    await expect(service.provision(partner, dto)).rejects.toThrow(
      'email_unavailable',
    );
    expect(prisma.user.create).not.toHaveBeenCalled();
  });

  it('does not treat an account managed by a different partner as its own', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-other-partner',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: 'p2',
      },
    ]);
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'confirmation_required',
      talerUserId: null,
    });
    expect(prisma.partnerLink.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        userId: 'u-other-partner',
        status: 'PENDING',
      }),
    });
  });

  it('gives up after repeated CAS misses on link reuse', async () => {
    const { service, prisma } = make();
    const revoked = {
      id: 'l1',
      userId: 'u1',
      externalId: 'm-1',
      status: 'REVOKED',
      grantId: null,
      user: liveUser,
    };
    links(prisma, revoked, revoked);
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u1',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: 'p1',
      },
    ]);
    prisma.partnerLink.updateMany.mockResolvedValue({ count: 0 });
    await expect(service.provision(partner, dto)).rejects.toThrow('link_busy');
    expect(prisma.partnerLink.updateMany).toHaveBeenCalledTimes(3);
  });

  it('treats a lost stale-link cleanup as a race too', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-existing',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: null,
      },
    ]);
    const other = {
      id: 'l-other',
      userId: 'u-existing',
      externalId: 'm-0',
      status: 'REVOKED',
      grantId: null,
    };
    links(prisma, null, other);
    prisma.partnerLink.deleteMany.mockResolvedValue({ count: 0 });
    await expect(service.provision(partner, dto)).rejects.toThrow('link_busy');
    expect(prisma.partnerLink.deleteMany).toHaveBeenCalledTimes(3);
  });

  it('turns a plain revocation failure into 503', async () => {
    const { service, prisma, revoker } = make();
    const unfinished = {
      id: 'l1',
      userId: 'u1',
      externalId: 'm-1',
      status: 'REVOKED',
      grantId: 'g-old',
      user: liveUser,
    };
    links(prisma, unfinished, unfinished);
    revoker.revokeLink.mockRejectedValueOnce(new Error('redis down'));
    await expect(service.provision(partner, dto)).rejects.toThrow(
      'revocation_unavailable',
    );
  });

  it('lets an HttpException from revocation pass through unchanged', async () => {
    const { service, prisma, revoker } = make();
    const unfinished = {
      id: 'l1',
      userId: 'u1',
      externalId: 'm-1',
      status: 'REVOKED',
      grantId: 'g-old',
      user: liveUser,
    };
    links(prisma, unfinished, unfinished);
    revoker.revokeLink.mockRejectedValueOnce(new ConflictException('weird'));
    await expect(service.provision(partner, dto)).rejects.toThrow(
      ConflictException,
    );
  });
});

describe('profileLanguage', () => {
  it.each([
    ['ru', 'ru'],
    ['ru-UA', 'ru'],
    ['en', 'en'],
    ['uk', 'en'],
    [undefined, 'en'],
    [null, 'en'],
  ])('%p → %p', (input: string | null | undefined, out: string) => {
    expect(profileLanguage(input)).toBe(out);
  });
});

describe('PartnerUsersService token and lifecycle', () => {
  const active = {
    id: 'l1',
    userId: 'u1',
    status: 'ACTIVE',
    grantId: 'g1',
    activatedAt: new Date('2026-10-01T10:00:00Z'),
    user: liveUser,
  };

  it('issues a messenger token for an ACTIVE link', async () => {
    const { service, prisma, tokens } = make();
    links(prisma, active);
    tokens.issueAccessToken.mockResolvedValue({
      accessToken: 'at',
      expiresIn: 900,
      grantId: 'g1',
    });
    await expect(service.issueToken(partner, 'm-1')).resolves.toEqual({
      accessToken: 'at',
      tokenType: 'Bearer',
      expiresIn: 900,
      talerUserId: 'u1',
    });
    expect(tokens.issueAccessToken).toHaveBeenCalledWith(active, partner);
  });

  it.each([
    [null, 'not_linked'],
    [{ ...active, status: 'REVOKED' }, 'not_linked'],
    [{ ...active, status: 'PENDING' }, 'confirmation_required'],
  ])('refuses a token for link %#', async (link: any, message: string) => {
    const { service, prisma } = make();
    links(prisma, link);
    await expect(service.issueToken(partner, 'm-1')).rejects.toThrow(message);
  });

  it('revokes the link and answers 410 when the account was deleted in TalerID', async () => {
    const { service, prisma, revoker } = make();
    const dead = { ...active, user: { ...liveUser, deletedAt: new Date() } };
    links(prisma, dead);
    const err = await service.issueToken(partner, 'm-1').catch((e) => e);
    expect(err.getStatus()).toBe(410);
    expect(revoker.revokeLink).toHaveBeenCalledWith(dead);
  });

  it('revokes and answers not_linked for a PENDING link whose account was deleted', async () => {
    const { service, prisma, revoker } = make();
    // activatedAt: null — a genuine PENDING link was never confirmed, so the
    // partner was never let in and must not learn the account was deleted.
    const deadPending = {
      ...active,
      status: 'PENDING',
      activatedAt: null,
      user: { ...liveUser, deletedAt: new Date() },
    };
    links(prisma, deadPending);
    await expect(service.issueToken(partner, 'm-1')).rejects.toThrow(
      'not_linked',
    );
    expect(revoker.revokeLink).toHaveBeenCalledWith(deadPending);
  });

  it('keeps answering 410 on repeat calls once the deletion-triggered revoke is complete', async () => {
    const { service, prisma, revoker } = make();
    // Task 19 revoked this link AFTER the account got deleted (revokedAt > deletedAt)
    // and finished the job (grantId: null) — the partner had consent (activatedAt set).
    const revokedByDeletion = {
      ...active,
      status: 'REVOKED',
      grantId: null,
      revokedAt: new Date('2026-10-01T11:00:00Z'),
      user: { ...liveUser, deletedAt: new Date('2026-10-01T10:30:00Z') },
    };
    links(prisma, revokedByDeletion);
    const first = await service.issueToken(partner, 'm-1').catch((e) => e);
    expect(first.getStatus()).toBe(410);
    const second = await service.issueToken(partner, 'm-1').catch((e) => e);
    expect(second.getStatus()).toBe(410);
    // Уже полностью отозвана — второй раз отзывать нечего.
    expect(revoker.revokeLink).not.toHaveBeenCalled();
  });

  it('answers 404, not 410, when the partner had already let go before the account was deleted', async () => {
    const { service, prisma, revoker } = make();
    // The partner itself revoked this link BEFORE the account was deleted
    // (revokedAt < deletedAt) — it must not learn about a deletion it has no
    // business knowing about for a link it already let go of.
    const revokedByPartner = {
      ...active,
      status: 'REVOKED',
      grantId: null,
      revokedAt: new Date('2026-10-01T09:00:00Z'),
      user: { ...liveUser, deletedAt: new Date('2026-10-01T10:00:00Z') },
    };
    links(prisma, revokedByPartner);
    await expect(service.issueToken(partner, 'm-1')).rejects.toThrow(
      'not_linked',
    );
    expect(revoker.revokeLink).not.toHaveBeenCalled();
  });

  it('reports the status without leaking the id of a pending account', async () => {
    const { service, prisma } = make();
    links(prisma, {
      ...active,
      status: 'PENDING',
      activatedAt: null,
      user: { ...liveUser, createdByPartnerId: null },
    });
    await expect(service.getUser(partner, 'm-1')).resolves.toEqual({
      status: 'confirmation_required',
      talerUserId: null,
      managed: false,
      linkedAt: null,
    });
    links(prisma, active);
    await expect(service.getUser(partner, 'm-1')).resolves.toEqual({
      status: 'active',
      talerUserId: 'u1',
      managed: true,
      linkedAt: '2026-10-01T10:00:00.000Z',
    });
  });

  it('reports a deleted account as revoked (ACTIVE link) or not_linked (PENDING link)', async () => {
    const { service, prisma } = make();
    links(prisma, { ...active, user: { ...liveUser, deletedAt: new Date() } });
    await expect(service.getUser(partner, 'm-1')).resolves.toEqual({
      status: 'revoked',
      talerUserId: null,
      managed: false,
      linkedAt: active.activatedAt.toISOString(),
    });
    // activatedAt: null — genuine PENDING, never confirmed by the partner.
    links(prisma, {
      ...active,
      status: 'PENDING',
      activatedAt: null,
      user: { ...liveUser, deletedAt: new Date() },
    });
    await expect(service.getUser(partner, 'm-1')).rejects.toThrow('not_linked');
  });

  it('reports revoked for a link Task 19 revoked after the account was deleted', async () => {
    const { service, prisma } = make();
    links(prisma, {
      ...active,
      status: 'REVOKED',
      grantId: null,
      revokedAt: new Date('2026-10-01T11:00:00Z'),
      user: { ...liveUser, deletedAt: new Date('2026-10-01T10:30:00Z') },
    });
    await expect(service.getUser(partner, 'm-1')).resolves.toEqual({
      status: 'revoked',
      talerUserId: null,
      managed: false,
      linkedAt: active.activatedAt.toISOString(),
    });
  });

  it('answers not_linked for a link the partner had already revoked before the account was deleted', async () => {
    const { service, prisma } = make();
    links(prisma, {
      ...active,
      status: 'REVOKED',
      grantId: null,
      revokedAt: new Date('2026-10-01T09:00:00Z'),
      user: { ...liveUser, deletedAt: new Date('2026-10-01T10:00:00Z') },
    });
    await expect(service.getUser(partner, 'm-1')).rejects.toThrow('not_linked');
  });

  it('renames only managed accounts', async () => {
    const { service, prisma } = make();
    links(prisma, active);
    await expect(
      service.patchUser(partner, 'm-1', { firstName: ' Олена ' }),
    ).resolves.toEqual({ ok: true });
    expect(prisma.profile.upsert).toHaveBeenCalledWith({
      where: { userId: 'u1' },
      update: { firstName: 'Олена' },
      create: { userId: 'u1', firstName: 'Олена' },
    });
    links(prisma, {
      ...active,
      user: { ...liveUser, createdByPartnerId: null },
    });
    await expect(
      service.patchUser(partner, 'm-1', { firstName: 'X' }),
    ).rejects.toThrow('profile_not_managed');
  });

  it('clears the first name on explicit null, trims lastName, and skips an empty patch', async () => {
    const { service, prisma, audit } = make();
    links(prisma, active);

    await expect(
      service.patchUser(partner, 'm-1', { firstName: null }),
    ).resolves.toEqual({ ok: true });
    expect(prisma.profile.upsert).toHaveBeenLastCalledWith({
      where: { userId: 'u1' },
      update: { firstName: null },
      create: { userId: 'u1', firstName: null },
    });

    await expect(
      service.patchUser(partner, 'm-1', { lastName: '  Coelho  ' }),
    ).resolves.toEqual({ ok: true });
    expect(prisma.profile.upsert).toHaveBeenLastCalledWith({
      where: { userId: 'u1' },
      update: { lastName: 'Coelho' },
      create: { userId: 'u1', lastName: 'Coelho' },
    });

    prisma.profile.upsert.mockClear();
    audit.log.mockClear();
    await expect(service.patchUser(partner, 'm-1', {})).resolves.toEqual({
      ok: true,
    });
    expect(prisma.profile.upsert).not.toHaveBeenCalled();
    expect(audit.log).not.toHaveBeenCalled();
  });

  it('revokes the link and keeps the account by default', async () => {
    const { service, prisma, revoker, profiles } = make();
    links(prisma, active);
    await service.deleteUser(partner, 'm-1', false);
    expect(revoker.revokeLink).toHaveBeenCalledWith(active);
    expect(profiles.deleteAccount).not.toHaveBeenCalled();
  });

  it('deletes a managed account and its channel subscriptions on request', async () => {
    const { service, prisma, profiles } = make();
    links(prisma, active);
    await service.deleteUser(partner, 'm-1', true);
    expect(profiles.deleteAccount).toHaveBeenCalledWith('u1');
    expect(prisma.conversationParticipant.deleteMany).toHaveBeenCalledWith({
      where: { userId: 'u1', conversation: { type: 'CHANNEL' } },
    });
  });

  it('writes the audit row for a deletion even if the channel cleanup fails afterward', async () => {
    const { service, prisma, audit } = make();
    links(prisma, active);
    prisma.conversationParticipant.deleteMany.mockRejectedValueOnce(
      new Error('db down'),
    );
    await expect(service.deleteUser(partner, 'm-1', true)).rejects.toThrow(
      'db down',
    );
    // Иначе повтор (аккаунт уже удалён, alreadyDeleted=true, отзыва больше нет)
    // никогда не залогировал бы само удаление.
    expect(audit.log).toHaveBeenCalledWith(
      partner,
      'ACCOUNT_DELETED',
      expect.objectContaining({ externalId: 'm-1', userId: 'u1' }),
    );
  });

  it('refuses to delete an account it does not manage, and changes nothing', async () => {
    const { service, prisma, revoker, profiles } = make();
    links(prisma, {
      ...active,
      user: { ...liveUser, createdByPartnerId: null },
    });
    await expect(service.deleteUser(partner, 'm-1', true)).rejects.toThrow(
      'account_not_managed',
    );
    expect(revoker.revokeLink).not.toHaveBeenCalled();
    expect(profiles.deleteAccount).not.toHaveBeenCalled();
  });

  it('is idempotent for an already revoked link, and writes no audit row', async () => {
    const { service, prisma, revoker, audit } = make();
    links(prisma, { ...active, status: 'REVOKED', grantId: null });
    await service.deleteUser(partner, 'm-1', false);
    expect(revoker.revokeLink).not.toHaveBeenCalled();
    expect(audit.log).not.toHaveBeenCalled();
  });

  it('finishes a revocation that was interrupted (REVOKED with a grant left)', async () => {
    const { service, prisma, revoker } = make();
    const unfinished = { ...active, status: 'REVOKED' };
    links(prisma, unfinished);
    await service.deleteUser(partner, 'm-1', false);
    expect(revoker.revokeLink).toHaveBeenCalledWith(unfinished);
  });

  it('treats a P2025 from revocation as already-gone and stays quiet', async () => {
    const { service, prisma, revoker, audit } = make();
    const unfinished = { ...active, status: 'REVOKED' };
    links(prisma, unfinished);
    revoker.revokeLink.mockRejectedValueOnce(
      Object.assign(new Error('not found'), { code: 'P2025' }),
    );
    const errorSpy = jest.spyOn((service as any).logger, 'error');
    await expect(
      service.deleteUser(partner, 'm-1', false),
    ).resolves.toBeUndefined();
    expect(errorSpy).not.toHaveBeenCalled();
    expect(audit.log).toHaveBeenCalledWith(
      partner,
      'LINK_REVOKED',
      expect.objectContaining({ externalId: 'm-1', userId: 'u1' }),
    );
  });

  it('is idempotent when retrying deleteAccount=true after the account is already gone', async () => {
    const { service, prisma, revoker, profiles, audit } = make();
    const alreadyGone = {
      ...active,
      status: 'REVOKED',
      grantId: null,
      user: { ...liveUser, deletedAt: new Date(), email: null },
    };
    links(prisma, alreadyGone);
    await service.deleteUser(partner, 'm-1', true);
    expect(revoker.revokeLink).not.toHaveBeenCalled();
    expect(profiles.deleteAccount).not.toHaveBeenCalled();
    expect(prisma.conversationParticipant.deleteMany).toHaveBeenCalledWith({
      where: { userId: 'u1', conversation: { type: 'CHANNEL' } },
    });
    expect(audit.log).not.toHaveBeenCalled();
  });

  it('refuses to delete a foreign account that was already deleted elsewhere, and touches nothing', async () => {
    const { service, prisma, revoker, profiles } = make();
    // Тот же снимок «полностью удалён» (deletedAt+email:null), но завёл его
    // не этот партнёр — alreadyDeleted не должен сработать на чужом аккаунте.
    const foreignGone = {
      ...active,
      status: 'REVOKED',
      grantId: null,
      user: {
        ...liveUser,
        deletedAt: new Date(),
        email: null,
        createdByPartnerId: null,
      },
    };
    links(prisma, foreignGone);
    await expect(service.deleteUser(partner, 'm-1', true)).rejects.toThrow(
      'account_not_managed',
    );
    expect(revoker.revokeLink).not.toHaveBeenCalled();
    expect(profiles.deleteAccount).not.toHaveBeenCalled();
    expect(prisma.conversationParticipant.deleteMany).not.toHaveBeenCalled();
  });

  it('refuses to delete an admin-blocked account and revokes nothing', async () => {
    const { service, prisma, revoker, profiles, audit } = make();
    // AdminService.deleteUser: deletedAt задан, почта сохранена — в отличие от
    // ProfileService.deleteAccount, который её обнуляет.
    const blocked = { ...active, user: { ...liveUser, deletedAt: new Date() } };
    links(prisma, blocked);
    await expect(service.deleteUser(partner, 'm-1', true)).rejects.toThrow(
      'account_not_managed',
    );
    expect(revoker.revokeLink).not.toHaveBeenCalled();
    expect(profiles.deleteAccount).not.toHaveBeenCalled();
    expect(audit.log).not.toHaveBeenCalled();
  });
});
