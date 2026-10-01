import { ConflictException } from '@nestjs/common';
import { countInWindow } from './partner-counter.util';
import { PartnerUsersService, profileLanguage } from './partner-users.service';
import { AccountNotManagedError } from '../profile/profile.service';

jest.mock('./partner-counter.util', () => ({
  ...jest.requireActual('./partner-counter.util'),
  countInWindow: jest.fn(),
}));
const windowCount = countInWindow as jest.Mock;

beforeEach(() => {
  windowCount.mockReset();
  // Далеко под дефолтным суточным потолком (5000) — не мешает ни одному
  // существующему тесту, которые о лимите не знают вовсе.
  windowCount.mockResolvedValue({ count: 1, retryAfter: 86400 });
});

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
  const decr = jest.fn().mockResolvedValue(0);
  const redis: any = { getClient: () => ({ decr }) };
  const service = new PartnerUsersService(
    prisma,
    tokens,
    revoker,
    systemChannel,
    profiles,
    audit,
    redis,
  );
  return {
    service,
    prisma,
    tokens,
    revoker,
    systemChannel,
    profiles,
    audit,
    redis,
    decr,
  };
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
        emailVerified: true,
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
        emailVerified: true,
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
        emailVerified: true,
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
        emailVerified: true,
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

  it("refuses a foreign managed account nobody has claimed yet, even though emailVerified is true (it is partner p2's claim, not the mailbox's)", async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-other-partner',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: 'p2',
        emailVerified: true,
      },
    ]);
    await expect(service.provision(partner, dto)).rejects.toThrow(
      'email_unverified',
    );
    expect(prisma.partnerLink.create).not.toHaveBeenCalled();
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('allows linking a foreign-managed account once it has been claimed by its real owner (first password set)', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-other-partner',
        passwordHash: 'claimed-by-real-owner',
        deletedAt: null,
        createdByPartnerId: 'p2',
        emailVerified: true,
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

  it('still refuses a foreign managed account when the email itself is also unverified', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-other-partner',
        passwordHash: null,
        deletedAt: null,
        createdByPartnerId: 'p2',
        emailVerified: false,
      },
    ]);
    await expect(service.provision(partner, dto)).rejects.toThrow(
      'email_unverified',
    );
    expect(prisma.partnerLink.create).not.toHaveBeenCalled();
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
        emailVerified: true,
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

  it('refuses to link an account whose email is not verified, and changes nothing', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-existing',
        passwordHash: 'hash',
        deletedAt: null,
        createdByPartnerId: null,
        emailVerified: false,
      },
    ]);
    await expect(service.provision(partner, dto)).rejects.toThrow(
      'email_unverified',
    );
    expect(prisma.partnerLink.create).not.toHaveBeenCalled();
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('does not require email verification to reactivate its own managed account (managed accounts are always verified by construction, but the gate is scoped to "not managed" anyway)', async () => {
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
        emailVerified: false,
      },
    ]);
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u1',
      created: false,
    });
  });

  it('selects and orders by emailVerified so a verified account among case variants wins', async () => {
    const { service, prisma } = make();
    await service.provision(partner, dto);
    expect(prisma.$queryRaw).toHaveBeenCalledTimes(1);
    const [strings] = prisma.$queryRaw.mock.calls[0];
    const sql = strings.join('');
    expect(sql).toContain('"emailVerified"');
    expect(sql).toContain('"emailVerified" DESC');
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

describe('PartnerUsersService.provision — FOR UPDATE re-check on managed relink', () => {
  const revoked = {
    id: 'l1',
    userId: 'u1',
    externalId: 'm-1',
    status: 'REVOKED',
    grantId: null,
    user: liveUser,
  };

  it('locks the user row and re-checks it before activating a managed relink', async () => {
    const { service, prisma } = make();
    links(prisma, revoked, revoked);
    prisma.$queryRaw
      // findOwner: still managed at read time.
      .mockResolvedValueOnce([
        {
          id: 'u1',
          passwordHash: null,
          deletedAt: null,
          createdByPartnerId: 'p1',
          emailVerified: true,
        },
      ])
      // FOR UPDATE re-check inside the transaction: still managed.
      .mockResolvedValueOnce([
        { passwordHash: null, createdByPartnerId: 'p1', deletedAt: null },
      ]);
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'active',
      talerUserId: 'u1',
      created: false,
    });
    expect(prisma.$queryRaw).toHaveBeenCalledTimes(2);
    const [strings] = prisma.$queryRaw.mock.calls[1];
    expect(strings.join('')).toContain('FOR UPDATE');
  });

  it('restarts provisioning (ending PENDING, not a stale ACTIVE) when the account stops being managed between the read and the write', async () => {
    const { service, prisma } = make();
    links(prisma, revoked, revoked);
    prisma.$queryRaw
      // attempt 1: findOwner — still managed.
      .mockResolvedValueOnce([
        {
          id: 'u1',
          passwordHash: null,
          deletedAt: null,
          createdByPartnerId: 'p1',
          emailVerified: true,
        },
      ])
      // attempt 1: FOR UPDATE re-check — a concurrent resetPassword just
      // claimed the account (first password set) while we were waiting.
      .mockResolvedValueOnce([
        {
          passwordHash: 'set-concurrently',
          createdByPartnerId: 'p1',
          deletedAt: null,
        },
      ])
      // attempt 2 (provision()'s retry): findOwner again, now fresh.
      .mockResolvedValueOnce([
        {
          id: 'u1',
          passwordHash: 'set-concurrently',
          deletedAt: null,
          createdByPartnerId: 'p1',
          emailVerified: true,
        },
      ]);
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'confirmation_required',
      talerUserId: null,
    });
    expect(prisma.$queryRaw).toHaveBeenCalledTimes(3);
    // Only one FOR UPDATE re-check happened (attempt 2 is no longer
    // "managed", so it never re-enters the locked branch at all).
    expect(
      prisma.$queryRaw.mock.calls.filter(([strings]) =>
        strings.join('').includes('FOR UPDATE'),
      ),
    ).toHaveLength(1);
    expect(prisma.partnerLink.updateMany).toHaveBeenLastCalledWith({
      where: { id: 'l1', userId: 'u1', status: 'REVOKED', grantId: null },
      data: expect.objectContaining({ status: 'PENDING' }),
    });
  });

  it('does not lock or re-check for the PENDING (not-managed) relink path', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-existing',
        passwordHash: 'hash',
        deletedAt: null,
        createdByPartnerId: null,
        emailVerified: true,
      },
    ]);
    await expect(service.provision(partner, dto)).resolves.toEqual({
      status: 'confirmation_required',
      talerUserId: null,
    });
    // Только findOwner — PENDING-связке лок не нужен: сама по себе она
    // ничего не открывает, пока не пройдёт код из письма.
    expect(prisma.$queryRaw).toHaveBeenCalledTimes(1);
  });
});

describe('PartnerUsersService.provision — daily account-creation cap', () => {
  it('checks the cap, via Redis, before creating the account', async () => {
    const { service, prisma, redis } = make();
    await service.provision(partner, dto);
    expect(windowCount).toHaveBeenCalledWith(
      redis,
      'partner:create:day:p1',
      86400,
    );
    expect(windowCount.mock.invocationCallOrder[0]).toBeLessThan(
      prisma.user.create.mock.invocationCallOrder[0],
    );
  });

  it('does not count a relink of an already-active account (idempotent path)', async () => {
    const { service, prisma } = make();
    links(prisma, { id: 'l1', userId: 'u1', status: 'ACTIVE', user: liveUser });
    await service.provision(partner, dto);
    expect(windowCount).not.toHaveBeenCalled();
  });

  it('does not count relinking an existing owner (confirmation_required path)', async () => {
    const { service, prisma } = make();
    prisma.$queryRaw.mockResolvedValue([
      {
        id: 'u-existing',
        passwordHash: 'hash',
        deletedAt: null,
        createdByPartnerId: null,
        emailVerified: true,
      },
    ]);
    await service.provision(partner, dto);
    expect(windowCount).not.toHaveBeenCalled();
  });

  it('answers 429 with retryAfter over the cap, and creates nothing', async () => {
    const { service, prisma } = make();
    windowCount.mockResolvedValueOnce({ count: 5001, retryAfter: 1234 });
    const err = await service.provision(partner, dto).catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({
      message: 'too_many_requests',
      retryAfter: 1234,
    });
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('answers 503 when the cap cannot be counted (Redis unavailable), and creates nothing', async () => {
    const { service, prisma } = make();
    windowCount.mockResolvedValueOnce(null);
    await expect(service.provision(partner, dto)).rejects.toThrow(
      'rate_limiter_unavailable',
    );
    expect(prisma.user.create).not.toHaveBeenCalled();
  });

  it('reads the limit from PARTNER_ACCOUNTS_PER_DAY instead of the 5000 default', async () => {
    const saved = process.env.PARTNER_ACCOUNTS_PER_DAY;
    process.env.PARTNER_ACCOUNTS_PER_DAY = '10';
    try {
      const { service } = make();
      windowCount.mockResolvedValueOnce({ count: 11, retryAfter: 1234 });
      await expect(service.provision(partner, dto)).rejects.toThrow(
        'too_many_requests',
      );
      windowCount.mockResolvedValueOnce({ count: 10, retryAfter: 1234 });
      await expect(service.provision(partner, dto)).resolves.toMatchObject({
        created: true,
      });
    } finally {
      if (saved === undefined) delete process.env.PARTNER_ACCOUNTS_PER_DAY;
      else process.env.PARTNER_ACCOUNTS_PER_DAY = saved;
    }
  });

  it('logs once exactly when the cap is first exceeded in the window, not on the next hit', async () => {
    const { service } = make();
    const logSpy = jest
      .spyOn((service as any).logger, 'error')
      .mockImplementation(() => undefined);
    windowCount.mockResolvedValueOnce({ count: 5001, retryAfter: 1234 });
    await service.provision(partner, dto).catch(() => undefined);
    expect(logSpy).toHaveBeenCalledTimes(1);

    logSpy.mockClear();
    windowCount.mockResolvedValueOnce({ count: 5002, retryAfter: 1234 });
    await service.provision(partner, dto).catch(() => undefined);
    expect(logSpy).not.toHaveBeenCalled();
  });

  it('gives the slot back when the create transaction fails after the slot was counted (race retry)', async () => {
    const { service, prisma, decr } = make();
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
    expect(decr).toHaveBeenCalledWith('partner:create:day:p1');
  });

  it('gives the slot back for a refused (429) request — a rejection should not keep counting against the cap', async () => {
    const { service, decr } = make();
    windowCount.mockResolvedValueOnce({ count: 5001, retryAfter: 1234 });
    await expect(service.provision(partner, dto)).rejects.toThrow(
      'too_many_requests',
    );
    expect(decr).toHaveBeenCalledWith('partner:create:day:p1');
  });

  it('logs the cap-exceeded error at most once per hour per partner (in-memory timestamp), regardless of the exact count', async () => {
    const { service } = make();
    const logSpy = jest
      .spyOn((service as any).logger, 'error')
      .mockImplementation(() => undefined);
    const nowSpy = jest.spyOn(Date, 'now');
    try {
      nowSpy.mockReturnValue(1_000_000);
      windowCount.mockResolvedValueOnce({ count: 5001, retryAfter: 1234 });
      await service.provision(partner, dto).catch(() => undefined);
      expect(logSpy).toHaveBeenCalledTimes(1);

      // 10 minutes later, a much higher count (not limit+1) — still within
      // the hour, so no second log no matter how far over the cap we are.
      nowSpy.mockReturnValue(1_000_000 + 10 * 60 * 1000);
      windowCount.mockResolvedValueOnce({ count: 9000, retryAfter: 1234 });
      await service.provision(partner, dto).catch(() => undefined);
      expect(logSpy).toHaveBeenCalledTimes(1);

      // just over an hour after the FIRST log — logs again.
      nowSpy.mockReturnValue(1_000_000 + 61 * 60 * 1000);
      windowCount.mockResolvedValueOnce({ count: 9500, retryAfter: 1234 });
      await service.provision(partner, dto).catch(() => undefined);
      expect(logSpy).toHaveBeenCalledTimes(2);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it('logs separately per partner (one partner exceeding the cap does not suppress the log for another)', async () => {
    const { service } = make();
    const logSpy = jest
      .spyOn((service as any).logger, 'error')
      .mockImplementation(() => undefined);
    const otherPartner: any = { id: 'p2', slug: 'other', name: 'Other' };
    windowCount.mockResolvedValueOnce({ count: 5001, retryAfter: 1234 });
    await service.provision(partner, dto).catch(() => undefined);
    windowCount.mockResolvedValueOnce({ count: 5001, retryAfter: 1234 });
    await service.provision(otherPartner, dto).catch(() => undefined);
    expect(logSpy).toHaveBeenCalledTimes(2);
  });

  it('parses PARTNER_ACCOUNTS_PER_DAY strictly: unset, empty, non-numeric, or negative all fall back to the 5000 default', async () => {
    for (const value of [undefined, '', 'abc', '-5', '-1']) {
      const saved = process.env.PARTNER_ACCOUNTS_PER_DAY;
      if (value === undefined) delete process.env.PARTNER_ACCOUNTS_PER_DAY;
      else process.env.PARTNER_ACCOUNTS_PER_DAY = value;
      try {
        const under = make();
        windowCount.mockResolvedValueOnce({ count: 5000, retryAfter: 1234 });
        await expect(
          under.service.provision(partner, dto),
        ).resolves.toMatchObject({ created: true });
        windowCount.mockResolvedValueOnce({ count: 5001, retryAfter: 1234 });
        await expect(under.service.provision(partner, dto)).rejects.toThrow(
          'too_many_requests',
        );
      } finally {
        if (saved === undefined) delete process.env.PARTNER_ACCOUNTS_PER_DAY;
        else process.env.PARTNER_ACCOUNTS_PER_DAY = saved;
      }
    }
  });

  it('PARTNER_ACCOUNTS_PER_DAY=0 disables account creation entirely (not "unset", a real zero)', async () => {
    const saved = process.env.PARTNER_ACCOUNTS_PER_DAY;
    process.env.PARTNER_ACCOUNTS_PER_DAY = '0';
    try {
      const { service, prisma } = make();
      windowCount.mockResolvedValueOnce({ count: 1, retryAfter: 1234 });
      await expect(service.provision(partner, dto)).rejects.toThrow(
        'too_many_requests',
      );
      expect(prisma.user.create).not.toHaveBeenCalled();
    } finally {
      if (saved === undefined) delete process.env.PARTNER_ACCOUNTS_PER_DAY;
      else process.env.PARTNER_ACCOUNTS_PER_DAY = saved;
    }
  });

  async function withCapEnv(
    value: string | undefined,
    fn: (service: PartnerUsersService) => Promise<void>,
  ) {
    const saved = process.env.PARTNER_ACCOUNTS_PER_DAY;
    if (value === undefined) delete process.env.PARTNER_ACCOUNTS_PER_DAY;
    else process.env.PARTNER_ACCOUNTS_PER_DAY = value;
    try {
      const { service } = make();
      await fn(service);
    } finally {
      if (saved === undefined) delete process.env.PARTNER_ACCOUNTS_PER_DAY;
      else process.env.PARTNER_ACCOUNTS_PER_DAY = saved;
    }
  }

  it.each([
    ['1e4', 'parseInt stops at "e" and would silently read this as 1'],
    ['5,000', 'parseInt stops at "," and would silently read this as 5'],
    [
      '0.5',
      'parseInt stops at "." and would silently read this as 0, disabling creation',
    ],
  ])(
    'treats %s as invalid rather than the value parseInt would stop at (%s)',
    async (value) => {
      await withCapEnv(value, async (service) => {
        windowCount.mockResolvedValueOnce({ count: 5000, retryAfter: 1234 });
        await expect(
          service.provision(partner, dto),
        ).resolves.toMatchObject({ created: true });
        windowCount.mockResolvedValueOnce({ count: 5001, retryAfter: 1234 });
        await expect(service.provision(partner, dto)).rejects.toThrow(
          'too_many_requests',
        );
      });
    },
  );

  it('accepts a plain integer surrounded by whitespace', async () => {
    await withCapEnv('  10  ', async (service) => {
      windowCount.mockResolvedValueOnce({ count: 10, retryAfter: 1234 });
      await expect(
        service.provision(partner, dto),
      ).resolves.toMatchObject({ created: true });
      windowCount.mockResolvedValueOnce({ count: 11, retryAfter: 1234 });
      await expect(service.provision(partner, dto)).rejects.toThrow(
        'too_many_requests',
      );
    });
  });

  it('warns at most once per instance when the configured value is invalid', async () => {
    await withCapEnv('1e4', async (service) => {
      const warnSpy = jest
        .spyOn((service as any).logger, 'warn')
        .mockImplementation(() => undefined);
      windowCount.mockResolvedValue({ count: 1, retryAfter: 1234 });
      await service.provision(partner, dto);
      await service.provision(partner, { ...dto, externalId: 'm-2' });
      expect(warnSpy).toHaveBeenCalledTimes(1);
    });
  });

  it('never warns when the configured value is a valid plain integer, including 0', async () => {
    for (const value of ['0', '10', '  5  ']) {
      await withCapEnv(value, async (service) => {
        const warnSpy = jest
          .spyOn((service as any).logger, 'warn')
          .mockImplementation(() => undefined);
        windowCount.mockResolvedValueOnce({ count: 1, retryAfter: 1234 });
        await service.provision(partner, dto).catch(() => undefined);
        expect(warnSpy).not.toHaveBeenCalled();
      });
    }
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
    expect(profiles.deleteAccount).toHaveBeenCalledWith('u1', {
      onlyIfManagedBy: 'p1',
    });
    expect(prisma.conversationParticipant.deleteMany).toHaveBeenCalledWith({
      where: { userId: 'u1', conversation: { type: 'CHANNEL' } },
    });
  });

  it('answers 409 and keeps the account when ProfileService finds it is no longer managed under FOR UPDATE (e.g. the person just set a password)', async () => {
    const { service, prisma, revoker, profiles, audit } = make();
    links(prisma, active);
    profiles.deleteAccount.mockRejectedValueOnce(new AccountNotManagedError());
    await expect(service.deleteUser(partner, 'm-1', true)).rejects.toThrow(
      'account_not_managed',
    );
    // The link is still revoked — only the account deletion itself was refused.
    expect(revoker.revokeLink).toHaveBeenCalledWith(active);
    expect(prisma.conversationParticipant.deleteMany).not.toHaveBeenCalled();
    expect(audit.log).not.toHaveBeenCalled();
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
