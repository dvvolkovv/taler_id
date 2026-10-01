import { hashLinkCode } from '../partner-core/partner-secrets.util';
import { countInWindow } from './partner-counter.util';
import { PartnerLinkCodeService } from './partner-link-code.service';

jest.mock('./partner-counter.util', () => ({
  ...jest.requireActual('./partner-counter.util'),
  countInWindow: jest.fn(),
}));
const windowCount = countInWindow as jest.Mock;

beforeEach(() => {
  windowCount.mockReset();
  // Оба окна свободны: первое письмо за минуту и за час.
  windowCount.mockResolvedValue({ count: 1, retryAfter: 60 });
});

// До описания тестов: withCode() ниже зовёт hashLinkCode, которому нужен ключ.
const savedKey = process.env.PARTNER_SECRETS_KEY;
process.env.PARTNER_SECRETS_KEY = 'b'.repeat(64);
afterAll(() => {
  if (savedKey === undefined) delete process.env.PARTNER_SECRETS_KEY;
  else process.env.PARTNER_SECRETS_KEY = savedKey;
});

const partner: any = { id: 'p1', slug: 'nadi', name: 'Nadi' };
const pending = {
  id: 'l1',
  userId: 'u1',
  status: 'PENDING',
  codeHash: null as string | null,
  codeExpiresAt: null as Date | null,
  codeAttempts: 0,
  user: {
    email: 'ivan@example.com',
    deletedAt: null,
    emailVerified: true,
    createdByPartnerId: null as string | null,
    passwordHash: null as string | null,
    profile: { language: 'ru' },
  },
};
const withCode = (over: any = {}) => ({
  ...pending,
  codeHash: hashLinkCode('l1', '123456'),
  codeExpiresAt: new Date(Date.now() + 60_000),
  codeAttempts: 0,
  ...over,
});

function make(link: any) {
  const prisma: any = {
    partnerLink: {
      findUnique: jest.fn().mockResolvedValue(link),
      // Попытку списывает сама БД: условия «не истёк, не сожжён» — в where.
      // Здесь попытка по умолчанию списалась; тест на истёкший код задаёт count: 0.
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      findUniqueOrThrow: jest
        .fn()
        .mockResolvedValue({ codeAttempts: (link?.codeAttempts ?? 0) + 1 }),
      update: jest.fn().mockResolvedValue({}),
    },
  };
  // Окна считает countInWindow (замокан выше); сервис сам зовёт del (кулдаун)
  // и getClient().decr (возврат суточного слота партнёра).
  const decr = jest.fn().mockResolvedValue(0);
  const redis: any = {
    del: jest.fn().mockResolvedValue(undefined),
    getClient: () => ({ decr }),
  };
  const email: any = {
    sendPartnerLinkCode: jest.fn().mockResolvedValue(undefined),
  };
  const audit: any = { log: jest.fn().mockResolvedValue(undefined) };
  return {
    service: new PartnerLinkCodeService(prisma, redis, email, audit),
    prisma,
    redis,
    email,
    audit,
    decr,
  };
}

describe('PartnerLinkCodeService.send', () => {
  it("stores only a hash and mails the code in the person's language", async () => {
    const { service, prisma, redis, email } = make(pending);
    await expect(service.send(partner, 'm-1')).resolves.toEqual({
      sent: true,
      expiresIn: 600,
    });
    // Кулдаун и часовое окно — по человеку (partner+userId), сутки — по партнёру.
    expect(windowCount).toHaveBeenNthCalledWith(
      1,
      redis,
      'partner:linkcode:cd:p1:u1',
      60,
    );
    expect(windowCount).toHaveBeenNthCalledWith(
      2,
      redis,
      'partner:linkcode:h:p1:u1',
      3600,
    );
    expect(windowCount).toHaveBeenNthCalledWith(
      3,
      redis,
      'partner:linkcode:day:p1',
      86400,
    );
    const [to, code, name, lang] = email.sendPartnerLinkCode.mock.calls[0];
    expect([to, name, lang]).toEqual(['ivan@example.com', 'Nadi', 'ru']);
    expect(code).toMatch(/^\d{6}$/);
    const data = prisma.partnerLink.update.mock.calls[0][0].data;
    expect(data.codeHash).toBe(hashLinkCode('l1', code));
    expect(data.codeAttempts).toBe(0);
    expect(data.codeExpiresAt.getTime()).toBeGreaterThan(Date.now() + 590_000);
  });

  it('answers 429 with retryAfter inside the one-minute cooldown', async () => {
    const { service, email } = make(pending);
    windowCount.mockResolvedValueOnce({ count: 2, retryAfter: 42 });
    const err = await service.send(partner, 'm-1').catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({
      message: 'too_many_requests',
      retryAfter: 42,
    });
    expect(windowCount).toHaveBeenCalledTimes(1);
    expect(email.sendPartnerLinkCode).not.toHaveBeenCalled();
  });

  it('answers 429 after five letters in an hour', async () => {
    const { service, email } = make(pending);
    windowCount
      .mockResolvedValueOnce({ count: 1, retryAfter: 60 }) // кулдаун в норме
      .mockResolvedValueOnce({ count: 6, retryAfter: 1800 }); // часовой лимит сработал
    const err = await service.send(partner, 'm-1').catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({
      message: 'too_many_requests',
      retryAfter: 1800,
    });
    expect(email.sendPartnerLinkCode).not.toHaveBeenCalled();
  });

  it('answers 429 over the daily send cap for the whole partner, without writing or mailing a code', async () => {
    const { service, prisma, email } = make(pending);
    windowCount
      .mockResolvedValueOnce({ count: 1, retryAfter: 60 }) // кулдаун в норме
      .mockResolvedValueOnce({ count: 1, retryAfter: 3600 }) // часовой лимит в норме
      .mockResolvedValueOnce({ count: 1001, retryAfter: 3600 }); // суточный потолок партнёра сработал
    const err = await service.send(partner, 'm-1').catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({
      message: 'too_many_requests',
      retryAfter: 3600,
    });
    // Потолок считает уже ВЫДАННЫЕ коды: per-link окна проверяются первыми,
    // и только затем сутки — иначе ретраи на свои же per-link 429 исчерпывали
    // бы общий бюджет партнёра за минуты и заперли бы линковку всем его людям.
    expect(windowCount).toHaveBeenCalledTimes(3);
    expect(windowCount).toHaveBeenLastCalledWith(
      expect.anything(),
      'partner:linkcode:day:p1',
      86400,
    );
    expect(prisma.partnerLink.update).not.toHaveBeenCalled();
    expect(email.sendPartnerLinkCode).not.toHaveBeenCalled();
  });

  it.each([0, 1, 2])(
    'refuses with 503 when Redis cannot count window #%i: the limits protect the inbox',
    async (failing: number) => {
      const { service, email } = make(pending);
      for (let i = 0; i < failing; i++)
        windowCount.mockResolvedValueOnce({ count: 1, retryAfter: 60 });
      windowCount.mockResolvedValueOnce(null);
      const err = await service.send(partner, 'm-1').catch((e) => e);
      expect(err.getStatus()).toBe(503);
      expect(err.message).toBe('rate_limiter_unavailable');
      expect(email.sendPartnerLinkCode).not.toHaveBeenCalled();
    },
  );

  it('409 for a link that is not waiting for a code', async () => {
    const { service } = make({ ...pending, status: 'ACTIVE' });
    await expect(service.send(partner, 'm-1')).rejects.toThrow('not_pending');
  });

  it("refuses with 409 when the linked account's email is not verified, before touching any rate-limit window", async () => {
    const unverified = {
      ...pending,
      user: { ...pending.user, emailVerified: false },
    };
    const { service } = make(unverified);
    await expect(service.send(partner, 'm-1')).rejects.toThrow(
      'email_unverified',
    );
    expect(windowCount).not.toHaveBeenCalled();
  });

  it("refuses with 409 for a foreign managed account nobody has claimed yet, even though emailVerified is true (it's partner p2's claim, not the mailbox's)", async () => {
    const foreignManaged = {
      ...pending,
      user: {
        ...pending.user,
        createdByPartnerId: 'p2',
        passwordHash: null,
      },
    };
    const { service } = make(foreignManaged);
    await expect(service.send(partner, 'm-1')).rejects.toThrow(
      'email_unverified',
    );
    expect(windowCount).not.toHaveBeenCalled();
  });

  it('allows sending a code once the foreign-managed account has been claimed (first password set)', async () => {
    const claimed = {
      ...pending,
      user: {
        ...pending.user,
        createdByPartnerId: 'p2',
        passwordHash: 'claimed-by-real-owner',
      },
    };
    const { service, email } = make(claimed);
    await expect(service.send(partner, 'm-1')).resolves.toEqual({
      sent: true,
      expiresIn: 600,
    });
    expect(email.sendPartnerLinkCode).toHaveBeenCalled();
  });

  it('404 for an unknown link', async () => {
    const { service } = make(null);
    await expect(service.send(partner, 'm-1')).rejects.toThrow('not_linked');
  });

  it('frees the cooldown, the hour window, and the daily slot, then answers 503, when mail fails', async () => {
    const { service, redis, email, decr } = make(pending);
    email.sendPartnerLinkCode.mockRejectedValue(new Error('smtp down'));
    const err = await service.send(partner, 'm-1').catch((e) => e);
    expect(err.getStatus()).toBe(503);
    expect(redis.del).toHaveBeenCalledWith('partner:linkcode:cd:p1:u1');
    // Иначе пять ретраев за время SMTP-аутажа заперли бы человека на час:
    // письма не доходят, а часовое окно всё равно тратится.
    expect(decr).toHaveBeenCalledWith('partner:linkcode:h:p1:u1');
    expect(decr).toHaveBeenCalledWith('partner:linkcode:day:p1');
  });

  it('frees all three window slots and answers 503 (not a raw 500) when hashing the code throws (e.g. wrong PARTNER_SECRETS_KEY)', async () => {
    const { service, redis, email, decr } = make(pending);
    const savedKeyForThisTest = process.env.PARTNER_SECRETS_KEY;
    // masterKey() в partner-secrets.util проверяет формат при каждом вызове —
    // временно портим его, не трогая реальный hashLinkCode моками.
    process.env.PARTNER_SECRETS_KEY = 'not-64-hex-chars';
    try {
      const err = await service.send(partner, 'm-1').catch((e) => e);
      expect(err.getStatus()).toBe(503);
      expect(err.message).toBe('secrets_unavailable');
    } finally {
      process.env.PARTNER_SECRETS_KEY = savedKeyForThisTest;
    }
    expect(redis.del).toHaveBeenCalledWith('partner:linkcode:cd:p1:u1');
    expect(decr).toHaveBeenCalledWith('partner:linkcode:h:p1:u1');
    expect(decr).toHaveBeenCalledWith('partner:linkcode:day:p1');
    expect(email.sendPartnerLinkCode).not.toHaveBeenCalled();
  });
});

describe('PartnerLinkCodeService.verify', () => {
  it('spends an attempt on this very code before comparing, then activates on the right code', async () => {
    const link = withCode();
    const { service, prisma } = make(link);
    await expect(service.verify(partner, 'm-1', '123456')).resolves.toEqual({
      status: 'active',
      talerUserId: 'u1',
    });
    expect(prisma.partnerLink.updateMany).toHaveBeenNthCalledWith(1, {
      where: {
        id: 'l1',
        status: 'PENDING',
        codeHash: link.codeHash,
        codeExpiresAt: { gt: expect.any(Date) },
        codeAttempts: { lt: 5 },
      },
      data: { codeAttempts: { increment: 1 } },
    });
    expect(prisma.partnerLink.updateMany).toHaveBeenLastCalledWith({
      where: {
        id: 'l1',
        status: 'PENDING',
        codeHash: link.codeHash,
        user: {
          emailVerified: true,
          OR: [
            { createdByPartnerId: null },
            { createdByPartnerId: 'p1' },
            { passwordHash: { not: null } },
          ],
        },
      },
      data: expect.objectContaining({
        status: 'ACTIVE',
        codeHash: null,
        codeAttempts: 0,
      }),
    });
  });

  it('does not spend an attempt when no code was ever sent', async () => {
    const { service, prisma } = make(pending);
    const err = await service.verify(partner, 'm-1', '123456').catch((e) => e);
    expect(err.getStatus()).toBe(410);
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
  });

  it("refuses with 409 when the linked account's email is not verified, without spending an attempt", async () => {
    const link = withCode();
    const unverified = {
      ...link,
      user: { ...link.user, emailVerified: false },
    };
    const { service, prisma } = make(unverified);
    await expect(service.verify(partner, 'm-1', '123456')).rejects.toThrow(
      'email_unverified',
    );
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
  });

  it('refuses with 409 for a foreign managed account nobody has claimed yet, without spending an attempt', async () => {
    const link = withCode();
    const foreignManaged = {
      ...link,
      user: { ...link.user, createdByPartnerId: 'p2', passwordHash: null },
    };
    const { service, prisma } = make(foreignManaged);
    await expect(service.verify(partner, 'm-1', '123456')).rejects.toThrow(
      'email_unverified',
    );
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
  });

  it('allows verifying once the foreign-managed account has been claimed (first password set)', async () => {
    const link = withCode();
    const claimed = {
      ...link,
      user: {
        ...link.user,
        createdByPartnerId: 'p2',
        passwordHash: 'claimed-by-real-owner',
      },
    };
    const { service } = make(claimed);
    await expect(service.verify(partner, 'm-1', '123456')).resolves.toEqual({
      status: 'active',
      talerUserId: 'u1',
    });
  });

  it('requires emailVerified:true AND not-foreign-managed in the activating updateMany where-clause (closes races on both)', async () => {
    const link = withCode();
    const { service, prisma } = make(link);
    await service.verify(partner, 'm-1', '123456');
    expect(prisma.partnerLink.updateMany).toHaveBeenLastCalledWith({
      where: {
        id: 'l1',
        status: 'PENDING',
        codeHash: link.codeHash,
        user: {
          emailVerified: true,
          OR: [
            { createdByPartnerId: null },
            { createdByPartnerId: 'p1' },
            { passwordHash: { not: null } },
          ],
        },
      },
      data: expect.objectContaining({ status: 'ACTIVE' }),
    });
  });

  it('does not revive the link when its code changed meanwhile', async () => {
    const { service, prisma } = make(withCode());
    prisma.partnerLink.updateMany
      .mockResolvedValueOnce({ count: 1 })
      .mockResolvedValueOnce({ count: 0 });
    const err = await service.verify(partner, 'm-1', '123456').catch((e) => e);
    expect(err.getStatus()).toBe(410);
  });

  it('answers 400 with attemptsLeft on a wrong code and audits the failure', async () => {
    const { service, audit } = make(withCode());
    const err = await service.verify(partner, 'm-1', '000000').catch((e) => e);
    expect(err.getStatus()).toBe(400);
    expect(err.getResponse()).toEqual({
      message: 'invalid_code',
      attemptsLeft: 4,
    });
    expect(audit.log).toHaveBeenCalledWith(partner, 'LINK_CODE_FAILED', {
      externalId: 'm-1',
      userId: 'u1',
      ip: undefined,
      meta: { attemptsLeft: 4, burned: false },
    });
  });

  it('burns the code on the fifth wrong attempt and audits it as burned', async () => {
    const link = withCode({ codeAttempts: 4 });
    const { service, prisma, audit } = make(link);
    const err = await service.verify(partner, 'm-1', '000000').catch((e) => e);
    expect(err.getStatus()).toBe(410);
    expect(prisma.partnerLink.updateMany).toHaveBeenLastCalledWith({
      where: { id: 'l1', status: 'PENDING', codeHash: link.codeHash },
      data: { codeHash: null, codeExpiresAt: null },
    });
    expect(audit.log).toHaveBeenCalledWith(partner, 'LINK_CODE_FAILED', {
      externalId: 'm-1',
      userId: 'u1',
      ip: undefined,
      meta: { attemptsLeft: 0, burned: true },
    });
  });

  it('answers 410 without comparing when no attempt can be spent (expired or burned), and gives the daily verify slot back', async () => {
    const { service, prisma, decr } = make(withCode());
    prisma.partnerLink.updateMany.mockResolvedValue({ count: 0 });
    // Верный код: если бы сравнение всё же случилось, связка ожила бы.
    const err = await service.verify(partner, 'm-1', '123456').catch((e) => e);
    expect(err.getStatus()).toBe(410);
    expect(prisma.partnerLink.updateMany).toHaveBeenCalledTimes(1);
    expect(decr).toHaveBeenCalledWith('partner:linkcode:verify:p1');
  });

  it('gives back the spent attempt and the daily verify slot, and answers 503, when comparing the code throws (bad PARTNER_SECRETS_KEY)', async () => {
    const link = withCode();
    const { service, prisma, decr } = make(link);
    const savedKeyForThisTest = process.env.PARTNER_SECRETS_KEY;
    // linkCodeMatches вызывает hashLinkCode, который проверяет формат ключа
    // при каждом вызове — портим его без моков, как в тесте на send().
    process.env.PARTNER_SECRETS_KEY = 'not-64-hex-chars';
    try {
      const err = await service
        .verify(partner, 'm-1', '123456')
        .catch((e) => e);
      expect(err.getStatus()).toBe(503);
      expect(err.message).toBe('secrets_unavailable');
    } finally {
      process.env.PARTNER_SECRETS_KEY = savedKeyForThisTest;
    }
    // Попытка была списана (codeAttempts: increment) ДО сравнения — теперь
    // должна быть возвращена тем же условным UPDATE по тому же codeHash.
    expect(prisma.partnerLink.updateMany).toHaveBeenLastCalledWith({
      where: { id: 'l1', status: 'PENDING', codeHash: link.codeHash },
      data: { codeAttempts: { decrement: 1 } },
    });
    expect(decr).toHaveBeenCalledWith('partner:linkcode:verify:p1');
  });

  it('answers 429 over the daily verify cap for the whole partner, before spending an attempt', async () => {
    const { service, prisma } = make(withCode());
    windowCount.mockResolvedValueOnce({ count: 3001, retryAfter: 1234 });
    const err = await service.verify(partner, 'm-1', '123456').catch((e) => e);
    expect(err.getStatus()).toBe(429);
    expect(err.getResponse()).toEqual({
      message: 'too_many_requests',
      retryAfter: 1234,
    });
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
  });

  it('answers 503 when the daily verify cap cannot be counted', async () => {
    const { service, prisma } = make(withCode());
    windowCount.mockResolvedValueOnce(null);
    const err = await service.verify(partner, 'm-1', '123456').catch((e) => e);
    expect(err.getStatus()).toBe(503);
    expect(err.message).toBe('rate_limiter_unavailable');
    expect(prisma.partnerLink.updateMany).not.toHaveBeenCalled();
  });
});

describe('PartnerLinkCodeService daily cap logging', () => {
  it('logs once when the daily send cap is first exceeded in the window, not on the next hit', async () => {
    const { service } = make(pending);
    const logSpy = jest
      .spyOn((service as any).logger, 'error')
      .mockImplementation(() => undefined);
    windowCount
      .mockResolvedValueOnce({ count: 1, retryAfter: 60 })
      .mockResolvedValueOnce({ count: 1, retryAfter: 3600 })
      .mockResolvedValueOnce({ count: 1001, retryAfter: 3600 }); // CAP+1
    await service.send(partner, 'm-1').catch(() => undefined);
    expect(logSpy).toHaveBeenCalledTimes(1);
    expect(logSpy.mock.calls[0][0]).toEqual(expect.stringContaining('nadi'));

    logSpy.mockClear();
    windowCount
      .mockResolvedValueOnce({ count: 1, retryAfter: 60 })
      .mockResolvedValueOnce({ count: 1, retryAfter: 3600 })
      .mockResolvedValueOnce({ count: 1002, retryAfter: 3600 }); // CAP+2
    await service.send(partner, 'm-1').catch(() => undefined);
    expect(logSpy).not.toHaveBeenCalled();
  });

  it('logs once when the daily verify cap is first exceeded in the window, not on the next hit', async () => {
    const { service } = make(withCode());
    const logSpy = jest
      .spyOn((service as any).logger, 'error')
      .mockImplementation(() => undefined);
    windowCount.mockResolvedValueOnce({ count: 3001, retryAfter: 1234 }); // CAP+1
    await service.verify(partner, 'm-1', '123456').catch(() => undefined);
    expect(logSpy).toHaveBeenCalledTimes(1);

    logSpy.mockClear();
    windowCount.mockResolvedValueOnce({ count: 3002, retryAfter: 1234 }); // CAP+2
    await service.verify(partner, 'm-1', '123456').catch(() => undefined);
    expect(logSpy).not.toHaveBeenCalled();
  });
});
