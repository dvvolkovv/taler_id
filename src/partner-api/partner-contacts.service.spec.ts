import { PartnerContactsService } from './partner-contacts.service';

const partner: any = { id: 'p1', slug: 'nadi' };

// Внешние id нарочно «перевёрнуты» относительно userId: пара хранится
// упорядоченной по userId, а не по порядку аргументов.
const activeLinks = [
  { externalId: 'a', userId: 'u-b', status: 'ACTIVE', user: { deletedAt: null } },
  { externalId: 'b', userId: 'u-a', status: 'ACTIVE', user: { deletedAt: null } },
];

function make(links: any[] = activeLinks) {
  const prisma: any = {
    partnerLink: {
      // Мок честно фильтрует по where.status/where.user — иначе тест на
      // PENDING-связку не отличил бы фильтрацию в базе от её отсутствия
      // (ровно так в это и не заметили баг из I1).
      findMany: jest.fn((args: any) => {
        const ids: string[] = args.where.externalId.in;
        const rows = links.filter(
          (l) =>
            ids.includes(l.externalId) &&
            (args.where.status === undefined || l.status === args.where.status) &&
            (args.where.user === undefined || l.user.deletedAt === args.where.user.deletedAt),
        );
        return Promise.resolve(rows.map(({ externalId, userId }) => ({ externalId, userId })));
      }),
    },
    blockedUser: { findFirst: jest.fn().mockResolvedValue(null) },
    partnerContact: {
      findUnique: jest.fn().mockResolvedValue(null),
      upsert: jest.fn().mockResolvedValue({}),
      createMany: jest.fn().mockResolvedValue({ count: 1 }),
      deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
      count: jest.fn().mockResolvedValue(0),
    },
    contactRequest: {
      findMany: jest.fn().mockResolvedValue([]),
      create: jest.fn().mockResolvedValue({}),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
  };
  const audit: any = { log: jest.fn().mockResolvedValue(undefined) };
  return { service: new PartnerContactsService(prisma, audit), prisma };
}

describe('PartnerContactsService.put', () => {
  it('creates an accepted contact and remembers that the partner created it', async () => {
    const { service, prisma } = make();
    await expect(service.put(partner, 'a', 'b')).resolves.toEqual({ contact: true, created: true });
    expect(prisma.contactRequest.create).toHaveBeenCalledWith({
      data: { senderId: 'u-a', receiverId: 'u-b', status: 'ACCEPTED' },
    });
    // !wasContact → upsert с непустым update: атомарный ON CONFLICT DO UPDATE.
    expect(prisma.partnerContact.upsert).toHaveBeenCalledWith({
      where: { partnerId_userAId_userBId: { partnerId: 'p1', userAId: 'u-a', userBId: 'u-b' } },
      create: { partnerId: 'p1', userAId: 'u-a', userBId: 'u-b', createdContact: true },
      update: { createdContact: true },
    });
    expect(prisma.partnerContact.createMany).not.toHaveBeenCalled();
  });

  it('records a contact that existed before the partner as not its own', async () => {
    const { service, prisma } = make();
    prisma.contactRequest.findMany.mockResolvedValue([{ id: 'c1', status: 'ACCEPTED' }]);
    await expect(service.put(partner, 'a', 'b')).resolves.toEqual({ contact: true, created: false });
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
    expect(prisma.contactRequest.updateMany).not.toHaveBeenCalled();
    // wasContact → createMany+skipDuplicates: атомарный ON CONFLICT DO NOTHING,
    // а не upsert с пустым update (Prisma эмулирует его как SELECT+INSERT).
    expect(prisma.partnerContact.createMany).toHaveBeenCalledWith({
      data: [{ partnerId: 'p1', userAId: 'u-a', userBId: 'u-b', createdContact: false }],
      skipDuplicates: true,
    });
    expect(prisma.partnerContact.upsert).not.toHaveBeenCalled();
  });

  it('upgrades every request of the pair instead of creating another row', async () => {
    const { service, prisma } = make();
    // Отклонённый запрос в одну сторону и висящий встречный: оба становятся
    // принятыми, иначе у человека остался бы «входящий запрос» от контакта.
    prisma.contactRequest.findMany.mockResolvedValue([
      { id: 'c1', status: 'REJECTED' },
      { id: 'c2', status: 'PENDING' },
    ]);
    await service.put(partner, 'a', 'b');
    expect(prisma.contactRequest.updateMany).toHaveBeenCalledWith({
      where: { id: { in: ['c1', 'c2'] } },
      data: { status: 'ACCEPTED' },
    });
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
  });

  it('reconciles createdContact to true whenever the pair is not currently accepted, even on a re-PUT', async () => {
    // Запросы были (значит, PartnerContact мог остаться в базе с прошлым
    // значением флага), но ни один не ACCEPTED — пара сейчас не контакты.
    const { service, prisma } = make();
    prisma.contactRequest.findMany.mockResolvedValue([{ id: 'c1', status: 'REJECTED' }]);
    await service.put(partner, 'a', 'b');
    expect(prisma.partnerContact.upsert).toHaveBeenCalledWith({
      where: { partnerId_userAId_userBId: { partnerId: 'p1', userAId: 'u-a', userBId: 'u-b' } },
      create: { partnerId: 'p1', userAId: 'u-a', userBId: 'u-b', createdContact: true },
      update: { createdContact: true },
    });
  });

  it('a repeat PUT racing on the PartnerContact row does not throw — skipDuplicates absorbs the conflict', async () => {
    const { service, prisma } = make();
    prisma.contactRequest.findMany.mockResolvedValue([{ id: 'c1', status: 'ACCEPTED' }]);
    // count: 0 — строка уже была (гонка с параллельным PUT), skipDuplicates
    // молча пропустил вставку; Prisma в этом случае не бросает P2002.
    prisma.partnerContact.createMany.mockResolvedValue({ count: 0 });
    await expect(service.put(partner, 'a', 'b')).resolves.toEqual({ contact: true, created: false });
  });

  it('answers the same PUT sent twice at once instead of failing on the unique index', async () => {
    const { service, prisma } = make();
    prisma.contactRequest.create.mockRejectedValueOnce(Object.assign(new Error('dup'), { code: 'P2002' }));
    // К повтору параллельный запрос уже всё записал: на ретрае wasContact уже
    // true, и запись PartnerContact идёт атомарным createMany, а не upsert —
    // второй гонки (уже без бюджета на повтор) здесь просто не может случиться.
    prisma.contactRequest.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ id: 'c1', status: 'ACCEPTED' }]);
    await expect(service.put(partner, 'a', 'b')).resolves.toEqual({ contact: true, created: false });
    expect(prisma.partnerContact.createMany).toHaveBeenCalledTimes(1);
    expect(prisma.partnerContact.createMany).toHaveBeenCalledWith({
      data: [{ partnerId: 'p1', userAId: 'u-a', userBId: 'u-b', createdContact: false }],
      skipDuplicates: true,
    });
    expect(prisma.partnerContact.upsert).not.toHaveBeenCalled();
  });

  it('never overrides a block', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.findFirst.mockResolvedValue({ blockerId: 'u-b', blockedId: 'u-a' });
    await expect(service.put(partner, 'a', 'b')).rejects.toThrow('blocked');
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
  });

  it('needs both links to be active', async () => {
    const { service } = make([activeLinks[0]]);
    await expect(service.put(partner, 'a', 'b')).rejects.toThrow('link_not_active');
  });

  it('a PENDING (not yet confirmed) link does not count as active', async () => {
    const { service } = make([activeLinks[0], { externalId: 'b', userId: 'u-a', status: 'PENDING', user: { deletedAt: null } }]);
    await expect(service.put(partner, 'a', 'b')).rejects.toThrow('link_not_active');
  });

  it('an ACTIVE link of a deleted account does not count as active either', async () => {
    const { service } = make([
      activeLinks[0],
      { externalId: 'b', userId: 'u-a', status: 'ACTIVE', user: { deletedAt: new Date() } },
    ]);
    await expect(service.put(partner, 'a', 'b')).rejects.toThrow('link_not_active');
  });

  it('refuses a contact with oneself', async () => {
    const { service } = make();
    await expect(service.put(partner, 'a', 'a')).rejects.toThrow('same_user');
  });
});

describe('PartnerContactsService.remove', () => {
  it('removes a contact the partner created when nobody else holds it', async () => {
    const { service, prisma } = make();
    prisma.partnerContact.findUnique.mockResolvedValue({ id: 'pc1', createdContact: true });
    await expect(service.remove(partner, 'a', 'b')).resolves.toEqual({ contact: false });
    expect(prisma.partnerContact.deleteMany).toHaveBeenCalledWith({ where: { id: 'pc1' } });
    expect(prisma.contactRequest.deleteMany).toHaveBeenCalled();
  });

  it('keeps a contact that existed before the partner', async () => {
    const { service, prisma } = make();
    prisma.partnerContact.findUnique.mockResolvedValue({ id: 'pc1', createdContact: false });
    prisma.contactRequest.findMany.mockResolvedValue([{ id: 'c1', status: 'ACCEPTED' }]);
    await expect(service.remove(partner, 'a', 'b')).resolves.toEqual({ contact: true });
    expect(prisma.contactRequest.deleteMany).not.toHaveBeenCalled();
  });

  it('keeps a contact another partner still holds', async () => {
    const { service, prisma } = make();
    prisma.partnerContact.findUnique.mockResolvedValue({ id: 'pc1', createdContact: true });
    prisma.partnerContact.count.mockResolvedValue(1);
    await service.remove(partner, 'a', 'b');
    expect(prisma.contactRequest.deleteMany).not.toHaveBeenCalled();
  });

  it('does nothing but report when the partner never made them contacts', async () => {
    const { service, prisma } = make();
    await expect(service.remove(partner, 'a', 'b')).resolves.toEqual({ contact: false });
    expect(prisma.partnerContact.deleteMany).not.toHaveBeenCalled();
  });

  it('requires ACTIVE links too — a PENDING link must not leak whether the pair are contacts', async () => {
    const { service, prisma } = make([activeLinks[0], { externalId: 'b', userId: 'u-a', status: 'PENDING', user: { deletedAt: null } }]);
    await expect(service.remove(partner, 'a', 'b')).rejects.toThrow('link_not_active');
    expect(prisma.partnerContact.deleteMany).not.toHaveBeenCalled();
  });
});
