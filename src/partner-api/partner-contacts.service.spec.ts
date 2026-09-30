import { PartnerContactsService } from './partner-contacts.service';

const partner: any = { id: 'p1', slug: 'nadi' };

function make() {
  const prisma: any = {
    // Внешние id нарочно «перевёрнуты» относительно userId: пара хранится
    // упорядоченной по userId, а не по порядку аргументов.
    partnerLink: {
      findMany: jest.fn().mockResolvedValue([
        { externalId: 'a', userId: 'u-b' },
        { externalId: 'b', userId: 'u-a' },
      ]),
    },
    blockedUser: { findFirst: jest.fn().mockResolvedValue(null) },
    partnerContact: {
      findUnique: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({}),
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
    expect(prisma.partnerContact.create).toHaveBeenCalledWith({
      data: { partnerId: 'p1', userAId: 'u-a', userBId: 'u-b', createdContact: true },
    });
  });

  it('records a contact that existed before the partner as not its own', async () => {
    const { service, prisma } = make();
    prisma.contactRequest.findMany.mockResolvedValue([{ id: 'c1', status: 'ACCEPTED' }]);
    await expect(service.put(partner, 'a', 'b')).resolves.toEqual({ contact: true, created: false });
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
    expect(prisma.contactRequest.updateMany).not.toHaveBeenCalled();
    expect(prisma.partnerContact.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ createdContact: false }),
    });
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

  it('answers the same PUT sent twice at once instead of failing on the unique index', async () => {
    const { service, prisma } = make();
    prisma.contactRequest.create.mockRejectedValueOnce(Object.assign(new Error('dup'), { code: 'P2002' }));
    // К повтору параллельный запрос уже всё записал.
    prisma.contactRequest.findMany
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ id: 'c1', status: 'ACCEPTED' }]);
    // Первая попытка до PartnerContact не дошла, а параллельный запрос его уже завёл.
    prisma.partnerContact.findUnique.mockResolvedValue({ id: 'pc1' });
    await expect(service.put(partner, 'a', 'b')).resolves.toEqual({ contact: true, created: false });
    expect(prisma.partnerContact.create).not.toHaveBeenCalled();
  });

  it('never overrides a block', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.findFirst.mockResolvedValue({ blockerId: 'u-b', blockedId: 'u-a' });
    await expect(service.put(partner, 'a', 'b')).rejects.toThrow('blocked');
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
  });

  it('needs both links to be active', async () => {
    const { service, prisma } = make();
    prisma.partnerLink.findMany.mockResolvedValue([{ externalId: 'a', userId: 'u-b' }]);
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
});
