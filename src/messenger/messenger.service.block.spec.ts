import { MessengerService } from './messenger.service';

function make() {
  const prisma: any = {
    contactRequest: {
      findFirst: jest.fn().mockResolvedValue(null),
      deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
      create: jest.fn().mockResolvedValue({}),
      update: jest.fn().mockResolvedValue({}),
    },
    blockedUser: {
      create: jest.fn().mockResolvedValue({}),
      delete: jest.fn().mockResolvedValue({ hadContact: false }),
      findUnique: jest.fn().mockResolvedValue(null),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
  };
  const service = Object.create(MessengerService.prototype) as MessengerService;
  (service as any).prisma = prisma;
  return { service, prisma };
}

describe('MessengerService block and unblock', () => {
  it('remembers that they were contacts when blocking', async () => {
    const { service, prisma } = make();
    prisma.contactRequest.findFirst.mockResolvedValue({ id: 'c1', status: 'ACCEPTED' });
    await service.blockUser('me', 'u2');
    expect(prisma.contactRequest.deleteMany).toHaveBeenCalled();
    expect(prisma.blockedUser.create).toHaveBeenCalledWith({
      data: { blockerId: 'me', blockedId: 'u2', hadContact: true },
    });
  });

  it('records hadContact=false when they were not contacts', async () => {
    const { service, prisma } = make();
    await service.blockUser('me', 'u2');
    expect(prisma.blockedUser.create).toHaveBeenCalledWith({
      data: { blockerId: 'me', blockedId: 'u2', hadContact: false },
    });
  });

  it('removes the block atomically, by the composite key', async () => {
    const { service, prisma } = make();
    await service.unblockUser('me', 'u2');
    expect(prisma.blockedUser.delete).toHaveBeenCalledWith({
      where: { blockerId_blockedId: { blockerId: 'me', blockedId: 'u2' } },
    });
  });

  it('does nothing when there was no block row to remove (P2025)', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.delete.mockRejectedValue(Object.assign(new Error('not found'), { code: 'P2025' }));
    await expect(service.unblockUser('me', 'u2')).resolves.toEqual({ ok: true });
    expect(prisma.blockedUser.updateMany).not.toHaveBeenCalled();
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
    expect(prisma.contactRequest.update).not.toHaveBeenCalled();
  });

  it('lets an unrelated error from delete() propagate', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.delete.mockRejectedValue(new Error('db down'));
    await expect(service.unblockUser('me', 'u2')).rejects.toThrow('db down');
  });

  it('does not invent a contact on unblock when they were never contacts', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.delete.mockResolvedValue({ hadContact: false });
    await service.unblockUser('me', 'u2');
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
    expect(prisma.contactRequest.update).not.toHaveBeenCalled();
  });

  it('restores the contact that existed before the block', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.delete.mockResolvedValue({ hadContact: true });
    await service.unblockUser('me', 'u2');
    // Проверяет и встречную блокировку: 'u2' как blockerId, 'me' как blockedId.
    expect(prisma.blockedUser.findUnique).toHaveBeenCalledWith({
      where: { blockerId_blockedId: { blockerId: 'u2', blockedId: 'me' } },
    });
    expect(prisma.contactRequest.create).toHaveBeenCalledWith({
      data: { senderId: 'me', receiverId: 'u2', status: 'ACCEPTED' },
    });
  });

  it('updates a PENDING request to ACCEPTED instead of creating a duplicate row', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.delete.mockResolvedValue({ hadContact: true });
    prisma.contactRequest.findFirst.mockResolvedValue({ id: 'c1', status: 'PENDING' });
    await service.unblockUser('me', 'u2');
    expect(prisma.contactRequest.update).toHaveBeenCalledWith({
      where: { id: 'c1' },
      data: { status: 'ACCEPTED' },
    });
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
  });

  it('does not restore the contact while the other side still blocks me — hands it the memory instead', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.delete.mockResolvedValue({ hadContact: true });
    // Встречная блокировка (u2 блокирует me) ещё жива.
    prisma.blockedUser.findUnique.mockResolvedValue({ hadContact: false });
    await service.unblockUser('me', 'u2');
    expect(prisma.blockedUser.updateMany).toHaveBeenCalledWith({
      where: { blockerId: 'u2', blockedId: 'me' },
      data: { hadContact: true },
    });
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
    expect(prisma.contactRequest.update).not.toHaveBeenCalled();
  });
});
