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
      findFirst: jest.fn().mockResolvedValue(null),
      deleteMany: jest.fn().mockResolvedValue({ count: 1 }),
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

  it('does not invent a contact on unblock', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.findFirst.mockResolvedValue({ hadContact: false });
    await service.unblockUser('me', 'u2');
    expect(prisma.blockedUser.deleteMany).toHaveBeenCalledWith({ where: { blockerId: 'me', blockedId: 'u2' } });
    expect(prisma.contactRequest.create).not.toHaveBeenCalled();
    expect(prisma.contactRequest.update).not.toHaveBeenCalled();
  });

  it('restores the contact that existed before the block', async () => {
    const { service, prisma } = make();
    prisma.blockedUser.findFirst.mockResolvedValue({ hadContact: true });
    await service.unblockUser('me', 'u2');
    expect(prisma.contactRequest.create).toHaveBeenCalledWith({
      data: { senderId: 'me', receiverId: 'u2', status: 'ACCEPTED' },
    });
  });
});
