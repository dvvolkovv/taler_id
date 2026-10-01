import { MessengerService } from './messenger.service';

describe('MessengerService.searchMessages', () => {
  function makeService(conversationsResult: any[] = []) {
    const prisma: any = {
      conversation: { findMany: jest.fn().mockResolvedValue(conversationsResult) },
      message: { findMany: jest.fn().mockResolvedValue([]) },
      user: { findMany: jest.fn().mockResolvedValue([]) },
    };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;
    return { service, prisma };
  }

  it('restricts the conversation lookup to given types', async () => {
    const { service, prisma } = makeService();
    await service.searchMessages('hello', 'u1', ['DIRECT', 'GROUP'] as any);
    expect(prisma.conversation.findMany).toHaveBeenCalledWith({
      where: { participants: { some: { userId: 'u1' } }, type: { in: ['DIRECT', 'GROUP'] } },
      select: { id: true },
    });
  });

  it('leaves the conversation lookup unrestricted without types', async () => {
    const { service, prisma } = makeService();
    await service.searchMessages('hello', 'u1');
    expect(prisma.conversation.findMany).toHaveBeenCalledWith({
      where: { participants: { some: { userId: 'u1' } } },
      select: { id: true },
    });
  });
});

describe('MessengerService.searchUsers', () => {
  it('hides partner-managed accounts, both by name and by phone', async () => {
    const prisma: any = { user: { findMany: jest.fn().mockResolvedValue([]) } };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;
    await service.searchUsers('ivan', 'me');
    await service.searchUsers('+380501234567', 'me');
    expect(prisma.user.findMany).toHaveBeenCalledTimes(2);
    for (const [args] of prisma.user.findMany.mock.calls) {
      expect(args.where.NOT).toEqual({
        passwordHash: null,
        createdByPartnerId: { not: null },
      });
    }
  });
});
