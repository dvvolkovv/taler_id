import { MessengerService } from './messenger.service';

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
