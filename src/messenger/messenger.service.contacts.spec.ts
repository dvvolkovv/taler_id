import { MessengerService } from './messenger.service';

describe('MessengerService.listContacts', () => {
  it('returns profile info for accepted contacts in both directions', async () => {
    const prisma: any = {
      contactRequest: {
        findMany: jest.fn().mockResolvedValue([
          { senderId: 'me', receiverId: 'u2' },
          { senderId: 'u3', receiverId: 'me' },
        ]),
      },
      user: {
        findMany: jest.fn().mockResolvedValue([
          { id: 'u2', username: 'ivan', profile: { firstName: 'Ivan', lastName: 'P' } },
          { id: 'u3', username: 'anna', profile: { firstName: 'Anna', lastName: 'K' } },
        ]),
      },
    };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;

    const contacts = await service.listContacts('me');
    expect(prisma.user.findMany.mock.calls[0][0].where.id.in).toEqual(['u2', 'u3']);
    expect(contacts).toHaveLength(2);
    expect(contacts[0]).toMatchObject({ id: 'u2', username: 'ivan' });
  });

  it('returns empty array when no contacts', async () => {
    const prisma: any = {
      contactRequest: { findMany: jest.fn().mockResolvedValue([]) },
      user: { findMany: jest.fn() },
    };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;
    await expect(service.listContacts('me')).resolves.toEqual([]);
    expect(prisma.user.findMany).not.toHaveBeenCalled();
  });
});
