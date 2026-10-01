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

describe('MessengerService.acceptContactRequest', () => {
  function make(request: any) {
    const prisma: any = {
      contactRequest: {
        findUnique: jest.fn().mockResolvedValue(request),
        update: jest.fn().mockResolvedValue({}),
      },
    };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;
    (service as any).getOrCreateDirectConversation = jest.fn().mockResolvedValue({ id: 'conv-1' });
    return { service, prisma };
  }

  it('refuses the sender accepting their own request', async () => {
    const { service, prisma } = make({ id: 'r1', senderId: 'me', receiverId: 'u2', status: 'PENDING' });
    await expect(service.acceptContactRequest('r1', 'me')).rejects.toThrow('Not your request');
    expect(prisma.contactRequest.update).not.toHaveBeenCalled();
  });

  it('lets the receiver accept', async () => {
    const { service, prisma } = make({ id: 'r1', senderId: 'u2', receiverId: 'me', status: 'PENDING' });
    await expect(service.acceptContactRequest('r1', 'me')).resolves.toEqual({
      senderId: 'u2',
      receiverId: 'me',
      conversationId: 'conv-1',
    });
    expect(prisma.contactRequest.update).toHaveBeenCalledWith({ where: { id: 'r1' }, data: { status: 'ACCEPTED' } });
  });
});

describe('MessengerService.sendContactRequest', () => {
  function make(receiver: any) {
    const prisma: any = {
      blockedUser: { findFirst: jest.fn().mockResolvedValue(null) },
      user: {
        // id 'u2' — получатель (управляемый аккаунт или обычный, по тесту);
        // любой другой id — отправитель, нужен только для текста уведомления.
        findUnique: jest.fn((args: any) =>
          Promise.resolve(args.where.id === 'u2' ? receiver : { username: 'me', profile: null }),
        ),
      },
      contactRequest: {
        findUnique: jest.fn().mockResolvedValue(null),
        upsert: jest.fn().mockResolvedValue({ id: 'r1', senderId: 'me', receiverId: 'u2', status: 'PENDING' }),
      },
    };
    const service = Object.create(MessengerService.prototype) as MessengerService;
    (service as any).prisma = prisma;
    return { service, prisma };
  }

  it('refuses a request to a partner-managed account that never set a TalerID password', async () => {
    const { service, prisma } = make({ createdByPartnerId: 'p1', passwordHash: null });
    await expect(service.sendContactRequest('me', 'u2')).rejects.toThrow('Не удалось отправить запрос');
    expect(prisma.contactRequest.findUnique).not.toHaveBeenCalled();
    expect(prisma.contactRequest.upsert).not.toHaveBeenCalled();
  });

  it('proceeds for an account the partner created but which set its own password', async () => {
    const { service, prisma } = make({ createdByPartnerId: 'p1', passwordHash: 'hash' });
    await expect(service.sendContactRequest('me', 'u2')).resolves.toBeTruthy();
    expect(prisma.contactRequest.upsert).toHaveBeenCalled();
  });

  it('proceeds for a normal user', async () => {
    const { service, prisma } = make({ createdByPartnerId: null, passwordHash: 'hash' });
    await expect(service.sendContactRequest('me', 'u2')).resolves.toBeTruthy();
    expect(prisma.contactRequest.upsert).toHaveBeenCalled();
  });
});
