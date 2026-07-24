import { SystemChannelService } from './system-channel.service';

function makePrisma() {
  return {
    user: {
      findUnique: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({ id: 'sys-user' }),
      findMany: jest
        .fn()
        .mockResolvedValueOnce([{ id: 'u1' }, { id: 'u2' }])
        .mockResolvedValue([]),
    },
    conversation: {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({ id: 'sys-chan' }),
    },
    conversationParticipant: {
      createMany: jest.fn().mockResolvedValue({ count: 2 }),
    },
  } as any;
}

const noopGateway = { deliverNewMessage: jest.fn() } as any;
const noopMessenger = {
  createMessage: jest.fn(),
  getMessageById: jest.fn(),
} as any;

describe('SystemChannelService.ensureSeeded', () => {
  it('creates system user and channel when missing, backfills subscriptions', async () => {
    const prisma = makePrisma();
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger);
    const res = await svc.ensureSeeded();
    expect(prisma.user.create).toHaveBeenCalled();
    expect(prisma.conversation.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          isSystem: true,
          type: 'CHANNEL',
        }),
      }),
    );
    expect(prisma.conversationParticipant.createMany).toHaveBeenCalledWith(
      expect.objectContaining({ skipDuplicates: true }),
    );
    expect(res).toEqual({ userId: 'sys-user', channelId: 'sys-chan' });
  });

  it('is idempotent: existing user/channel not recreated, backfill still runs', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger);
    await svc.ensureSeeded();
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.conversation.create).not.toHaveBeenCalled();
    expect(prisma.conversationParticipant.createMany).toHaveBeenCalled();
  });

  it('onApplicationBootstrap swallows seed errors', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockRejectedValue(new Error('db down'));
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger);
    await expect(svc.onApplicationBootstrap()).resolves.toBeUndefined();
  });

  it('backfill uses SUBSCRIBER role for regular users', async () => {
    const prisma = makePrisma();
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger);
    await svc.ensureSeeded();
    const createManyCall = prisma.conversationParticipant.createMany.mock.calls[0][0];
    expect(createManyCall.data).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ role: 'SUBSCRIBER' }),
      ]),
    );
  });

  it('system channel owner participant has OWNER role', async () => {
    const prisma = makePrisma();
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger);
    await svc.ensureSeeded();
    const createCall = prisma.conversation.create.mock.calls[0][0];
    expect(createCall.data.participants.create).toEqual(
      expect.objectContaining({ role: 'OWNER' }),
    );
  });
});

describe('SystemChannelService.subscribeUser', () => {
  it('calls createMany with SUBSCRIBER role and skipDuplicates when system channels exist', async () => {
    const prisma: any = {
      conversation: {
        findMany: jest.fn().mockResolvedValue([{ id: 'sys-chan-1' }, { id: 'sys-chan-2' }]),
      },
      conversationParticipant: {
        createMany: jest.fn().mockResolvedValue({ count: 2 }),
      },
    };
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger);
    await svc.subscribeUser('new-user-id');

    expect(prisma.conversationParticipant.createMany).toHaveBeenCalledWith({
      data: [
        { conversationId: 'sys-chan-1', userId: 'new-user-id', role: 'SUBSCRIBER' },
        { conversationId: 'sys-chan-2', userId: 'new-user-id', role: 'SUBSCRIBER' },
      ],
      skipDuplicates: true,
    });
  });

  it('does NOT call createMany when no system channels exist', async () => {
    const prisma: any = {
      conversation: {
        findMany: jest.fn().mockResolvedValue([]),
      },
      conversationParticipant: {
        createMany: jest.fn(),
      },
    };
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger);
    await svc.subscribeUser('new-user-id');

    expect(prisma.conversationParticipant.createMany).not.toHaveBeenCalled();
  });
});
