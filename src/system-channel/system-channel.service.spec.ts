import { NotFoundException } from '@nestjs/common';
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
      update: jest.fn().mockResolvedValue({ id: 'sys-chan', avatarUrl: 'set' }),
    },
    conversationParticipant: {
      createMany: jest.fn().mockResolvedValue({ count: 2 }),
    },
  } as any;
}

/** Returns a RedisService mock where SETNX resolves to 'OK' (lock acquired) by default. */
function makeRedis(setnxResult: string | null = 'OK') {
  return {
    getClient: jest.fn().mockReturnValue({
      set: jest.fn().mockResolvedValue(setnxResult),
    }),
  } as any;
}

const noopGateway = { deliverNewMessage: jest.fn() } as any;
const noopMessenger = {
  createMessage: jest.fn(),
  getMessageById: jest.fn(),
} as any;
const noopRedis = makeRedis();

describe('SystemChannelService.ensureSeeded', () => {
  it('creates system user and channel when missing, backfills subscriptions', async () => {
    const prisma = makePrisma();
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger, noopRedis);
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
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger, noopRedis);
    await svc.ensureSeeded();
    expect(prisma.user.create).not.toHaveBeenCalled();
    expect(prisma.conversation.create).not.toHaveBeenCalled();
    expect(prisma.conversationParticipant.createMany).toHaveBeenCalled();
  });

  it('sets avatarUrl on pre-existing channel without one (idempotent backfill)', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan', avatarUrl: null });
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger, noopRedis);
    await svc.ensureSeeded();
    expect(prisma.conversation.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'sys-chan' },
        data: { avatarUrl: expect.stringContaining('/brand/logo-dark.png') },
      }),
    );
  });

  it('background seed swallows errors (bootstrap must never crash the app)', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockRejectedValue(new Error('db down'));
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger, noopRedis);
    await expect((svc as any).seedInBackground()).resolves.toBeUndefined();
    // сам bootstrap — синхронный fire-and-forget, не блокирует app.listen()
    expect(svc.onApplicationBootstrap()).toBeUndefined();
  });

  it('backfill uses SUBSCRIBER role for regular users', async () => {
    const prisma = makePrisma();
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger, noopRedis);
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
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger, noopRedis);
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
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger, noopRedis);
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
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger, noopRedis);
    await svc.subscribeUser('new-user-id');

    expect(prisma.conversationParticipant.createMany).not.toHaveBeenCalled();
  });
});

describe('SystemChannelService.autopostLatestRelease', () => {
  it('posts when latest release not yet posted (lock acquired)', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    (prisma as any).message = { findFirst: jest.fn().mockResolvedValue(null) };
    const messenger = {
      createMessage: jest.fn().mockResolvedValue({ id: 'm1' }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'm1', content: 'x' }),
    } as any;
    const gateway = { deliverNewMessage: jest.fn() } as any;
    const redis = makeRedis('OK'); // lock acquired
    const svc = new SystemChannelService(prisma, gateway, messenger, redis);
    await svc.autopostLatestRelease();
    expect(messenger.createMessage).toHaveBeenCalledWith(
      'sys-chan', 'sys-user', expect.stringContaining('🚀 Taler ID'),
      undefined, undefined, undefined,
      expect.objectContaining({ newsType: 'release' }),
    );
    expect(gateway.deliverNewMessage).toHaveBeenCalledWith(
      expect.objectContaining({ senderName: 'Taler ID' }),
      'sys-user', 'sys-chan',
      expect.objectContaining({ senderName: 'Taler ID', systemPost: true }),
    );
  });

  it('skips when latest already posted (version-idempotency guard)', async () => {
    const { APP_RELEASES } = require('../app-releases');
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    (prisma as any).message = {
      findFirst: jest.fn().mockResolvedValue({ metadata: { version: APP_RELEASES[0].version } }),
    };
    const messenger = { createMessage: jest.fn(), getMessageById: jest.fn() } as any;
    const redis = makeRedis('OK');
    const svc = new SystemChannelService(prisma, { deliverNewMessage: jest.fn() } as any, messenger, redis);
    await svc.autopostLatestRelease();
    expect(messenger.createMessage).not.toHaveBeenCalled();
  });

  it('skips when Redis SETNX lock is NOT acquired (another node holds it)', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    (prisma as any).message = { findFirst: jest.fn().mockResolvedValue(null) };
    const messenger = {
      createMessage: jest.fn().mockResolvedValue({ id: 'm1' }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'm1', content: 'x' }),
    } as any;
    const gateway = { deliverNewMessage: jest.fn() } as any;
    const redis = makeRedis(null); // SETNX returns null → lock already held
    const svc = new SystemChannelService(prisma, gateway, messenger, redis);
    await svc.autopostLatestRelease();
    expect(messenger.createMessage).not.toHaveBeenCalled();
  });

  it('proceeds when Redis SETNX returns OK (lock acquired)', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    (prisma as any).message = { findFirst: jest.fn().mockResolvedValue(null) };
    const messenger = {
      createMessage: jest.fn().mockResolvedValue({ id: 'm1' }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'm1', content: 'x' }),
    } as any;
    const gateway = { deliverNewMessage: jest.fn() } as any;
    const redis = makeRedis('OK'); // lock acquired
    const svc = new SystemChannelService(prisma, gateway, messenger, redis);
    await svc.autopostLatestRelease();
    expect(messenger.createMessage).toHaveBeenCalled();
  });
});

describe('SystemChannelService.postNews', () => {
  it('posts manual critical news with metadata', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    const messenger = {
      createMessage: jest.fn().mockResolvedValue({ id: 'm1' }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'm1' }),
    } as any;
    const svc = new SystemChannelService(prisma, { deliverNewMessage: jest.fn() } as any, messenger, makeRedis());
    const res = await svc.postNews({ type: 'critical', text_ru: 'Обновитесь до 1.2.0', minVersion: '1.2.0' });
    expect(messenger.createMessage).toHaveBeenCalledWith(
      'sys-chan', 'sys-user', expect.stringContaining('Обновитесь'),
      undefined, undefined, undefined,
      expect.objectContaining({ newsType: 'critical', minVersion: '1.2.0' }),
    );
    expect(res).toEqual({ messageId: 'm1' });
  });

  it('formats RU+EN when text_en provided', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan' });
    const messenger = {
      createMessage: jest.fn().mockResolvedValue({ id: 'm2' }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'm2' }),
    } as any;
    const svc = new SystemChannelService(prisma, { deliverNewMessage: jest.fn() } as any, messenger, makeRedis());
    await svc.postNews({ type: 'news', text_ru: 'Новости', text_en: 'News update' });
    const calledContent: string = messenger.createMessage.mock.calls[0][2];
    expect(calledContent).toContain('— EN —');
    expect(calledContent).toContain('Новости');
    expect(calledContent).toContain('News update');
  });

  it('throws NotFoundException when channel not seeded', async () => {
    const prisma = makePrisma();
    // user exists but channel is null (conversation.findFirst returns null by default)
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    const messenger = {
      createMessage: jest.fn(),
      getMessageById: jest.fn(),
    } as any;
    const svc = new SystemChannelService(prisma, { deliverNewMessage: jest.fn() } as any, messenger, makeRedis());
    await expect(svc.postNews({ type: 'news', text_ru: 'Test' })).rejects.toThrow(NotFoundException);
  });
});
