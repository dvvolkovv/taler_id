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

  it('canonicalizes avatarUrl on pre-existing channel (overwrites stale logo)', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({ id: 'sys-user' });
    prisma.conversation.findFirst.mockResolvedValue({ id: 'sys-chan', avatarUrl: 'https://old/brand/logo-dark.png' });
    const svc = new SystemChannelService(prisma, noopGateway, noopMessenger, noopRedis);
    await svc.ensureSeeded();
    expect(prisma.conversation.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'sys-chan' },
        data: { avatarUrl: expect.stringContaining('/brand/app-icon-dark.png') },
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
    // postNews теперь всегда возвращает pinned (false, если dto.pin не передан)
    expect(res).toEqual({ messageId: 'm1', pinned: false });
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

describe('SystemChannelService pin support', () => {
  const buildService = () => {
    const prisma: any = {
      conversation: { findFirst: jest.fn().mockResolvedValue({ id: 'chan-1' }) },
      user: { findUnique: jest.fn().mockResolvedValue({ id: 'sys-1' }) },
      message: { findFirst: jest.fn() },
    };
    const messenger: any = {
      createMessage: jest.fn().mockResolvedValue({ id: 'msg-1' }),
      getMessageById: jest.fn().mockResolvedValue({ id: 'msg-1', content: 'x' }),
      pinMessage: jest.fn().mockResolvedValue({ pinnedAt: new Date(), pinnedCount: 1, alreadyPinned: false }),
      unpinMessage: jest.fn().mockResolvedValue({ pinnedCount: 0, wasPinned: true }),
    };
    // server.to() всегда возвращает один и тот же объект с emit — так можно
    // проверять и выбор комнаты, и то, что реально ушло (см.
    // messenger.controller.pins.spec.ts).
    const emit = jest.fn();
    const gateway: any = {
      deliverNewMessage: jest.fn(),
      server: { to: jest.fn().mockReturnValue({ emit }) },
    };
    const redis: any = { getClient: () => ({ set: jest.fn() }) };
    return {
      svc: new SystemChannelService(prisma, gateway, messenger, redis),
      prisma,
      messenger,
      gateway,
      emit,
    };
  };

  it('pins the post it just created, silently', async () => {
    const { svc, messenger } = buildService();

    const res = await svc.postNews({ type: 'news', text_ru: 'Тест', pin: true });

    expect(res).toMatchObject({ messageId: 'msg-1', pinned: true });
    expect(messenger.pinMessage).toHaveBeenCalledWith('chan-1', 'msg-1', 'sys-1', { silent: true });
  });

  it('does not pin when the flag is absent', async () => {
    const { svc, messenger } = buildService();

    const res = await svc.postNews({ type: 'news', text_ru: 'Тест' });

    expect(res).toMatchObject({ messageId: 'msg-1', pinned: false });
    expect(messenger.pinMessage).not.toHaveBeenCalled();
  });

  it('does not fail the post when pinning throws (best-effort pin)', async () => {
    const { svc, messenger } = buildService();
    messenger.pinMessage.mockRejectedValue(new Error('pin boom'));

    // Объявление уже разослано подписчикам к этому моменту — падение здесь
    // должно быть проглочено, а не превратиться в 500 (regression на пункт A).
    await expect(
      svc.postNews({ type: 'news', text_ru: 'Тест', pin: true }),
    ).resolves.toEqual({ messageId: 'msg-1', pinned: false });
  });

  it('emits message_pinned to the channel room after post-and-pin', async () => {
    const { svc, messenger, gateway, emit } = buildService();
    const pinnedAt = new Date('2026-08-08T12:00:00.000Z');
    messenger.pinMessage.mockResolvedValue({ pinnedAt, pinnedCount: 5, alreadyPinned: false });

    await svc.postNews({ type: 'news', text_ru: 'Тест', pin: true });

    expect(gateway.server.to).toHaveBeenCalledWith('chan-1');
    expect(emit).toHaveBeenCalledWith('message_pinned', {
      conversationId: 'chan-1',
      messageId: 'msg-1',
      pinnedById: 'sys-1',
      pinnedAt,
      pinnedCount: 5,
    });
  });

  it('pins an existing post through pinPost', async () => {
    const { svc, messenger } = buildService();

    const res = await svc.pinPost('msg-9', true);

    expect(messenger.pinMessage).toHaveBeenCalledWith('chan-1', 'msg-9', 'sys-1', { silent: true });
    expect(messenger.unpinMessage).not.toHaveBeenCalled();
    expect(res).toEqual({ pinned: true, pinnedCount: 1 });
  });

  it('pinPost does not emit when the post was already pinned', async () => {
    const { svc, messenger, emit } = buildService();
    messenger.pinMessage.mockResolvedValue({ pinnedAt: new Date(), pinnedCount: 1, alreadyPinned: true });

    await svc.pinPost('msg-9', true);

    expect(emit).not.toHaveBeenCalled();
  });

  it('unpins an existing post through pinPost', async () => {
    const { svc, messenger } = buildService();

    const res = await svc.pinPost('msg-9', false);

    expect(messenger.unpinMessage).toHaveBeenCalledWith('chan-1', 'msg-9', 'sys-1');
    expect(messenger.pinMessage).not.toHaveBeenCalled();
    expect(res).toEqual({ pinned: false, pinnedCount: 0 });
  });

  it('pinPost emits message_unpinned when an existing pin is removed', async () => {
    const { svc, gateway, emit } = buildService();

    await svc.pinPost('msg-9', false);

    expect(gateway.server.to).toHaveBeenCalledWith('chan-1');
    expect(emit).toHaveBeenCalledWith('message_unpinned', {
      conversationId: 'chan-1',
      messageId: 'msg-9',
      pinnedCount: 0,
    });
  });

  it('pinPost unpin emits nothing when the post was not pinned', async () => {
    const { svc, messenger, emit } = buildService();
    messenger.unpinMessage.mockResolvedValue({ pinnedCount: 0, wasPinned: false });

    await svc.pinPost('msg-9', false);

    expect(emit).not.toHaveBeenCalled();
  });

  it('refuses to pin when the system channel is not seeded', async () => {
    const { svc, prisma, messenger } = buildService();
    prisma.conversation.findFirst.mockResolvedValue(null);

    await expect(svc.pinPost('msg-9', true)).rejects.toThrow(NotFoundException);
    expect(messenger.pinMessage).not.toHaveBeenCalled();
  });
});
