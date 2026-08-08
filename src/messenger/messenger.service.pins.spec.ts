import {
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { MessengerService } from './messenger.service';

describe('MessengerService pin/unpin', () => {
  let service: MessengerService;
  let prisma: any;

  beforeEach(() => {
    prisma = {
      conversation: { findUnique: jest.fn() },
      conversationParticipant: { findUnique: jest.fn(), update: jest.fn() },
      message: {
        findUnique: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
        findMany: jest.fn(),
        count: jest.fn().mockResolvedValue(1),
        create: jest.fn(),
        aggregate: jest.fn(),
      },
      user: { findUnique: jest.fn() },
    };
    service = new MessengerService(prisma, {} as any);
  });

  const conv = (type: string) => ({ id: 'conv-1', type });

  it('allows the channel OWNER to pin a message', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('CHANNEL'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'OWNER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-1', conversationId: 'conv-1', content: 'hi', deletedAt: null, pinnedAt: null,
    });
    prisma.message.updateMany.mockResolvedValue({ count: 1 });

    const res = await service.pinMessage('conv-1', 'msg-1', 'u-owner', { silent: true });

    expect(res.pinnedAt).toBeInstanceOf(Date);
    expect(res.alreadyPinned).toBe(false);
    expect(prisma.message.updateMany).toHaveBeenCalledWith({
      where: { id: 'msg-1', conversationId: 'conv-1', pinnedAt: null },
      data: { pinnedAt: expect.any(Date), pinnedById: 'u-owner' },
    });
  });

  it('forbids a SUBSCRIBER from pinning in a channel', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('CHANNEL'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'SUBSCRIBER' });

    await expect(
      service.pinMessage('conv-1', 'msg-1', 'u-sub'),
    ).rejects.toThrow(ForbiddenException);
    expect(prisma.message.update).not.toHaveBeenCalled();
    expect(prisma.message.updateMany).not.toHaveBeenCalled();
  });

  it('lets any participant pin in a DIRECT conversation', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('DIRECT'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-1', conversationId: 'conv-1', content: 'hi', deletedAt: null, pinnedAt: null,
    });
    prisma.message.updateMany.mockResolvedValue({ count: 1 });

    await expect(
      service.pinMessage('conv-1', 'msg-1', 'u-member', { silent: true }),
    ).resolves.toMatchObject({ alreadyPinned: false });
    expect(prisma.message.updateMany).toHaveBeenCalledWith({
      where: { id: 'msg-1', conversationId: 'conv-1', pinnedAt: null },
      data: { pinnedAt: expect.any(Date), pinnedById: 'u-member' },
    });
  });

  it('refuses to pin a message that belongs to a different conversation', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('DIRECT'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-9', conversationId: 'other-conv', deletedAt: null, pinnedAt: null,
    });

    await expect(
      service.pinMessage('conv-1', 'msg-9', 'u-member'),
    ).rejects.toThrow(NotFoundException);
  });

  it('rejects pinning a system message', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('DIRECT'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-1',
      conversationId: 'conv-1',
      content: '{"action":"member_added"}',
      deletedAt: null,
      pinnedAt: null,
      isSystem: true,
    });

    await expect(
      service.pinMessage('conv-1', 'msg-1', 'u-member'),
    ).rejects.toThrow(BadRequestException);
    expect(prisma.message.updateMany).not.toHaveBeenCalled();
  });

  it('is idempotent on re-pin — pinnedAt is not overwritten', async () => {
    const pinnedAt = new Date('2026-08-01T00:00:00Z');
    prisma.conversation.findUnique.mockResolvedValue(conv('DIRECT'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-1', conversationId: 'conv-1', content: 'hi', deletedAt: null, pinnedAt,
    });

    const res = await service.pinMessage('conv-1', 'msg-1', 'u-member');

    expect(res.alreadyPinned).toBe(true);
    expect(res.pinnedAt).toEqual(pinnedAt);
    expect(prisma.message.update).not.toHaveBeenCalled();
    expect(prisma.message.updateMany).not.toHaveBeenCalled();
  });

  it('loses a concurrent pin race and behaves like an already-pinned message', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('DIRECT'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-1', conversationId: 'conv-1', content: 'hi', deletedAt: null, pinnedAt: null,
    });
    prisma.message.updateMany.mockResolvedValue({ count: 0 });

    const res = await service.pinMessage('conv-1', 'msg-1', 'u-member');

    expect(res.alreadyPinned).toBe(true);
    expect(res.systemMessageId).toBeNull();
    expect(prisma.message.create).not.toHaveBeenCalled();
  });

  it('creates a system message and returns its id on the default (non-silent) path', async () => {
    const longContent = 'A'.repeat(120);
    prisma.conversation.findUnique.mockResolvedValue(conv('DIRECT'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findUnique.mockResolvedValue({
      id: 'msg-1', conversationId: 'conv-1', content: longContent, deletedAt: null, pinnedAt: null,
    });
    prisma.message.updateMany.mockResolvedValue({ count: 1 });
    prisma.user.findUnique.mockResolvedValue({
      id: 'u-member',
      profile: { firstName: 'Ada', lastName: 'Lovelace' },
    });
    prisma.message.create.mockResolvedValue({ id: 'sys-1' });

    const res = await service.pinMessage('conv-1', 'msg-1', 'u-member');

    expect(res.alreadyPinned).toBe(false);
    expect(res.systemMessageId).toBe('sys-1');
    expect(prisma.message.create).toHaveBeenCalledTimes(1);
    const createArgs = prisma.message.create.mock.calls[0][0];
    expect(createArgs.data.isSystem).toBe(true);
    const parsed = JSON.parse(createArgs.data.content);
    expect(parsed.action).toBe('message_pinned');
    expect(parsed.preview).toBe(longContent.slice(0, 80));
  });

  it('unpin clears both fields', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('GROUP'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'ADMIN' });
    prisma.message.updateMany.mockResolvedValue({ count: 1 });
    prisma.message.count.mockResolvedValue(0);

    const res = await service.unpinMessage('conv-1', 'msg-1', 'u-admin');

    expect(res.pinnedCount).toBe(0);
    expect(prisma.message.updateMany).toHaveBeenCalledWith({
      where: { id: 'msg-1', conversationId: 'conv-1' },
      data: { pinnedAt: null, pinnedById: null },
    });
  });

  it('forbids a non-admin MEMBER from unpinning in a GROUP', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('GROUP'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });

    await expect(
      service.unpinMessage('conv-1', 'msg-1', 'u-member'),
    ).rejects.toThrow(ForbiddenException);
    expect(prisma.message.updateMany).not.toHaveBeenCalled();
  });

  it('reports wasPinned=false when unpinning a message that was never pinned', async () => {
    prisma.conversation.findUnique.mockResolvedValue(conv('GROUP'));
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'ADMIN' });
    prisma.message.updateMany.mockResolvedValue({ count: 0 });

    const res = await service.unpinMessage('conv-1', 'msg-1', 'u-admin');

    expect(res.wasPinned).toBe(false);
  });

  it('lists pinned messages newest-first with a flattened senderName', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findMany.mockResolvedValue([
      {
        id: 'm2', content: 'second', pinnedAt: new Date('2026-08-02'),
        sender: { username: 'bob', profile: { firstName: 'Bob', lastName: null } },
      },
      {
        id: 'm1', content: 'first', pinnedAt: new Date('2026-08-01'),
        sender: { username: 'ann', profile: null },
      },
    ]);
    prisma.message.count.mockResolvedValue(2);

    const res = await service.listPinned('conv-1', 'u-member');

    expect(res.total).toBe(2);
    expect(res.messages.map((m: any) => m.id)).toEqual(['m2', 'm1']);
    expect(res.messages[0].senderName).toBe('Bob');
    expect(res.messages[1].senderName).toBe('ann');
    expect(res.messages[0].sender).toBeUndefined();
    expect(prisma.message.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ orderBy: [{ pinnedAt: 'desc' }, { id: 'desc' }] }),
    );
  });

  it('excludes soft-deleted and hidden messages from the pinned list', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findMany.mockResolvedValue([]);
    prisma.message.count.mockResolvedValue(0);

    await service.listPinned('conv-1', 'u-member');

    const where = prisma.message.findMany.mock.calls[0][0].where;
    expect(where).toMatchObject({
      conversationId: 'conv-1',
      pinnedAt: { not: null },
      deletedAt: null,
      NOT: { hiddenFor: { some: { userId: 'u-member' } } },
    });
  });

  it('refuses to list pins for a non-participant', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue(null);

    await expect(service.listPinned('conv-1', 'stranger')).rejects.toThrow(ForbiddenException);
    expect(prisma.message.findMany).not.toHaveBeenCalled();
  });

  it('clamps limit and offset to safe bounds on both ends', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.findMany.mockResolvedValue([]);
    prisma.message.count.mockResolvedValue(0);

    await service.listPinned('conv-1', 'u-member', 5000, 20);

    const highArgs = prisma.message.findMany.mock.calls[0][0];
    expect(highArgs.take).toBe(100);
    expect(highArgs.skip).toBe(20);

    await service.listPinned('conv-1', 'u-member', 0, -5);

    const lowArgs = prisma.message.findMany.mock.calls[1][0];
    expect(lowArgs.take).toBe(1);
    expect(lowArgs.skip).toBe(0);
  });

  it('unpins everything in a conversation for an admin', async () => {
    prisma.conversation.findUnique.mockResolvedValue({ id: 'conv-1', type: 'CHANNEL' });
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'ADMIN' });
    prisma.message.updateMany.mockResolvedValue({ count: 3 });

    await expect(service.unpinAll('conv-1', 'u-admin')).resolves.toEqual({ unpinned: 3 });
    expect(prisma.message.updateMany).toHaveBeenCalledWith({
      where: { conversationId: 'conv-1', pinnedAt: { not: null } },
      data: { pinnedAt: null, pinnedById: null },
    });
  });

  it('forbids a SUBSCRIBER from unpinning everything', async () => {
    prisma.conversation.findUnique.mockResolvedValue({ id: 'conv-1', type: 'CHANNEL' });
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'SUBSCRIBER' });

    await expect(service.unpinAll('conv-1', 'u-sub')).rejects.toThrow(ForbiddenException);
    expect(prisma.message.updateMany).not.toHaveBeenCalled();
  });

  it('defaults pinsDismissedAt to the newest pin when no cursor is given', async () => {
    const newestPinnedAt = new Date('2026-08-07T00:00:00Z');
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.aggregate.mockResolvedValue({ _max: { pinnedAt: newestPinnedAt } });
    prisma.conversationParticipant.update.mockResolvedValue({});

    const res = await service.dismissPins('conv-1', 'u-member');

    expect(res.pinsDismissedAt).toEqual(newestPinnedAt);
    expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
      where: { conversationId_userId: { conversationId: 'conv-1', userId: 'u-member' } },
      data: { pinsDismissedAt: newestPinnedAt },
    });
  });

  it('uses the caller-supplied cursor without querying for the newest pin', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.conversationParticipant.update.mockResolvedValue({});
    const upTo = new Date('2026-08-06T12:00:00Z');

    const res = await service.dismissPins('conv-1', 'u-member', upTo);

    expect(res.pinsDismissedAt).toEqual(upTo);
    expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
      where: { conversationId_userId: { conversationId: 'conv-1', userId: 'u-member' } },
      data: { pinsDismissedAt: upTo },
    });
    expect(prisma.message.aggregate).not.toHaveBeenCalled();
  });

  it('falls back to the newest pin when the cursor is an invalid date', async () => {
    const newestPinnedAt = new Date('2026-08-07T00:00:00Z');
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.message.aggregate.mockResolvedValue({ _max: { pinnedAt: newestPinnedAt } });
    prisma.conversationParticipant.update.mockResolvedValue({});

    const res = await service.dismissPins('conv-1', 'u-member', new Date('garbage'));

    expect(res.pinsDismissedAt).toEqual(newestPinnedAt);
    expect(prisma.message.aggregate).toHaveBeenCalled();
    expect(prisma.conversationParticipant.update).toHaveBeenCalledWith({
      where: { conversationId_userId: { conversationId: 'conv-1', userId: 'u-member' } },
      data: { pinsDismissedAt: newestPinnedAt },
    });
  });

  it('clamps a future cursor to now instead of trusting a skewed client clock', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue({ role: 'MEMBER' });
    prisma.conversationParticipant.update.mockResolvedValue({});
    const farFuture = new Date('9999-01-01T00:00:00Z');

    const before = Date.now();
    const res = await service.dismissPins('conv-1', 'u-member', farFuture);
    const after = Date.now();

    expect(res.pinsDismissedAt).toBeInstanceOf(Date);
    expect(res.pinsDismissedAt.getTime()).not.toBe(farFuture.getTime());
    expect(res.pinsDismissedAt.getTime()).toBeGreaterThanOrEqual(before);
    expect(res.pinsDismissedAt.getTime()).toBeLessThanOrEqual(after);
    expect(prisma.message.aggregate).not.toHaveBeenCalled();
  });

  it('refuses to dismiss pins for a non-participant', async () => {
    prisma.conversationParticipant.findUnique.mockResolvedValue(null);

    await expect(service.dismissPins('conv-1', 'stranger')).rejects.toThrow(ForbiddenException);
    expect(prisma.conversationParticipant.update).not.toHaveBeenCalled();
  });
});

describe('MessengerService conversation payload — pins', () => {
  it('exposes pinnedCount, a truncated topPinned and pinsDismissedAt', () => {
    const service = new MessengerService({} as any, {} as any);
    const dismissedAt = new Date('2026-08-05T00:00:00Z');
    const pinnedAt = new Date('2026-08-06T00:00:00Z');

    const out = (service as any)._formatConversation(
      {
        id: 'conv-1',
        type: 'CHANNEL',
        participants: [{ userId: 'me', role: 'SUBSCRIBER', pinsDismissedAt: dismissedAt }],
        messages: [],
        _count: { participants: 100 },
      },
      'me',
      { sys: { username: 'talerid', profile: { firstName: 'Taler ID', lastName: '' } } },
      undefined,
      undefined,
      {
        'conv-1': {
          count: 2,
          top: { id: 'm9', content: 'x'.repeat(500), senderId: 'sys', sentAt: pinnedAt, pinnedAt },
        },
      },
    );

    expect(out.pinnedCount).toBe(2);
    expect(out.topPinned.id).toBe('m9');
    expect(out.topPinned.content).toHaveLength(200);
    expect(out.topPinned.senderName).toBe('Taler ID');
    expect(out.topPinned.pinnedAt).toEqual(pinnedAt);
    expect(out.pinsDismissedAt).toEqual(dismissedAt);
  });

  it('reports no pins when the conversation has none', () => {
    const service = new MessengerService({} as any, {} as any);
    const out = (service as any)._formatConversation(
      { id: 'c', type: 'DIRECT', participants: [{ userId: 'me' }], messages: [] },
      'me',
    );
    expect(out.pinnedCount).toBe(0);
    expect(out.topPinned).toBeNull();
    expect(out.pinsDismissedAt).toBeNull();
  });

  it('falls back to the username when the pin author has no profile name', () => {
    const service = new MessengerService({} as any, {} as any);
    const pinnedAt = new Date('2026-08-06T00:00:00Z');
    const out = (service as any)._formatConversation(
      { id: 'c', type: 'GROUP', participants: [{ userId: 'me' }], messages: [] },
      'me',
      { u1: { username: 'ann', profile: null } },
      undefined,
      undefined,
      { c: { count: 1, top: { id: 'm1', content: 'hi', senderId: 'u1', sentAt: pinnedAt, pinnedAt } } },
    );
    expect(out.topPinned.senderName).toBe('ann');
  });

  it('excludes messages hidden for the caller from the pins query', async () => {
    const prisma: any = {
      // Как минимум одна беседа обязательна: _loadPinnedMap коротким замыканием
      // возвращает {} без похода в БД, если список conversationId пуст, и тогда
      // message.findMany вовсе не вызовется — нечего будет проверять ниже.
      conversation: {
        findMany: jest.fn().mockResolvedValue([
          { id: 'c1', type: 'DIRECT', _count: { participants: 2 }, messages: [] },
        ]),
      },
      conversationParticipant: {
        findMany: jest.fn().mockResolvedValue([{ conversationId: 'c1', userId: 'me' }]),
      },
      message: {
        findMany: jest.fn().mockResolvedValue([]),
        count: jest.fn().mockResolvedValue(0),
      },
      user: { findMany: jest.fn().mockResolvedValue([]) },
      contactAlias: { findMany: jest.fn().mockResolvedValue([]) },
      callLog: { findMany: jest.fn().mockResolvedValue([]) },
    };
    const service = new MessengerService(prisma, {} as any);

    await service.getConversations('me');

    // Первый вызов message.findMany в getConversations — это выборка пинов.
    const pinsCall = prisma.message.findMany.mock.calls.find(
      (c: any[]) => c[0]?.where?.pinnedAt !== undefined,
    );
    expect(pinsCall).toBeDefined();
    expect(pinsCall[0].where).toMatchObject({
      pinnedAt: { not: null },
      deletedAt: null,
      NOT: { hiddenFor: { some: { userId: 'me' } } },
    });
    expect(pinsCall[0].orderBy).toEqual([{ pinnedAt: 'desc' }, { id: 'desc' }]);
  });

  it('folds multiple pin rows per conversation into a count and a first-seen top', async () => {
    const t1 = new Date('2026-08-01T00:00:00Z');
    const t2 = new Date('2026-08-02T00:00:00Z');
    const t3 = new Date('2026-08-03T00:00:00Z');
    const t4 = new Date('2026-08-04T00:00:00Z');
    const prisma: any = {
      conversation: {
        findMany: jest.fn().mockResolvedValue([
          { id: 'c1', type: 'DIRECT', _count: { participants: 2 }, messages: [] },
          { id: 'c2', type: 'GROUP', _count: { participants: 3 }, messages: [] },
        ]),
      },
      conversationParticipant: {
        findMany: jest.fn().mockResolvedValue([
          { conversationId: 'c1', userId: 'me' },
          { conversationId: 'c2', userId: 'me' },
        ]),
      },
      message: {
        // orderBy: [{pinnedAt:'desc'},{id:'desc'}] в реальном запросе гарантирует
        // «новейший первым» внутри беседы — мок уже возвращает ряды в этом
        // порядке, как если бы Prisma применила ту сортировку.
        findMany: jest.fn().mockResolvedValue([
          { id: 'p1', conversationId: 'c1', content: 'c1 newest', senderId: 'u1', sentAt: t4, pinnedAt: t4 },
          { id: 'p2', conversationId: 'c1', content: 'c1 older', senderId: 'u1', sentAt: t3, pinnedAt: t3 },
          { id: 'p3', conversationId: 'c2', content: 'c2 newest', senderId: 'u2', sentAt: t2, pinnedAt: t2 },
          { id: 'p4', conversationId: 'c2', content: 'c2 older', senderId: 'u2', sentAt: t1, pinnedAt: t1 },
        ]),
        count: jest.fn().mockResolvedValue(0),
      },
      user: { findMany: jest.fn().mockResolvedValue([]) },
      contactAlias: { findMany: jest.fn().mockResolvedValue([]) },
      callLog: { findMany: jest.fn().mockResolvedValue([]) },
    };
    const service = new MessengerService(prisma, {} as any);

    const out = await service.getConversations('me');

    const c1 = out.find((c: any) => c.id === 'c1');
    const c2 = out.find((c: any) => c.id === 'c2');
    expect(c1.pinnedCount).toBe(2);
    expect(c1.topPinned.id).toBe('p1'); // первая встреченная строка, вторая (p2) не должна её перезаписать
    expect(c2.pinnedCount).toBe(2);
    expect(c2.topPinned.id).toBe('p3'); // аналогично: p4 не перезаписывает top
  });

  it('an existing DIRECT conversation carries its pins through getOrCreateDirectConversation', async () => {
    const pinnedAt = new Date('2026-08-06T00:00:00Z');
    const tx: any = {
      $executeRaw: jest.fn().mockResolvedValue(undefined),
      conversation: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'conv-dm',
          type: 'DIRECT',
          participants: [{ userId: 'u-a' }, { userId: 'u-b' }],
          messages: [],
        }),
      },
      message: {
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'p1',
            conversationId: 'conv-dm',
            content: 'pinned dm',
            senderId: 'u-b',
            sentAt: pinnedAt,
            pinnedAt,
          },
        ]),
      },
    };
    const prisma: any = {
      $transaction: jest.fn((cb: any) => cb(tx)),
    };
    const service = new MessengerService(prisma, {} as any);

    const out = await service.getOrCreateDirectConversation('u-a', 'u-b');

    expect(out.pinnedCount).toBe(1);
    expect(out.topPinned.id).toBe('p1');
    // userMap на этой ветке намеренно не прокидывается (см. _loadPinnedMap
    // call site) — имя автора пина клиент получит из отдельного listPinned.
    expect(out.topPinned.senderName).toBeNull();
  });
});
