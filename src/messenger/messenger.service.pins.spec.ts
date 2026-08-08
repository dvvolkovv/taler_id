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
      expect.objectContaining({ orderBy: { pinnedAt: 'desc' } }),
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
