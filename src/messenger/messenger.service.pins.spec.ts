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
});
