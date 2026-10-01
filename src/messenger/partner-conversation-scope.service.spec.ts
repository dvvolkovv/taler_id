import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { PartnerConversationScope } from './partner-conversation-scope.service';

describe('PartnerConversationScope', () => {
  let prisma: any;
  let scope: PartnerConversationScope;

  beforeEach(() => {
    prisma = {
      conversation: { findUnique: jest.fn() },
      message: { findUnique: jest.fn(), findMany: jest.fn() },
      conversationParticipant: { findMany: jest.fn() },
      contactRequest: { findMany: jest.fn() },
    };
    scope = new PartnerConversationScope(prisma);
  });

  it.each(['DIRECT', 'GROUP'])(
    'allows %s conversations',
    async (type: string) => {
      prisma.conversation.findUnique.mockResolvedValue({ type });
      await expect(scope.assertConversation('c1')).resolves.toBeUndefined();
    },
  );

  it.each(['CHANNEL', 'SAVED', 'AI_ANALYST', 'AI_ASSISTANT'])(
    'refuses %s conversations',
    async (type: string) => {
      prisma.conversation.findUnique.mockResolvedValue({ type });
      await expect(scope.assertConversation('c1')).rejects.toThrow(
        ForbiddenException,
      );
    },
  );

  it('leaves unknown ids and missing params to the handler', async () => {
    prisma.conversation.findUnique.mockResolvedValue(null);
    await expect(scope.assertConversation('ghost')).resolves.toBeUndefined();
    await expect(scope.assertConversation(undefined)).resolves.toBeUndefined();
    expect(prisma.conversation.findUnique).toHaveBeenCalledTimes(1);
  });

  it('checks the conversation of a message', async () => {
    prisma.message.findUnique.mockResolvedValue({
      conversation: { type: 'SAVED' },
    });
    await expect(scope.assertMessage('m1')).rejects.toThrow(ForbiddenException);
    prisma.message.findUnique.mockResolvedValue({
      conversation: { type: 'GROUP' },
    });
    await expect(scope.assertMessage('m2')).resolves.toBeUndefined();
  });

  it('lists only direct chats and groups as visible', async () => {
    prisma.conversationParticipant.findMany.mockResolvedValue([
      { conversationId: 'c1' },
      { conversationId: 'c3' },
    ]);
    await expect(scope.visibleConversationIds('u1')).resolves.toEqual(
      new Set(['c1', 'c3']),
    );
    expect(prisma.conversationParticipant.findMany).toHaveBeenCalledWith({
      where: {
        userId: 'u1',
        conversation: { type: { in: ['DIRECT', 'GROUP'] } },
      },
      select: { conversationId: true },
    });
  });

  it('checks every source message of a forward', async () => {
    prisma.message.findMany.mockResolvedValue([
      { conversation: { type: 'DIRECT' } },
      { conversation: { type: 'GROUP' } },
    ]);
    await expect(scope.assertMessages(['m1', 'm2'])).resolves.toBeUndefined();

    prisma.message.findMany.mockResolvedValue([
      { conversation: { type: 'DIRECT' } },
      { conversation: { type: 'SAVED' } },
    ]);
    await expect(scope.assertMessages(['m1', 'm3'])).rejects.toThrow(
      ForbiddenException,
    );
  });

  it('skips the query for an empty forward', async () => {
    await expect(scope.assertMessages([])).resolves.toBeUndefined();
    await expect(scope.assertMessages(undefined)).resolves.toBeUndefined();
    expect(prisma.message.findMany).not.toHaveBeenCalled();
  });

  it('still treats null the same as undefined (no-op)', async () => {
    await expect(scope.assertMessages(null as any)).resolves.toBeUndefined();
    expect(prisma.message.findMany).not.toHaveBeenCalled();
  });

  it('refuses a non-array messageIds (e.g. a bare string) instead of throwing a raw TypeError', async () => {
    await expect(scope.assertMessages('m1' as any)).rejects.toThrow(
      BadRequestException,
    );
    await expect(scope.assertMessages('m1' as any)).rejects.toThrow(
      'invalid_message_ids',
    );
    expect(prisma.message.findMany).not.toHaveBeenCalled();
  });

  it('refuses an array containing a non-string element', async () => {
    await expect(scope.assertMessages(['m1', 42] as any)).rejects.toThrow(
      'invalid_message_ids',
    );
    expect(prisma.message.findMany).not.toHaveBeenCalled();
  });

  describe('isPartnerConversation / isPartnerMessage (strict, for the socket gate)', () => {
    // В отличие от assertConversation/assertMessage (REST — пропускают
    // неизвестный id, ответит обработчик 404), у сокета нет такого
    // обработчика: фильтр либо пропускает пакет, либо тихо отказывает.
    it.each(['DIRECT', 'GROUP'])(
      'true for a confirmed %s conversation',
      async (type: string) => {
        prisma.conversation.findUnique.mockResolvedValue({ type });
        await expect(scope.isPartnerConversation('c1')).resolves.toBe(true);
      },
    );

    it.each(['CHANNEL', 'SAVED', 'AI_ANALYST'])(
      'false for a %s conversation',
      async (type: string) => {
        prisma.conversation.findUnique.mockResolvedValue({ type });
        await expect(scope.isPartnerConversation('c1')).resolves.toBe(false);
      },
    );

    it('false for an unknown conversation id (unlike assertConversation, does not pass through)', async () => {
      prisma.conversation.findUnique.mockResolvedValue(null);
      await expect(scope.isPartnerConversation('ghost')).resolves.toBe(false);
    });

    it.each(['DIRECT', 'GROUP'])(
      'true for a message in a confirmed %s conversation',
      async (type: string) => {
        prisma.message.findUnique.mockResolvedValue({ conversation: { type } });
        await expect(scope.isPartnerMessage('m1')).resolves.toBe(true);
      },
    );

    it('false for a message in a SAVED conversation', async () => {
      prisma.message.findUnique.mockResolvedValue({
        conversation: { type: 'SAVED' },
      });
      await expect(scope.isPartnerMessage('m1')).resolves.toBe(false);
    });

    it('false for an unknown message id', async () => {
      prisma.message.findUnique.mockResolvedValue(null);
      await expect(scope.isPartnerMessage('ghost')).resolves.toBe(false);
    });
  });

  it('names the people who are not contacts', async () => {
    prisma.contactRequest.findMany.mockResolvedValue([
      { senderId: 'u1', receiverId: 'u2' },
      { senderId: 'u3', receiverId: 'u1' },
    ]);
    await expect(
      scope.assertAllContacts('u1', ['u2', 'u3']),
    ).resolves.toBeUndefined();
    prisma.contactRequest.findMany.mockResolvedValue([
      { senderId: 'u1', receiverId: 'u2' },
    ]);
    const err = await scope
      .assertAllContacts('u1', ['u2', 'u4', 'u1'])
      .catch((e) => e);
    expect(err).toBeInstanceOf(ForbiddenException);
    expect(err.getResponse()).toEqual({
      message: 'not_a_contact',
      userIds: ['u4'],
    });
  });
});
