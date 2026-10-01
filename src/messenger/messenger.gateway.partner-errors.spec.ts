import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { AiTwinService } from './ai-twin.service';
import { AiAnalystService } from '../ai-analyst/ai-analyst.service';
import { AssistantChatService } from '../assistant/assistant-chat.service';
import { FcmService } from '../common/fcm.service';
import { ApnsService } from '../common/apns.service';
import { PartnerRealtimeService } from '../partner-core/partner-realtime.service';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { PartnerWebhooksService } from '../partner-core/partner-webhooks.service';
import { PartnerConversationScope } from './partner-conversation-scope.service';

/**
 * Follow-up к партнёрскому API: сокет больше не отдаёт партнёру сырой текст
 * отказа (русские фразы, текст ошибки Prisma/Error) — только машинный код.
 * Обычные клиенты TalerID получают байт-в-байт то же, что и раньше.
 * Коды — в docs/partner-messenger-api.md, раздел «Сокет: от сервера».
 */
describe('MessengerGateway socket errors: machine codes for partner, unchanged text for native', () => {
  let gateway: MessengerGateway;
  let service: any;
  let prisma: any;

  function partnerClient() {
    return {
      data: {
        userId: 'sender',
        partner: { partnerId: 'p1', partnerSlug: 'nadi' },
      },
      emit: jest.fn(),
    };
  }
  function nativeClient() {
    return { data: { userId: 'sender' }, emit: jest.fn() };
  }

  beforeEach(async () => {
    service = {
      assertParticipant: jest.fn().mockResolvedValue(undefined),
      getConversationType: jest.fn().mockResolvedValue('GROUP'),
      getParticipants: jest
        .fn()
        .mockResolvedValue([{ userId: 'sender' }, { userId: 'recipient' }]),
      hasContactWith: jest.fn().mockResolvedValue(true),
      createMessage: jest
        .fn()
        .mockResolvedValue({ id: 'm1', conversationId: 'conv-1' }),
      getUserDisplayName: jest.fn().mockResolvedValue('Sender'),
      loadReplyPreview: jest.fn().mockResolvedValue(null),
      editMessage: jest.fn().mockResolvedValue({ id: 'm1', content: 'edited' }),
      deleteMessage: jest.fn().mockResolvedValue({}),
      toggleReaction: jest.fn().mockResolvedValue([{ emoji: '👍', count: 1 }]),
    };
    prisma = {
      blockedUser: { findFirst: jest.fn().mockResolvedValue(null) },
      conversation: {
        findUnique: jest.fn().mockResolvedValue({ type: 'DIRECT' }),
      },
    };
    const mod = await Test.createTestingModule({
      providers: [
        MessengerGateway,
        { provide: MessengerService, useValue: service },
        { provide: PrismaService, useValue: prisma },
        { provide: RedisService, useValue: {} },
        { provide: AiTwinService, useValue: { registerEmitters: jest.fn() } },
        { provide: AiAnalystService, useValue: {} },
        { provide: AssistantChatService, useValue: {} },
        { provide: FcmService, useValue: {} },
        { provide: ApnsService, useValue: {} },
        { provide: ConfigService, useValue: { get: () => undefined } },
        {
          provide: PartnerTokensService,
          useValue: { verify: jest.fn().mockResolvedValue(null) },
        },
        {
          provide: PartnerRealtimeService,
          useValue: { registerDisconnector: jest.fn() },
        },
        {
          provide: PartnerConversationScope,
          useValue: { assertConversation: jest.fn(), assertMessage: jest.fn() },
        },
        {
          provide: PartnerWebhooksService,
          useValue: { planFanOut: jest.fn().mockResolvedValue(null) },
        },
      ],
    }).compile();
    gateway = mod.get(MessengerGateway);
    (gateway as any).server = {
      to: jest.fn().mockReturnValue({ emit: jest.fn() }),
      in: jest.fn(),
    };
    jest
      .spyOn((gateway as any).logger, 'error')
      .mockImplementation(() => undefined);
  });

  describe('join: not a participant', () => {
    beforeEach(() => {
      service.assertParticipant.mockRejectedValue(new Error('nope'));
    });

    it('partner socket gets the code', async () => {
      const client = partnerClient();
      await gateway.handleJoin(client as any, { conversationId: 'conv-1' });
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'not_a_participant',
      });
    });

    it('native socket keeps the exact previous text', async () => {
      const client = nativeClient();
      await gateway.handleJoin(client as any, { conversationId: 'conv-1' });
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'Not a participant',
      });
    });
  });

  describe('message: DIRECT, recipient blocked the sender', () => {
    beforeEach(() => {
      service.getConversationType.mockResolvedValue('DIRECT');
      prisma.blockedUser.findFirst.mockResolvedValue({ id: 'b1' });
    });

    it('partner socket gets `blocked`, not the Russian sentence', async () => {
      const client = partnerClient();
      await gateway.handleMessage(
        client as any,
        { conversationId: 'conv-1', content: 'hi' } as any,
      );
      expect(client.emit).toHaveBeenCalledWith('error', { message: 'blocked' });
      expect(client.emit).not.toHaveBeenCalledWith('error', {
        message: 'Вы заблокированы этим пользователем',
      });
    });

    it('native socket keeps the exact previous text', async () => {
      const client = nativeClient();
      await gateway.handleMessage(
        client as any,
        { conversationId: 'conv-1', content: 'hi' } as any,
      );
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'Вы заблокированы этим пользователем',
      });
    });
  });

  describe('message: DIRECT, no longer contacts', () => {
    beforeEach(() => {
      service.getConversationType.mockResolvedValue('DIRECT');
      prisma.blockedUser.findFirst.mockResolvedValue(null);
      service.hasContactWith.mockResolvedValue(false);
    });

    it('partner socket gets `not_a_contact`, not the Russian sentence', async () => {
      const client = partnerClient();
      await gateway.handleMessage(
        client as any,
        { conversationId: 'conv-1', content: 'hi' } as any,
      );
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'not_a_contact',
      });
      expect(client.emit).not.toHaveBeenCalledWith('error', {
        message: 'Пользователь удалил вас из контактов',
      });
    });

    it('native socket keeps the exact previous text', async () => {
      const client = nativeClient();
      await gateway.handleMessage(
        client as any,
        { conversationId: 'conv-1', content: 'hi' } as any,
      );
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'Пользователь удалил вас из контактов',
      });
    });
  });

  describe('message: unexpected failure (raw Error text must never reach a partner socket)', () => {
    beforeEach(() => {
      // GROUP skips the DIRECT-only blocked/contact checks above, isolating
      // the generic catch-all.
      service.getConversationType.mockResolvedValue('GROUP');
      service.createMessage.mockRejectedValue(
        new Error('column "foo" does not exist'),
      );
    });

    it('partner socket gets `internal_error`, never the raw Error/Prisma text', async () => {
      const client = partnerClient();
      await gateway.handleMessage(
        client as any,
        { conversationId: 'conv-1', content: 'hi' } as any,
      );
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'internal_error',
      });
      expect(client.emit).not.toHaveBeenCalledWith('error', {
        message: 'column "foo" does not exist',
      });
    });

    it('native socket keeps getting the raw message, exactly as before', async () => {
      const client = nativeClient();
      await gateway.handleMessage(
        client as any,
        { conversationId: 'conv-1', content: 'hi' } as any,
      );
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'column "foo" does not exist',
      });
    });

    it('logs the real error server-side regardless of caller', async () => {
      const client = partnerClient();
      await gateway.handleMessage(
        client as any,
        { conversationId: 'conv-1', content: 'hi' } as any,
      );
      expect((gateway as any).logger.error).toHaveBeenCalledWith(
        expect.stringContaining('column "foo" does not exist'),
        expect.anything(),
      );
    });
  });

  describe('message: fan-out reuses the already-known conversation type (no duplicate DB lookup)', () => {
    it('does not call prisma.conversation.findUnique a second time for the type fanOutToParticipants would otherwise look up itself', async () => {
      const saved = process.env.PARTNER_API_ENABLED;
      // Even with the flag ON (the one case where fanOutToParticipants WOULD
      // otherwise query the DB), the type handleMessage already knows must
      // still win and skip that query entirely.
      process.env.PARTNER_API_ENABLED = 'true';
      try {
        service.getConversationType.mockResolvedValue('GROUP');
        const client = nativeClient();
        await gateway.handleMessage(
          client as any,
          { conversationId: 'conv-1', content: 'hi' } as any,
        );
        expect(prisma.conversation.findUnique).not.toHaveBeenCalled();
      } finally {
        if (saved === undefined) delete process.env.PARTNER_API_ENABLED;
        else process.env.PARTNER_API_ENABLED = saved;
      }
    });
  });

  describe('edit_message: unexpected failure', () => {
    beforeEach(() => {
      service.editMessage.mockRejectedValue(new Error('edit exploded'));
    });

    it('partner socket gets `internal_error`', async () => {
      const client = partnerClient();
      await gateway.handleEditMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        content: 'x',
      });
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'internal_error',
      });
      expect(client.emit).not.toHaveBeenCalledWith('error', {
        message: 'edit exploded',
      });
    });

    it('native socket keeps the raw message, exactly as before', async () => {
      const client = nativeClient();
      await gateway.handleEditMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        content: 'x',
      });
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'edit exploded',
      });
    });

    it('logs the real error server-side (previously not logged at all)', async () => {
      const client = partnerClient();
      await gateway.handleEditMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        content: 'x',
      });
      expect((gateway as any).logger.error).toHaveBeenCalledWith(
        expect.stringContaining('edit exploded'),
      );
    });
  });

  describe('delete_message: unexpected failure', () => {
    beforeEach(() => {
      service.deleteMessage.mockRejectedValue(new Error('delete exploded'));
    });

    it('partner socket gets `internal_error`', async () => {
      const client = partnerClient();
      await gateway.handleDeleteMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        scope: 'all',
      });
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'internal_error',
      });
      expect(client.emit).not.toHaveBeenCalledWith('error', {
        message: 'delete exploded',
      });
    });

    it('native socket keeps the raw message, exactly as before', async () => {
      const client = nativeClient();
      await gateway.handleDeleteMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        scope: 'all',
      });
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'delete exploded',
      });
    });

    it('logs the real error server-side (previously not logged at all)', async () => {
      const client = partnerClient();
      await gateway.handleDeleteMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        scope: 'all',
      });
      expect((gateway as any).logger.error).toHaveBeenCalledWith(
        expect.stringContaining('delete exploded'),
      );
    });
  });

  describe('react_message: unexpected failure', () => {
    beforeEach(() => {
      service.toggleReaction.mockRejectedValue(new Error('react exploded'));
    });

    it('partner socket gets `internal_error`', async () => {
      const client = partnerClient();
      await gateway.handleReactMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        emoji: '👍',
      });
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'internal_error',
      });
      expect(client.emit).not.toHaveBeenCalledWith('error', {
        message: 'react exploded',
      });
    });

    it('native socket keeps the raw message, exactly as before', async () => {
      const client = nativeClient();
      await gateway.handleReactMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        emoji: '👍',
      });
      expect(client.emit).toHaveBeenCalledWith('error', {
        message: 'react exploded',
      });
    });

    it('logs the real error server-side (previously not logged at all)', async () => {
      const client = partnerClient();
      await gateway.handleReactMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        emoji: '👍',
      });
      expect((gateway as any).logger.error).toHaveBeenCalledWith(
        expect.stringContaining('react exploded'),
      );
    });
  });
});
