import { Test } from '@nestjs/testing';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { AiTwinService } from './ai-twin.service';
import { AiAnalystService } from '../ai-analyst/ai-analyst.service';
import { AssistantChatService } from '../assistant/assistant-chat.service';
import { FcmService } from '../common/fcm.service';
import { ApnsService } from '../common/apns.service';
import { ConfigService } from '@nestjs/config';
import { PartnerRealtimeService } from '../partner-core/partner-realtime.service';
import { PartnerTokensService } from '../partner-core/partner-tokens.service';
import { PartnerWebhooksService } from '../partner-core/partner-webhooks.service';
import { partnerUserRoom } from '../partner-core/partner.constants';
import { PartnerConversationScope } from './partner-conversation-scope.service';

/**
 * «Закрыто по умолчанию»: партнёрский сокет больше не сидит в `user:<id>` —
 * там летит всё подряд (AI-ассистент, звонки, биллинг, «Избранное»). Эти
 * тесты проверяют, что события личных чатов и групп явно продублированы в
 * `puser:<id>` (чтобы партнёрский сокет их всё-таки получил), а всё остальное
 * (CHANNEL/SAVED/AI-беседы) туда не попадает.
 *
 * emitToUserInConversation шлёт ОДИН emit с массивом комнат, когда мирорит
 * (Socket.IO схлопывает пересечение, это один publish в Redis-адаптере, а не
 * два), поэтому `emitted` здесь хранит `rooms: string[]` всегда — и для
 * немирорнутого случая это массив из одной комнаты.
 */
describe('MessengerGateway partner room isolation', () => {
  let gateway: MessengerGateway;
  let mockMessenger: any;
  let mockPrisma: any;
  let emitted: Array<{ rooms: string[]; event: string; data: any }> = [];
  let socketsByRoom: Record<string, Array<{ data: { userId: string } }>> = {};

  function makeMockServer() {
    const to = jest.fn((room: string | string[]) => ({
      emit: (event: string, data: any) => {
        emitted.push({
          rooms: Array.isArray(room) ? room : [room],
          event,
          data,
        });
      },
    }));
    return {
      to,
      in: (room: string | string[]) => ({
        fetchSockets: async () => {
          const rooms = Array.isArray(room) ? room : [room];
          return rooms.flatMap((r) => socketsByRoom[r] ?? []);
        },
        socketsLeave: jest.fn(),
      }),
    };
  }

  function emittedTo(room: string, event?: string) {
    return emitted.some(
      (e) =>
        e.rooms.includes(room) && (event === undefined || e.event === event),
    );
  }

  beforeEach(async () => {
    emitted = [];
    socketsByRoom = {};
    const mod = await Test.createTestingModule({
      providers: [
        MessengerGateway,
        {
          provide: MessengerService,
          useValue: {
            getParticipants: jest
              .fn()
              .mockResolvedValue([
                { userId: 'sender' },
                { userId: 'recipient' },
              ]),
            markDelivered: jest.fn().mockResolvedValue(undefined),
            isParticipantMuted: jest.fn().mockResolvedValue(false),
            getFcmTokens: jest.fn().mockResolvedValue([]),
            getFcmTokensForUser: jest.fn().mockResolvedValue([]),
            toggleReaction: jest
              .fn()
              .mockResolvedValue([{ emoji: '👍', count: 1 }]),
            advanceReadHorizon: jest.fn().mockResolvedValue({
              lastReadAt: new Date('2026-10-01T00:00:00Z'),
              lastReadMessageId: 'm1',
            }),
            deleteMessage: jest.fn().mockResolvedValue({}),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            blockedUser: { findFirst: jest.fn().mockResolvedValue(null) },
            profile: {
              findUnique: jest.fn().mockResolvedValue({ language: 'ru' }),
            },
            conversation: {
              findUnique: jest.fn().mockResolvedValue({ type: 'DIRECT' }),
            },
          },
        },
        { provide: RedisService, useValue: {} },
        { provide: AiTwinService, useValue: { registerEmitters: jest.fn() } },
        { provide: AiAnalystService, useValue: {} },
        { provide: AssistantChatService, useValue: {} },
        {
          provide: FcmService,
          useValue: {
            sendNewMessage: jest.fn().mockResolvedValue(undefined),
            sendReadSync: jest.fn().mockResolvedValue(undefined),
          },
        },
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
    (gateway as any).server = makeMockServer();
    mockMessenger = mod.get(MessengerService);
    mockPrisma = mod.get(PrismaService);
  });

  function setConvType(type: string | null) {
    mockPrisma.conversation.findUnique.mockResolvedValue(
      type ? { type } : null,
    );
  }

  describe('emitToUserInConversation (helper)', () => {
    it('mirrors into puser:<id> for DIRECT', () => {
      gateway.emitToUserInConversation('u1', 'DIRECT', 'evt', { x: 1 });
      expect(emittedTo('user:u1', 'evt')).toBe(true);
      expect(emittedTo(partnerUserRoom('u1'), 'evt')).toBe(true);
    });

    it('mirrors into puser:<id> for GROUP', () => {
      gateway.emitToUserInConversation('u1', 'GROUP', 'evt', { x: 1 });
      expect(emittedTo(partnerUserRoom('u1'))).toBe(true);
    });

    it('does NOT mirror for CHANNEL', () => {
      gateway.emitToUserInConversation('u1', 'CHANNEL', 'evt', { x: 1 });
      expect(emitted).toEqual([
        { rooms: ['user:u1'], event: 'evt', data: { x: 1 } },
      ]);
    });

    it('does NOT mirror for SAVED', () => {
      gateway.emitToUserInConversation('u1', 'SAVED', 'evt', { x: 1 });
      expect(emitted).toEqual([
        { rooms: ['user:u1'], event: 'evt', data: { x: 1 } },
      ]);
    });

    it('does NOT mirror when the conversation type is unknown (null)', () => {
      gateway.emitToUserInConversation('u1', null, 'evt', { x: 1 });
      expect(emitted).toEqual([
        { rooms: ['user:u1'], event: 'evt', data: { x: 1 } },
      ]);
    });

    it('emits ONCE (not twice) when mirroring — one Redis publish, Socket.IO de-dupes the room overlap', () => {
      const toSpy = (gateway as any).server.to;
      gateway.emitToUserInConversation('u1', 'DIRECT', 'evt', { x: 1 });
      expect(toSpy).toHaveBeenCalledTimes(1);
      expect(toSpy).toHaveBeenCalledWith(['user:u1', partnerUserRoom('u1')]);
    });
  });

  describe('fanOutToParticipants mirrors new_message / message_updated by conversation type', () => {
    const enrichedMsg = {
      id: 'msg-1',
      conversationId: 'conv-1',
      senderId: 'sender',
      content: 'hi',
      senderName: 'Alice',
      reactions: [],
    };

    it('DIRECT: new_message reaches both user: and puser: of the recipient', async () => {
      setConvType('DIRECT');
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(emittedTo('user:recipient', 'new_message')).toBe(true);
      expect(emittedTo(partnerUserRoom('recipient'), 'new_message')).toBe(true);
    });

    it('GROUP: new_message reaches both rooms too', async () => {
      setConvType('GROUP');
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(emittedTo(partnerUserRoom('recipient'), 'new_message')).toBe(true);
    });

    it('CHANNEL: new_message stays user:-only, no puser: mirror', async () => {
      setConvType('CHANNEL');
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(emittedTo('user:recipient', 'new_message')).toBe(true);
      expect(emittedTo(partnerUserRoom('recipient'))).toBe(false);
    });

    it('DIRECT: the delivered echo to the sender also mirrors into puser:sender', async () => {
      setConvType('DIRECT');
      socketsByRoom['user:recipient'] = [{ data: { userId: 'recipient' } }];
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(emittedTo(partnerUserRoom('sender'), 'message_updated')).toBe(
        true,
      );
    });

    it('online check counts a recipient socket that only holds the puser: room', async () => {
      setConvType('DIRECT');
      // Recipient has NO socket in user:recipient — only a partner socket in
      // puser:recipient. Delivery must still be marked, or a partner-only
      // reader would never flip the sender's message to "delivered".
      socketsByRoom[partnerUserRoom('recipient')] = [
        { data: { userId: 'recipient' } },
      ];
      await gateway.fanOutToParticipants(enrichedMsg, 'sender', 'conv-1', {});
      expect(mockMessenger.markDelivered).toHaveBeenCalledWith('msg-1');
      expect(emittedTo('user:sender', 'message_updated')).toBe(true);
    });
  });

  describe('message_reaction_updated mirrors by conversation type', () => {
    const payload = { conversationId: 'conv-1', messageId: 'm1', emoji: '👍' };
    const client = { data: { userId: 'reactor' }, emit: jest.fn() };

    it('DIRECT: mirrors to puser: for each participant', async () => {
      setConvType('DIRECT');
      await gateway.handleReactMessage(client as any, payload);
      expect(
        emittedTo(partnerUserRoom('recipient'), 'message_reaction_updated'),
      ).toBe(true);
    });

    it('CHANNEL: stays user:-only', async () => {
      setConvType('CHANNEL');
      await gateway.handleReactMessage(client as any, payload);
      expect(emittedTo('user:recipient', 'message_reaction_updated')).toBe(
        true,
      );
      expect(emittedTo(partnerUserRoom('recipient'))).toBe(false);
    });
  });

  describe('mark_read (conversation_read / messages_read) mirrors by conversation type', () => {
    const payload = { conversationId: 'conv-1' };
    const client = { data: { userId: 'sender' }, emit: jest.fn() };

    it('DIRECT: conversation_read to participants and messages_read to the reader both mirror', async () => {
      setConvType('DIRECT');
      await gateway.handleMarkRead(client as any, payload as any);
      expect(emittedTo(partnerUserRoom('recipient'), 'conversation_read')).toBe(
        true,
      );
      expect(emittedTo(partnerUserRoom('sender'), 'messages_read')).toBe(true);
    });

    it('SAVED: no puser: mirror for either event', async () => {
      setConvType('SAVED');
      await gateway.handleMarkRead(client as any, payload as any);
      expect(emittedTo('user:recipient', 'conversation_read')).toBe(true);
      expect(
        emitted.some((e) => e.rooms.some((r) => r.startsWith('puser:'))),
      ).toBe(false);
    });
  });

  describe('delete_message scope:self (message_deleted) mirrors by conversation type', () => {
    const client = { data: { userId: 'sender' }, emit: jest.fn() };

    it('DIRECT: "deleted for me" mirrors into the author\'s own puser:', async () => {
      setConvType('DIRECT');
      await gateway.handleDeleteMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        scope: 'self',
      });
      expect(emittedTo('user:sender', 'message_deleted')).toBe(true);
      expect(emittedTo(partnerUserRoom('sender'), 'message_deleted')).toBe(
        true,
      );
    });

    it('CHANNEL: "deleted for me" stays user:-only', async () => {
      setConvType('CHANNEL');
      await gateway.handleDeleteMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        scope: 'self',
      });
      expect(emittedTo('user:sender', 'message_deleted')).toBe(true);
      expect(emittedTo(partnerUserRoom('sender'))).toBe(false);
    });

    it('scope "all" still broadcasts to the conversation room, untouched by this change', async () => {
      await gateway.handleDeleteMessage(client as any, {
        conversationId: 'conv-1',
        messageId: 'm1',
        scope: 'all',
      });
      expect(emittedTo('conv-1', 'message_deleted')).toBe(true);
    });
  });

  describe('evictFromConversationRoom', () => {
    it('evicts both the personal and the partner room of the user', () => {
      const socketsLeave = jest.fn();
      const inSpy = jest.fn().mockReturnValue({ socketsLeave });
      (gateway as any).server.in = inSpy;
      gateway.evictFromConversationRoom('u1', 'conv-1');
      expect(inSpy).toHaveBeenCalledWith(['user:u1', partnerUserRoom('u1')]);
      expect(socketsLeave).toHaveBeenCalledWith('conv-1');
    });
  });
});
