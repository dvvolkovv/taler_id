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
import { PartnerConversationScope } from './partner-conversation-scope.service';

/**
 * Tests for the extracted deliverNewMessage(...) method used by both the
 * socket `message` handler and the MCP send_message tool. Verifies delivery
 * parity: room emit, per-participant online/offline handling, block skip,
 * markDelivered + message_updated, FCM push (mute-respecting).
 */
describe('MessengerGateway.deliverNewMessage', () => {
  let gateway: MessengerGateway;
  let mockMessenger: MessengerService;
  let mockPrisma: PrismaService;
  let mockFcm: FcmService;
  let mockWebhooks: PartnerWebhooksService;
  // emitToUserInConversation шлёт ОДИН emit с массивом комнат, когда
  // мирорит в puser:<id> (один publish в Redis-адаптере вместо двух) —
  // поэтому rooms всегда массив, даже когда в нём одна комната.
  let emitted: Array<{ rooms: string[]; event: string; data: any }> = [];
  let socketsInConv: Array<{ data: { userId: string } }> = [];
  let socketsInUser: Record<string, Array<{ data: { userId: string } }>> = {};

  beforeEach(async () => {
    emitted = [];
    socketsInConv = [];
    socketsInUser = {};
    const mockServer = {
      to: (room: string | string[]) => ({
        emit: (event: string, data: any) => {
          emitted.push({ rooms: Array.isArray(room) ? room : [room], event, data });
        },
      }),
      // fanOutToParticipants' online check now passes an array
      // ([`user:x`, `puser:x`]) instead of a single room string, to count a
      // partner socket (puser:<id>) as online too — see partner.constants.ts
      // partnerUserRoom. Normalize to an array so both call shapes work.
      in: (room: string | string[]) => ({
        fetchSockets: async () => {
          const rooms = Array.isArray(room) ? room : [room];
          const userRoom = rooms.find((r) => r.startsWith('user:'));
          if (userRoom) {
            const userId = userRoom.slice(5);
            return socketsInUser[userId] ?? [];
          }
          return socketsInConv;
        },
      }),
    };
    const mod = await Test.createTestingModule({
      providers: [
        MessengerGateway,
        {
          provide: MessengerService,
          useValue: {
            getParticipants: jest.fn().mockResolvedValue([
              { userId: 'sender' },
              { userId: 'recipient' },
            ]),
            markDelivered: jest.fn().mockResolvedValue(undefined),
            isParticipantMuted: jest.fn().mockResolvedValue(false),
            getFcmTokens: jest.fn().mockResolvedValue(['tok-a', 'tok-b']),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            blockedUser: {
              findFirst: jest.fn().mockResolvedValue(null),
            },
            profile: {
              findUnique: jest.fn().mockResolvedValue({ language: 'ru' }),
            },
            // fanOutToParticipants now looks the conversation type up once
            // (to decide puser:<id> mirroring) — see partner room isolation.
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
          useValue: { sendNewMessage: jest.fn().mockResolvedValue(undefined) },
        },
        { provide: ApnsService, useValue: {} },
        { provide: ConfigService, useValue: { get: () => undefined } },
        { provide: PartnerTokensService, useValue: { verify: jest.fn().mockResolvedValue(null) } },
        { provide: PartnerRealtimeService, useValue: { registerDisconnector: jest.fn() } },
        { provide: PartnerConversationScope, useValue: { assertConversation: jest.fn(), assertMessage: jest.fn() } },
        { provide: PartnerWebhooksService, useValue: { planFanOut: jest.fn().mockResolvedValue(null) } },
      ],
    }).compile();
    gateway = mod.get(MessengerGateway);
    (gateway as any).server = mockServer;
    mockMessenger = mod.get(MessengerService);
    mockPrisma = mod.get(PrismaService);
    mockFcm = mod.get(FcmService);
    mockWebhooks = mod.get(PartnerWebhooksService);
  });

  const baseMsg = {
    id: 'msg-1',
    conversationId: 'conv-1',
    senderId: 'sender',
    content: 'hello',
    fileUrl: null,
    fileType: null,
    sentAt: new Date(),
    senderName: 'Alice',
    reactions: [],
  };

  it('emits new_message to the conversation room', async () => {
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    const roomBroadcast = emitted.find(
      (e) => e.rooms.includes('conv-1') && e.event === 'new_message',
    );
    expect(roomBroadcast).toBeDefined();
    expect(roomBroadcast!.data.id).toBe('msg-1');
    expect(roomBroadcast!.data.senderName).toBe('Alice');
  });

  it('emits new_message to each other participant user room (skips sender)', async () => {
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    const perUser = emitted.filter(
      (e) => e.rooms.includes('user:recipient') && e.event === 'new_message',
    );
    expect(perUser).toHaveLength(1);
    // Sender should NOT receive the per-user new_message (they get room emit
    // if joined, plus their own echo path).
    const senderEmit = emitted.filter(
      (e) => e.rooms.includes('user:sender') && e.event === 'new_message',
    );
    expect(senderEmit).toHaveLength(0);
  });

  it('skips delivery to a recipient who has blocked the sender', async () => {
    (mockPrisma.blockedUser.findFirst as jest.Mock).mockResolvedValue({
      blockerId: 'recipient',
      blockedId: 'sender',
    });
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    const perUser = emitted.filter(
      (e) => e.rooms.includes('user:recipient') && e.event === 'new_message',
    );
    expect(perUser).toHaveLength(0);
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
    expect(mockMessenger.markDelivered).not.toHaveBeenCalled();
  });

  it('marks delivered + emits message_updated when recipient is online', async () => {
    socketsInUser['recipient'] = [{ data: { userId: 'recipient' } }];
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(mockMessenger.markDelivered).toHaveBeenCalledWith('msg-1');
    const updated = emitted.find(
      (e) => e.event === 'message_updated' && e.rooms.includes('user:sender'),
    );
    expect(updated).toBeDefined();
    expect(updated!.data).toEqual({ id: 'msg-1', isDelivered: true });
  });

  it('does NOT push FCM when recipient is currently viewing the conversation', async () => {
    socketsInConv = [{ data: { userId: 'recipient' } }];
    socketsInUser['recipient'] = [{ data: { userId: 'recipient' } }];
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('pushes FCM to all recipient tokens when offline and unmuted', async () => {
    // no sockets → offline, not in conv
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(mockFcm.sendNewMessage).toHaveBeenCalledTimes(2);
    expect(mockFcm.sendNewMessage).toHaveBeenCalledWith(
      'tok-a',
      'Alice',
      'hello',
      'conv-1',
    );
    expect(mockFcm.sendNewMessage).toHaveBeenCalledWith(
      'tok-b',
      'Alice',
      'hello',
      'conv-1',
    );
  });

  it('pushes readable text for a system message, never the raw JSON', async () => {
    // System messages carry JSON in `content` for the client to render. The
    // push has no renderer, so before this the shade showed `{"action":...}`.
    await gateway.deliverNewMessage(
      {
        ...baseMsg,
        isSystem: true,
        content: JSON.stringify({
          action: 'message_pinned',
          actor: 'Alice',
          preview: 'Встреча в 14:00',
        }),
      },
      'sender',
      'conv-1',
    );

    const bodies = mockFcm.sendNewMessage.mock.calls.map((c: any[]) => c[2]);
    expect(bodies.length).toBeGreaterThan(0);
    for (const body of bodies) {
      expect(body.startsWith('{')).toBe(false);
      expect(body).toBe('Alice закрепил сообщение: Встреча в 14:00');
    }
  });

  it('skips FCM when the conversation is muted for the recipient', async () => {
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('a mention pushes through a muted conversation', async () => {
    // Чат приглушают, чтобы не читать поток, а не чтобы пропустить, когда
    // позвали по имени — как в Telegram.
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    await gateway.deliverNewMessage(
      { ...baseMsg, content: 'глянь @bob', mentionedUserIds: ['recipient'] },
      'sender',
      'conv-1',
    );
    expect(mockFcm.sendNewMessage).toHaveBeenCalled();
  });

  it('a mention of somebody ELSE does not break the mute for me', async () => {
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    await gateway.deliverNewMessage(
      { ...baseMsg, content: 'глянь @carol', mentionedUserIds: ['someone-else'] },
      'sender',
      'conv-1',
    );
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('skips FCM when opts.silent=true', async () => {
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1', {
      silent: true,
    });
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('uses file emoji in push text for file messages', async () => {
    await gateway.deliverNewMessage(
      { ...baseMsg, content: '', fileUrl: 'https://x/a.png', fileType: 'image' },
      'sender',
      'conv-1',
    );
    expect(mockFcm.sendNewMessage).toHaveBeenCalledWith(
      'tok-a',
      'Alice',
      '🖼 Фото',
      'conv-1',
    );
  });

  it('uses "Контакт" push text for [CONTACT] messages', async () => {
    await gateway.deliverNewMessage(
      { ...baseMsg, content: '[CONTACT] {"name":"Bob"}' },
      'sender',
      'conv-1',
    );
    expect(mockFcm.sendNewMessage).toHaveBeenCalledWith(
      'tok-a',
      'Alice',
      '📇 Контакт',
      'conv-1',
    );
  });

  // ── Regression: AI-branch ordering (commit 79c8644) ──────────────────────
  // broadcastNewMessage must NOT call getParticipants or markDelivered.
  // Before the split, deliverNewMessage (which includes fan-out) was called
  // BEFORE the AI_ANALYST / AI_INFORMER early-returns, causing extra DB
  // round-trips per AI message. The socket handler now calls broadcastNewMessage
  // eagerly and fanOutToParticipants only after those early-returns; this test
  // asserts the structural invariant on broadcastNewMessage itself.
  it('broadcastNewMessage does NOT call getParticipants or markDelivered (AI-branch safety)', async () => {
    gateway.broadcastNewMessage(baseMsg, 'conv-1');
    expect(mockMessenger.getParticipants).not.toHaveBeenCalled();
    expect(mockMessenger.markDelivered).not.toHaveBeenCalled();
  });

  it('deliverNewMessage is a composition: broadcastNewMessage + fanOutToParticipants', async () => {
    const broadcastSpy = jest.spyOn(gateway, 'broadcastNewMessage');
    const fanOutSpy = jest.spyOn(gateway, 'fanOutToParticipants');
    await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
    expect(broadcastSpy).toHaveBeenCalledWith(baseMsg, 'conv-1');
    expect(fanOutSpy).toHaveBeenCalledWith(baseMsg, 'sender', 'conv-1', {});
  });

  // ── Critical-news bypass mute (server-scoped via opts.systemPost) ───────────
  it('critical newsType WITH systemPost:true bypasses mute: FCM sent even when muted', async () => {
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    const criticalMsg = {
      ...baseMsg,
      metadata: { newsType: 'critical' },
    };
    await gateway.deliverNewMessage(criticalMsg, 'sender', 'conv-1', {
      systemPost: true,
    });
    expect(mockFcm.sendNewMessage).toHaveBeenCalled();
  });

  it('critical newsType WITHOUT systemPost (opts omitted) respects mute: FCM NOT sent', async () => {
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    const criticalMsg = {
      ...baseMsg,
      metadata: { newsType: 'critical' },
    };
    // No opts — client-supplied metadata alone must not trigger bypass
    await gateway.deliverNewMessage(criticalMsg, 'sender', 'conv-1');
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('non-critical newsType respects mute regardless of systemPost', async () => {
    (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
    const newsMsg = {
      ...baseMsg,
      metadata: { newsType: 'news' },
    };
    await gateway.deliverNewMessage(newsMsg, 'sender', 'conv-1', {
      systemPost: true,
    });
    expect(mockFcm.sendNewMessage).not.toHaveBeenCalled();
  });

  it('continues fan-out when one participant fails (resilience)', async () => {
    (mockMessenger.getParticipants as jest.Mock).mockResolvedValue([
      { userId: 'sender' },
      { userId: 'broken' },
      { userId: 'recipient' },
    ]);
    // блок-запрос для broken падает, для recipient — нет
    (mockPrisma.blockedUser.findFirst as jest.Mock).mockImplementation(
      async ({ where }: any) => {
        if (where.blockerId === 'broken') throw new Error('db timeout');
        return null;
      },
    );
    await gateway.fanOutToParticipants(
      { id: 'm1', content: 'hi' },
      'sender',
      'conv-1',
      {},
    );
    // recipient всё равно получил per-user emit
    expect(
      emitted.some((e) => e.rooms.includes('user:recipient') && e.event === 'new_message'),
    ).toBe(true);
  });

  it('conv-level fetchSockets failure does not abort fan-out (everyone treated offline)', async () => {
    socketsInConv = null as any; // заставим общий fetchSockets кинуть
    const origIn = (gateway as any).server.in.bind((gateway as any).server);
    (gateway as any).server.in = (room: string | string[]) => {
      // conv-level fetch uses a bare conversationId string; the per-participant
      // online check uses an array containing a user: room — only the former
      // should hit the simulated cross-node timeout.
      const rooms = Array.isArray(room) ? room : [room];
      if (!rooms.some((r) => r.startsWith('user:'))) {
        return { fetchSockets: async () => { throw new Error('cross-node timeout'); } };
      }
      return origIn(room);
    };
    await gateway.fanOutToParticipants(
      { id: 'm2', content: 'hello' },
      'sender',
      'conv-1',
      {},
    );
    // FCM ушёл (recipient оффлайн/вне разговора)
    expect(mockFcm.sendNewMessage).toHaveBeenCalled();
  });

  describe('partner webhooks', () => {
    let enqueue: jest.Mock;
    let savedPartnerApiEnabled: string | undefined;

    beforeEach(() => {
      // Эти тесты специально проверяют путь, где fanOutToParticipants САМ
      // смотрит тип беседы в базе (никто не передал известный тип через
      // opts.conversationType) — он включается только при PARTNER_API_ENABLED,
      // иначе партнёрских сокетов всё равно не бывает и смотреть незачем.
      savedPartnerApiEnabled = process.env.PARTNER_API_ENABLED;
      process.env.PARTNER_API_ENABLED = 'true';
      enqueue = jest.fn();
      (mockWebhooks.planFanOut as jest.Mock).mockResolvedValue({ enqueue });
    });

    afterEach(() => {
      if (savedPartnerApiEnabled === undefined) {
        delete process.env.PARTNER_API_ENABLED;
      } else {
        process.env.PARTNER_API_ENABLED = savedPartnerApiEnabled;
      }
    });

    it('queues a webhook for a recipient who does not have the chat open', async () => {
      await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
      expect(mockWebhooks.planFanOut).toHaveBeenCalledWith({
        conversationId: 'conv-1',
        participantIds: ['sender', 'recipient'],
        senderId: 'sender',
        systemPost: false,
        // fanOutToParticipants уже знает тип беседы из своего единственного
        // conversation.findUnique (см. мок PrismaService выше) — повторного
        // запроса planFanOut не делает (Правки по ревью задач 29–31).
        conversationType: 'DIRECT',
      });
      expect(enqueue).toHaveBeenCalledWith('recipient', {
        message: { id: 'msg-1', senderId: 'sender', sentAt: baseMsg.sentAt },
        senderName: 'Alice',
        preview: 'hello',
        kind: 'text',
        mentionsRecipient: false,
      });
    });

    it('does not queue for a recipient who has the chat open', async () => {
      socketsInConv = [{ data: { userId: 'recipient' } }];
      await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
      expect(enqueue).not.toHaveBeenCalled();
    });

    it('does not queue for a muted chat or a silent message', async () => {
      (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
      await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1');
      (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(false);
      await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1', { silent: true });
      expect(enqueue).not.toHaveBeenCalled();
    });

    // A silent message never pushes and never webhooks for ANY participant
    // (see the opts.silent branch above) — planFanOut's own DB round-trip
    // (partnerLink.findMany, and conversation.findUnique for a GROUP title)
    // is pure waste when we already know the answer will be "don't enqueue".
    it('skips planFanOut entirely for a silent message (no wasted DB query)', async () => {
      await gateway.deliverNewMessage(baseMsg, 'sender', 'conv-1', { silent: true });
      expect(mockWebhooks.planFanOut).not.toHaveBeenCalled();
    });

    // Adjustment 7: a mention bypasses mute for the TalerID FCM push (see
    // "a mention pushes through a muted conversation" above) — the partner
    // webhook follows the same rule, since nadi's own push to their person
    // depends on this event arriving.
    it('queues the webhook with mentionsRecipient:true when the chat is muted but the recipient is mentioned', async () => {
      (mockMessenger.isParticipantMuted as jest.Mock).mockResolvedValue(true);
      await gateway.deliverNewMessage(
        { ...baseMsg, content: 'глянь @bob', mentionedUserIds: ['recipient'] },
        'sender',
        'conv-1',
      );
      expect(enqueue).toHaveBeenCalledWith(
        'recipient',
        expect.objectContaining({ mentionsRecipient: true }),
      );
    });
  });

  describe('conversation-type resolution (latency)', () => {
    let savedPartnerApiEnabled: string | undefined;

    beforeEach(() => {
      savedPartnerApiEnabled = process.env.PARTNER_API_ENABLED;
      delete process.env.PARTNER_API_ENABLED;
    });

    afterEach(() => {
      if (savedPartnerApiEnabled === undefined) {
        delete process.env.PARTNER_API_ENABLED;
      } else {
        process.env.PARTNER_API_ENABLED = savedPartnerApiEnabled;
      }
    });

    it('skips the Prisma lookup when PARTNER_API_ENABLED is not "true" and no known type was supplied', async () => {
      await gateway.fanOutToParticipants(baseMsg, 'sender', 'conv-1', {});
      expect(mockPrisma.conversation.findUnique).not.toHaveBeenCalled();
    });

    it('passes null as the conversation type to planFanOut when disabled and unknown', async () => {
      process.env.PARTNER_API_ENABLED = 'true'; // so planFanOut is actually invoked
      const planFanOut = mockWebhooks.planFanOut as jest.Mock;
      delete process.env.PARTNER_API_ENABLED;
      await gateway.fanOutToParticipants(baseMsg, 'sender', 'conv-1', {});
      expect(planFanOut).toHaveBeenCalledWith(
        expect.objectContaining({ conversationType: null }),
      );
    });

    it('uses the caller-supplied conversation type and skips the Prisma lookup, regardless of PARTNER_API_ENABLED', async () => {
      process.env.PARTNER_API_ENABLED = 'true';
      await gateway.fanOutToParticipants(baseMsg, 'sender', 'conv-1', {
        conversationType: 'GROUP',
      });
      expect(mockPrisma.conversation.findUnique).not.toHaveBeenCalled();
      expect(mockWebhooks.planFanOut).toHaveBeenCalledWith(
        expect.objectContaining({ conversationType: 'GROUP' }),
      );
    });

    it('does not block the real-time per-participant emit on planFanOut resolving (latency)', async () => {
      process.env.PARTNER_API_ENABLED = 'true';
      let resolvePlan!: (v: any) => void;
      (mockWebhooks.planFanOut as jest.Mock).mockReturnValue(
        new Promise((resolve) => {
          resolvePlan = resolve;
        }),
      );
      const done = gateway.fanOutToParticipants(baseMsg, 'sender', 'conv-1', {
        conversationType: 'DIRECT',
      });
      // Дать шанс всем уже запланированным микро/макро-тасках пройти — если
      // бы planFanOut всё ещё ожидался ДО цикла, emit ниже не случился бы.
      await new Promise((r) => setImmediate(r));
      expect(
        emitted.some(
          (e) => e.rooms.includes('user:recipient') && e.event === 'new_message',
        ),
      ).toBe(true);
      resolvePlan({ enqueue: jest.fn() });
      await done;
    });
  });
});
