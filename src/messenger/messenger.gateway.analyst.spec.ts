import { Test } from '@nestjs/testing';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { AiTwinService } from './ai-twin.service';
import { AiAnalystService } from '../ai-analyst/ai-analyst.service';
import { OutboundBotService } from '../outbound-bot/outbound-bot.service';
import { FcmService } from '../common/fcm.service';
import { ApnsService } from '../common/apns.service';
import { ConfigService } from '@nestjs/config';

interface SubmitTaskInput {
  onChunk: (text: string) => void;
  onTool?: (tool: string, input: string) => void;
}

describe('MessengerGateway._dispatchToAnalyst', () => {
  let gateway: MessengerGateway;
  let mockAnalyst: AiAnalystService;
  let mockMessenger: MessengerService;
  let emitted: Array<{ room: string; event: string; data: any }> = [];

  beforeEach(async () => {
    emitted = [];
    const mockServer = {
      to: (room: string) => ({
        emit: (event: string, data: any) => { emitted.push({ room, event, data }); },
      }),
    };
    const mod = await Test.createTestingModule({
      providers: [
        MessengerGateway,
        { provide: MessengerService, useValue: {
          createMessage: jest.fn().mockImplementation(async (convId, _userId, content, _fd, _topic, isSystem, meta) => ({
            id: 'msg-1', conversationId: convId, senderId: 'bot', content,
            isSystem, metadata: meta ?? null, sentAt: new Date(),
          })),
        }},
        { provide: PrismaService, useValue: {
          profile: { findUnique: jest.fn().mockResolvedValue({ language: 'ru' }) },
        }},
        { provide: RedisService, useValue: {} },
        { provide: AiTwinService, useValue: {} },
        { provide: AiAnalystService, useValue: { submitTask: jest.fn() } },
        { provide: OutboundBotService, useValue: {} },
        { provide: FcmService, useValue: {} },
        { provide: ApnsService, useValue: {} },
        { provide: ConfigService, useValue: { get: () => undefined } },
      ],
    }).compile();
    gateway = mod.get(MessengerGateway);
    (gateway as any).server = mockServer;
    mockAnalyst = mod.get(AiAnalystService);
    mockMessenger = mod.get(MessengerService);
  });

  function replayWorker(callbacks: SubmitTaskInput, script: Array<['tool', string, string] | ['chunk', string]>) {
    for (const step of script) {
      if (step[0] === 'tool') callbacks.onTool?.(step[1], step[2]);
      else callbacks.onChunk(step[1]);
    }
  }

  it('emits typing with thinking emoji before first tool/chunk', async () => {
    (mockAnalyst.submitTask as jest.Mock).mockImplementation(async (input) => {
      replayWorker(input, [['chunk', 'Привет']]);
      return { text: 'Привет', outputFiles: [] };
    });
    await (gateway as any)._dispatchToAnalyst('user-1', 'conv-1', 'hi', []);
    const first = emitted[0];
    expect(first.room).toBe('user:user-1');
    expect(first.event).toBe('typing');
    expect(first.data.typingText).toContain('🤔');
    expect(first.data.typingText).toContain('Думаю');
    expect(first.data.isTyping).toBe(true);
    expect(first.data.conversationId).toBe('conv-1');
  });

  it('emits typing event for each tool with localized label', async () => {
    (mockAnalyst.submitTask as jest.Mock).mockImplementation(async (input) => {
      replayWorker(input, [
        ['tool', 'WebSearch', 'query:cats'],
        ['tool', 'Read', '/etc/hosts'],
        ['chunk', 'done'],
      ]);
      return { text: 'done', outputFiles: [] };
    });
    await (gateway as any)._dispatchToAnalyst('user-1', 'conv-1', 'hi', []);
    const typingEvents = emitted.filter(e => e.event === 'typing' && e.data.isTyping);
    // thinking + WebSearch + Read + preparing
    expect(typingEvents).toHaveLength(4);
    expect(typingEvents[1].data.typingText).toContain('🔍');
    expect(typingEvents[1].data.typingText).toContain('Ищу в интернете');
    expect(typingEvents[2].data.typingText).toContain('📄');
    expect(typingEvents[2].data.typingText).toContain('Читаю файл');
    expect(typingEvents[3].data.typingText).toContain('✍️');
  });

  it('emits analyst_chunk for each delta', async () => {
    (mockAnalyst.submitTask as jest.Mock).mockImplementation(async (input) => {
      replayWorker(input, [['chunk', 'Hello '], ['chunk', 'world']]);
      return { text: 'Hello world', outputFiles: [] };
    });
    await (gateway as any)._dispatchToAnalyst('user-1', 'conv-1', 'hi', []);
    const chunks = emitted.filter(e => e.event === 'analyst_chunk');
    expect(chunks).toHaveLength(2);
    expect(chunks[0].data.text).toBe('Hello ');
    expect(chunks[1].data.text).toBe('world');
  });

  it('persists metadata.steps with correct counts', async () => {
    (mockAnalyst.submitTask as jest.Mock).mockImplementation(async (input) => {
      replayWorker(input, [
        ['tool', 'WebSearch', 'q1'],
        ['tool', 'WebSearch', 'q2'],
        ['tool', 'Read', 'f1'],
        ['tool', 'Bash', 'ls'],
        ['chunk', 'answer'],
      ]);
      return { text: 'answer', outputFiles: [] };
    });
    await (gateway as any)._dispatchToAnalyst('user-1', 'conv-1', 'hi', []);
    const createCall = (mockMessenger.createMessage as jest.Mock).mock.calls[0];
    // Positional args per createMessage signature:
    // [conversationId, senderId, content, fileData, topicId, isSystem, metadata]
    const metadata = createCall[6];
    expect(metadata.steps).toEqual(expect.arrayContaining([
      { kind: 'search', count: 2 },
      { kind: 'file',   count: 1 },
      { kind: 'cmd',    count: 1 },
    ]));
    expect(typeof metadata.durationMs).toBe('number');
  });

  it('emits analyst_seam after saving final message', async () => {
    (mockAnalyst.submitTask as jest.Mock).mockImplementation(async (input) => {
      replayWorker(input, [['tool', 'Read', 'f'], ['chunk', 'ok']]);
      return { text: 'ok', outputFiles: [] };
    });
    await (gateway as any)._dispatchToAnalyst('user-1', 'conv-1', 'hi', []);
    const seam = emitted.find(e => e.event === 'analyst_seam');
    expect(seam).toBeDefined();
    expect(seam!.data.messageId).toBe('msg-1');
    expect(seam!.data.steps).toEqual(expect.arrayContaining([{ kind: 'file', count: 1 }]));
  });

  it('emits typing isTyping=false to clear indicator after done', async () => {
    (mockAnalyst.submitTask as jest.Mock).mockImplementation(async (input) => {
      replayWorker(input, [['chunk', 'done']]);
      return { text: 'done', outputFiles: [] };
    });
    await (gateway as any)._dispatchToAnalyst('user-1', 'conv-1', 'hi', []);
    const clears = emitted.filter(e => e.event === 'typing' && e.data.isTyping === false);
    expect(clears.length).toBeGreaterThanOrEqual(1);
  });

  it('on error, emits error typing and saves error message', async () => {
    (mockAnalyst.submitTask as jest.Mock).mockRejectedValue(new Error('worker down'));
    await (gateway as any)._dispatchToAnalyst('user-1', 'conv-1', 'hi', []);
    const errorTyping = emitted.find(e => e.event === 'typing' && e.data.typingText?.includes('❌'));
    expect(errorTyping).toBeDefined();
    const createCall = (mockMessenger.createMessage as jest.Mock).mock.calls[0];
    expect(createCall[2]).toContain('❌');
  });

  it('uses English labels when Profile.language=en', async () => {
    const prisma = (gateway as any).prisma;
    prisma.profile.findUnique.mockResolvedValue({ language: 'en' });
    (mockAnalyst.submitTask as jest.Mock).mockImplementation(async (input) => {
      replayWorker(input, [['tool', 'WebSearch', 'q'], ['chunk', 'done']]);
      return { text: 'done', outputFiles: [] };
    });
    await (gateway as any)._dispatchToAnalyst('user-2', 'conv-2', 'hi', []);
    const searchTyping = emitted.find(e => e.event === 'typing' && e.data.typingText?.includes('🔍'));
    expect(searchTyping!.data.typingText).toContain('Searching the web');
  });

  it('times out after 3 minutes and emits error typing', async () => {
    jest.useFakeTimers();
    (mockAnalyst.submitTask as jest.Mock).mockImplementation(() => new Promise(() => {}));
    const p = (gateway as any)._dispatchToAnalyst('user-1', 'conv-1', 'hi', []);
    jest.advanceTimersByTime(3 * 60 * 1000 + 100);
    await p;
    const errorTyping = emitted.find(e => e.event === 'typing' && e.data.typingText?.includes('❌'));
    expect(errorTyping).toBeDefined();
    const createArgs = (mockMessenger.createMessage as jest.Mock).mock.calls[0];
    expect(createArgs[2]).toMatch(/timeout|Ошибка|Error/i);
    jest.useRealTimers();
  });
});
