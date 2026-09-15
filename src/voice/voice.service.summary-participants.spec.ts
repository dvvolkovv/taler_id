// Regression cover for fabricated participants and assignees in the meeting recap.
//
// The mixed recording carries no speaker labels, so the only names Whisper's
// transcript contains are the ones people say out loud — vocatives ("Володь"),
// and third parties who were merely discussed ("Илья", "Серёга"). GPT-4o used to
// receive nothing but that transcript, so it promoted those third parties to
// participants and handed them action items, while the real roster sat unused in
// the very same MeetingSummary row.
//
// Meeting 4bb0e777 (three humans + assistant, 56 min) came back with "в обсуждении
// приняли участие Володя, Илья, Дим" and a task assigned to "Серега" — none of whom
// were in the room under those names.
//
// These tests pin that the roster we already know reaches the model.
process.env.LIVEKIT_WS_URL = 'wss://test.example.com/livekit';

// Transcription goes over axios rather than the global fetch: Node's fetch
// carries a 300 s headers timeout that cannot be set per call, and Whisper on a
// long chunk runs past it. The summary call — the one these tests inspect —
// still uses fetch.
const axiosPost = jest.fn();
jest.mock('axios', () => ({
  __esModule: true,
  default: { post: (...args: any[]) => axiosPost(...args) },
}));

import { Test, TestingModule } from '@nestjs/testing';
import { VoiceService } from './voice.service';
import { PrismaService } from '../prisma/prisma.service';
import { FileStorageService } from '../common/file-storage.service';
import { GatingService } from '../billing/services/gating.service';
import { MeteringService } from '../billing/services/metering.service';
import { LedgerService } from '../billing/services/ledger.service';
import { PricingService } from '../billing/services/pricing.service';
import { RoomChatBufferService } from './room-chat-buffer.service';

const OWNER_ID = 'c79530ed-5ba8-44e3-b7d4-4a591c7c1db6';
const TRANSCRIPT_LINE = '[00:24] Роман, ты умеешь создавать задачи в календаре?';

const mockPrisma = {
  meetingSummary: { findUnique: jest.fn(), update: jest.fn() },
};
const mockFileStorage = { getObject: jest.fn() };
const mockGating = { startSession: jest.fn(), endSession: jest.fn() };
const mockMetering = { reportUsage: jest.fn() };
const mockLedger = { debit: jest.fn(), refund: jest.fn() };
const mockPricing = { calculatePlanckCost: jest.fn() };
const mockChatBuffer = {
  append: jest.fn(),
  remove: jest.fn(),
  hitRateLimit: jest.fn(),
  read: jest.fn(),
};

/** The chat/completions payload the summary step sent, parsed. */
function summaryRequest(fetchMock: jest.Mock): any {
  const call = fetchMock.mock.calls.find(([url]) =>
    String(url).includes('/chat/completions'),
  );
  expect(call).toBeDefined();
  return JSON.parse((call![1] as any).body);
}

/** Everything the model was shown, system prompt and user turn alike. */
function promptText(fetchMock: jest.Mock): string {
  return summaryRequest(fetchMock)
    .messages.map((m: any) => m.content)
    .join('\n');
}

/** Transcription is detached from the request now: it returns `processing` and
 *  the work lands later. Tests have to wait for it themselves. */
async function settled(check: () => boolean, ms = 3000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('detached transcription did not finish in time');
}

/** Start transcription and wait for the meeting to reach a verdict. */
async function runToCompletion(service: any, userId: string, id: string) {
  await service.transcribeExistingRecording(userId, id);
  await settled(() =>
    mockPrisma.meetingSummary.update.mock.calls.some(
      ([arg]: any) => arg.data.status === 'done' || arg.data.status === 'failed',
    ),
  );
}

describe('transcribeExistingRecording — participant roster in the summary prompt', () => {
  let service: VoiceService;
  let fetchMock: jest.Mock;

  const meeting = (over: Record<string, unknown> = {}) => ({
    id: 'm-1',
    roomName: 'personal-c79530ed-36fc367a',
    recordingUrl: 'https://x/messenger/files/download?key=recordings%2Fa.mp3',
    participantIds: [OWNER_ID],
    participants: [
      'Dmitry Volkov',
      'Роман · ассистент Дмитрия',
      'Dmitry Timoshenko',
      'Vladimir',
    ],
    participantTracks: {},
    durationSec: 3341,
    ...over,
  });

  beforeEach(async () => {
    jest.clearAllMocks();

    mockPrisma.meetingSummary.findUnique.mockResolvedValue(meeting());
    mockPrisma.meetingSummary.update.mockResolvedValue({ id: 'm-1' });
    mockGating.startSession.mockResolvedValue({ id: 's-1' });
    mockGating.endSession.mockResolvedValue(undefined);
    mockPricing.calculatePlanckCost.mockResolvedValue(1n);
    mockLedger.debit.mockResolvedValue({ id: 'tx-1' });
    mockLedger.refund.mockResolvedValue(undefined);

    mockFileStorage.getObject.mockResolvedValue({
      stream: (async function* () {
        yield Buffer.alloc(1024, 7);
      })(),
      contentType: 'audio/mpeg',
    });

    axiosPost.mockResolvedValue({
      status: 200,
      data: {
        segments: [{ start: 24, end: 30, text: TRANSCRIPT_LINE.slice(8) }],
        text: TRANSCRIPT_LINE.slice(8),
      },
    });

    fetchMock = jest.fn(async () => {
      return {
        ok: true,
        json: async () => ({
          usage: { total_tokens: 100 },
          choices: [
            {
              message: {
                content: JSON.stringify({
                  summary: 's',
                  keyPoints: [],
                  actionItems: [],
                  decisions: [],
                }),
              },
            },
          ],
        }),
      };
    });
    (global as any).fetch = fetchMock;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VoiceService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: FileStorageService, useValue: mockFileStorage },
        { provide: GatingService, useValue: mockGating },
        { provide: MeteringService, useValue: mockMetering },
        { provide: LedgerService, useValue: mockLedger },
        { provide: PricingService, useValue: mockPricing },
        { provide: RoomChatBufferService, useValue: mockChatBuffer },
      ],
    }).compile();

    service = module.get<VoiceService>(VoiceService);
  });

  it('shows the model who was actually in the room', async () => {
    await runToCompletion(service, OWNER_ID, 'm-1');

    const prompt = promptText(fetchMock);
    for (const name of [
      'Dmitry Volkov',
      'Роман · ассистент Дмитрия',
      'Dmitry Timoshenko',
      'Vladimir',
    ]) {
      expect(prompt).toContain(name);
    }
  });

  it('tells the model that names outside the roster are not participants', async () => {
    await runToCompletion(service, OWNER_ID, 'm-1');

    // Whatever the wording, the roster has to be framed as exhaustive — otherwise
    // the model reads it as a hint and keeps recruiting whoever gets mentioned.
    expect(promptText(fetchMock)).toMatch(
      /не был|не присутствовал|только эти|лишь эти/i,
    );
  });

  it('still sends the transcript itself', async () => {
    await runToCompletion(service, OWNER_ID, 'm-1');

    expect(promptText(fetchMock)).toContain(TRANSCRIPT_LINE.slice(8));
  });

  it('adds no roster block when the recorder saved no participants', async () => {
    // Legacy rows and failed recorder sessions leave participants empty; an
    // empty "Участники встречи:" header would read as "nobody was there".
    mockPrisma.meetingSummary.findUnique.mockResolvedValue(
      meeting({ participants: [] }),
    );

    await runToCompletion(service, OWNER_ID, 'm-1');

    expect(promptText(fetchMock)).not.toMatch(/Участники встречи/i);
  });
});
