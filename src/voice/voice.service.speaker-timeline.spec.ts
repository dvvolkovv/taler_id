// The recorder's speech timeline has to survive the whole trip: saved with the
// meeting, then used to name Whisper's segments. The matching rule itself is
// covered in speaker-labeling.spec.ts — this pins the wiring around it, which is
// where the existing per-track diarization quietly died (the recorder never sent
// `participantTracks`, so that branch has never run in production).
process.env.LIVEKIT_WS_URL = 'wss://test.example.com/livekit';

// Transcription goes over axios rather than the global fetch: Node's fetch
// carries a 300 s headers timeout that cannot be set per call, and Whisper on a
// long chunk runs past it. The summary call still uses fetch.
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

const TIMELINE = [
  { identity: 'guest-1', name: 'Dmitry Volkov', intervals: [[0, 10]] },
  { identity: 'guest-2', name: 'Vladimir', intervals: [[12, 20]] },
];

const mockPrisma = {
  meetingSummary: {
    findUnique: jest.fn(),
    update: jest.fn(),
    create: jest.fn(),
  },
  callLog: { findUnique: jest.fn() },
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

/** The transcript text handed to the final `status: done` update. */
function savedTranscript(): string {
  const call = mockPrisma.meetingSummary.update.mock.calls
    .map(([arg]: any) => arg)
    .find((arg) => typeof arg.data.transcript === 'string');
  expect(call).toBeDefined();
  return call.data.transcript;
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

describe('transcribeExistingRecording — speaker labels from the recorder timeline', () => {
  let service: VoiceService;

  const meeting = (over: Record<string, unknown> = {}) => ({
    id: 'm-1',
    roomName: 'personal-c79530ed-36fc367a',
    recordingUrl: 'https://x/messenger/files/download?key=recordings%2Fa.mp3',
    participantIds: [OWNER_ID],
    participants: ['Dmitry Volkov', 'Vladimir'],
    participantTracks: {},
    speakerTimeline: TIMELINE,
    durationSec: 30,
    ...over,
  });

  beforeEach(async () => {
    jest.clearAllMocks();

    mockPrisma.meetingSummary.findUnique.mockResolvedValue(meeting());
    mockPrisma.meetingSummary.update.mockResolvedValue({ id: 'm-1' });
    mockPrisma.meetingSummary.create.mockResolvedValue({ id: 'm-new' });
    mockPrisma.callLog.findUnique.mockResolvedValue(null);
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
        segments: [
          { start: 1, end: 5, text: 'первый' },
          { start: 13, end: 18, text: 'второй' },
        ],
        text: 'первый второй',
      },
    });

    (global as any).fetch = jest.fn(async () => {
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

  it('names each transcript line after whoever was speaking then', async () => {
    await runToCompletion(service, OWNER_ID, 'm-1');

    expect(savedTranscript()).toBe(
      '[00:01] Dmitry Volkov: первый\n[00:13] Vladimir: второй',
    );
  });

  it('leaves lines unnamed when the recorder sent no timeline', async () => {
    // Legacy meetings and recordings made before the recorder shipped this.
    mockPrisma.meetingSummary.findUnique.mockResolvedValue(
      meeting({ speakerTimeline: null }),
    );

    await runToCompletion(service, OWNER_ID, 'm-1');

    expect(savedTranscript()).toBe('[00:01] первый\n[00:13] второй');
  });

  it('stores the timeline the recorder sends with the meeting', async () => {
    await service.saveMeetingSummary({
      roomName: 'personal-c79530ed-36fc367a',
      transcript: '',
      summary: '',
      keyPoints: [],
      actionItems: [],
      decisions: [],
      participants: ['Dmitry Volkov', 'Vladimir'],
      speakerTimeline: TIMELINE,
    });

    expect(mockPrisma.meetingSummary.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ speakerTimeline: TIMELINE }),
      }),
    );
  });
});
