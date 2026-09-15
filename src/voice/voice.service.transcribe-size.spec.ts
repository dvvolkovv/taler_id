// Regression cover for the 25 MiB Whisper upload cap.
//
// LiveKit writes the mixed meeting recording at ~70 kbps, so a meeting crosses
// OpenAI's 26 214 400-byte limit at roughly 50 minutes. Before this was fixed,
// transcribeExistingRecording streamed the raw buffer straight to Whisper and a
// 56-minute meeting came back as `Whisper error 413` → 500 in the mobile app.
//
// These tests pin the two behaviours that keep that from happening again:
//   1. an oversized recording is re-encoded before upload, and what actually
//      goes to OpenAI is under the cap;
//   2. a recording that already fits is uploaded untouched (no pointless ffmpeg).
process.env.LIVEKIT_WS_URL = 'wss://test.example.com/livekit';

import * as fs from 'fs';

const execFileMock = jest.fn();
jest.mock('child_process', () => ({
  ...jest.requireActual('child_process'),
  execFile: (...args: any[]) => {
    const cb = args[args.length - 1];
    execFileMock(args[0], args[1]);
    const bin = args[0] as string;
    const argv = args[1] as string[];
    if (bin === 'ffprobe') {
      return cb(null, { stdout: '600.0\n', stderr: '' });
    }
    // Stand in for ffmpeg: emit an output file a fraction of the input's size,
    // which is what a 70 kbps → 32 kbps 16 kHz mono re-encode actually does.
    const out = argv[argv.length - 1];
    fs.writeFileSync(out, Buffer.alloc(3 * 1024 * 1024, 1));
    return cb(null, { stdout: '', stderr: '' });
  },
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

const WHISPER_CAP = 26_214_400;
const OWNER_ID = 'c79530ed-5ba8-44e3-b7d4-4a591c7c1db6';

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

/** Byte length of each multipart body handed to the transcriptions endpoint. */
function whisperUploadSizes(fetchMock: jest.Mock): number[] {
  return fetchMock.mock.calls
    .filter(([url]) => String(url).includes('/audio/transcriptions'))
    .map(([, init]) => {
      const form = (init as any).body as FormData;
      const file = form.get('file') as Blob;
      return file.size;
    });
}

describe('transcribeExistingRecording — Whisper upload cap', () => {
  let service: VoiceService;
  let fetchMock: jest.Mock;

  const meeting = (over: Record<string, unknown> = {}) => ({
    id: 'm-1',
    roomName: 'personal-c79530ed-36fc367a',
    recordingUrl: 'https://x/messenger/files/download?key=recordings%2Fa.mp3',
    participantIds: [OWNER_ID],
    participantTracks: {},
    durationSec: 3341,
    ...over,
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    execFileMock.mockClear();

    mockPrisma.meetingSummary.findUnique.mockResolvedValue(meeting());
    mockPrisma.meetingSummary.update.mockResolvedValue({ id: 'm-1' });
    mockGating.startSession.mockResolvedValue({ id: 's-1' });
    mockGating.endSession.mockResolvedValue(undefined);
    mockPricing.calculatePlanckCost.mockResolvedValue(1n);
    mockLedger.debit.mockResolvedValue({ id: 'tx-1' });
    mockLedger.refund.mockResolvedValue(undefined);

    fetchMock = jest.fn(async (url: any, init: any) => {
      if (String(url).includes('/audio/transcriptions')) {
        // Behave like the real endpoint: anything over 25 MiB is refused with a
        // 413 before a single byte is transcribed.
        const uploaded = ((init.body as FormData).get('file') as Blob).size;
        if (uploaded > WHISPER_CAP) {
          return {
            ok: false,
            status: 413,
            text: async () =>
              `{"error":{"message":"413: Maximum content size limit (${WHISPER_CAP}) exceeded (${uploaded} bytes read)","type":"server_error"}}`,
          };
        }
        return {
          ok: true,
          json: async () => ({
            segments: [{ start: 0, end: 5, text: 'привет' }],
            text: 'привет',
          }),
        };
      }
      // GPT-4o summary
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

  /** fileStorage.getObject returns an async-iterable stream of one chunk. */
  const stubDownload = (bytes: number) => {
    mockFileStorage.getObject.mockResolvedValue({
      stream: (async function* () {
        yield Buffer.alloc(bytes, 7);
      })(),
      contentType: 'audio/mpeg',
    });
  };

  it('re-encodes a recording that exceeds the cap and uploads under it', async () => {
    // 27.5 MiB — the size of the 56-minute meeting that produced the 413.
    stubDownload(28_853_685);

    await service.transcribeExistingRecording(OWNER_ID, 'm-1');

    const sizes = whisperUploadSizes(fetchMock);
    expect(sizes.length).toBeGreaterThan(0);
    for (const size of sizes) {
      expect(size).toBeLessThan(WHISPER_CAP);
    }
    expect(execFileMock).toHaveBeenCalledWith('ffmpeg', expect.any(Array));
  });

  it('leaves a recording that already fits alone', async () => {
    stubDownload(5 * 1024 * 1024);

    await service.transcribeExistingRecording(OWNER_ID, 'm-1');

    expect(whisperUploadSizes(fetchMock)).toEqual([5 * 1024 * 1024]);
    expect(execFileMock).not.toHaveBeenCalled();
  });

  it('marks the meeting done rather than failed for an oversized recording', async () => {
    stubDownload(28_853_685);

    await service.transcribeExistingRecording(OWNER_ID, 'm-1');

    const statuses = mockPrisma.meetingSummary.update.mock.calls.map(
      ([arg]: any) => arg.data.status,
    );
    expect(statuses).toContain('done');
    expect(statuses).not.toContain('failed');
  });
});
