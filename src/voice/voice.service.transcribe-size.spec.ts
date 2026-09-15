// Regression cover for the two limits a meeting recording runs into on its way
// to Whisper. Both were found the hard way on a 56-minute meeting:
//
//   1. OpenAI refuses uploads over 25 MiB (26 214 400 bytes) with a 413. LiveKit
//      writes the mixed recording at ~70 kbps, so a meeting crosses that line at
//      roughly 50 minutes and the mobile app got a 500.
//   2. Once the upload was small enough, a single Whisper call on an hour of
//      audio ran past the 300 s headers timeout baked into Node's global fetch
//      and died as a bare "TypeError: fetch failed" (UND_ERR_HEADERS_TIMEOUT).
//
// So size decides whether we re-encode, and duration decides whether we split.
process.env.LIVEKIT_WS_URL = 'wss://test.example.com/livekit';

import * as fs from 'fs';
import * as path from 'path';

/** What the mocked ffprobe reports; individual tests set it. */
let probeDuration = 60;
/** How many chunk files the mocked segmenter emits; individual tests set it. */
let chunkCount = 3;
const execFileMock = jest.fn();

jest.mock('child_process', () => ({
  ...jest.requireActual('child_process'),
  execFile: (...args: any[]) => {
    const cb = args[args.length - 1];
    const bin = args[0] as string;
    const argv = args[1] as string[];
    execFileMock(bin, argv);

    if (bin === 'ffprobe') {
      return cb(null, { stdout: `${probeDuration}\n`, stderr: '' });
    }

    const out = argv[argv.length - 1];
    if (argv.includes('segment')) {
      // Stand in for `-f segment`: emit chunk files next to the pattern.
      const dir = path.dirname(out);
      for (let i = 0; i < chunkCount; i++) {
        fs.writeFileSync(
          path.join(dir, `part-${String(i).padStart(3, '0')}.mp3`),
          Buffer.alloc(64 * 1024, i + 1),
        );
      }
      return cb(null, { stdout: '', stderr: '' });
    }
    // Stand in for the 16 kHz mono re-encode: a fraction of the input's size.
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
/** Mirrors WHISPER_CHUNK_SECONDS in the service. */
const CHUNK_SECONDS = 900;
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
    .map(([, init]) => ((init as any).body.get('file') as Blob).size);
}

const ffmpegCalls = () =>
  execFileMock.mock.calls.filter(([bin]) => bin === 'ffmpeg');

describe('transcribeExistingRecording — Whisper size and duration limits', () => {
  let service: VoiceService;
  let fetchMock: jest.Mock;
  /** Peak number of overlapping transcription requests during one run. */
  let maxInFlight = 0;
  let inFlight = 0;

  const meeting = (over: Record<string, unknown> = {}) => ({
    id: 'm-1',
    roomName: 'personal-c79530ed-36fc367a',
    recordingUrl: 'https://x/messenger/files/download?key=recordings%2Fa.mp3',
    participantIds: [OWNER_ID],
    participants: ['Tester'],
    participantTracks: {},
    durationSec: 3341,
    ...over,
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    execFileMock.mockClear();
    probeDuration = 60;
    chunkCount = 3;
    maxInFlight = 0;
    inFlight = 0;

    mockPrisma.meetingSummary.findUnique.mockResolvedValue(meeting());
    mockPrisma.meetingSummary.update.mockResolvedValue({ id: 'm-1' });
    mockGating.startSession.mockResolvedValue({ id: 's-1' });
    mockGating.endSession.mockResolvedValue(undefined);
    mockPricing.calculatePlanckCost.mockResolvedValue(1n);
    mockLedger.debit.mockResolvedValue({ id: 'tx-1' });
    mockLedger.refund.mockResolvedValue(undefined);

    fetchMock = jest.fn(async (url: any, init: any) => {
      if (String(url).includes('/audio/transcriptions')) {
        // Behave like the real endpoint: over 25 MiB is refused with a 413
        // before a single byte is transcribed.
        const uploaded = (init.body.get('file') as Blob).size;
        if (uploaded > WHISPER_CAP) {
          return {
            ok: false,
            status: 413,
            text: async () =>
              `{"error":{"message":"413: Maximum content size limit (${WHISPER_CAP}) exceeded (${uploaded} bytes read)","type":"server_error"}}`,
          };
        }
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        // Yield so concurrent calls actually overlap rather than resolving
        // one-by-one on the microtask queue.
        await new Promise((r) => setTimeout(r, 5));
        inFlight -= 1;
        return {
          ok: true,
          json: async () => ({
            segments: [{ start: 0, end: 5, text: 'привет' }],
            text: 'привет',
          }),
        };
      }
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

  const statuses = () =>
    mockPrisma.meetingSummary.update.mock.calls.map(
      ([arg]: any) => arg.data.status,
    );

  it('re-encodes a recording that exceeds the cap and uploads under it', async () => {
    // 27.5 MiB — the size of the 56-minute meeting that produced the 413.
    stubDownload(28_853_685);

    await service.transcribeExistingRecording(OWNER_ID, 'm-1');

    const sizes = whisperUploadSizes(fetchMock);
    expect(sizes.length).toBeGreaterThan(0);
    for (const size of sizes) expect(size).toBeLessThan(WHISPER_CAP);
    expect(ffmpegCalls().length).toBeGreaterThan(0);
    expect(statuses()).toContain('done');
    expect(statuses()).not.toContain('failed');
  });

  it('uploads a short recording untouched, without re-encoding it', async () => {
    stubDownload(5 * 1024 * 1024);

    await service.transcribeExistingRecording(OWNER_ID, 'm-1');

    expect(whisperUploadSizes(fetchMock)).toEqual([5 * 1024 * 1024]);
    expect(ffmpegCalls()).toHaveLength(0);
  });

  it('splits a recording that fits the cap but is too long for one call', async () => {
    // The case that died as UND_ERR_HEADERS_TIMEOUT: comfortably under 25 MiB,
    // but nearly an hour of audio behind it.
    probeDuration = CHUNK_SECONDS + 100;
    stubDownload(12_724_209);

    await service.transcribeExistingRecording(OWNER_ID, 'm-1');

    // Three chunks from the mocked segmenter → three separate Whisper calls.
    expect(whisperUploadSizes(fetchMock)).toHaveLength(3);
    expect(
      ffmpegCalls().some(([, argv]) => argv.includes('segment')),
    ).toBe(true);
    expect(statuses()).toContain('done');
    expect(statuses()).not.toContain('failed');
  });

  it('shifts segment timestamps of later chunks onto the meeting clock', async () => {
    probeDuration = CHUNK_SECONDS + 100;
    stubDownload(12_724_209);

    await service.transcribeExistingRecording(OWNER_ID, 'm-1');

    // Every chunk's mocked segment starts at 0; only the offsets distinguish
    // them, so a transcript with three identical [00:00] lines would mean the
    // stitching silently collapsed the recording onto its first chunk.
    const transcript = mockPrisma.meetingSummary.update.mock.calls
      .map(([arg]: any) => arg.data.transcript)
      .filter(Boolean)[0] as string;
    const stamps = transcript.split('\n').map((l) => l.slice(0, 7));
    expect(stamps).toEqual(['[00:00]', '[16:40]', '[33:20]']);
  });

  it('transcribes chunks concurrently but no more than four at a time', async () => {
    probeDuration = CHUNK_SECONDS + 100;
    chunkCount = 9;
    stubDownload(12_724_209);

    await service.transcribeExistingRecording(OWNER_ID, 'm-1');

    expect(whisperUploadSizes(fetchMock)).toHaveLength(9);
    expect(maxInFlight).toBeGreaterThan(1);
    expect(maxInFlight).toBeLessThanOrEqual(4);

    // Order must survive the overlap: nine chunks, each one probeDuration apart.
    const transcript = mockPrisma.meetingSummary.update.mock.calls
      .map(([arg]: any) => arg.data.transcript)
      .filter(Boolean)[0] as string;
    const starts = transcript
      .split('\n')
      .map((l) => l.match(/^\[(\d+):(\d+)\]/)!)
      .map((m) => Number(m[1]) * 60 + Number(m[2]));
    expect(starts).toEqual([...starts].sort((a, b) => a - b));
    expect(starts).toHaveLength(9);
  });
});
