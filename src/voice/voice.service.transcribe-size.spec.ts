// Regression cover for the three limits a meeting recording runs into on its way
// to Whisper. All three were found on one 56-minute meeting, each hiding behind
// the previous one:
//
//   1. OpenAI refuses uploads over 25 MiB (26 214 400 bytes) with a 413. LiveKit
//      writes the mixed recording at ~70 kbps, so a meeting crosses that line at
//      roughly 50 minutes and the mobile app got a 500.
//   2. Once the upload was small enough, a single Whisper call on an hour of
//      audio ran past the 300 s headers timeout baked into Node's global fetch
//      and died as a bare "TypeError: fetch failed".
//   3. Splitting helped but did not settle it: four concurrent chunks get queued
//      on OpenAI's side, and the same 13-minute chunk that answered in ~200 s on
//      DEV took over 300 s on PROD. Hence axios with an explicit timeout — the
//      transcription request must not inherit an unsettable one.
//
// So: size decides whether we re-encode, duration decides whether we split, and
// the timeout is stated outright rather than inherited.
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

/** Transcription requests go through axios; the summary still goes through fetch. */
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

const transcribeCalls = () =>
  axiosPost.mock.calls.filter(([url]) =>
    String(url).includes('/audio/transcriptions'),
  );

/** Byte length of the audio part in each transcription request. */
const whisperUploadSizes = () =>
  transcribeCalls().map(([, form]) => (form.get('file') as Blob).size);

const ffmpegCalls = () =>
  execFileMock.mock.calls.filter(([bin]) => bin === 'ffmpeg');

/** The request no longer waits for transcription — it returns `processing` and
 *  the work runs detached. Tests have to wait for it themselves. */
async function settled(check: () => boolean, ms = 3000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('detached transcription did not finish in time');
}

describe('transcribeExistingRecording — Whisper size, duration and timeout', () => {
  let service: VoiceService;
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
    axiosPost.mockReset();
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

    axiosPost.mockImplementation(async (_url: string, form: any) => {
      // Behave like the real endpoint: over 25 MiB is refused with a 413 before
      // a single byte is transcribed.
      const uploaded = (form.get('file') as Blob).size;
      if (uploaded > WHISPER_CAP) {
        return {
          status: 413,
          data: {
            error: {
              message: `413: Maximum content size limit (${WHISPER_CAP}) exceeded (${uploaded} bytes read)`,
              type: 'server_error',
            },
          },
        };
      }
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      // Yield so concurrent calls actually overlap rather than resolving
      // one-by-one on the microtask queue.
      await new Promise((r) => setTimeout(r, 5));
      inFlight -= 1;
      return {
        status: 200,
        data: {
          segments: [{ start: 0, end: 5, text: 'привет' }],
          text: 'привет',
        },
      };
    });

    // GPT-4o summary still goes over fetch.
    (global as any).fetch = jest.fn(async () => ({
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
    }));

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

  /** Start transcription and wait for the detached half to reach a verdict. */
  const runToCompletion = async () => {
    const accepted = await service.transcribeExistingRecording(OWNER_ID, 'm-1');
    expect(accepted).toMatchObject({ status: 'processing' });
    await settled(() => statuses().some((s) => s === 'done' || s === 'failed'));
  };

  const savedTranscript = () =>
    mockPrisma.meetingSummary.update.mock.calls
      .map(([arg]: any) => arg.data.transcript)
      .filter((t: unknown) => typeof t === 'string')[0] as string;

  it('states a timeout on the transcription request instead of inheriting one', async () => {
    stubDownload(5 * 1024 * 1024);

    await runToCompletion();

    const [, , config] = transcribeCalls()[0];
    // Without this the call rides Node's unsettable 300 s fetch timeout, which
    // is what killed the 53-minute run on PROD.
    expect(config.timeout).toBeGreaterThanOrEqual(10 * 60 * 1000);
    expect(config.maxBodyLength).toBe(Infinity);
  });

  it('re-encodes a recording that exceeds the cap and uploads under it', async () => {
    // 27.5 MiB — the size of the 56-minute meeting that produced the 413.
    stubDownload(28_853_685);

    await runToCompletion();

    const sizes = whisperUploadSizes();
    expect(sizes.length).toBeGreaterThan(0);
    for (const size of sizes) expect(size).toBeLessThan(WHISPER_CAP);
    expect(ffmpegCalls().length).toBeGreaterThan(0);
    expect(statuses()).toContain('done');
    expect(statuses()).not.toContain('failed');
  });

  it('uploads a short recording untouched, without re-encoding it', async () => {
    stubDownload(5 * 1024 * 1024);

    await runToCompletion();

    expect(whisperUploadSizes()).toEqual([5 * 1024 * 1024]);
    expect(ffmpegCalls()).toHaveLength(0);
  });

  it('splits a recording that fits the cap but is too long for one call', async () => {
    probeDuration = CHUNK_SECONDS + 100;
    stubDownload(12_724_209);

    await runToCompletion();

    expect(whisperUploadSizes()).toHaveLength(3);
    expect(ffmpegCalls().some(([, argv]) => argv.includes('segment'))).toBe(
      true,
    );
    expect(statuses()).toContain('done');
    expect(statuses()).not.toContain('failed');
  });

  it('shifts segment timestamps of later chunks onto the meeting clock', async () => {
    probeDuration = CHUNK_SECONDS + 100;
    stubDownload(12_724_209);

    await runToCompletion();

    // Every chunk's mocked segment starts at 0; only the offsets distinguish
    // them, so a transcript with three identical [00:00] lines would mean the
    // stitching silently collapsed the recording onto its first chunk.
    const stamps = savedTranscript()
      .split('\n')
      .map((l) => l.match(/\[\d+:\d+\]/)![0]);
    expect(stamps).toEqual(['[00:00]', '[16:40]', '[33:20]']);
  });

  it('transcribes chunks concurrently but no more than four at a time', async () => {
    probeDuration = CHUNK_SECONDS + 100;
    chunkCount = 9;
    stubDownload(12_724_209);

    await runToCompletion();

    expect(whisperUploadSizes()).toHaveLength(9);
    expect(maxInFlight).toBeGreaterThan(1);
    expect(maxInFlight).toBeLessThanOrEqual(4);

    // Order must survive the overlap.
    const starts = savedTranscript()
      .split('\n')
      .map((l) => l.match(/\[(\d+):(\d+)\]/)!)
      .map((m) => Number(m[1]) * 60 + Number(m[2]));
    expect(starts).toEqual([...starts].sort((a, b) => a - b));
    expect(starts).toHaveLength(9);
  });

  it('marks the meeting failed and refunds when Whisper rejects the upload', async () => {
    axiosPost.mockResolvedValue({
      status: 413,
      data: { error: { message: 'too big' } },
    });
    stubDownload(5 * 1024 * 1024);

    // The caller is told "processing" and walks away — a Whisper refusal can no
    // longer come back as an HTTP error, so the meeting's own status and the
    // refund are the only things that report it.
    await expect(
      service.transcribeExistingRecording(OWNER_ID, 'm-1'),
    ).resolves.toMatchObject({ status: 'processing' });

    await settled(() => statuses().includes('failed'));
    expect(statuses()).not.toContain('done');
    expect(mockLedger.refund).toHaveBeenCalled();
  });

  it('reports insufficient funds to the caller instead of failing in the background', async () => {
    mockLedger.debit.mockRejectedValue(new Error('insufficient funds'));
    stubDownload(5 * 1024 * 1024);

    // Billing stays on the request's side of the line precisely so this is an
    // error the user sees at once, not a meeting that quietly turns failed.
    await expect(
      service.transcribeExistingRecording(OWNER_ID, 'm-1'),
    ).rejects.toThrow(/insufficient funds/);

    expect(statuses()).toContain('failed');
    expect(transcribeCalls()).toHaveLength(0);
  });
});
