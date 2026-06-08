import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { VoiceGateService } from './voice-gate.service';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

const mockConfig = {
  get: jest.fn((key: string, fallback?: any) => {
    const env: Record<string, any> = {
      MANAX_BASE_URL: 'http://127.0.0.1:8791',
      MANAX_API_KEY: 'test-key',
      OWNER_VOICE_THRESHOLD: '0.5',
      OWNER_VOICE_WINDOW_MS: '1000',
      OWNER_VOICE_ENABLED: 'true',
    };
    return env[key] ?? fallback;
  }),
};

// embedAudio is now async-polling: POST submit → GET status → GET full job.
// This helper sets up the 3-call mock chain for a successful poll.
function mockJobCompleted(jobBody: any) {
  mockedAxios.post.mockResolvedValueOnce({ status: 202, data: { jobId: 'j-mock' } });
  mockedAxios.get
    .mockResolvedValueOnce({ status: 200, data: { status: 'completed' } })
    .mockResolvedValueOnce({ status: 200, data: jobBody });
}

describe('VoiceGateService.embedAudio', () => {
  let service: VoiceGateService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VoiceGateService,
        { provide: ConfigService, useValue: mockConfig },
      ],
    }).compile();
    service = module.get(VoiceGateService);
  });

  it('extracts the highest-coverage embedding from a successful Manax response', async () => {
    mockJobCompleted({
      jobId: 'j-mock',
      status: 'completed',
      result: {
        durationSec: 1.0,
        speakerEmbeddings: [
          { speakerId: 'spk_a', vector: [0.1, 0.2], coverageFraction: 0.4 },
          { speakerId: 'spk_b', vector: [0.7, 0.8], coverageFraction: 0.9 },
        ],
      },
    });
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toEqual([0.7, 0.8]);
    expect(result.speakerId).toBe('spk_b');
  });

  it('returns null embedding when Manax returns no embeddings', async () => {
    mockJobCompleted({ jobId: 'j-mock', status: 'completed', result: { speakerEmbeddings: [] } });
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
  });

  it('returns null embedding when Manax HTTP fails (fail-open)', async () => {
    mockedAxios.post.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
    expect(result.error).toBe('manax_unavailable');
  });

  it('returns manax_unavailable when Manax job ends in failed status', async () => {
    mockedAxios.post.mockResolvedValueOnce({ status: 202, data: { jobId: 'j-mock' } });
    mockedAxios.get
      .mockResolvedValueOnce({ status: 200, data: { status: 'failed' } })
      .mockResolvedValueOnce({ status: 200, data: { jobId: 'j-mock', status: 'failed', error: 'boom' } });
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
    expect(result.error).toBe('manax_unavailable');
  });
});

describe('VoiceGateService.verify', () => {
  let service: VoiceGateService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VoiceGateService,
        { provide: ConfigService, useValue: mockConfig },
      ],
    }).compile();
    service = module.get(VoiceGateService);
  });

  it('returns isOwner=true when cosine >= threshold', async () => {
    mockJobCompleted({
      jobId: 'j-mock', status: 'completed',
      result: { speakerEmbeddings: [{ speakerId: 's', vector: [1, 0, 0], coverageFraction: 1 }] },
    });
    const r = await service.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBe(true);
    expect(r.similarity).toBeCloseTo(1.0, 6);
  });

  it('returns isOwner=false when cosine < threshold', async () => {
    mockJobCompleted({
      jobId: 'j-mock', status: 'completed',
      result: { speakerEmbeddings: [{ speakerId: 's', vector: [0, 1, 0], coverageFraction: 1 }] },
    });
    const r = await service.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBe(false);
    expect(r.similarity).toBeCloseTo(0.0, 6);
  });

  it('returns isOwner=null (fail-open) when Manax returns no embedding', async () => {
    mockJobCompleted({ jobId: 'j-mock', status: 'completed', result: { speakerEmbeddings: [] } });
    const r = await service.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBeNull();
  });

  it('returns isOwner=null when ownerEmbedding is empty', async () => {
    const r = await service.verify(Buffer.alloc(32_000), []);
    expect(r.isOwner).toBeNull();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });
});

describe('VoiceGateService.enroll', () => {
  let service: VoiceGateService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [VoiceGateService, { provide: ConfigService, useValue: mockConfig }],
    }).compile();
    service = module.get(VoiceGateService);
  });

  it('returns ok=true with embedding from Manax on success', async () => {
    mockJobCompleted({
      jobId: 'j-mock', status: 'completed',
      result: { durationSec: 22.4, speakerEmbeddings: [{ speakerId: 'spk_abc', vector: [0.1, 0.2, 0.3], coverageFraction: 0.95 }] },
    });
    const r = await service.enroll(Buffer.alloc(1000));
    expect(r.ok).toBe(true);
    expect(r.speakerId).toBe('spk_abc');
    expect(r.embedding).toEqual([0.1, 0.2, 0.3]);
    expect(r.embeddingDim).toBe(3);
    expect(r.audioSec).toBeCloseTo(22.4);
  });

  it('returns no_speech_detected when Manax returns 0 embeddings', async () => {
    mockJobCompleted({ jobId: 'j-mock', status: 'completed', result: { speakerEmbeddings: [] } });
    const r = await service.enroll(Buffer.alloc(1000));
    expect(r.ok).toBe(false);
    expect(r.error).toBe('no_speech_detected');
  });

  it('returns manax_unavailable on HTTP failure', async () => {
    mockedAxios.post.mockRejectedValueOnce(new Error('boom'));
    const r = await service.enroll(Buffer.alloc(1000));
    expect(r.ok).toBe(false);
    expect(r.error).toBe('manax_unavailable');
  });
});

describe('VoiceGateService feature-disabled', () => {
  function disabledStub() {
    return {
      get: jest.fn((k: string, fallback?: any) =>
        k === 'OWNER_VOICE_ENABLED' ? 'false' : fallback,
      ),
    };
  }

  it('returns feature_disabled from enroll() when OWNER_VOICE_ENABLED=false', async () => {
    const svc = new VoiceGateService(disabledStub() as any);
    const r = await svc.enroll(Buffer.alloc(1000));
    expect(r.ok).toBe(false);
    expect(r.error).toBe('feature_disabled');
  });

  it('returns isOwner=null from verify() when feature is disabled', async () => {
    const svc = new VoiceGateService(disabledStub() as any);
    const r = await svc.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBeNull();
  });
});
