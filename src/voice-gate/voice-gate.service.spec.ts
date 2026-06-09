import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { VoiceGateService } from './voice-gate.service';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

const mockConfig = {
  get: jest.fn((key: string, fallback?: any) => {
    const env: Record<string, any> = {
      VOICE_EMBED_URL: 'http://127.0.0.1:18082',
      OWNER_VOICE_THRESHOLD: '0.5',
      OWNER_VOICE_WINDOW_MS: '1000',
      OWNER_VOICE_ENABLED: 'true',
    };
    return env[key] ?? fallback;
  }),
};

function mockEmbedOk(vector: number[], audioSec = 1.0) {
  mockedAxios.post.mockResolvedValueOnce({
    status: 200,
    data: { vector, dim: vector.length, audioSec, inferenceMs: 50 },
  });
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

  it('returns the embedding from a successful sidecar response', async () => {
    mockEmbedOk([0.1, 0.2, 0.3], 1.5);
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toEqual([0.1, 0.2, 0.3]);
    expect(result.audioSec).toBeCloseTo(1.5);
  });

  it('returns null embedding when sidecar returns empty vector', async () => {
    mockedAxios.post.mockResolvedValueOnce({ status: 200, data: { vector: [], dim: 0, audioSec: 0 } });
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
    expect(result.error).toBe('no_speech_detected');
  });

  it('returns embed_unavailable on HTTP failure', async () => {
    mockedAxios.post.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
    expect(result.error).toBe('embed_unavailable');
  });

  it('treats HTTP 422 (audio_too_short) as no_speech_detected', async () => {
    mockedAxios.post.mockRejectedValueOnce({
      isAxiosError: true,
      response: { status: 422, data: { detail: 'audio_too_short' } },
      message: 'Request failed with status code 422',
    });
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
    expect(result.error).toBe('no_speech_detected');
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
    mockEmbedOk([1, 0, 0]);
    const r = await service.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBe(true);
    expect(r.similarity).toBeCloseTo(1.0, 6);
  });

  it('returns isOwner=false when cosine < threshold', async () => {
    mockEmbedOk([0, 1, 0]);
    const r = await service.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBe(false);
    expect(r.similarity).toBeCloseTo(0.0, 6);
  });

  it('returns isOwner=null (fail-open) when sidecar returns no embedding', async () => {
    mockedAxios.post.mockResolvedValueOnce({ status: 200, data: { vector: [], dim: 0, audioSec: 0 } });
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

  it('returns ok=true with embedding and a freshly-generated speakerId', async () => {
    mockEmbedOk([0.1, 0.2, 0.3], 22.4);
    const r = await service.enroll(Buffer.alloc(1000));
    expect(r.ok).toBe(true);
    expect(r.speakerId).toMatch(/^spk_[0-9a-f]{20}$/);
    expect(r.embedding).toEqual([0.1, 0.2, 0.3]);
    expect(r.embeddingDim).toBe(3);
    expect(r.audioSec).toBeCloseTo(22.4);
  });

  it('returns no_speech_detected when sidecar returns 0 embeddings', async () => {
    mockedAxios.post.mockResolvedValueOnce({ status: 200, data: { vector: [], dim: 0, audioSec: 0 } });
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
