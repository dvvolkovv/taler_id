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
    mockedAxios.post.mockResolvedValueOnce({
      status: 200,
      data: {
        jobId: 'j1',
        status: 'completed',
        result: {
          durationSec: 1.0,
          speakerEmbeddings: [
            { speakerId: 'spk_a', vector: [0.1, 0.2], coverageFraction: 0.4 },
            { speakerId: 'spk_b', vector: [0.7, 0.8], coverageFraction: 0.9 },
          ],
        },
      },
    });
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toEqual([0.7, 0.8]);
    expect(result.speakerId).toBe('spk_b');
  });

  it('returns null embedding when Manax returns no embeddings', async () => {
    mockedAxios.post.mockResolvedValueOnce({
      status: 200,
      data: { jobId: 'j1', status: 'completed', result: { speakerEmbeddings: [] } },
    });
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
  });

  it('returns null embedding when Manax HTTP fails (fail-open)', async () => {
    mockedAxios.post.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
    expect(result.error).toBe('manax_unavailable');
  });
});
