import { Test, TestingModule } from '@nestjs/testing';
import { HttpException, HttpStatus } from '@nestjs/common';
import { VoiceGateController } from './voice-gate.controller';
import { VoiceGateService } from './voice-gate.service';
import { PrismaService } from '../prisma/prisma.service';

describe('VoiceGateController.ownerStatus', () => {
  let controller: VoiceGateController;
  const mockPrisma = {
    profile: { findUnique: jest.fn(), update: jest.fn() },
  };
  const mockService = { isEnabled: jest.fn(() => true), enroll: jest.fn() };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [VoiceGateController],
      providers: [
        { provide: VoiceGateService, useValue: mockService },
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();
    controller = module.get(VoiceGateController);
  });

  it('returns enrolled=true with speakerId when ownerSpeakerId is set', async () => {
    mockPrisma.profile.findUnique.mockResolvedValueOnce({
      ownerSpeakerId: 'spk_abc',
      ownerEmbedding: [0.1, 0.2],
      updatedAt: new Date('2026-06-08T12:00:00Z'),
    });
    const r = await controller.ownerStatus({ user: { sub: 'u1' } } as any);
    expect(r).toEqual({
      enrolled: true,
      speakerId: 'spk_abc',
      enrolledAt: '2026-06-08T12:00:00.000Z',
    });
  });

  it('returns enrolled=false when ownerSpeakerId is null', async () => {
    mockPrisma.profile.findUnique.mockResolvedValueOnce({
      ownerSpeakerId: null,
      ownerEmbedding: [],
    });
    const r = await controller.ownerStatus({ user: { sub: 'u1' } } as any);
    expect(r).toEqual({ enrolled: false });
  });

  it('returns enrolled=false when profile is missing', async () => {
    mockPrisma.profile.findUnique.mockResolvedValueOnce(null);
    const r = await controller.ownerStatus({ user: { sub: 'u1' } } as any);
    expect(r).toEqual({ enrolled: false });
  });
});

describe('VoiceGateController.enroll', () => {
  let controller: VoiceGateController;
  const mockPrisma = {
    profile: { findUnique: jest.fn(), update: jest.fn() },
  };
  const mockService = { isEnabled: jest.fn(() => true), enroll: jest.fn() };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [VoiceGateController],
      providers: [
        { provide: VoiceGateService, useValue: mockService },
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();
    controller = module.get(VoiceGateController);
  });

  function fakeFile(_sizeBytes: number, durationSec: number): any {
    // 16kHz mono int16 = 32000 bytes/sec
    const buf = Buffer.alloc(Math.max(44, Math.round(durationSec * 32000)));
    return {
      buffer: buf,
      mimetype: 'audio/wav',
      size: buf.length,
      originalname: 'enroll.wav',
    };
  }

  it('returns 400 audio_too_short for < 15 sec', async () => {
    const file = fakeFile(0, 10);
    await expect(
      controller.enroll({ user: { sub: 'u1' } } as any, file),
    ).rejects.toMatchObject({
      response: { ok: false, error: 'audio_too_short', minSec: 15 },
      status: 400,
    });
  });

  it('saves embedding to Profile and returns 200 on success', async () => {
    const file = fakeFile(0, 22);
    mockService.enroll.mockResolvedValueOnce({
      ok: true,
      speakerId: 'spk_abc',
      embedding: [0.1, 0.2, 0.3],
      embeddingDim: 3,
      audioSec: 22.4,
    });
    const r = await controller.enroll({ user: { sub: 'u1' } } as any, file);
    expect(mockPrisma.profile.update).toHaveBeenCalledWith({
      where: { userId: 'u1' },
      data: { ownerSpeakerId: 'spk_abc', ownerEmbedding: [0.1, 0.2, 0.3] },
    });
    expect(r).toEqual({
      ok: true,
      speakerId: 'spk_abc',
      embeddingDim: 3,
      audioSec: 22.4,
    });
  });

  it('returns 422 no_speech_detected', async () => {
    const file = fakeFile(0, 22);
    mockService.enroll.mockResolvedValueOnce({ ok: false, error: 'no_speech_detected' });
    await expect(
      controller.enroll({ user: { sub: 'u1' } } as any, file),
    ).rejects.toMatchObject({ status: 422 });
  });

  it('returns 503 when feature_disabled', async () => {
    const file = fakeFile(0, 22);
    mockService.enroll.mockResolvedValueOnce({ ok: false, error: 'feature_disabled' });
    await expect(
      controller.enroll({ user: { sub: 'u1' } } as any, file),
    ).rejects.toMatchObject({ status: 503 });
  });
});
