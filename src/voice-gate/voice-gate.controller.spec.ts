import { Test, TestingModule } from '@nestjs/testing';
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
