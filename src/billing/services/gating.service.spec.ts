import { Test } from '@nestjs/testing';
import { GatingService } from './gating.service';
import { PricingService } from './pricing.service';
import { LedgerService } from './ledger.service';
import { PrismaService } from '../../prisma/prisma.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';
import { FeatureDisabledException } from '../exceptions/feature-disabled.exception';

describe('GatingService', () => {
  let service: GatingService;
  let pricing: any;
  let ledger: any;
  let prisma: any;

  beforeEach(async () => {
    pricing = {
      getMinReservePlanck: jest.fn(),
      getConfig: jest.fn(),
    };
    ledger = { getBalance: jest.fn() };
    prisma = {
      userFeatureToggle: { findUnique: jest.fn() },
      aiSession: { create: jest.fn(), update: jest.fn() },
      billingConfig: { findUnique: jest.fn() },
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        GatingService,
        { provide: PricingService, useValue: pricing },
        { provide: LedgerService, useValue: ledger },
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();

    service = moduleRef.get(GatingService);
  });

  const baseConfig = { billingEnforced: true };

  it('throws FeatureDisabledException when toggle is off', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: false });

    await expect(service.startSession('u1', 'voice_assistant')).rejects.toThrow(
      FeatureDisabledException,
    );
  });

  it('throws InsufficientFundsException when balance below minReserve', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: true });
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);
    ledger.getBalance.mockResolvedValue(1_000n);

    await expect(service.startSession('u1', 'voice_assistant')).rejects.toThrow(
      InsufficientFundsException,
    );
  });

  it('creates an active AiSession on success', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: true });
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);
    ledger.getBalance.mockResolvedValue(100_000_000n);
    prisma.aiSession.create.mockResolvedValue({ id: 's1', status: 'active' });

    const session = await service.startSession('u1', 'voice_assistant', 'room42');

    expect(prisma.aiSession.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        userId: 'u1',
        featureKey: 'voice_assistant',
        contextRef: 'room42',
        status: 'active',
      }),
      select: { id: true },
    });
    expect(session.id).toBe('s1');
  });

  it('treats missing toggle row as enabled (default-on)', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue(null);
    pricing.getMinReservePlanck.mockResolvedValue(1n);
    ledger.getBalance.mockResolvedValue(1_000_000n);
    prisma.aiSession.create.mockResolvedValue({ id: 's2' });

    await expect(service.startSession('u1', 'web_search')).resolves.toBeDefined();
  });

  it('skips both gates when billingEnforced=false but still creates session', async () => {
    pricing.getConfig.mockResolvedValue({ billingEnforced: false });
    prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: false });
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);
    ledger.getBalance.mockResolvedValue(0n);
    prisma.aiSession.create.mockResolvedValue({ id: 's3' });

    const s = await service.startSession('u1', 'voice_assistant');
    expect(s.id).toBe('s3');
  });

  it('endSession marks completed', async () => {
    prisma.aiSession.update.mockResolvedValue({ id: 's1', status: 'completed' });

    await service.endSession('s1', 'completed');

    expect(prisma.aiSession.update).toHaveBeenCalledWith({
      where: { id: 's1' },
      data: { status: 'completed', endedAt: expect.any(Date) },
    });
  });
});
