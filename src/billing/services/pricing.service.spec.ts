import { Test } from '@nestjs/testing';
import { PricingService } from './pricing.service';
import { PrismaService } from '../../prisma/prisma.service';

describe('PricingService', () => {
  let service: PricingService;
  let prisma: {
    aiPricebook: { findUnique: jest.Mock };
    billingConfig: { findUnique: jest.Mock };
  };

  beforeEach(async () => {
    prisma = {
      aiPricebook: { findUnique: jest.fn() },
      billingConfig: { findUnique: jest.fn() },
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        PricingService,
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();

    service = moduleRef.get(PricingService);
  });

  it('calculates planck cost for voice_assistant 1 minute at 2x markup and $11,700 rate', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue({
      featureKey: 'voice_assistant',
      unit: 'minute',
      costUsdPerUnit: '0.15',
      markupMultiplier: '2.0',
      minReservePlanck: 26000000n,
    });
    prisma.billingConfig.findUnique.mockResolvedValue({
      id: 'singleton',
      talUsdRate: '11700',
    });

    const planck = await service.calculatePlanckCost('voice_assistant', 1);
    // $0.30 / $11,700 * 1e12 = 25_641_025.64…  rounded up
    expect(planck).toBe(25641026n);
  });

  it('rounds up in favor of the service', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue({
      featureKey: 'web_search',
      unit: 'request',
      costUsdPerUnit: '0.005',
      markupMultiplier: '2.0',
      minReservePlanck: 1000000n,
    });
    prisma.billingConfig.findUnique.mockResolvedValue({
      id: 'singleton',
      talUsdRate: '11700',
    });

    // 1 request: $0.01 / $11,700 * 1e12 = 854_700.85… → 854_701
    const planck = await service.calculatePlanckCost('web_search', 1);
    expect(planck).toBe(854701n);
  });

  it('throws on unknown featureKey', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue(null);
    prisma.billingConfig.findUnique.mockResolvedValue({ talUsdRate: '11700' });

    await expect(service.calculatePlanckCost('nope', 1)).rejects.toThrow(/unknown feature/i);
  });

  it('caches pricebook rows for 60 seconds', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue({
      featureKey: 'voice_assistant',
      unit: 'minute',
      costUsdPerUnit: '0.15',
      markupMultiplier: '2.0',
      minReservePlanck: 26000000n,
    });
    prisma.billingConfig.findUnique.mockResolvedValue({ talUsdRate: '11700' });

    await service.calculatePlanckCost('voice_assistant', 1);
    await service.calculatePlanckCost('voice_assistant', 2);
    expect(prisma.aiPricebook.findUnique).toHaveBeenCalledTimes(1);
  });

  it('exposes getMinReserve', async () => {
    prisma.aiPricebook.findUnique.mockResolvedValue({
      featureKey: 'voice_assistant',
      minReservePlanck: 26000000n,
    } as any);
    prisma.billingConfig.findUnique.mockResolvedValue({ talUsdRate: '11700' });

    expect(await service.getMinReservePlanck('voice_assistant')).toBe(26000000n);
  });
});
