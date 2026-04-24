import { Test } from '@nestjs/testing';
import { MeteringService } from './metering.service';
import { PricingService } from './pricing.service';
import { LedgerService } from './ledger.service';
import { GatingService } from './gating.service';
import { PrismaService } from '../../prisma/prisma.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';

describe('MeteringService', () => {
  let service: MeteringService;
  let prisma: any;
  let pricing: any;
  let ledger: any;
  let gating: any;
  let gateway: any;

  beforeEach(async () => {
    prisma = {
      aiSession: { findMany: jest.fn(), update: jest.fn(), findUnique: jest.fn() },
      usageLog: { create: jest.fn() },
    };
    pricing = { calculatePlanckCost: jest.fn(), getMinReservePlanck: jest.fn(), getConfig: jest.fn() };
    ledger = { debit: jest.fn(), getBalance: jest.fn() };
    gating = { endSession: jest.fn() };
    gateway = { emitToUser: jest.fn() };

    const moduleRef = await Test.createTestingModule({
      providers: [
        MeteringService,
        { provide: PrismaService, useValue: prisma },
        { provide: PricingService, useValue: pricing },
        { provide: LedgerService, useValue: ledger },
        { provide: GatingService, useValue: gating },
        { provide: 'MESSENGER_GATEWAY', useValue: gateway },
      ],
    }).compile();

    service = moduleRef.get(MeteringService);
  });

  it('debits elapsed time for each active voice_assistant session', async () => {
    const now = new Date('2026-04-24T10:00:30Z');
    const startedAt = new Date('2026-04-24T10:00:00Z');

    jest.useFakeTimers().setSystemTime(now);
    prisma.aiSession.findMany.mockResolvedValue([
      {
        id: 's1',
        userId: 'u1',
        featureKey: 'voice_assistant',
        status: 'active',
        lastMeteredAt: startedAt,
        totalSpentPlanck: 0n,
      },
    ]);
    pricing.calculatePlanckCost.mockResolvedValue(12_820_000n); // ~30 sec at rate
    pricing.getConfig.mockResolvedValue({ billingEnforced: true });
    ledger.debit.mockResolvedValue({ id: 'tx1' });
    ledger.getBalance.mockResolvedValue(999_999_999n);
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);

    await service.tick();

    expect(pricing.calculatePlanckCost).toHaveBeenCalledWith('voice_assistant', 0.5); // 30s = 0.5 min
    expect(ledger.debit).toHaveBeenCalledWith(
      'u1',
      12_820_000n,
      'SPEND',
      expect.objectContaining({ featureKey: 'voice_assistant', sessionId: 's1' }),
    );
    expect(prisma.aiSession.update).toHaveBeenCalledWith({
      where: { id: 's1' },
      data: expect.objectContaining({ totalSpentPlanck: { increment: 12_820_000n }, lastMeteredAt: now }),
    });

    jest.useRealTimers();
  });

  it('terminates session and emits ai_session_terminated on InsufficientFunds', async () => {
    prisma.aiSession.findMany.mockResolvedValue([
      {
        id: 's1',
        userId: 'u1',
        featureKey: 'voice_assistant',
        lastMeteredAt: new Date(Date.now() - 10_000),
        totalSpentPlanck: 0n,
        contextRef: 'room42',
      },
    ]);
    pricing.calculatePlanckCost.mockResolvedValue(5_000_000n);
    pricing.getConfig.mockResolvedValue({ billingEnforced: true });
    ledger.debit.mockRejectedValue(
      new InsufficientFundsException('voice_assistant', 5_000_000n, 100n),
    );

    await service.tick();

    expect(gating.endSession).toHaveBeenCalledWith('s1', 'terminated_no_funds');
    expect(gateway.emitToUser).toHaveBeenCalledWith('u1', 'ai_session_terminated', {
      sessionId: 's1',
      reason: 'no_funds',
      featureKey: 'voice_assistant',
      contextRef: 'room42',
    });
  });

  it('emits low_balance_warning when balance < 3× minReserve', async () => {
    prisma.aiSession.findMany.mockResolvedValue([
      {
        id: 's1',
        userId: 'u1',
        featureKey: 'voice_assistant',
        lastMeteredAt: new Date(Date.now() - 10_000),
        totalSpentPlanck: 0n,
      },
    ]);
    pricing.calculatePlanckCost.mockResolvedValue(1_000_000n);
    pricing.getConfig.mockResolvedValue({ billingEnforced: true });
    ledger.debit.mockResolvedValue({ id: 'tx1' });
    ledger.getBalance.mockResolvedValue(50_000_000n); // between 1× and 3× of 26M
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);

    await service.tick();

    expect(gateway.emitToUser).toHaveBeenCalledWith(
      'u1',
      'billing_low_balance_warning',
      expect.objectContaining({ sessionId: 's1' }),
    );
  });

  it('in dry-run, debit errors are swallowed and session continues', async () => {
    prisma.aiSession.findMany.mockResolvedValue([
      {
        id: 's1',
        userId: 'u1',
        featureKey: 'voice_assistant',
        lastMeteredAt: new Date(Date.now() - 10_000),
        totalSpentPlanck: 0n,
      },
    ]);
    pricing.calculatePlanckCost.mockResolvedValue(1_000_000n);
    pricing.getConfig.mockResolvedValue({ billingEnforced: false });
    ledger.debit.mockRejectedValue(new InsufficientFundsException('voice_assistant', 1n, 0n));

    await service.tick();

    expect(gating.endSession).not.toHaveBeenCalled();
    expect(gateway.emitToUser).not.toHaveBeenCalledWith(
      'u1',
      'ai_session_terminated',
      expect.anything(),
    );
  });

  it('reportUsage writes a final adjustment when agent reports more than cron debited', async () => {
    prisma.aiSession.findMany.mockResolvedValue([]);
    pricing.calculatePlanckCost.mockResolvedValue(20_000_000n);
    pricing.getConfig.mockResolvedValue({ billingEnforced: true });
    ledger.debit.mockResolvedValue({ id: 'txAdj' });
    ledger.getBalance.mockResolvedValue(100_000_000n);

    // session already debited 15M; agent says total should be 20M
    prisma.aiSession.update.mockResolvedValue({});
    prisma.aiSession.findUnique.mockResolvedValue({
      id: 's1',
      userId: 'u1',
      featureKey: 'voice_assistant',
      totalSpentPlanck: 15_000_000n,
      status: 'active',
    });

    await service.reportUsage('s1', 1.0, 'ai-twin-agent');

    expect(ledger.debit).toHaveBeenCalledWith(
      'u1',
      5_000_000n,
      'SPEND',
      expect.objectContaining({ sessionId: 's1' }),
    );
  });
});
