import { Test } from '@nestjs/testing';
import { GatingService } from './gating.service';
import { PricingService } from './pricing.service';
import { LedgerService } from './ledger.service';
import { PrismaService } from '../../prisma/prisma.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';
import { FeatureDisabledException } from '../exceptions/feature-disabled.exception';
import { WalletService } from '../../blockchain/wallet.service';

describe('GatingService', () => {
  let service: GatingService;
  let pricing: any;
  let ledger: any;
  let prisma: any;
  let gateway: { emitToUser: jest.Mock };
  let wallet: { getOrCreate: jest.Mock };

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
    gateway = { emitToUser: jest.fn() };
    wallet = { getOrCreate: jest.fn() };

    const moduleRef = await Test.createTestingModule({
      providers: [
        GatingService,
        { provide: PricingService, useValue: pricing },
        { provide: LedgerService, useValue: ledger },
        { provide: PrismaService, useValue: prisma },
        { provide: 'MESSENGER_GATEWAY', useValue: gateway },
        { provide: WalletService, useValue: wallet },
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

    const session = await service.startSession(
      'u1',
      'voice_assistant',
      'room42',
    );

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
    expect(gateway.emitToUser).toHaveBeenCalledWith(
      'u1',
      'ai_session_started',
      {
        sessionId: 's1',
        featureKey: 'voice_assistant',
      },
    );
  });

  it('treats missing toggle row as enabled (default-on)', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue(null);
    pricing.getMinReservePlanck.mockResolvedValue(1n);
    ledger.getBalance.mockResolvedValue(1_000_000n);
    prisma.aiSession.create.mockResolvedValue({ id: 's2' });

    const s = await service.startSession('u1', 'web_search');
    expect(s.id).toBe('s2');
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

  it('allows session when balance exactly equals minReserve (boundary)', async () => {
    pricing.getConfig.mockResolvedValue(baseConfig);
    prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: true });
    pricing.getMinReservePlanck.mockResolvedValue(26_000_000n);
    ledger.getBalance.mockResolvedValue(26_000_000n); // exactly equal
    prisma.aiSession.create.mockResolvedValue({ id: 'sBoundary' });

    const s = await service.startSession('u1', 'voice_assistant');
    expect(s.id).toBe('sBoundary');
  });

  it('startSession runs assertCanStart before opening the session', async () => {
    const check = jest
      .spyOn(service, 'assertCanStart')
      .mockResolvedValue(undefined);
    prisma.aiSession.create.mockResolvedValue({ id: 's4' });

    await service.startSession('u1', 'interpreter', 'ctx-1');

    expect(check).toHaveBeenCalledWith('u1', 'interpreter');
    expect(check.mock.invocationCallOrder[0]).toBeLessThan(
      prisma.aiSession.create.mock.invocationCallOrder[0],
    );
  });

  describe('assertCanStart', () => {
    it('passes without opening a session, so nothing is metered yet', async () => {
      pricing.getConfig.mockResolvedValue(baseConfig);
      prisma.userFeatureToggle.findUnique.mockResolvedValue(null);
      pricing.getMinReservePlanck.mockResolvedValue(24_000_000n);
      ledger.getBalance.mockResolvedValue(24_000_000n);

      await expect(
        service.assertCanStart('u1', 'interpreter'),
      ).resolves.toBeUndefined();

      expect(pricing.getMinReservePlanck).toHaveBeenCalledWith('interpreter');
      expect(prisma.aiSession.create).not.toHaveBeenCalled();
      expect(gateway.emitToUser).not.toHaveBeenCalled();
    });

    it('creates the wallet before reading the balance', async () => {
      pricing.getConfig.mockResolvedValue(baseConfig);
      prisma.userFeatureToggle.findUnique.mockResolvedValue(null);
      pricing.getMinReservePlanck.mockResolvedValue(1n);
      ledger.getBalance.mockResolvedValue(1n);

      await service.assertCanStart('u1', 'interpreter');

      expect(wallet.getOrCreate).toHaveBeenCalledWith('u1');
      expect(wallet.getOrCreate.mock.invocationCallOrder[0]).toBeLessThan(
        ledger.getBalance.mock.invocationCallOrder[0],
      );
    });

    it('throws FeatureDisabledException when the toggle is off', async () => {
      pricing.getConfig.mockResolvedValue(baseConfig);
      prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: false });

      await expect(service.assertCanStart('u1', 'interpreter')).rejects.toThrow(
        FeatureDisabledException,
      );
    });

    it('throws InsufficientFundsException below the reserve', async () => {
      pricing.getConfig.mockResolvedValue(baseConfig);
      prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: true });
      pricing.getMinReservePlanck.mockResolvedValue(24_000_000n);
      ledger.getBalance.mockResolvedValue(23_999_999n);

      await expect(service.assertCanStart('u1', 'interpreter')).rejects.toThrow(
        InsufficientFundsException,
      );
    });

    it('only logs when billing is not enforced', async () => {
      pricing.getConfig.mockResolvedValue({ billingEnforced: false });
      prisma.userFeatureToggle.findUnique.mockResolvedValue({ enabled: false });
      pricing.getMinReservePlanck.mockResolvedValue(24_000_000n);
      ledger.getBalance.mockResolvedValue(0n);

      await expect(
        service.assertCanStart('u1', 'interpreter'),
      ).resolves.toBeUndefined();
      expect(prisma.aiSession.create).not.toHaveBeenCalled();
    });
  });

  it('endSession marks completed and does NOT emit ai_session_terminated', async () => {
    prisma.aiSession.update.mockResolvedValue({
      id: 's1',
      userId: 'u1',
      featureKey: 'voice_assistant',
      status: 'completed',
    });

    await service.endSession('s1', 'completed');

    expect(prisma.aiSession.update).toHaveBeenCalledWith({
      where: { id: 's1' },
      data: { status: 'completed', endedAt: expect.any(Date) },
    });
    // Normal completion is a client-driven flow — no push event needed.
    expect(gateway.emitToUser).not.toHaveBeenCalledWith(
      'u1',
      'ai_session_terminated',
      expect.anything(),
    );
  });

  it('endSession emits ai_session_terminated with reason=no_funds when terminated', async () => {
    prisma.aiSession.update.mockResolvedValue({
      id: 's1',
      userId: 'u1',
      featureKey: 'voice_assistant',
    });

    await service.endSession('s1', 'terminated_no_funds');

    expect(gateway.emitToUser).toHaveBeenCalledWith(
      'u1',
      'ai_session_terminated',
      {
        sessionId: 's1',
        reason: 'no_funds',
        featureKey: 'voice_assistant',
      },
    );
  });

  it('endSession emits ai_session_terminated with reason=failed on failed', async () => {
    prisma.aiSession.update.mockResolvedValue({
      id: 's9',
      userId: 'u9',
      featureKey: 'ai_twin',
    });

    await service.endSession('s9', 'failed');

    expect(gateway.emitToUser).toHaveBeenCalledWith(
      'u9',
      'ai_session_terminated',
      {
        sessionId: 's9',
        reason: 'failed',
        featureKey: 'ai_twin',
      },
    );
  });
});
