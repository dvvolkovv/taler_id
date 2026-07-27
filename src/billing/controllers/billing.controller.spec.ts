import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { BillingController } from './billing.controller';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerService } from '../services/ledger.service';
import { PricingService } from '../services/pricing.service';
import { WalletService } from '../../blockchain/wallet.service';
import { PACKAGES } from '../constants/packages';

const mockPrisma = {
  billingTransaction: { findMany: jest.fn() },
};

const mockLedger = {
  credit: jest.fn(),
  getBalance: jest.fn(),
};

const mockPricing = {};

const mockWallet = {
  getOrCreate: jest.fn(),
};

const USER = { sub: 'user-1' };

describe('BillingController.purchase (stub top-up gate)', () => {
  let controller: BillingController;
  const originalFlag = process.env.BILLING_STUB_PURCHASE_ENABLED;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockWallet.getOrCreate.mockResolvedValue(undefined);
    mockLedger.credit.mockResolvedValue({ id: 'tx-1' });
    mockLedger.getBalance.mockResolvedValue(1_000n);

    const module: TestingModule = await Test.createTestingModule({
      controllers: [BillingController],
      providers: [
        { provide: PrismaService, useValue: mockPrisma },
        { provide: LedgerService, useValue: mockLedger },
        { provide: PricingService, useValue: mockPricing },
        { provide: WalletService, useValue: mockWallet },
      ],
    }).compile();

    controller = module.get<BillingController>(BillingController);
  });

  afterAll(() => {
    process.env.BILLING_STUB_PURCHASE_ENABLED = originalFlag;
  });

  it('refuses to credit balance when the flag is unset (production default)', async () => {
    delete process.env.BILLING_STUB_PURCHASE_ENABLED;

    await expect(controller.purchase(USER, PACKAGES[0].id)).rejects.toThrow(
      ForbiddenException,
    );
    expect(mockLedger.credit).not.toHaveBeenCalled();
  });

  it('refuses for any value other than the literal "true"', async () => {
    process.env.BILLING_STUB_PURCHASE_ENABLED = '1';

    await expect(controller.purchase(USER, PACKAGES[0].id)).rejects.toThrow(
      ForbiddenException,
    );
    expect(mockLedger.credit).not.toHaveBeenCalled();
  });

  it('credits the package amount when explicitly enabled', async () => {
    process.env.BILLING_STUB_PURCHASE_ENABLED = 'true';
    const pkg = PACKAGES[0];

    const result = await controller.purchase(USER, pkg.id);

    expect(mockLedger.credit).toHaveBeenCalledWith(
      'user-1',
      pkg.amountPlanck,
      'TOPUP_STUB',
      expect.objectContaining({ packageId: pkg.id }),
    );
    expect(result.txId).toBe('tx-1');
  });

  it('rejects an unknown package before crediting anything', async () => {
    process.env.BILLING_STUB_PURCHASE_ENABLED = 'true';

    await expect(controller.purchase(USER, 'no-such-package')).rejects.toThrow();
    expect(mockLedger.credit).not.toHaveBeenCalled();
  });
});
