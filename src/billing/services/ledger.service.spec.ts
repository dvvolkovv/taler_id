import { Test } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { LedgerService } from './ledger.service';
import { InsufficientFundsException } from '../exceptions/insufficient-funds.exception';

describe('LedgerService', () => {
  let service: LedgerService;
  let prisma: any;

  beforeEach(async () => {
    const walletUpdate = jest.fn();
    const walletFindUnique = jest.fn();
    const txCreate = jest.fn();
    const txFindUnique = jest.fn();
    const txUpdate = jest.fn();
    const gatewayMock = { emitToUser: jest.fn() };

    prisma = {
      $transaction: jest.fn(async (fn: any) =>
        fn({
          userWallet: { findUnique: walletFindUnique, update: walletUpdate },
          billingTransaction: {
            create: txCreate,
            findUnique: txFindUnique,
            update: txUpdate,
          },
          $executeRaw: jest.fn(),
        }),
      ),
      billingTransaction: { create: txCreate, findUnique: txFindUnique, update: txUpdate },
      userWallet: { findUnique: walletFindUnique, update: walletUpdate },
      _walletFindUnique: walletFindUnique,
      _walletUpdate: walletUpdate,
      _txCreate: txCreate,
      _txFindUnique: txFindUnique,
      _txUpdate: txUpdate,
      _gatewayEmit: gatewayMock.emitToUser,
    };

    const moduleRef = await Test.createTestingModule({
      providers: [
        LedgerService,
        { provide: PrismaService, useValue: prisma },
        { provide: 'MESSENGER_GATEWAY', useValue: gatewayMock },
      ],
    }).compile();

    service = moduleRef.get(LedgerService);
  });

  it('credit increases balance and records TOPUP_STUB transaction', async () => {
    prisma._walletFindUnique.mockResolvedValue({ userId: 'u1', balancePlanck: 100n });
    prisma._walletUpdate.mockResolvedValue({ userId: 'u1', balancePlanck: 600n });
    prisma._txCreate.mockResolvedValue({ id: 'tx1' });

    await service.credit('u1', 500n, 'TOPUP_STUB', { note: 'test' });

    expect(prisma._walletUpdate).toHaveBeenCalledWith({
      where: { userId: 'u1' },
      data: { balancePlanck: { increment: 500n } },
    });
    expect(prisma._txCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          userId: 'u1',
          type: 'TOPUP_STUB',
          amountPlanck: 500n,
          metadata: { note: 'test' },
        }),
      }),
    );
    // emitBalance fires after commit with the post-commit balance (fetched outside tx).
    expect(prisma._gatewayEmit).toHaveBeenCalledWith(
      'u1',
      'billing_balance_changed',
      expect.objectContaining({ reason: 'TOPUP_STUB', txId: 'tx1' }),
    );
  });

  it('debit throws InsufficientFundsException when balance below amount', async () => {
    prisma._walletFindUnique.mockResolvedValue({ userId: 'u1', balancePlanck: 10n });

    await expect(
      service.debit('u1', 500n, 'SPEND', { featureKey: 'voice_assistant' }),
    ).rejects.toThrow(InsufficientFundsException);

    expect(prisma._walletUpdate).not.toHaveBeenCalled();
    expect(prisma._txCreate).not.toHaveBeenCalled();
  });

  it('debit succeeds when balance sufficient and records SPEND', async () => {
    prisma._walletFindUnique.mockResolvedValue({ userId: 'u1', balancePlanck: 1000n });
    prisma._walletUpdate.mockResolvedValue({ userId: 'u1', balancePlanck: 500n });
    prisma._txCreate.mockResolvedValue({ id: 'tx2' });

    await service.debit('u1', 500n, 'SPEND', { featureKey: 'voice_assistant', sessionId: 's1' });

    expect(prisma._walletUpdate).toHaveBeenCalledWith({
      where: { userId: 'u1' },
      data: { balancePlanck: { decrement: 500n } },
    });
    expect(prisma._txCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          type: 'SPEND',
          amountPlanck: 500n,
          featureKey: 'voice_assistant',
          sessionId: 's1',
        }),
      }),
    );
    expect(prisma._gatewayEmit).toHaveBeenCalledWith(
      'u1',
      'billing_balance_changed',
      expect.objectContaining({ reason: 'SPEND', txId: 'tx2' }),
    );
  });

  it('refund credits the inverse and marks original REVERSED', async () => {
    // First call (inside $transaction): returns the original SPEND tx being refunded.
    // Second call (outside tx, in emitBalance): returns the newly-created REFUND row so
    // emitBalance knows whose userId to notify.
    prisma._txFindUnique
      .mockResolvedValueOnce({
        id: 'txOrig',
        userId: 'u1',
        type: 'SPEND',
        amountPlanck: 500n,
        status: 'COMPLETED',
      })
      .mockResolvedValueOnce({
        id: 'txRefund',
        userId: 'u1',
        type: 'REFUND',
      });
    prisma._walletFindUnique.mockResolvedValue({ userId: 'u1', balancePlanck: 500n });
    prisma._walletUpdate.mockResolvedValue({ userId: 'u1', balancePlanck: 500n });
    prisma._txCreate.mockResolvedValue({ id: 'txRefund' });

    await service.refund('txOrig', 'openai 5xx');

    expect(prisma._txUpdate).toHaveBeenCalledWith({
      where: { id: 'txOrig' },
      data: { status: 'REVERSED' },
    });
    expect(prisma._txCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          type: 'REFUND',
          amountPlanck: 500n,
          metadata: expect.objectContaining({ originalTxId: 'txOrig', reason: 'openai 5xx' }),
        }),
      }),
    );
    expect(prisma._gatewayEmit).toHaveBeenCalledWith(
      'u1',
      'billing_balance_changed',
      expect.objectContaining({ reason: 'REFUND', txId: 'txRefund' }),
    );
  });

  it('credit throws on zero or negative amount', async () => {
    await expect(service.credit('u1', 0n, 'TOPUP_STUB')).rejects.toThrow(
      /credit amount must be > 0/,
    );
    await expect(service.credit('u1', -5n, 'TOPUP_STUB')).rejects.toThrow(
      /credit amount must be > 0/,
    );
    expect(prisma._walletUpdate).not.toHaveBeenCalled();
  });

  it('debit throws on zero or negative amount', async () => {
    await expect(service.debit('u1', 0n, 'SPEND')).rejects.toThrow(
      /debit amount must be > 0/,
    );
    await expect(service.debit('u1', -5n, 'SPEND')).rejects.toThrow(
      /debit amount must be > 0/,
    );
    expect(prisma._walletUpdate).not.toHaveBeenCalled();
  });

  it('debit throws NotFoundException when wallet is missing', async () => {
    prisma._walletFindUnique.mockResolvedValue(null);

    await expect(service.debit('u1', 100n, 'SPEND')).rejects.toThrow(NotFoundException);
    expect(prisma._walletUpdate).not.toHaveBeenCalled();
    expect(prisma._txCreate).not.toHaveBeenCalled();
  });

  it('credit throws NotFoundException when wallet is missing', async () => {
    prisma._walletFindUnique.mockResolvedValue(null);

    await expect(service.credit('u1', 100n, 'TOPUP_STUB')).rejects.toThrow(NotFoundException);
    expect(prisma._walletUpdate).not.toHaveBeenCalled();
    expect(prisma._txCreate).not.toHaveBeenCalled();
  });

  it('refund throws NotFoundException when original tx missing', async () => {
    prisma._txFindUnique.mockResolvedValue(null);

    await expect(service.refund('nonexistent', 'reason')).rejects.toThrow(NotFoundException);
    expect(prisma._walletUpdate).not.toHaveBeenCalled();
    expect(prisma._txCreate).not.toHaveBeenCalled();
  });

  it('refund throws when original tx is already REVERSED', async () => {
    prisma._txFindUnique.mockResolvedValue({
      id: 'txOrig',
      userId: 'u1',
      type: 'SPEND',
      amountPlanck: 500n,
      status: 'REVERSED',
    });

    await expect(service.refund('txOrig', 'reason')).rejects.toThrow(/already reversed/);
    expect(prisma._walletUpdate).not.toHaveBeenCalled();
    expect(prisma._txCreate).not.toHaveBeenCalled();
  });
});
