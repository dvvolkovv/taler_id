import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { WalletService } from './wallet.service';
import { PrismaService } from '../prisma/prisma.service';

jest.mock('@polkadot/api', () => ({
  ApiPromise: { create: jest.fn() },
  WsProvider: jest.fn(),
  Keyring: jest.fn().mockImplementation(() => ({
    addFromMnemonic: jest.fn().mockReturnValue({
      address: '5TestSS58Address',
      sign: jest.fn(),
    }),
  })),
}));
jest.mock('@polkadot/util-crypto', () => ({
  mnemonicGenerate: jest.fn().mockReturnValue('word '.repeat(12).trim()),
  cryptoWaitReady: jest.fn().mockResolvedValue(true),
}));

describe('WalletService', () => {
  let service: WalletService;
  let prisma: any;

  beforeEach(async () => {
    prisma = {
      userWallet: {
        findUnique: jest.fn(),
        create: jest.fn(),
      },
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        WalletService,
        { provide: PrismaService, useValue: prisma },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((k: string) =>
              k === 'WALLET_ENCRYPTION_KEY' ? 'unit-test-secret-key-32chars-xxxxxxxx' : undefined,
            ),
          },
        },
      ],
    }).compile();
    service = moduleRef.get(WalletService);
  });

  it('getOrCreate creates wallet with encrypted mnemonic when missing', async () => {
    prisma.userWallet.findUnique.mockResolvedValue(null);
    prisma.userWallet.create.mockImplementation(({ data }: any) =>
      Promise.resolve({ ...data, userId: 'u1', balancePlanck: 0n }),
    );

    const w = await service.getOrCreate('u1');
    expect(prisma.userWallet.create).toHaveBeenCalled();
    const createdArg = prisma.userWallet.create.mock.calls[0][0].data;
    expect(createdArg.userId).toBe('u1');
    expect(createdArg.custodialAddress).toBe('5TestSS58Address');
    expect(createdArg.custodialKeyEnc).not.toContain('word'); // encrypted, not plain
    expect(w.custodialAddress).toBe('5TestSS58Address');
  });

  it('getOrCreate returns existing wallet without re-creating', async () => {
    prisma.userWallet.findUnique.mockResolvedValue({
      userId: 'u1',
      custodialAddress: 'existing',
      custodialKeyEnc: 'x',
      balancePlanck: 42n,
    });

    const w = await service.getOrCreate('u1');
    expect(prisma.userWallet.create).not.toHaveBeenCalled();
    expect(w.custodialAddress).toBe('existing');
  });
});
