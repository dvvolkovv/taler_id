import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BlockchainService } from './blockchain.service';

// Mock @polkadot/api (not available in unit test env)
jest.mock('@polkadot/api', () => ({
  ApiPromise: { create: jest.fn() },
  WsProvider: jest.fn(),
  Keyring: jest.fn().mockImplementation(() => ({
    addFromMnemonic: jest.fn().mockReturnValue({ address: '5FakeAddress' }),
  })),
}));

jest.mock('@polkadot/api-contract', () => ({
  ContractPromise: jest.fn(),
}));

describe('BlockchainService', () => {
  let service: BlockchainService;
  let configService: jest.Mocked<ConfigService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BlockchainService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, def?: string) => {
              const map: Record<string, string> = {
                BLOCKCHAIN_ENABLED: 'false',
                TALER_NODE_WS: 'wss://node.dev.gsmsoft.eu/',
              };
              return map[key] ?? def;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<BlockchainService>(BlockchainService);
    configService = module.get(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('hashTalerId', () => {
    it('produces a 32-byte SHA-256 hash from UUID', () => {
      const uuid = '550e8400-e29b-41d4-a716-446655440000';
      const hash = service.hashTalerId(uuid);
      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32);
    });

    it('same UUID always produces the same hash', () => {
      const uuid = 'test-uuid-123';
      const h1 = service.hashTalerId(uuid);
      const h2 = service.hashTalerId(uuid);
      expect(Array.from(h1)).toEqual(Array.from(h2));
    });

    it('different UUIDs produce different hashes', () => {
      const h1 = service.hashTalerId('user-1');
      const h2 = service.hashTalerId('user-2');
      expect(Array.from(h1)).not.toEqual(Array.from(h2));
    });
  });

  describe('when blockchain is disabled', () => {
    it('attestVerification returns null when not connected', async () => {
      const result = await service.attestVerification('user-id', 2);
      expect(result).toBeNull();
    });

    it('attestKyb returns null when not connected', async () => {
      const result = await service.attestKyb('user-id', true);
      expect(result).toBeNull();
    });

    it('revokeVerification returns null when not connected', async () => {
      const result = await service.revokeVerification('user-id');
      expect(result).toBeNull();
    });

    it('getOnChainVerification returns null when not connected', async () => {
      const result = await service.getOnChainVerification('user-id');
      expect(result).toBeNull();
    });

    it('isConnected returns false before init', () => {
      expect(service.isConnected).toBe(false);
    });
  });

  describe('onModuleInit', () => {
    it('stays disconnected when BLOCKCHAIN_ENABLED=false', async () => {
      await service.onModuleInit();
      expect(service.isConnected).toBe(false);
    });
  });
});
