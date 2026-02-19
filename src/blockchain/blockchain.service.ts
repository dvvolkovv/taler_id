import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiPromise, WsProvider, Keyring } from '@polkadot/api';
import { ContractPromise } from '@polkadot/api-contract';
import { KeyringPair } from '@polkadot/keyring/types';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class BlockchainService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(BlockchainService.name);
  private api: ApiPromise | null = null;
  private contract: ContractPromise | null = null;
  private attester: KeyringPair | null = null;
  private connected = false;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit() {
    const enabled = this.config.get<string>('BLOCKCHAIN_ENABLED', 'false');
    if (enabled !== 'true') {
      this.logger.warn('Blockchain integration disabled (BLOCKCHAIN_ENABLED != true)');
      return;
    }
    await this.connect();
  }

  async onModuleDestroy() {
    if (this.api) {
      await this.api.disconnect();
      this.logger.log('Disconnected from Taler blockchain');
    }
  }

  private async connect() {
    const wsUrl = this.config.get<string>('TALER_NODE_WS', 'wss://node.dev.gsmsoft.eu/');
    const seedPhrase = this.config.get<string>('BLOCKCHAIN_ATTESTER_SEED', '');
    const contractAddress = this.config.get<string>('KYC_CONTRACT_ADDRESS', '');
    const abiPath = this.config.get<string>(
      'KYC_CONTRACT_ABI_PATH',
      path.join(__dirname, '../../kyc-attestation/kyc_attestation.json'),
    );

    try {
      this.logger.log('Connecting to Taler blockchain: ' + wsUrl);
      const provider = new WsProvider(wsUrl);
      this.api = await ApiPromise.create({ provider });

      const chain = await this.api.rpc.system.chain();
      const nodeVersion = await this.api.rpc.system.version();
      this.logger.log('Connected to chain: ' + chain + ' v' + nodeVersion);

      if (!seedPhrase) {
        this.logger.warn('BLOCKCHAIN_ATTESTER_SEED not set — blockchain writes disabled');
        this.connected = true;
        return;
      }
      const keyring = new Keyring({ type: 'sr25519' });
      this.attester = keyring.addFromMnemonic(seedPhrase);
      this.logger.log('Attester account: ' + this.attester.address);

      if (contractAddress && fs.existsSync(abiPath)) {
        const abi = JSON.parse(fs.readFileSync(abiPath, 'utf8'));
        this.contract = new ContractPromise(this.api, abi, contractAddress);
        this.logger.log('KYC Attestation Contract loaded: ' + contractAddress);
      } else {
        this.logger.warn('KYC_CONTRACT_ADDRESS or ABI not set — on-chain writes disabled');
      }

      this.connected = true;
    } catch (err: any) {
      this.logger.error('Failed to connect to Taler blockchain: ' + (err?.message || String(err)));
    }
  }

  hashTalerId(internalUuid: string): Uint8Array {
    return createHash('sha256').update(internalUuid).digest();
  }

  private gasLimit(): any {
    return this.api!.registry.createType('WeightV2', {
      refTime: 3_000_000_000n,
      proofSize: 131_072n,
    });
  }

  async attestVerification(userId: string, kycStatus: 1 | 2 | 3): Promise<{ txHash: string } | null> {
    if (!this.connected || !this.api || !this.contract || !this.attester) {
      this.logger.warn('Blockchain not ready — skipping attestation for user ' + userId);
      return null;
    }

    const hash = Array.from(this.hashTalerId(userId));
    const timestamp = Math.floor(Date.now() / 1000);

    try {
      const dryRun = await this.contract.query['attestVerification'](
        this.attester.address,
        { gasLimit: this.gasLimit() },
        hash,
        kycStatus,
        timestamp,
      );

      if (!dryRun.result.isOk) {
        this.logger.error('attestVerification dry-run failed: ' + dryRun.result.asErr.toString());
        return null;
      }

      const tx = this.contract.tx['attestVerification'](
        { gasLimit: dryRun.gasRequired as any },
        hash,
        kycStatus,
        timestamp,
      );

      const txHash = await this.sendAndWait(tx);
      this.logger.log('KYC attestation on-chain: user=' + userId + ' status=' + kycStatus + ' tx=' + txHash);
      return { txHash };
    } catch (err: any) {
      this.logger.error('attestVerification error: ' + (err?.message || String(err)));
      return null;
    }
  }

  async attestKyb(tenantOwnerId: string, verified: boolean): Promise<{ txHash: string } | null> {
    if (!this.connected || !this.api || !this.contract || !this.attester) {
      this.logger.warn('Blockchain not ready — skipping KYB attestation');
      return null;
    }

    const hash = Array.from(this.hashTalerId(tenantOwnerId));
    try {
      const dryRun = await this.contract.query['attestKyb'](
        this.attester.address,
        { gasLimit: this.gasLimit() },
        hash,
        verified,
      );

      const tx = this.contract.tx['attestKyb'](
        { gasLimit: dryRun.gasRequired as any },
        hash,
        verified,
      );
      const txHash = await this.sendAndWait(tx);
      this.logger.log('KYB attestation on-chain: tenantOwner=' + tenantOwnerId + ' tx=' + txHash);
      return { txHash };
    } catch (err: any) {
      this.logger.error('attestKyb error: ' + (err?.message || String(err)));
      return null;
    }
  }

  async revokeVerification(userId: string): Promise<{ txHash: string } | null> {
    if (!this.connected || !this.api || !this.contract || !this.attester) {
      this.logger.warn('Blockchain not ready — skipping revocation for user ' + userId);
      return null;
    }

    const hash = Array.from(this.hashTalerId(userId));
    try {
      const dryRun = await this.contract.query['revokeVerification'](
        this.attester.address,
        { gasLimit: this.gasLimit() },
        hash,
      );

      const tx = this.contract.tx['revokeVerification'](
        { gasLimit: dryRun.gasRequired as any },
        hash,
      );
      const txHash = await this.sendAndWait(tx);
      this.logger.log('KYC revocation on-chain: user=' + userId + ' tx=' + txHash);
      return { txHash };
    } catch (err: any) {
      this.logger.error('revokeVerification error: ' + (err?.message || String(err)));
      return null;
    }
  }

  async getOnChainVerification(userId: string): Promise<{
    kycStatus: number;
    kycTimestamp: number;
    kybStatus: number;
    isActive: boolean;
  } | null> {
    if (!this.connected || !this.api || !this.contract) return null;

    const hash = Array.from(this.hashTalerId(userId));
    try {
      const { result, output } = await this.contract.query['getVerification'](
        '5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM',
        { gasLimit: this.gasLimit() },
        hash,
      );

      if (result.isOk && output) {
        const raw = output.toJSON() as any;
        if (!raw || !Array.isArray(raw)) return null;
        const [kycStatus, kycTimestamp, kybStatus, isActive] = raw;
        return { kycStatus, kycTimestamp, kybStatus, isActive };
      }
      return null;
    } catch (err: any) {
      this.logger.error('getVerification error: ' + (err?.message || String(err)));
      return null;
    }
  }

  private sendAndWait(tx: any): Promise<string> {
    return new Promise((resolve, reject) => {
      tx.signAndSend(this.attester!, (result: any) => {
        const { status, dispatchError, txHash } = result;
        if (status.isInBlock || status.isFinalized) {
          if (dispatchError) {
            reject(new Error('Dispatch error: ' + dispatchError.toString()));
          } else {
            resolve(txHash.toHex());
          }
        } else if (status.isDropped || status.isInvalid) {
          reject(new Error('Transaction ' + status.type));
        }
      }).catch(reject);
    });
  }

  get isConnected() {
    return this.connected;
  }
}
