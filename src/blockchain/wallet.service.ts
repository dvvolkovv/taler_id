import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Keyring } from '@polkadot/api';
import { mnemonicGenerate, cryptoWaitReady } from '@polkadot/util-crypto';
import { PrismaService } from '../prisma/prisma.service';
import { encrypt, decrypt } from './crypto/encryption';

const SS58_PREFIX = 10960;

@Injectable()
export class WalletService implements OnModuleInit {
  private readonly log = new Logger(WalletService.name);
  private keyring?: Keyring;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  async onModuleInit() {
    await this.ensureKeyring();
  }

  private getEncryptionKey(): string {
    const k = this.config.get<string>('WALLET_ENCRYPTION_KEY');
    if (!k || k.length < 32) {
      throw new Error('WALLET_ENCRYPTION_KEY must be set (>=32 chars)');
    }
    return k;
  }

  private async ensureKeyring(): Promise<Keyring> {
    if (!this.keyring) {
      await cryptoWaitReady();
      this.keyring = new Keyring({ type: 'sr25519', ss58Format: SS58_PREFIX });
    }
    return this.keyring;
  }

  async getOrCreate(userId: string): Promise<{
    userId: string;
    custodialAddress: string;
    balancePlanck: bigint;
  }> {
    const existing = await this.prisma.userWallet.findUnique({
      where: { userId },
    });
    if (existing) return existing;

    const keyring = await this.ensureKeyring();
    const mnemonic = mnemonicGenerate();
    const pair = keyring.addFromMnemonic(mnemonic);
    const enc = encrypt(mnemonic, this.getEncryptionKey());

    const w = await this.prisma.userWallet.create({
      data: {
        userId,
        custodialAddress: pair.address,
        custodialKeyEnc: enc,
        balancePlanck: 0n,
      },
    });

    this.log.log(`created custodial wallet ${pair.address} for user ${userId}`);
    return w;
  }

  /**
   * Decrypt a user's mnemonic for signing. Never return this over the wire.
   */
  async loadKeypairForSigning(userId: string) {
    const w = await this.prisma.userWallet.findUnique({ where: { userId } });
    if (!w) throw new Error(`no wallet for user ${userId}`);

    let mnemonic: string;
    try {
      mnemonic = decrypt(w.custodialKeyEnc, this.getEncryptionKey());
    } catch (e) {
      // Never log the original crypto error — it may leak timing / structural info.
      // GCM integrity failure here means either the key rotated or the ciphertext
      // was tampered with. Both are unrecoverable without the original key material.
      throw new Error(`failed to decrypt wallet key for user ${userId}`);
    }

    const keyring = await this.ensureKeyring();
    return keyring.addFromMnemonic(mnemonic);
  }
}
