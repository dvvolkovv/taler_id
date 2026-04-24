import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ApiPromise, WsProvider } from '@polkadot/api';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { LedgerService } from '../billing/services/ledger.service';

@Injectable()
export class DepositWatcher implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger(DepositWatcher.name);
  private api?: ApiPromise;
  private unsubscribe?: () => void;

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly ledger: LedgerService,
  ) {}

  async onModuleInit(): Promise<void> {
    if (this.config.get<string>('BLOCKCHAIN_ENABLED') !== 'true') {
      this.log.warn('BLOCKCHAIN_ENABLED != true, skipping deposit watcher');
      return;
    }
    const url = this.config.get<string>('BLOCKCHAIN_NODE_URL', 'wss://node.dev.gsmsoft.eu/');
    const provider = new WsProvider(url);
    this.api = await ApiPromise.create({ provider });
    this.log.log(`deposit watcher connected to ${url}`);

    this.unsubscribe = (await this.api.query.system.events(async (events: any) => {
      for (const record of events) {
        const { event } = record;
        if (event.section !== 'balances' || event.method !== 'Transfer') continue;
        const [from, to, amount] = event.data.toJSON() as [string, string, string | number];
        try {
          await this.handleTransfer(String(to), String(from), BigInt(amount));
        } catch (err) {
          this.log.error(`failed to handle transfer: ${String(err)}`);
        }
      }
    })) as unknown as () => void;
  }

  async onModuleDestroy(): Promise<void> {
    try { this.unsubscribe?.(); } catch {}
    try { await this.api?.disconnect(); } catch {}
  }

  private async handleTransfer(toAddress: string, fromAddress: string, amount: bigint): Promise<void> {
    const wallet = await this.prisma.userWallet.findUnique({ where: { custodialAddress: toAddress } });
    if (!wallet) return; // transfer to unrelated address

    // Idempotency: events() subscription fires once per event per subscription lifetime,
    // but restart + replay could duplicate. For MVP we accept this risk and log raw data
    // for debugging; a future tx-hash dedupe column can be added when needed.
    await this.ledger.credit(wallet.userId, amount, 'TOPUP_ONCHAIN', {
      fromAddress,
      toAddress,
    });
    this.log.log(`credited ${amount} planck to ${wallet.userId} from ${fromAddress}`);
  }
}
