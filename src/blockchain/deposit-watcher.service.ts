import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ApiPromise, WsProvider } from '@polkadot/api';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { LedgerService } from '../billing/services/ledger.service';
import { Prisma } from '@prisma/client';

@Injectable()
export class DepositWatcher implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger(DepositWatcher.name);
  private api?: ApiPromise;
  private unsubscribe?: () => void;
  private processing = false;

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

    // Subscribe to finalized heads. This gives us a stream of blocks that are
    // guaranteed not to be reorged. On each finalized head, we catch up from
    // BillingConfig.lastSeenBlock to the new head's number, processing every
    // block in between. This makes the watcher idempotent on restart — the
    // same block range is never processed twice.
    this.unsubscribe = (await this.api.rpc.chain.subscribeFinalizedHeads(async (head) => {
      if (this.processing) return; // one tick at a time; avoid overlapping catch-up
      this.processing = true;
      try {
        await this.catchUp(head.number.toNumber());
      } catch (err) {
        this.log.error(`catch-up failed: ${String(err)}`);
      } finally {
        this.processing = false;
      }
    })) as unknown as () => void;
  }

  async onModuleDestroy(): Promise<void> {
    try { this.unsubscribe?.(); } catch {}
    try { await this.api?.disconnect(); } catch {}
  }

  private async catchUp(finalizedHeadNumber: number): Promise<void> {
    if (!this.api) return;
    const cfg = await this.prisma.billingConfig.findUnique({ where: { id: 'singleton' } });
    const lastSeen = cfg?.lastSeenBlock ?? finalizedHeadNumber - 1; // skip history on first run

    if (lastSeen >= finalizedHeadNumber) return;

    for (let n = lastSeen + 1; n <= finalizedHeadNumber; n++) {
      await this.processBlock(n);
      await this.prisma.billingConfig.update({
        where: { id: 'singleton' },
        data: { lastSeenBlock: n },
      });
    }
  }

  private async processBlock(blockNumber: number): Promise<void> {
    if (!this.api) return;

    const blockHash = await this.api.rpc.chain.getBlockHash(blockNumber);
    const apiAt = await this.api.at(blockHash);
    const events = (await apiAt.query.system.events()) as unknown as Array<{
      event: { section: string; method: string; data: any };
    }>;

    for (let i = 0; i < events.length; i++) {
      const record = events[i];
      const { event } = record;
      if (event.section !== 'balances' || event.method !== 'Transfer') continue;

      const [fromRaw, toRaw, amountRaw] = (event.data as any).toJSON() as [
        string,
        string,
        string | number,
      ];

      const to = String(toRaw);
      const from = String(fromRaw);
      const amount = BigInt(amountRaw as string | number);
      // Idempotency key: block hash + event index. Unique across all blocks.
      const chainTxHash = `${blockHash.toHex()}-${i}`;

      try {
        await this.handleTransfer(to, from, amount, chainTxHash, blockNumber);
      } catch (err) {
        // Prisma P2002 = unique constraint violation on chainTxHash → already credited.
        if (
          err instanceof Prisma.PrismaClientKnownRequestError &&
          err.code === 'P2002'
        ) {
          this.log.debug(`duplicate transfer ${chainTxHash} ignored (idempotent)`);
          continue;
        }
        this.log.error(`failed to handle transfer ${chainTxHash}: ${String(err)}`);
        // Don't throw — continue processing other events in this block.
      }
    }
  }

  private async handleTransfer(
    toAddress: string,
    fromAddress: string,
    amount: bigint,
    chainTxHash: string,
    blockNumber: number,
  ): Promise<void> {
    const wallet = await this.prisma.userWallet.findUnique({
      where: { custodialAddress: toAddress },
    });
    if (!wallet) return;

    await this.ledger.credit(
      wallet.userId,
      amount,
      'TOPUP_ONCHAIN',
      { fromAddress, toAddress, blockNumber },
      { chainTxHash },
    );
    this.log.log(
      `credited ${amount} planck to ${wallet.userId} from ${fromAddress} (tx ${chainTxHash})`,
    );
  }
}
