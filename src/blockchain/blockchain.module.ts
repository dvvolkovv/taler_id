import { Module } from '@nestjs/common';
import { BlockchainService } from './blockchain.service';
import { BlockchainController } from './blockchain.controller';
import { WalletService } from './wallet.service';
import { DepositWatcher } from './deposit-watcher.service';
import { PrismaModule } from '../prisma/prisma.module';
import { LedgerService } from '../billing/services/ledger.service';

@Module({
  imports: [PrismaModule],
  providers: [
    BlockchainService,
    WalletService,
    DepositWatcher,
    // TODO(Task 8): Remove this temporary local provider. BillingModule will
    // own LedgerService and we'll import BillingModule here instead. Keeping
    // it local now lets Task 7 compile and run standalone without a full
    // BillingModule definition.
    LedgerService,
  ],
  controllers: [BlockchainController],
  exports: [BlockchainService, WalletService],
})
export class BlockchainModule {}
