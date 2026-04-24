import { Module, forwardRef } from '@nestjs/common';
import { BlockchainService } from './blockchain.service';
import { BlockchainController } from './blockchain.controller';
import { WalletService } from './wallet.service';
import { DepositWatcher } from './deposit-watcher.service';
import { PrismaModule } from '../prisma/prisma.module';
import { BillingModule } from '../billing/billing.module';

@Module({
  imports: [PrismaModule, forwardRef(() => BillingModule)],
  providers: [BlockchainService, WalletService, DepositWatcher],
  controllers: [BlockchainController],
  exports: [BlockchainService, WalletService],
})
export class BlockchainModule {}
