import { Module, forwardRef } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from '../prisma/prisma.module';
import { BlockchainModule } from '../blockchain/blockchain.module';
import { MessengerModule } from '../messenger/messenger.module';
import { PricingService } from './services/pricing.service';
import { LedgerService } from './services/ledger.service';
import { GatingService } from './services/gating.service';
import { MeteringService } from './services/metering.service';
import { BillingController } from './controllers/billing.controller';
import { MeteringController } from './controllers/metering.controller';
import { AdminBillingController } from './controllers/admin-billing.controller';
import { MeteringSecretGuard } from './guards/metering-secret.guard';

@Module({
  imports: [
    PrismaModule,
    ScheduleModule.forRoot(),
    forwardRef(() => BlockchainModule),
    // MessengerModule exports the real MessengerGateway under the 'MESSENGER_GATEWAY'
    // token. forwardRef guards against future circular deps if messenger ever needs
    // a billing service — it's safe to keep even when not strictly required today.
    forwardRef(() => MessengerModule),
  ],
  providers: [
    PricingService,
    LedgerService,
    GatingService,
    MeteringService,
    MeteringSecretGuard,
    // MESSENGER_GATEWAY is now provided by MessengerModule (useExisting: MessengerGateway).
  ],
  controllers: [BillingController, MeteringController, AdminBillingController],
  exports: [PricingService, LedgerService, GatingService, MeteringService],
})
export class BillingModule {}
