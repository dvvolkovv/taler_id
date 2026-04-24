import { Module, forwardRef } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { PrismaModule } from '../prisma/prisma.module';
import { BlockchainModule } from '../blockchain/blockchain.module';
import { PricingService } from './services/pricing.service';
import { LedgerService } from './services/ledger.service';
import { GatingService } from './services/gating.service';
import { MeteringService } from './services/metering.service';
import { BillingController } from './controllers/billing.controller';
import { MeteringController } from './controllers/metering.controller';
import { MeteringSecretGuard } from './guards/metering-secret.guard';

@Module({
  imports: [PrismaModule, ScheduleModule.forRoot(), forwardRef(() => BlockchainModule)],
  providers: [
    PricingService,
    LedgerService,
    GatingService,
    MeteringService,
    MeteringSecretGuard,
    // Stub MESSENGER_GATEWAY until Task 11 wires the real MessengerGateway.
    // Task 11 will override this with `{ provide: 'MESSENGER_GATEWAY', useExisting: MessengerGateway }`
    // inside MessengerModule's providers (re-exported back into BillingModule via forwardRef).
    {
      provide: 'MESSENGER_GATEWAY',
      useValue: {
        emitToUser: () => {
          /* no-op until Task 11 wires the real gateway */
        },
      },
    },
  ],
  controllers: [BillingController, MeteringController],
  exports: [PricingService, LedgerService, GatingService, MeteringService],
})
export class BillingModule {}
