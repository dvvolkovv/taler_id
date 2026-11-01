import { Module } from '@nestjs/common';
import { BillingModule } from '../billing/billing.module';
import { InterpreterAgentClient } from './interpreter-agent.client';
import { InterpreterLivekitService } from './interpreter-livekit.service';
import { InterpreterSecretGuard } from './interpreter-secret.guard';
import { InterpreterController } from './interpreter.controller';
import { InterpreterReconciler } from './interpreter.reconciler';
import { InterpreterService } from './interpreter.service';

/**
 * Face-to-face interpreter: two people side by side, each on their own phone.
 * Prisma and Redis come from their global modules; the reconciler's
 * @Interval needs the ScheduleModule registered in AppModule.
 */
@Module({
  imports: [BillingModule],
  controllers: [InterpreterController],
  providers: [
    InterpreterService,
    InterpreterReconciler,
    InterpreterAgentClient,
    InterpreterLivekitService,
    InterpreterSecretGuard,
  ],
})
export class InterpreterModule {}
