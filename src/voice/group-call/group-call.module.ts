import { Module, forwardRef } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { GroupCallService } from './group-call.service';
import { GroupCallGateway } from './group-call.gateway';
import { GroupCallController } from './group-call.controller';
import { GroupCallHostGuard } from './guards/group-call-host.guard';
import { GroupCallTimeoutProcessor } from './jobs/timeout.processor';
import { GroupCallCleanupCron } from './jobs/cleanup.cron';
import { VoiceModule } from '../voice.module';
import { ApnsService } from '../../common/apns.service';
import { FcmService } from '../../common/fcm.service';
import { RedisModule } from '../../redis/redis.module';

/**
 * Group voice call (Phase 1) module. PrismaModule is global so we don't
 * import it. ApnsService/FcmService aren't wrapped in a CommonModule in
 * this codebase — every consumer registers them as local providers, which
 * is how MessengerModule does it. We mirror that here. VoiceModule already
 * imports GroupCallModule (so VoiceController can wire group-call routes
 * once Task 11 lands), so the reverse VoiceService dependency uses
 * `forwardRef` to break the cycle.
 *
 * RedisModule is `@Global()` so importing it here is technically redundant,
 * but listing it explicitly documents the dependency (Task 9 `muteAll` rate
 * limit) and keeps the module self-describing for future readers.
 */
@Module({
  imports: [
    forwardRef(() => VoiceModule),
    BullModule.registerQueue({ name: 'group-call-timeouts' }),
    RedisModule,
  ],
  controllers: [GroupCallController],
  providers: [
    GroupCallService,
    GroupCallGateway,
    ApnsService,
    FcmService,
    GroupCallHostGuard,
    GroupCallTimeoutProcessor,
    GroupCallCleanupCron,
  ],
  exports: [GroupCallService],
})
export class GroupCallModule {}
