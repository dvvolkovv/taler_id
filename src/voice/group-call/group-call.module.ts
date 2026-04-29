import { Module, forwardRef } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { GroupCallService } from './group-call.service';
import { GroupCallGateway } from './group-call.gateway';
import { VoiceModule } from '../voice.module';
import { ApnsService } from '../../common/apns.service';
import { FcmService } from '../../common/fcm.service';

/**
 * Group voice call (Phase 1) module. PrismaModule is global so we don't
 * import it. ApnsService/FcmService aren't wrapped in a CommonModule in
 * this codebase — every consumer registers them as local providers, which
 * is how MessengerModule does it. We mirror that here. VoiceModule already
 * imports GroupCallModule (so VoiceController can wire group-call routes
 * once Task 11 lands), so the reverse VoiceService dependency uses
 * `forwardRef` to break the cycle.
 */
@Module({
  imports: [
    forwardRef(() => VoiceModule),
    BullModule.registerQueue({ name: 'group-call-timeouts' }),
  ],
  providers: [GroupCallService, GroupCallGateway, ApnsService, FcmService],
  exports: [GroupCallService],
})
export class GroupCallModule {}
