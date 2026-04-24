import { Module, forwardRef } from '@nestjs/common';
import { RedisModule } from '../redis/redis.module';
import { ConfigModule } from '@nestjs/config';
import { MessengerController } from './messenger.controller';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';
import { AiTwinService } from './ai-twin.service';
import { AiAnalystService } from '../ai-analyst/ai-analyst.service';
import { OutboundBotModule } from '../outbound-bot/outbound-bot.module';
import { BillingModule } from '../billing/billing.module';
import { FcmService } from '../common/fcm.service';
import { ApnsService } from '../common/apns.service';
import { FileStorageService } from '../common/file-storage.service';
import { ThumbnailService } from '../common/thumbnail.service';
import { VideoTranscodeService } from '../common/video-transcode.service';

@Module({
  imports: [
    ConfigModule,
    RedisModule,
    OutboundBotModule,
    // AiTwinService gates dispatch through GatingService/MeteringService (Task 14).
    // forwardRef because BillingModule imports MessengerModule (for MESSENGER_GATEWAY
    // token) — the cycle is real and must be broken at both ends.
    forwardRef(() => BillingModule),
  ],
  controllers: [MessengerController],
  providers: [
    MessengerService,
    MessengerGateway,
    AiTwinService,
    AiAnalystService,
    FcmService,
    ApnsService,
    FileStorageService,
    ThumbnailService,
    VideoTranscodeService,
    // Expose MessengerGateway under the 'MESSENGER_GATEWAY' token so BillingModule
    // (and any other feature module) can @Inject('MESSENGER_GATEWAY') without a
    // hard type dependency on MessengerGateway itself — keeps the billing code
    // decoupled and testable via a small MeteringGateway interface.
    { provide: 'MESSENGER_GATEWAY', useExisting: MessengerGateway },
  ],
  exports: [MessengerGateway, 'MESSENGER_GATEWAY'],
})
export class MessengerModule {}
