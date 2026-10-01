import { Module } from '@nestjs/common';
import { PartnerCoreModule } from '../partner-core/partner-core.module';
import { ProfileModule } from '../profile/profile.module';
import { SystemChannelModule } from '../system-channel/system-channel.module';
import { PartnerApiController } from './partner-api.controller';
import { PartnerAuditService } from './partner-audit.service';
import { PartnerContactsService } from './partner-contacts.service';
import { PartnerKeyGuard } from './partner-key.guard';
import { PartnerLinkCodeService } from './partner-link-code.service';
import { PartnerRateLimitGuard } from './partner-rate-limit.guard';
import { PartnerUsersService } from './partner-users.service';
import { PartnerWebhookSinkController } from './partner-webhook-sink.controller';
import { PartnerWebhookSinkStore } from './partner-webhook-sink.store';

// PrismaModule, RedisModule и EmailModule глобальные.
@Module({
  imports: [PartnerCoreModule, SystemChannelModule, ProfileModule],
  controllers: [PartnerApiController, PartnerWebhookSinkController],
  providers: [
    PartnerKeyGuard,
    PartnerRateLimitGuard,
    PartnerAuditService,
    PartnerUsersService,
    PartnerLinkCodeService,
    PartnerContactsService,
    PartnerWebhookSinkStore,
  ],
})
export class PartnerApiModule {}
