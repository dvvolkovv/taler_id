import { Logger, Module, OnModuleInit } from '@nestjs/common';
import { OidcModule } from '../oidc/oidc.module';
import { PartnerLinkRevokerService } from './partner-link-revoker.service';
import { PartnerRealtimeService } from './partner-realtime.service';
import { PartnerRegistryService } from './partner-registry.service';
import { reportPartnerSecretsKey } from './partner-secrets.util';
import { PartnerTokensService } from './partner-tokens.service';

/**
 * Ядро партнёрского API без HTTP. Импортируют мессенджер (опознание токенов,
 * вебхуки), профиль (отзыв связок при удалении аккаунта) и партнёрский API.
 * Сам ничего из них не импортирует — так нет циклов между модулями.
 * PrismaModule и RedisModule глобальные.
 */
@Module({
  imports: [OidcModule],
  providers: [
    PartnerRegistryService,
    PartnerTokensService,
    PartnerRealtimeService,
    PartnerLinkRevokerService,
  ],
  exports: [
    PartnerRegistryService,
    PartnerTokensService,
    PartnerRealtimeService,
    PartnerLinkRevokerService,
  ],
})
export class PartnerCoreModule implements OnModuleInit {
  private readonly logger = new Logger('PartnerCore');

  onModuleInit(): void {
    reportPartnerSecretsKey(this.logger);
  }
}
