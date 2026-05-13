import { Module } from '@nestjs/common';
import { OidcModule } from '../oidc/oidc.module';
import { OAuthRegistrationController } from './oauth-registration.controller';
import { OAuthRegistrationService } from './oauth-registration.service';
import { OidcBearerGuard } from './oidc-bearer.guard';

@Module({
  imports: [OidcModule],
  controllers: [OAuthRegistrationController],
  providers: [OAuthRegistrationService, OidcBearerGuard],
  exports: [OAuthRegistrationService],
})
export class OAuthRegistrationModule {}
