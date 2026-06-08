import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { OidcModule } from '../oidc/oidc.module';
import { OAuthAccountController } from './oauth-account.controller';
import { OAuthRegistrationController } from './oauth-registration.controller';
import { OAuthRegistrationService } from './oauth-registration.service';
import { OidcBearerGuard } from './oidc-bearer.guard';

@Module({
  imports: [OidcModule, AuthModule],
  controllers: [OAuthRegistrationController, OAuthAccountController],
  providers: [OAuthRegistrationService, OidcBearerGuard],
  exports: [OAuthRegistrationService],
})
export class OAuthRegistrationModule {}
