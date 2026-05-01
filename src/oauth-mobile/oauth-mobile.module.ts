import { Module } from '@nestjs/common';
import { OidcModule } from '../oidc/oidc.module';
import { AuthModule } from '../auth/auth.module';
import { OAuthMobileController } from './oauth-mobile.controller';
import { OAuthMobileService } from './oauth-mobile.service';

@Module({
  imports: [OidcModule, AuthModule],
  controllers: [OAuthMobileController],
  providers: [OAuthMobileService],
})
export class OAuthMobileModule {}
