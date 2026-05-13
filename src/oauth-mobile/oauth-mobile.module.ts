import { Module } from '@nestjs/common';
import { OidcModule } from '../oidc/oidc.module';
import { OAuthMobileController } from './oauth-mobile.controller';
import { OAuthMobileService } from './oauth-mobile.service';

@Module({
  imports: [OidcModule],
  controllers: [OAuthMobileController],
  providers: [OAuthMobileService],
})
export class OAuthMobileModule {}
