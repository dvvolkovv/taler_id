import { Module } from '@nestjs/common';
import { OAuthRegistrationController } from './oauth-registration.controller';
import { OAuthRegistrationService } from './oauth-registration.service';

@Module({
  controllers: [OAuthRegistrationController],
  providers: [OAuthRegistrationService],
  exports: [OAuthRegistrationService],
})
export class OAuthRegistrationModule {}
