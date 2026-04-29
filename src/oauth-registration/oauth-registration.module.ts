import { Module } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { OAuthRegistrationController } from './oauth-registration.controller';
import { OAuthRegistrationService } from './oauth-registration.service';

@Module({
  controllers: [OAuthRegistrationController],
  providers: [OAuthRegistrationService, PrismaService],
  exports: [OAuthRegistrationService],
})
export class OAuthRegistrationModule {}
