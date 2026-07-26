import { Module } from '@nestjs/common';
import { OidcModule } from '../oidc/oidc.module';
import { MailModule } from '../mail/mail.module';
import { PartnerController } from './partner.controller';
import { PartnerService } from './partner.service';

// PrismaService comes from the @Global PrismaModule; OidcModule provides
// OIDC_PROVIDER for server-side token minting; MailModule provides
// MailAccountService for @talerid.io mailbox auto-provisioning on mail scope.
@Module({
  imports: [OidcModule, MailModule],
  controllers: [PartnerController],
  providers: [PartnerService],
})
export class PartnerModule {}
