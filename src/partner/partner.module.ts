import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { OidcModule } from '../oidc/oidc.module';
import { MailModule } from '../mail/mail.module';
import { PartnerController } from './partner.controller';
import { PartnerService } from './partner.service';

// PrismaService comes from the @Global PrismaModule; OidcModule provides
// OIDC_PROVIDER for server-side token minting; MailModule provides
// MailAccountService for @talerid.io mailbox provisioning; JwtModule provides
// JwtService to verify the account-linking id_token (attach-phone).
@Module({
  imports: [OidcModule, MailModule, JwtModule.register({})],
  controllers: [PartnerController],
  providers: [PartnerService],
})
export class PartnerModule {}
