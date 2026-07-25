import { Module } from '@nestjs/common';
import { OidcModule } from '../oidc/oidc.module';
import { PartnerController } from './partner.controller';
import { PartnerService } from './partner.service';

// PrismaService comes from the @Global PrismaModule; OidcModule provides
// OIDC_PROVIDER for server-side token minting.
@Module({
  imports: [OidcModule],
  controllers: [PartnerController],
  providers: [PartnerService],
})
export class PartnerModule {}
