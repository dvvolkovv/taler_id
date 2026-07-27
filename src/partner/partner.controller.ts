import {
  Body,
  Controller,
  HttpCode,
  Post,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { ProvisionDto } from './dto/provision.dto';
import { AttachPhoneDto } from './dto/attach-phone.dto';
import { PartnerSecretGuard } from './partner-secret.guard';
import { PartnerService } from './partner.service';

@Controller('partner')
export class PartnerController {
  constructor(private readonly partnerService: PartnerService) {}

  // Server-to-server: create-or-find a TalerID account by phone and mint
  // MCP OAuth tokens. Guarded by x-partner-secret + kill-switch (see guard).
  // 30/min per IP — provisioning is a one-off per user (ecosystem opt-in).
  @Throttle({ medium: { ttl: 60_000, limit: 30 } })
  @Post('provision')
  @UseGuards(PartnerSecretGuard)
  @HttpCode(200)
  async provision(@Body() dto: ProvisionDto) {
    return this.partnerService.provision(dto);
  }

  // Server-to-server: attach a Linkeon-SMS-verified phone to the EXISTING
  // account proven by the id_token (from the linkeon-partner-web code flow),
  // merging any phone-provisioned duplicate. Same guard as provision.
  @Throttle({ medium: { ttl: 60_000, limit: 30 } })
  @Post('attach-phone')
  @UseGuards(PartnerSecretGuard)
  @HttpCode(200)
  async attachPhone(@Body() dto: AttachPhoneDto) {
    return this.partnerService.attachPhone(dto);
  }
}
