import { Body, Controller, Delete, Get, Headers, Ip, Param, Patch, Post, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { RegisterClientDto } from './dto/register-client.dto';
import { UpdateClientDto } from './dto/update-client.dto';
import { OAuthRegistrationService } from './oauth-registration.service';

@Controller('oauth')
@UseGuards(JwtAuthGuard)
export class OAuthRegistrationController {
  constructor(private readonly svc: OAuthRegistrationService) {}

  @Post('register')
  @Throttle({ short: { limit: 3, ttl: 60_000 } })
  register(
    @CurrentUser() user: any,
    @Body() dto: RegisterClientDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.svc.register(user.sub, dto, ip, userAgent ?? '');
  }

  @Get('clients')
  list(@CurrentUser() user: any) {
    return this.svc.listMine(user.sub);
  }

  @Get('clients/:clientId')
  get(@CurrentUser() user: any, @Param('clientId') clientId: string) {
    return this.svc.getMine(user.sub, clientId);
  }

  @Patch('clients/:clientId')
  update(
    @CurrentUser() user: any,
    @Param('clientId') clientId: string,
    @Body() dto: UpdateClientDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.svc.updateMine(user.sub, clientId, dto, ip, userAgent ?? '');
  }

  @Delete('clients/:clientId')
  remove(
    @CurrentUser() user: any,
    @Param('clientId') clientId: string,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.svc.deleteMine(user.sub, clientId, ip, userAgent ?? '');
  }

  @Post('clients/:clientId/rotate-secret')
  @Throttle({ short: { limit: 3, ttl: 60_000 } })
  rotateSecret(
    @CurrentUser() user: any,
    @Param('clientId') clientId: string,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.svc.rotateSecret(user.sub, clientId, ip, userAgent ?? '');
  }
}
