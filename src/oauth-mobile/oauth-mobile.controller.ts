import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { OAuthAuthorizeQueryDto } from './dto/oauth-authorize-query.dto';
import { OAuthApproveDto } from './dto/oauth-approve.dto';
import { OAuthMobileService } from './oauth-mobile.service';

@Controller('oauth/mobile')
@UseGuards(JwtAuthGuard)
export class OAuthMobileController {
  constructor(private readonly svc: OAuthMobileService) {}

  @Get('grant-info')
  grantInfo(@CurrentUser() user: any, @Query() query: OAuthAuthorizeQueryDto) {
    return this.svc.getGrantInfo(user.sub, query);
  }

  @Post('approve')
  @Throttle({ short: { limit: 10, ttl: 60_000 } })
  approve(@CurrentUser() user: any, @Body() body: OAuthApproveDto) {
    return this.svc.approve(user.sub, body);
  }
}
