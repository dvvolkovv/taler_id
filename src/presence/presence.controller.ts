import { Controller, Get, Post, Param, HttpCode, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { PresenceService } from './presence.service';

@Controller('presence')
@UseGuards(JwtAuthGuard)
export class PresenceController {
  constructor(private readonly service: PresenceService) {}

  @Post('ping')
  @HttpCode(204)
  @Throttle({ default: { limit: 3, ttl: 30_000 } })
  async ping(@CurrentUser() user: any): Promise<void> {
    await this.service.ping(user.sub);
  }

  @Get('me')
  async getMe(@CurrentUser() user: any) {
    return this.service.getPresence(user.sub, user.sub);
  }

  @Get(':userId')
  async getOne(@CurrentUser() user: any, @Param('userId') userId: string) {
    return this.service.getPresence(user.sub, userId);
  }
}
