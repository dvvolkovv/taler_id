import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { GroupCallService } from './group-call.service';
import { CreateGroupCallDto } from './dto/create-group-call.dto';
import { InviteUsersDto } from './dto/invite-users.dto';
import { KickUserDto } from './dto/kick-user.dto';
import { GroupCallHostGuard } from './guards/group-call-host.guard';

@Controller('voice/group-calls')
@UseGuards(JwtAuthGuard)
export class GroupCallController {
  constructor(private readonly service: GroupCallService) {}

  @Post()
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async create(@Req() req: any, @Body() dto: CreateGroupCallDto) {
    return this.service.createCall(req.user.sub, dto.inviteeIds);
  }

  @Get('active')
  async active(@Req() req: any) {
    const calls = await this.service.getActiveCallsForUser(req.user.sub);
    return { calls };
  }

  @Get(':id')
  async detail(@Req() req: any, @Param('id') id: string) {
    const groupCall = await this.service.getCall(id, req.user.sub);
    return { groupCall };
  }

  @Post(':id/join')
  @HttpCode(200)
  async join(@Req() req: any, @Param('id') id: string) {
    return this.service.joinCall(id, req.user.sub);
  }

  @Post(':id/decline')
  @HttpCode(200)
  async decline(@Req() req: any, @Param('id') id: string) {
    await this.service.declineCall(id, req.user.sub);
    return { ok: true };
  }

  @Post(':id/leave')
  @HttpCode(200)
  async leave(@Req() req: any, @Param('id') id: string) {
    await this.service.leaveCall(id, req.user.sub);
    return { ok: true };
  }

  @Post(':id/invite')
  @UseGuards(GroupCallHostGuard)
  async invite(
    @Req() req: any,
    @Param('id') id: string,
    @Body() dto: InviteUsersDto,
  ) {
    return this.service.inviteMore(id, req.user.sub, dto.userIds);
  }

  @Post(':id/kick')
  @UseGuards(GroupCallHostGuard)
  @HttpCode(200)
  async kick(
    @Req() req: any,
    @Param('id') id: string,
    @Body() dto: KickUserDto,
  ) {
    await this.service.kick(id, req.user.sub, dto.userId);
    return { ok: true };
  }

  @Post(':id/mute-all')
  @UseGuards(GroupCallHostGuard)
  @HttpCode(200)
  async muteAll(@Req() req: any, @Param('id') id: string) {
    await this.service.muteAll(id, req.user.sub);
    return { ok: true };
  }

  @Post(':id/end')
  @UseGuards(GroupCallHostGuard)
  @HttpCode(200)
  async end(@Req() req: any, @Param('id') id: string) {
    await this.service.forceEnd(id, req.user.sub);
    return { ok: true };
  }
}
