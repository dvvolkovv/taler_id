import { Controller, Get, Post, Patch, Delete, Body, Param, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { CalendarService } from './calendar.service';

@Controller('calendar')
@UseGuards(JwtAuthGuard)
export class CalendarController {
  constructor(private readonly service: CalendarService) {}

  @Get()
  findAll(@CurrentUser() user: any, @Query('from') from?: string, @Query('to') to?: string) {
    return this.service.findByRange(user.sub, from, to);
  }

  @Get('invites')
  getMyInvites(@CurrentUser() user: any) {
    return this.service.getMyInvites(user.sub);
  }

  @Patch('invites/:id/accept')
  acceptInvite(@CurrentUser() user: any, @Param('id') id: string) {
    return this.service.acceptInvite(id, user.sub);
  }

  @Patch('invites/:id/decline')
  declineInvite(@CurrentUser() user: any, @Param('id') id: string) {
    return this.service.declineInvite(id, user.sub);
  }

  @Patch('invites/:id/maybe')
  maybeInvite(@CurrentUser() user: any, @Param('id') id: string) {
    return this.service.maybeInvite(id, user.sub);
  }

  @Get(':id')
  findOne(@CurrentUser() user: any, @Param('id') id: string) {
    return this.service.findOne(user.sub, id);
  }

  @Post()
  create(@CurrentUser() user: any, @Body() body: any) {
    return this.service.create(user.sub, body);
  }

  @Patch(':id')
  update(@CurrentUser() user: any, @Param('id') id: string, @Body() body: any) {
    return this.service.update(user.sub, id, body);
  }

  @Delete(':id')
  remove(@CurrentUser() user: any, @Param('id') id: string) {
    return this.service.remove(user.sub, id);
  }

  @Get(':id/invites')
  getEventInvites(@CurrentUser() user: any, @Param('id') id: string) {
    return this.service.getEventInvites(id, user.sub);
  }
}
