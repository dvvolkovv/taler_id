import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { CalendarService } from './calendar.service';
import { TasksService } from '../tasks/tasks.service';

@Controller('calendar')
@UseGuards(JwtAuthGuard)
export class CalendarController {
  constructor(
    private readonly service: CalendarService,
    private readonly tasks: TasksService,
  ) {}

  @Get()
  async findAll(
    @CurrentUser() user: any,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    // Events + task/routine occurrences (read-only synthetic items) so the app
    // calendar shows routines Linkeon moved from events to tasks.
    const [events, taskItems] = await Promise.all([
      this.service.findByRange(user.sub, from, to),
      this.tasks.occurrencesForCalendar(user.sub, from, to),
    ]);
    return [...events, ...taskItems].sort(
      (a: any, b: any) =>
        new Date(a.startAt).getTime() - new Date(b.startAt).getTime(),
    );
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
