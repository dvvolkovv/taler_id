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
import { TasksService } from './tasks.service';

/**
 * App-facing REST API for tasks/routines (JWT). Mirrors the MCP task tools so
 * the mobile/desktop app can create and complete tasks (until now tasks were
 * MCP-only, created by Linkeon; the app could only display them via the
 * read-only /calendar merge). Same service the MCP tools use.
 */
@Controller('tasks')
@UseGuards(JwtAuthGuard)
export class TasksController {
  constructor(private readonly tasks: TasksService) {}

  @Get()
  list(
    @CurrentUser() user: any,
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('includeDone') includeDone?: string,
  ) {
    return this.tasks.list(user.sub, {
      from,
      to,
      includeDone: includeDone === 'true',
    });
  }

  @Post()
  create(@CurrentUser() user: any, @Body() body: any) {
    return this.tasks.create(user.sub, {
      title: body.title,
      due: body.due ?? undefined,
      deadline: body.deadline ?? undefined,
      note: body.note ?? undefined,
      recurrence: body.recurrence ?? undefined,
      ...(body.id ? { id: body.id } : {}),
      createdBy: body.createdBy ?? 'MANUAL',
    });
  }

  @Patch(':id')
  update(
    @CurrentUser() user: any,
    @Param('id') id: string,
    @Body() body: any,
  ) {
    return this.tasks.update(user.sub, id, body);
  }

  @Post(':id/status')
  setStatus(
    @CurrentUser() user: any,
    @Param('id') id: string,
    @Body() body: any,
  ) {
    return this.tasks.setStatus(user.sub, id, body.status, body.occurrenceDate);
  }

  @Delete(':id')
  remove(@CurrentUser() user: any, @Param('id') id: string) {
    return this.tasks.remove(user.sub, id);
  }
}
