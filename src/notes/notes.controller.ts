import { Controller, Get, Post, Patch, Delete, Body, Param, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { NotesService } from './notes.service';

@Controller('notes')
@UseGuards(JwtAuthGuard)
export class NotesController {
  constructor(private readonly service: NotesService) {}

  @Get()
  findAll(@CurrentUser() user: any, @Query('limit') limit?: string, @Query('offset') offset?: string) {
    return this.service.findAll(user.sub, limit ? parseInt(limit) : 50, offset ? parseInt(offset) : 0);
  }

  @Get(':id')
  findOne(@CurrentUser() user: any, @Param('id') id: string) {
    return this.service.findOne(user.sub, id);
  }

  @Post()
  create(@CurrentUser() user: any, @Body() body: { title: string; content: string; source?: string }) {
    return this.service.create(user.sub, body);
  }

  @Patch(':id')
  update(@CurrentUser() user: any, @Param('id') id: string, @Body() body: { title?: string; content?: string }) {
    return this.service.update(user.sub, id, body);
  }

  @Delete(':id')
  remove(@CurrentUser() user: any, @Param('id') id: string) {
    return this.service.remove(user.sub, id);
  }
}
