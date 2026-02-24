import { Controller, Get, Post, Body, Param, Query, UseGuards } from '@nestjs/common';
import { MessengerService } from './messenger.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';

@Controller('messenger')
@UseGuards(JwtAuthGuard)
export class MessengerController {
  constructor(private readonly service: MessengerService) {}

  @Post('conversations')
  create(@Body('participantId') participantId: string, @CurrentUser() user: any) {
    return this.service.getOrCreateDirectConversation(user.sub, participantId);
  }

  @Get('conversations')
  list(@CurrentUser() user: any) {
    return this.service.getConversations(user.sub);
  }

  @Get('conversations/:id/messages')
  messages(
    @Param('id') id: string,
    @Query('cursor') cursor: string,
    @Query('limit') limit: string,
    @CurrentUser() user: any,
  ) {
    return this.service.getMessages(id, user.sub, cursor, limit ? +limit : 30);
  }

  @Get('users/search')
  search(@Query('q') q: string, @CurrentUser() user: any) {
    if (!q || q.length < 2) return [];
    return this.service.searchUsers(q, user.sub);
  }
}
