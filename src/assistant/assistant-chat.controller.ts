import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { AssistantChatService } from './assistant-chat.service';
import { LogEntriesDto, TurnDto } from './dto/assistant-chat.dto';

@Controller('assistant/chat')
@UseGuards(JwtAuthGuard)
export class AssistantChatController {
  constructor(private readonly chat: AssistantChatService) {}

  /** Get-or-create the user's AI_ASSISTANT thread. History is read via
   *  the standard GET /messenger/conversations/:id/messages. */
  @Get()
  async getThread(@CurrentUser() user: any) {
    const conversationId = await this.chat.getOrCreateThread(user.sub);
    return { conversationId };
  }

  /** Batch-append voice-session replicas and action bubbles. */
  @Post('log')
  async log(@CurrentUser() user: any, @Body() dto: LogEntriesDto) {
    return this.chat.appendEntries(user.sub, dto.entries as any);
  }

  /** Text turn: persist user text, call GPT-4o with client-provided
   *  tool schemas; tools execute on the client. */
  @Post('turn')
  async turn(@CurrentUser() user: any, @Body() dto: TurnDto) {
    return this.chat.textTurn(user.sub, dto);
  }
}
