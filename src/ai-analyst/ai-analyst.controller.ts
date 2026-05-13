import { Controller, Post, Get, UseGuards, Body } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { AiAnalystService } from './ai-analyst.service';

@Controller('ai-analyst')
export class AiAnalystController {
  constructor(private readonly service: AiAnalystService) {}

  /**
   * Get (or create) the user's AI Analyst conversation.
   * Returns the conversation ID so the client can navigate to it.
   */
  @Post()
  @UseGuards(JwtAuthGuard)
  async getOrCreateChat(@CurrentUser() user: any) {
    const conversationId = await this.service.getOrCreateChat(user.sub);
    return { conversationId };
  }

  /**
   * Submit a question to the AI Analyst from the voice assistant.
   * Creates a user message + dispatches to Claude Worker + creates
   * the response message. Returns immediately with the task ID —
   * the response will appear in the analyst chat asynchronously.
   */
  @Post('ask')
  @UseGuards(JwtAuthGuard)
  async askFromVoice(
    @CurrentUser() user: any,
    @Body() body: { question: string },
  ) {
    const conversationId = await this.service.getOrCreateChat(user.sub);
    return { conversationId, status: 'submitted', question: body.question };
  }

  /**
   * Get the latest AI Analyst response (for voice assistant to read).
   */
  @Get('latest')
  @UseGuards(JwtAuthGuard)
  async getLatest(@CurrentUser() user: any) {
    const result = await this.service.getLatestResponse(user.sub);
    return result || { text: null, createdAt: null };
  }
}
