import { Controller, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { AssistantChatService } from './assistant-chat.service';

@Controller('assistant/chat')
@UseGuards(JwtAuthGuard)
export class AssistantChatController {
  constructor(private readonly chat: AssistantChatService) {}
}
