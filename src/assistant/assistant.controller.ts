import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { AssistantService } from './assistant.service';
import { SaveTranscriptDto } from './dto/save-transcript.dto';

@Controller('assistant')
@UseGuards(JwtAuthGuard)
export class AssistantController {
  constructor(private readonly assistantService: AssistantService) {}

  @Post('transcripts')
  saveTranscript(@CurrentUser() user: any, @Body() dto: SaveTranscriptDto) {
    return this.assistantService.saveTranscript(user.sub, dto.messages);
  }
}
