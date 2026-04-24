import { Controller, Post, Body, UseGuards, UseFilters } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { AssistantService } from './assistant.service';
import { SaveTranscriptDto } from './dto/save-transcript.dto';
import { BillingExceptionFilter } from '../billing/filters/billing-exception.filter';

@Controller('assistant')
@UseGuards(JwtAuthGuard)
export class AssistantController {
  constructor(private readonly assistantService: AssistantService) {}

  @Post('transcripts')
  saveTranscript(@CurrentUser() user: any, @Body() dto: SaveTranscriptDto) {
    return this.assistantService.saveTranscript(user.sub, dto.messages);
  }

  // web_search is exposed as an OpenAI Realtime tool. BillingExceptionFilter
  // maps InsufficientFundsException → 402 { error: 'insufficient_funds', ... }
  // and FeatureDisabledException → 403 { error: 'feature_disabled', ... } so
  // the client forwards a structured payload back to the tool-call, letting
  // the LLM verbalize the problem to the user gracefully.
  @Post('web-search')
  @UseFilters(BillingExceptionFilter)
  async webSearch(@CurrentUser() user: any, @Body() body: { query: string }) {
    return this.assistantService.webSearch(user.sub, body.query);
  }
}
