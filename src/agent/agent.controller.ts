import { Body, Controller, Logger, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { AgentService } from './agent.service';
import { RunAgentRequestDto } from './dto/run-agent-request.dto';
import { RunAgentResponseDto } from './dto/run-agent-response.dto';

@Controller('agent')
export class AgentController {
  private readonly logger = new Logger(AgentController.name);
  constructor(private readonly agent: AgentService) {}

  @UseGuards(JwtAuthGuard)
  @Post('run')
  async run(
    @CurrentUser() user: any,
    @Body() body: RunAgentRequestDto,
  ): Promise<RunAgentResponseDto> {
    return this.agent.runAgent({
      goal: body.goal,
      userId: user?.sub,
      conversationId: body.conversationId,
    });
  }
}
