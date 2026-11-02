import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import type { Response } from 'express';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { AgentEndedDto } from './dto/agent-ended.dto';
import { CreateInterpreterSessionDto } from './dto/create-interpreter-session.dto';
import { JoinInterpreterSessionDto } from './dto/join-interpreter-session.dto';
import { InterpreterSecretGuard } from './interpreter-secret.guard';
import {
  InterpreterService,
  type InterpreterUser,
} from './interpreter.service';

/**
 * Face-to-face interpreter. Each route checks that the caller takes part in
 * the session it names — in the service, which answers 404 to anyone else.
 */
@Controller('interpreter')
export class InterpreterController {
  constructor(private readonly interpreter: InterpreterService) {}

  @Get('languages')
  @UseGuards(JwtAuthGuard)
  languages() {
    return this.interpreter.languages();
  }

  @Post('sessions')
  @UseGuards(JwtAuthGuard)
  create(
    @CurrentUser() user: InterpreterUser,
    @Body() dto: CreateInterpreterSessionDto,
  ) {
    return this.interpreter.create(user, dto.lang);
  }

  // Ahead of the sessions/:id routes, so that "join" is never taken for an id.
  @Post('sessions/join')
  @UseGuards(JwtAuthGuard)
  join(
    @CurrentUser() user: InterpreterUser,
    @Body() dto: JoinInterpreterSessionDto,
  ) {
    return this.interpreter.join(user, dto.code, dto.lang);
  }

  @Post('sessions/:id/code')
  @UseGuards(JwtAuthGuard)
  newCode(
    @CurrentUser() user: InterpreterUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.interpreter.newCode(user.sub, id);
  }

  @Get('sessions/:id')
  @UseGuards(JwtAuthGuard)
  get(
    @CurrentUser() user: InterpreterUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.interpreter.get(user.sub, id);
  }

  @Post('sessions/:id/end')
  @UseGuards(JwtAuthGuard)
  end(
    @CurrentUser() user: InterpreterUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.interpreter.end(user.sub, id);
  }

  /**
   * Post-deploy smoke of both engines, with the agent's own status. Behind
   * auth, unlike translator/selftest: every call opens OpenAI sessions.
   */
  @Get('selftest')
  @UseGuards(JwtAuthGuard)
  async selftest(@Res({ passthrough: true }) res: Response) {
    const { status, body } = await this.interpreter.selftest();
    res.status(status);
    return body;
  }

  /**
   * The agent reports that it stopped by itself. Not throttled: all reports
   * come from the agent's single address, and a lost one costs the host money.
   */
  @Post('internal/sessions/:id/agent-ended')
  @UseGuards(InterpreterSecretGuard)
  @SkipThrottle({ short: true, medium: true, long: true })
  @HttpCode(200)
  agentEnded(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AgentEndedDto,
  ) {
    return this.interpreter.agentEnded(id, dto.reason);
  }
}
