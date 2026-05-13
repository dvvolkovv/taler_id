import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  Headers,
  HttpException,
  HttpStatus,
  UseGuards,
  Request,
  ServiceUnavailableException,
} from '@nestjs/common';
import { OutboundBotService } from './outbound-bot.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { GatingService } from '../billing/services/gating.service';
import { MeteringService } from '../billing/services/metering.service';

@Controller('outbound-bot')
export class OutboundBotController {
  constructor(
    private readonly service: OutboundBotService,
    private readonly gating: GatingService,
    private readonly metering: MeteringService,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Get('chat')
  async getOrCreateChat(@Request() req: any) {
    const conversationId = await this.service.getOrCreateChat(req.user.sub);
    return { conversationId };
  }

  @UseGuards(JwtAuthGuard)
  @Post('tasks')
  async createTask(@Request() req: any, @Body() body: { title: string }) {
    if (!body.title?.trim())
      throw new HttpException('Title is required', HttpStatus.BAD_REQUEST);
    const result = await this.service.createTask(
      req.user.sub,
      body.title.trim(),
    );
    return result;
  }

  @UseGuards(JwtAuthGuard)
  @Get('campaigns')
  async getCampaigns(@Request() req: any) {
    const conversationId = await this.service.getOrCreateChat(req.user.sub);
    return this.service.getCampaigns(req.user.sub, conversationId);
  }

  @UseGuards(JwtAuthGuard)
  @Get('campaigns/:id')
  async getCampaign(@Param('id') id: string) {
    const campaign = await this.service.getCampaign(id);
    if (!campaign)
      throw new HttpException('Campaign not found', HttpStatus.NOT_FOUND);
    return campaign;
  }

  @UseGuards(JwtAuthGuard)
  @Get('campaigns/:id/listen')
  async listenToCall(@Request() req: any, @Param('id') id: string) {
    const result = await this.service.getActiveCall(id, req.user.sub);
    if (!result)
      throw new HttpException('No active call', HttpStatus.NOT_FOUND);
    return result;
  }

  @Post('call-callback')
  async callCallback(
    @Headers('x-outbound-secret') secret: string,
    @Body()
    body: {
      callId: string;
      campaignId: string;
      transcript: any;
      summary: string;
      durationSec: number;
      status: string;
      recordingUrl?: string;
      // Task 15: agent echoes the billing session it was dispatched with
      // and the call duration in minutes so we can finalize the debit.
      billingSessionId?: string;
      units?: number;
    },
  ) {
    const expected = process.env.OUTBOUND_CALLBACK_SECRET;
    if (!expected) {
      throw new ServiceUnavailableException(
        'outbound callback secret not configured',
      );
    }
    if (!secret || secret !== expected)
      throw new HttpException('Invalid secret', HttpStatus.UNAUTHORIZED);
    await this.service.handleCallCallback(body);

    // Finalize billing: agent-reported duration is authoritative over the
    // cron estimate. reportUsage debits any positive diff; endSession flips
    // the session to 'completed'. Wrapped in try/catch so a metering failure
    // never propagates into the agent — the transcript save already succeeded.
    const MAX_UNITS_PER_REPORT = 24 * 60;
    if (
      body.billingSessionId &&
      typeof body.units === 'number' &&
      Number.isFinite(body.units) &&
      body.units >= 0
    ) {
      const safeUnits = Math.min(body.units, MAX_UNITS_PER_REPORT);
      try {
        await this.metering.reportUsage(
          body.billingSessionId,
          safeUnits,
          'outbound-call-agent',
        );
      } catch (_) {
        // reportUsage throws on unknown sessionId — swallow to keep the callback idempotent.
      }
      await this.gating
        .endSession(body.billingSessionId, 'completed')
        .catch(() => {});
    }

    return { ok: true };
  }
}
