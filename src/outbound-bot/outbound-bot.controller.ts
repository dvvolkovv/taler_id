import { Controller, Post, Get, Body, Param, Headers, HttpException, HttpStatus, UseGuards, Request } from '@nestjs/common';
import { OutboundBotService } from './outbound-bot.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';

@Controller('outbound-bot')
export class OutboundBotController {
  constructor(private readonly service: OutboundBotService) {}

  @UseGuards(JwtAuthGuard)
  @Get('chat')
  async getOrCreateChat(@Request() req: any) {
    const conversationId = await this.service.getOrCreateChat(req.user.sub);
    return { conversationId };
  }

  @UseGuards(JwtAuthGuard)
  @Post('tasks')
  async createTask(@Request() req: any, @Body() body: { title: string }) {
    if (!body.title?.trim()) throw new HttpException('Title is required', HttpStatus.BAD_REQUEST);
    const result = await this.service.createTask(req.user.sub, body.title.trim());
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
    if (!campaign) throw new HttpException('Campaign not found', HttpStatus.NOT_FOUND);
    return campaign;
  }

  @UseGuards(JwtAuthGuard)
  @Get('campaigns/:id/listen')
  async listenToCall(@Request() req: any, @Param('id') id: string) {
    const result = await this.service.getActiveCall(id, req.user.sub);
    if (!result) throw new HttpException('No active call', HttpStatus.NOT_FOUND);
    return result;
  }

  @Post('call-callback')
  async callCallback(
    @Headers('x-outbound-secret') secret: string,
    @Body() body: {
      callId: string; campaignId: string; transcript: any;
      summary: string; durationSec: number; status: string; recordingUrl?: string;
    },
  ) {
    const expected = process.env.OUTBOUND_CALLBACK_SECRET || 'outbound-secret-2026';
    if (!secret || secret !== expected) throw new HttpException('Invalid secret', HttpStatus.UNAUTHORIZED);
    await this.service.handleCallCallback(body);
    return { ok: true };
  }
}
