import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { PrismaService } from '../prisma/prisma.service';
import { VoiceGateService } from './voice-gate.service';

@Controller('voice-gate')
@UseGuards(JwtAuthGuard)
export class VoiceGateController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly service: VoiceGateService,
  ) {}

  @Get('owner-status')
  async ownerStatus(@Req() req: any) {
    const userId = req.user.sub;
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile || !profile.ownerSpeakerId) {
      return { enrolled: false };
    }
    return {
      enrolled: true,
      speakerId: profile.ownerSpeakerId,
      enrolledAt: profile.updatedAt.toISOString(),
    };
  }
}
