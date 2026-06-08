import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Post,
  Req,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
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

  @Post('enroll')
  @UseInterceptors(FileInterceptor('audio'))
  async enroll(@Req() req: any, @UploadedFile() file: Express.Multer.File) {
    if (!file || !file.buffer) {
      throw new HttpException(
        { ok: false, error: 'audio_too_short', minSec: 15 },
        HttpStatus.BAD_REQUEST,
      );
    }
    // 16kHz mono int16: 32000 bytes/sec. Reject < 15 sec at the byte level
    // before paying Manax for it.
    const minBytes = 15 * 32_000;
    if (file.size < minBytes) {
      throw new HttpException(
        { ok: false, error: 'audio_too_short', minSec: 15 },
        HttpStatus.BAD_REQUEST,
      );
    }
    const userId = req.user.sub;
    const result = await this.service.enroll(file.buffer);
    if (result.ok && result.embedding && result.speakerId) {
      await this.prisma.profile.update({
        where: { userId },
        data: {
          ownerSpeakerId: result.speakerId,
          ownerEmbedding: result.embedding,
        },
      });
      return {
        ok: true,
        speakerId: result.speakerId,
        embeddingDim: result.embeddingDim,
        audioSec: result.audioSec,
      };
    }
    const code =
      result.error === 'feature_disabled'
        ? HttpStatus.SERVICE_UNAVAILABLE
        : result.error === 'manax_unavailable'
        ? HttpStatus.SERVICE_UNAVAILABLE
        : result.error === 'no_speech_detected'
        ? HttpStatus.UNPROCESSABLE_ENTITY
        : HttpStatus.BAD_REQUEST;
    throw new HttpException({ ok: false, error: result.error }, code);
  }

  @Delete('owner')
  @HttpCode(204)
  async deleteOwner(@Req() req: any) {
    const userId = req.user.sub;
    await this.prisma.profile.update({
      where: { userId },
      data: { ownerSpeakerId: null, ownerEmbedding: [] },
    });
  }
}
