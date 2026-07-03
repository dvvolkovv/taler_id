import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from '../prisma/prisma.module';
import { VoiceGateController } from './voice-gate.controller';
import { VoiceGateService } from './voice-gate.service';

@Module({
  imports: [ConfigModule, PrismaModule],
  controllers: [VoiceGateController],
  providers: [VoiceGateService],
  exports: [VoiceGateService],
})
export class VoiceGateModule {}
