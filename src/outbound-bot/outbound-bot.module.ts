import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { RedisModule } from '../redis/redis.module';
import { OutboundBotController } from './outbound-bot.controller';
import { OutboundBotService } from './outbound-bot.service';
import { VoximplantService } from './voximplant.service';

@Module({
  imports: [ConfigModule, RedisModule],
  controllers: [OutboundBotController],
  providers: [OutboundBotService, VoximplantService],
  exports: [OutboundBotService],
})
export class OutboundBotModule {}
