import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { RedisModule } from '../redis/redis.module';
import { AiAnalystController } from './ai-analyst.controller';
import { AiAnalystService } from './ai-analyst.service';

@Module({
  imports: [ConfigModule, RedisModule],
  controllers: [AiAnalystController],
  providers: [AiAnalystService],
  exports: [AiAnalystService],
})
export class AiAnalystModule {}
