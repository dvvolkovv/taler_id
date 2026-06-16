import { DynamicModule, Logger, Module, forwardRef } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PrismaModule } from '../prisma/prisma.module';
import { RedisModule } from '../redis/redis.module';
import { MessengerModule } from '../messenger/messenger.module';
import { InformerBotController } from './informer-bot.controller';
import { InformerBotService } from './informer-bot.service';
import { InformerClient } from './informer.client';
import { InformerWatcher } from './informer.watcher';

@Module({})
export class InformerBotModule {
  static register(): DynamicModule {
    const logger = new Logger('InformerBotModule');
    const key = process.env.INFORMER_API_KEY;
    const secret = process.env.INFORMER_API_SECRET;
    if (!key || !secret) {
      logger.warn(
        'INFORMER_API_KEY/SECRET not set — module disabled (controller, watcher, /profile/me flag will all reflect this).',
      );
      return { module: InformerBotModule };
    }
    return {
      module: InformerBotModule,
      imports: [
        ConfigModule,
        PrismaModule,
        RedisModule,
        forwardRef(() => MessengerModule),
      ],
      controllers: [InformerBotController],
      providers: [
        {
          provide: InformerClient,
          useFactory: (cfg: ConfigService) =>
            new InformerClient({
              baseUrl:
                cfg.get<string>('INFORMER_API_BASE_URL') ||
                'https://apiadmin.test.gsmsoft.eu',
              key: cfg.get<string>('INFORMER_API_KEY')!,
              secret: cfg.get<string>('INFORMER_API_SECRET')!,
              timeoutMs: 25000,
            }),
          inject: [ConfigService],
        },
        InformerBotService,
        InformerWatcher,
      ],
      exports: [InformerBotService],
    };
  }
}
