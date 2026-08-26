import { DynamicModule, Global, Logger, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PrismaModule } from '../prisma/prisma.module';
import { RedisModule } from '../redis/redis.module';
import { MessengerModule } from '../messenger/messenger.module';
import { InformerBotController } from './informer-bot.controller';
import { InformerBotService } from './informer-bot.service';
import { InformerClient } from './informer.client';
import { InformerRatesService } from './informer.rates';
import { InformerWatcher } from './informer.watcher';
import { PendingStateStore } from './informer.pending-state';

@Global()
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
      return { module: InformerBotModule, global: true };
    }
    return {
      module: InformerBotModule,
      global: true,
      imports: [
        ConfigModule,
        PrismaModule,
        RedisModule,
        // NO forwardRef here. A forwardRef inside a DYNAMIC module's imports
        // makes Nest register a SECOND instance of the target module (different
        // container token) -> a second MessengerGateway bound to the same
        // socket.io namespace -> every inbound event handled twice, every
        // call_invite VoIP push sent twice (incident 2026-07-18: a second ring
        // from the same peer interrupted an active call; all the msg/call_ended
        // dedup patches since 2026-06-16 were treating this symptom). There is
        // no module-level cycle: InformerBotModule is @Global and
        // MessengerModule never imports it - provider-level forwardRefs in the
        // services are enough.
        MessengerModule,
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
        InformerRatesService,
        PendingStateStore,
      ],
      exports: [InformerBotService],
    };
  }
}
