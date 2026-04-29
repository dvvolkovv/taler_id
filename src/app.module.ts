import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { ServeStaticModule } from '@nestjs/serve-static';
import { BullModule } from '@nestjs/bullmq';
import { AppController } from './app.controller';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { RedisModule } from './redis/redis.module';
import { KycModule } from './kyc/kyc.module';
import { ProfileModule } from './profile/profile.module';
import { TenantModule } from "./tenant/tenant.module";
import { BlockchainModule } from "./blockchain/blockchain.module";
import { EmailModule } from "./email/email.module";
import { AdminModule } from "./admin/admin.module";
import { OidcModule } from "./oidc/oidc.module";
import { AssistantModule } from "./assistant/assistant.module";
import { MessengerModule } from "./messenger/messenger.module";
import { VoiceModule } from "./voice/voice.module";
import { ProfileSectionsModule } from "./profile-sections/profile-sections.module";
import { NotesModule } from "./notes/notes.module";
import { CalendarModule } from "./calendar/calendar.module";
import { AiAnalystModule } from "./ai-analyst/ai-analyst.module";
import { OutboundBotModule } from "./outbound-bot/outbound-bot.module";
import { DeviceKeysModule } from "./device-keys/device-keys.module";
import { BillingModule } from "./billing/billing.module";
import { ScheduleModule } from "@nestjs/schedule";
import configuration from './config/configuration';

@Module({
  imports: [
    ConfigModule.forRoot({ envFilePath: ".env",
      isGlobal: true,
      load: [configuration],
    }),
    ThrottlerModule.forRoot([
      { name: 'short', ttl: 1000, limit: 10 },
      { name: 'medium', ttl: 60000, limit: 100 },
      { name: 'long', ttl: 3600000, limit: 1000 },
    ]),
    // Flutter Web mobile app
    ServeStaticModule.forRoot({
      rootPath: '/home/dvolkov/taler-id/public/mobile',
      serveRoot: '/ui/mobile',
      exclude: ['/ui/admin{/*path}'],
    }),
    // Main UI (admin panel, invite pages, etc.)
    ServeStaticModule.forRoot({
      rootPath: '/home/dvolkov/taler-id/public',
      serveRoot: '/ui',
      serveStaticOptions: { index: false },
      exclude: ['/ui/mobile{/*path}'],
    }),
    // Uploaded user files (avatars, documents)
    ServeStaticModule.forRoot({
      rootPath: '/home/dvolkov/taler-id/uploads',
      serveRoot: '/uploads',
    }),
    // Root path (/) - main landing page
    ServeStaticModule.forRoot({
      rootPath: '/home/dvolkov/taler-id/public',
      serveRoot: '/',
      exclude: ['/ui{/*path}', '/uploads{/*path}'],
    }),
    // Global BullMQ Redis connection. `BullModule.registerQueue({ name })` in
    // feature modules (GroupCallModule, etc.) attaches to this connection;
    // without forRootAsync those queues would have no Redis client at runtime.
    // We mirror RedisService's URL parsing (`redis://[:pass@]host[:port][/db]`).
    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        const url = config.get<string>('redis.url') ?? 'redis://localhost:6379';
        const parsed = new URL(url);
        return {
          connection: {
            host: parsed.hostname,
            port: Number(parsed.port) || 6379,
            password: parsed.password || undefined,
            db:
              parsed.pathname && parsed.pathname.length > 1
                ? Number(parsed.pathname.slice(1))
                : 0,
          },
        };
      },
    }),
    PrismaModule,
    RedisModule,
    AuthModule,
    KycModule,
    ProfileModule,
    TenantModule,
    BlockchainModule,
    EmailModule,
    AdminModule,
    OidcModule,
    AssistantModule,
    MessengerModule,
    VoiceModule,
    ProfileSectionsModule,
    ScheduleModule.forRoot(),
    NotesModule,
    CalendarModule,
    AiAnalystModule,
    OutboundBotModule,
    DeviceKeysModule,
    BillingModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
