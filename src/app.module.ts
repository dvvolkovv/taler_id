import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { ServeStaticModule } from '@nestjs/serve-static';
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
