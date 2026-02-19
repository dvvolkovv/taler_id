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
import configuration from './config/configuration';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),
    ThrottlerModule.forRoot([
      { name: 'short', ttl: 1000, limit: 10 },
      { name: 'medium', ttl: 60000, limit: 100 },
      { name: 'long', ttl: 3600000, limit: 1000 },
    ]),
    ServeStaticModule.forRoot({
      rootPath: '/home/dvolkov/taler-id/public',
      serveRoot: '/ui',
      serveStaticOptions: { index: false },
    }),
    PrismaModule,
    RedisModule,
    AuthModule,
    KycModule,
    ProfileModule,
    TenantModule,
    BlockchainModule,
    EmailModule,
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
