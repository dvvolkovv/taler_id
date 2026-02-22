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
    // Flutter Web mobile app
    ServeStaticModule.forRoot({
      rootPath: '/home/dvolkov/taler-id/public/mobile',
      serveRoot: '/ui/mobile',
      exclude: ['/api{/*path}', '/auth{/*path}', '/kyc{/*path}', '/profile{/*path}', '/tenant{/*path}', '/admin{/*path}', '/sessions{/*path}', '/ui/admin{/*path}'],
    }),
    // Main UI (admin panel, invite pages, etc.)
    ServeStaticModule.forRoot({
      rootPath: '/home/dvolkov/taler-id/public',
      serveRoot: '/ui',
      serveStaticOptions: { index: false },
      exclude: ['/api{/*path}', '/auth{/*path}', '/kyc{/*path}', '/profile{/*path}', '/tenant{/*path}', '/admin{/*path}', '/sessions{/*path}', '/ui/mobile{/*path}'],
    }),
    // Root path (/) - main landing page
    ServeStaticModule.forRoot({
      rootPath: '/home/dvolkov/taler-id/public',
      serveRoot: '/',
      exclude: ['/api{/*path}', '/auth{/*path}', '/kyc{/*path}', '/profile{/*path}', '/tenant{/*path}', '/admin{/*path}', '/sessions{/*path}', '/oauth{/*path}', '/ui{/*path}'],
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
