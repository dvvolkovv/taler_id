import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { OidcInteractionController } from './oidc-interaction.controller.js';
import { OidcService, OIDC_PROVIDER } from './oidc.service.js';
import { createOidcProvider } from './oidc-provider.factory.js';

@Module({
  controllers: [OidcInteractionController],
  providers: [
    OidcService,
    {
      provide: OIDC_PROVIDER,
      useFactory: async (
        configService: ConfigService,
        prisma: PrismaService,
        redis: RedisService,
      ) => {
        const issuer =
          configService.get<string>('oidc.issuer') ||
          `${configService.get<string>('baseUrl') || 'http://localhost:3000'}/oauth`;

        const cookieKeysStr =
          configService.get<string>('oidc.cookieKeys') || 'taler-oidc-default-key';
        const cookieKeys = cookieKeysStr.split(',');

        const privateKeyPath = configService.get<string>('jwt.privateKeyPath') || '';
        const publicKeyPath = configService.get<string>('jwt.publicKeyPath') || '';

        const walletxClientSecret =
          process.env.WALLETX_CLIENT_SECRET || 'walletx_secret_2026';

        return createOidcProvider({
          issuer,
          prisma,
          redisClient: redis.getClient(),
          privateKeyPath,
          publicKeyPath,
          cookieKeys,
          walletxClientSecret,
        });
      },
      inject: [ConfigService, PrismaService, RedisService],
    },
  ],
  exports: [OIDC_PROVIDER, OidcService],
})
export class OidcModule {}
