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

        // These keys sign the provider's interaction/session cookies, so the
        // literal that used to sit here as a fallback would let anyone reading
        // this repository forge a signed OIDC session. All three environments
        // set OIDC_COOKIE_KEYS today (checked before removing it) — refuse to
        // start rather than quietly falling back to a published value.
        const cookieKeysStr = configService.get<string>('oidc.cookieKeys');
        if (!cookieKeysStr || cookieKeysStr === 'taler-oidc-default-key') {
          throw new Error(
            'OIDC_COOKIE_KEYS must be set to a private value — it signs the ' +
              'OIDC session cookies. See .env.example.',
          );
        }
        const cookieKeys = cookieKeysStr.split(',').filter(Boolean);

        const privateKeyPath =
          configService.get<string>('jwt.privateKeyPath') || '';
        const publicKeyPath =
          configService.get<string>('jwt.publicKeyPath') || '';

        // Same shape as linkeon-partner below: undefined means "use the secret
        // stored on the OAuthClient row". It used to fall back to a literal
        // committed in this file, so any environment without the variable set
        // authenticated the walletx client with a secret published in the repo
        // — and rotating the DB row changed nothing, because the constant
        // overrode it.
        const walletxClientSecret =
          process.env.WALLETX_CLIENT_SECRET || undefined;

        // Confidential secret for the linkeon-partner verifiedPartner client,
        // kept in env (undefined falls back to the DB row's clientSecret).
        const linkeonPartnerClientSecret =
          process.env.LINKEON_PARTNER_CLIENT_SECRET || undefined;

        return createOidcProvider({
          issuer,
          prisma,
          redisClient: redis.getClient(),
          privateKeyPath,
          publicKeyPath,
          cookieKeys,
          walletxClientSecret,
          linkeonPartnerClientSecret,
        });
      },
      inject: [ConfigService, PrismaService, RedisService],
    },
  ],
  exports: [OIDC_PROVIDER, OidcService],
})
export class OidcModule {}
