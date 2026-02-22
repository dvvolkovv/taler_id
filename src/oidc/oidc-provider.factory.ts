import * as crypto from 'crypto';
import * as fs from 'fs';
import type Redis from 'ioredis';
import type { PrismaService } from '../prisma/prisma.service';
import { RedisOidcAdapter } from './adapters/redis-adapter.js';

export interface OidcProviderConfig {
  issuer: string;
  prisma: PrismaService;
  redisClient: Redis;
  privateKeyPath: string;
  publicKeyPath: string;
  cookieKeys: string[];
  walletxClientSecret: string;
}

export async function createOidcProvider(config: OidcProviderConfig) {
  // Dynamic import for ESM-only oidc-provider
  const { default: Provider } = await import('oidc-provider');

  const privateKeyPem = fs.readFileSync(config.privateKeyPath, 'utf8');
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const jwk: any = privateKey.export({ format: 'jwk' });
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  jwk.kid = 'taler-id-rsa';

  // Load OAuth clients from database
  const dbClients = await config.prisma.oAuthClient.findMany();
  const clients = dbClients.map((c) => ({
    client_id: c.clientId,
    client_secret: c.clientId === 'walletx' ? config.walletxClientSecret : c.clientSecret,
    redirect_uris: c.redirectUris,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: c.allowedScopes.join(' '),
    token_endpoint_auth_method: 'client_secret_basic' as const,
    client_name: c.name,
    logo_uri: c.logoUri || undefined,
  }));

  const provider = new Provider(config.issuer, {
    adapter: (model: string) => new RedisOidcAdapter(model, config.redisClient),

    jwks: { keys: [jwk] },

    clients,

    claims: {
      openid: ['sub'],
      profile: ['name', 'given_name', 'family_name', 'middle_name', 'locale', 'updated_at'],
      email: ['email', 'email_verified'],
      phone: ['phone_number', 'phone_number_verified'],
      kyc: ['kyc_status', 'kyc_type', 'kyc_verified_at'],
      wallet: ['wallet_address'],
    },

    scopes: ['openid', 'profile', 'email', 'phone', 'kyc', 'wallet', 'offline_access'],

    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true },
      userinfo: { enabled: true },
    },

    pkce: {
      required: () => true,
    },

    responseTypes: ['code'],

    ttl: {
      AccessToken: 900,
      AuthorizationCode: 60,
      IdToken: 3600,
      RefreshToken: 30 * 24 * 3600,
      Interaction: 600,
      Session: 14 * 24 * 3600,
      Grant: 30 * 24 * 3600,
    },

    cookies: {
      keys: config.cookieKeys,
      long: { httpOnly: true, sameSite: 'lax' as const },
      short: { httpOnly: true, sameSite: 'lax' as const },
    },

    interactions: {
      url: (_ctx: any, interaction: any) => {
        return `/oauth/interaction/${interaction.uid}`;
      },
    },

    findAccount: async (_ctx: any, sub: string) => {
      const user = await config.prisma.user.findUnique({
        where: { id: sub },
        include: { profile: true, kycRecord: true },
      });
      if (!user) return undefined;

      return {
        accountId: sub,
        async claims(_use: string, scope: string) {
          const scopes = typeof scope === 'string' ? scope.split(' ') : [];
          const result: Record<string, any> = { sub };

          if (scopes.includes('profile') && user.profile) {
            result.given_name = user.profile.firstName;
            result.family_name = user.profile.lastName;
            result.middle_name = user.profile.middleName;
            result.name = [user.profile.firstName, user.profile.lastName]
              .filter(Boolean)
              .join(' ');
            result.locale = user.profile.language;
            result.updated_at = Math.floor(user.profile.updatedAt.getTime() / 1000);
          }

          if (scopes.includes('email')) {
            result.email = user.email;
            result.email_verified = user.emailVerified;
          }

          if (scopes.includes('phone')) {
            result.phone_number = user.phone;
            result.phone_number_verified = user.phoneVerified;
          }

          if (scopes.includes('kyc') && user.kycRecord) {
            result.kyc_status = user.kycRecord.status;
            result.kyc_type = user.kycRecord.kycType;
            result.kyc_verified_at = user.kycRecord.verifiedAt
              ? user.kycRecord.verifiedAt.toISOString()
              : null;
          }

          if (scopes.includes('wallet') && user.profile) {
            result.wallet_address = user.profile.walletAddress;
          }

          return result;
        },
      };
    },

    rotateRefreshToken: true,
  });

  return provider;
}
