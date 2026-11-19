import * as crypto from 'crypto';
import * as fs from 'fs';
import type Redis from 'ioredis';
import type { PrismaService } from '../prisma/prisma.service';
import { RedisOidcAdapter } from './adapters/redis-adapter.js';
import { PrismaClientAdapter } from './adapters/prisma-client-adapter.js';
import { MCP_SCOPES } from '../mcp/mcp.constants';
import { MESSENGER_SCOPE } from '../partner-core/partner.constants';
import {
  COMPANIES_SCOPE,
  SELECTION_TTL_DAYS,
} from '../companies/companies.constants';
import { createLoadExistingGrant } from '../companies/load-existing-grant';
import { createFindAccount } from './find-account';

export interface OidcProviderConfig {
  issuer: string;
  prisma: PrismaService;
  redisClient: Redis;
  privateKeyPath: string;
  publicKeyPath: string;
  cookieKeys: string[];
  walletxClientSecret?: string;
  linkeonPartnerClientSecret?: string;
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

  const provider = new Provider(config.issuer, {
    adapter: (model: string) => {
      if (model === 'Client') {
        return new PrismaClientAdapter(
          config.prisma,
          config.walletxClientSecret,
          config.linkeonPartnerClientSecret,
        );
      }
      return new RedisOidcAdapter(model, config.redisClient);
    },

    jwks: { keys: [jwk] },

    claims: {
      openid: ['sub'],
      profile: [
        'name',
        'given_name',
        'family_name',
        'middle_name',
        'locale',
        'updated_at',
      ],
      email: ['email', 'email_verified'],
      phone: ['phone_number', 'phone_number_verified'],
      kyc: ['kyc_status', 'kyc_type', 'kyc_verified_at'],
      wallet: ['wallet_address'],
      [COMPANIES_SCOPE]: ['acting_as', 'companies'],
    },

    scopes: [
      'openid',
      'profile',
      'email',
      'phone',
      'kyc',
      'wallet',
      // Только клиентам, которым выдан вручную; через DCR не получить
      // (prisma-client-adapter). Спека 2026-11-19-companies-oauth-design.md.
      COMPANIES_SCOPE,
      'offline_access',
      // единый источник — mcp.constants: новый MCP-scope нельзя «забыть» в OIDC
      ...MCP_SCOPES,
      // Токены партнёров (nadi) выпускает только партнёрский API на сервере.
      // Через DCR этот scope не получить — prisma-client-adapter его вырезает;
      // на consent-экран он не попадёт, потому что есть только в allowedScopes
      // партнёрских клиентов, а у них нет redirect URI.
      MESSENGER_SCOPE,
    ],

    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true },
      userinfo: { enabled: true },
      registration: {
        // env читается при старте — для переключения нужен рестарт процесса
        enabled: process.env.OIDC_DCR_ENABLED === 'true',
      },
    },

    pkce: {
      required: () => true,
    },

    // сужение дефолта намеренное: JWT-методы (client_secret_jwt/private_key_jwt)
    // не использует ни один клиент; 'none' нужен public MCP-клиентам (PKCE)
    clientAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],

    responseTypes: ['code'],

    // Партнёрские токены узнаются по виду «43 символа base64url»: формат access-токенов (formats)
    // не менять без PARTNER_TOKEN_FORMAT в src/partner-core/partner-tokens.service.ts.
    ttl: {
      AccessToken: 900,
      AuthorizationCode: 60,
      IdToken: 3600,
      RefreshToken: 30 * 24 * 3600,
      Interaction: 600,
      Session: 14 * 24 * 3600,
      // Выбор компаний чистится по тому же сроку (company-selection.ts): если
      // поднять одно без другого, второй вход стирал бы ещё живой выбор.
      Grant: SELECTION_TTL_DAYS * 24 * 3600,
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

    loadExistingGrant: createLoadExistingGrant(config.prisma),

    findAccount: createFindAccount(config.prisma),

    rotateRefreshToken: true,
  });

  return provider;
}
