export default () => ({
  port: parseInt(process.env.PORT ?? '3000', 10) || 3000,
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  jwt: {
    privateKeyPath: process.env.JWT_PRIVATE_KEY_PATH,
    publicKeyPath: process.env.JWT_PUBLIC_KEY_PATH,
    accessExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshExpiry: process.env.JWT_REFRESH_EXPIRY || '30d',
  },
  oidc: {
    issuer:
      process.env.OIDC_ISSUER ||
      `${process.env.BASE_URL || 'http://localhost:3000'}/oauth`,
    cookieKeys: process.env.OIDC_COOKIE_KEYS || 'taler-oidc-default-key',
  },
  database: {
    url: process.env.DATABASE_URL,
  },
  redis: {
    url: process.env.REDIS_URL,
  },
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS ?? '12', 10) || 12,
    bruteForceMaxAttempts:
      parseInt(process.env.BRUTE_FORCE_MAX_ATTEMPTS ?? '5', 10) || 5,
    bruteForceLockouttMinutes:
      parseInt(process.env.BRUTE_FORCE_LOCKOUT_MINUTES ?? '15', 10) || 15,
  },
  email: {
    smtp: {
      host: process.env.SMTP_HOST || 'localhost',
      port: parseInt(process.env.SMTP_PORT ?? '587', 10) || 587,
      user: process.env.SMTP_USER || '',
      pass: process.env.SMTP_PASS || '',
    },
  },
  // KYC config (we run against an internal mock_ss service — SumSub-compatible
  // wire contract, no HMAC, no app token; the env names keep the `SUMSUB_`
  // prefix to avoid breaking existing infra/scripts/secrets).
  sumsub: {
    baseUrl:
      process.env.SUMSUB_BASE_URL || 'https://mockss-test.up.railway.app',
    levelName: process.env.SUMSUB_LEVEL_NAME || 'trientes-kyc-level',
    kybLevelName: process.env.SUMSUB_KYB_LEVEL_NAME || 'basic-kyb-level',
    ttlInSecs: parseInt(process.env.SUMSUB_TTL_SECS || '600', 10) || 600,
    webhookSecret: process.env.SUMSUB_WEBHOOK_SECRET || '',
  },
});
