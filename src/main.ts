import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { AuditLogInterceptor } from './common/interceptors/audit-log.interceptor';
import { PrismaService } from './prisma/prisma.service';
import { OIDC_PROVIDER } from './oidc/oidc.service';
import { RedisService } from './redis/redis.service';
import { GatingService } from './billing/services/gating.service';
import { RedisIoAdapter } from './redis-io.adapter';
import { WebSocket, WebSocketServer } from 'ws';
import { verify, type JwtPayload } from 'jsonwebtoken';
import * as fs from 'fs';
import { isApiAccessToken } from './common/utils/access-token.util';
import { json } from 'express';
import { VoiceGateService } from './voice-gate/voice-gate.service';
import { PcmWindow, wrapWavMono, pcmRms16 } from './voice-gate/pcm-window';

// The realtime proxy talks to OpenAI on the server's own API key, and the model
// used to come straight from a query parameter — so anyone holding a token
// could point it at the most expensive realtime model and burn credits at
// whatever rate they liked. No shipped client sends `model` at all; the
// parameter survives only as an allow-listed override for experiments.
const DEFAULT_REALTIME_MODEL = 'gpt-realtime-mini-2025-12-15';
const ALLOWED_REALTIME_MODELS = new Set(
  (process.env.REALTIME_ALLOWED_MODELS ?? DEFAULT_REALTIME_MODEL)
    .split(',')
    .map((m) => m.trim())
    .filter(Boolean),
);

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['log', 'warn', 'error'],
    rawBody: true,
  });

  // Increase body size limit for large meeting transcripts (default ~100KB is too small)
  app.use(json({ limit: '10mb' }));

  // Socket.IO across multiple app nodes (DO load balancer): relay room joins
  // and emits through Redis pub/sub so `new_message` reaches a recipient whose
  // socket lives on a different node. Must be set before gateways init.
  const redisIoAdapter = new RedisIoAdapter(app);
  await redisIoAdapter.connectToRedis();
  app.useWebSocketAdapter(redisIoAdapter);

  // Container sanity: a STATIC module appearing twice means Nest built two
  // instances of it (e.g. forwardRef inside a dynamic module's imports) and
  // every gateway/cron in it runs twice. Bit us 2026-06-16..07-18: a second
  // MessengerGateway double-handled every socket event and double-sent every
  // call VoIP push. Dynamic modules (Config/Bull/ServeStatic...) legitimately
  // repeat, so only flag names we know are static.
  {
    const { ModulesContainer } = await import('@nestjs/core');
    const names = [...app.get(ModulesContainer).values()]
      .map((m) => m.metatype?.name)
      .filter((n): n is string => !!n && !/^(ConfigModule|ConfigHostModule|BullModule|ScheduleModule|ServeStaticModule|JwtModule|PassportModule|ThrottlerModule|HttpModule)$/.test(n));
    const dup = [...new Set(names.filter((n, i) => names.indexOf(n) !== i))];
    if (dup.length) {
      console.error(`[BOOT-GUARD] duplicated static modules in container: ${dup.join(', ')} — a gateway in them will double-handle every event!`);
    }
  }

  // Swagger/OpenAPI Configuration
  const config = new DocumentBuilder()
    .setTitle('Taler ID API')
    .setDescription(
      'Identity Provider API - Authentication, KYC/KYB, and OAuth 2.0 Provider',
    )
    .setVersion('1.0')
    .setContact('Taler Team', 'https://taler.tirol', '')
    .addServer('http://localhost:3000', 'Local Development')
    .addServer('https://id.taler.tirol', 'Production')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter JWT token',
      },
      'JWT',
    )
    .addOAuth2(
      {
        type: 'oauth2',
        description: 'OAuth 2.0 Authorization Code + PKCE',
        flows: {
          authorizationCode: {
            authorizationUrl: 'https://id.taler.tirol/oauth/auth',
            tokenUrl: 'https://id.taler.tirol/oauth/token',
            scopes: {
              openid: 'Verify identity (required)',
              profile: 'Name, locale, updated_at',
              email: 'Email address and verification status',
              phone: 'Phone number and verification status',
              kyc: 'KYC status, type, and verification date',
              wallet: 'Blockchain wallet address',
              offline_access: 'Refresh token for long-lived access',
            },
          },
        },
      },
      'OAuth2',
    )
    .addTag('auth', 'Authentication endpoints')
    .addTag('users', 'User management')
    .addTag('kyc', 'KYC/KYB verification')
    .addTag('tenant', 'Tenant management')
    .addTag('sessions', 'Session management')
    .addTag('admin', 'Admin endpoints')
    .addTag('oauth', 'OAuth 2.0 / OpenID Connect Provider')
    .addTag(
      'oauth-interaction',
      'OAuth interaction endpoints (login & consent)',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);

  // Add oidc-provider endpoints (served by Express middleware, not NestJS controllers)
  document.paths['/oauth/auth'] = {
    get: {
      tags: ['oauth'],
      summary: 'Authorization Endpoint',
      description:
        'Initiates the OAuth 2.0 Authorization Code + PKCE flow. Redirects to the login/consent interaction page.',
      parameters: [
        {
          name: 'client_id',
          in: 'query',
          required: true,
          schema: { type: 'string' },
          description: 'Registered OAuth client ID',
          example: 'walletx',
        },
        {
          name: 'response_type',
          in: 'query',
          required: true,
          schema: { type: 'string', enum: ['code'] },
          description: 'Must be "code"',
        },
        {
          name: 'scope',
          in: 'query',
          required: true,
          schema: { type: 'string' },
          description: 'Space-separated scopes',
          example: 'openid profile email kyc wallet',
        },
        {
          name: 'redirect_uri',
          in: 'query',
          required: true,
          schema: { type: 'string' },
          description: "Must match one of client's registered redirect URIs",
        },
        {
          name: 'code_challenge',
          in: 'query',
          required: true,
          schema: { type: 'string' },
          description: 'PKCE code challenge (BASE64URL(SHA256(code_verifier)))',
        },
        {
          name: 'code_challenge_method',
          in: 'query',
          required: true,
          schema: { type: 'string', enum: ['S256'] },
          description: 'Must be "S256"',
        },
        {
          name: 'state',
          in: 'query',
          required: false,
          schema: { type: 'string' },
          description: 'Opaque value for CSRF protection',
        },
        {
          name: 'nonce',
          in: 'query',
          required: false,
          schema: { type: 'string' },
          description: 'Random value included in id_token',
        },
      ],
      responses: {
        '303': {
          description: 'Redirect to interaction page for login/consent',
        },
        '400': { description: 'Invalid request parameters' },
      },
    },
  };
  document.paths['/oauth/token'] = {
    post: {
      tags: ['oauth'],
      summary: 'Token Endpoint',
      description:
        'Exchange authorization code for tokens, or refresh an access token.',
      requestBody: {
        required: true,
        content: {
          'application/x-www-form-urlencoded': {
            schema: {
              type: 'object',
              properties: {
                grant_type: {
                  type: 'string',
                  enum: ['authorization_code', 'refresh_token'],
                  description: 'Grant type',
                },
                code: {
                  type: 'string',
                  description:
                    'Authorization code (for authorization_code grant)',
                },
                redirect_uri: {
                  type: 'string',
                  description:
                    'Must match the redirect_uri used in /oauth/auth',
                },
                code_verifier: {
                  type: 'string',
                  description:
                    'PKCE code verifier (plain random string, 43-128 chars)',
                },
                refresh_token: {
                  type: 'string',
                  description: 'Refresh token (for refresh_token grant)',
                },
                client_id: {
                  type: 'string',
                  description: 'Client ID (if not using Basic auth)',
                },
              },
              required: ['grant_type'],
            },
          },
        },
      },
      responses: {
        '200': {
          description: 'Token response',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  access_token: { type: 'string' },
                  token_type: { type: 'string', example: 'Bearer' },
                  expires_in: { type: 'number', example: 900 },
                  id_token: {
                    type: 'string',
                    description: 'JWT with user claims',
                  },
                  refresh_token: { type: 'string' },
                  scope: { type: 'string' },
                },
              },
            },
          },
        },
        '400': {
          description: 'Invalid grant, expired code, or invalid code_verifier',
        },
        '401': { description: 'Invalid client credentials' },
      },
      security: [{ basicAuth: [] }],
    },
  };
  document.paths['/oauth/me'] = {
    get: {
      tags: ['oauth'],
      summary: 'UserInfo Endpoint',
      description:
        'Returns claims about the authenticated user based on the scopes granted.',
      security: [{ OAuth2: ['openid'] }],
      responses: {
        '200': {
          description: 'User claims',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  sub: { type: 'string', description: 'User ID' },
                  name: {
                    type: 'string',
                    description: 'Full name (scope: profile)',
                  },
                  given_name: {
                    type: 'string',
                    description: 'First name (scope: profile)',
                  },
                  family_name: {
                    type: 'string',
                    description: 'Last name (scope: profile)',
                  },
                  email: {
                    type: 'string',
                    description: 'Email address (scope: email)',
                  },
                  email_verified: {
                    type: 'boolean',
                    description: 'Email verified (scope: email)',
                  },
                  phone_number: {
                    type: 'string',
                    description: 'Phone number (scope: phone)',
                  },
                  phone_number_verified: {
                    type: 'boolean',
                    description: 'Phone verified (scope: phone)',
                  },
                  kyc_status: {
                    type: 'string',
                    enum: ['NONE', 'PENDING', 'APPROVED', 'REJECTED'],
                    description: 'KYC status (scope: kyc)',
                  },
                  kyc_type: {
                    type: 'string',
                    description: 'KYC type (scope: kyc)',
                  },
                  kyc_verified_at: {
                    type: 'string',
                    format: 'date-time',
                    description: 'KYC verification date (scope: kyc)',
                  },
                  wallet_address: {
                    type: 'string',
                    description: 'Blockchain wallet (scope: wallet)',
                  },
                },
              },
            },
          },
        },
        '401': { description: 'Missing or invalid access token' },
      },
    },
  };
  document.paths['/oauth/token/revocation'] = {
    post: {
      tags: ['oauth'],
      summary: 'Token Revocation',
      description: 'Revoke an access token or refresh token.',
      requestBody: {
        required: true,
        content: {
          'application/x-www-form-urlencoded': {
            schema: {
              type: 'object',
              properties: {
                token: { type: 'string', description: 'Token to revoke' },
                token_type_hint: {
                  type: 'string',
                  enum: ['access_token', 'refresh_token'],
                },
              },
              required: ['token'],
            },
          },
        },
      },
      responses: {
        '200': { description: 'Token revoked successfully' },
      },
      security: [{ basicAuth: [] }],
    },
  };
  document.paths['/oauth/jwks'] = {
    get: {
      tags: ['oauth'],
      summary: 'JSON Web Key Set',
      description:
        'Returns the public keys used to verify JWT signatures (id_token, access_token).',
      responses: {
        '200': {
          description: 'JWKS',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  keys: {
                    type: 'array',
                    items: {
                      type: 'object',
                      properties: {
                        kty: { type: 'string', example: 'RSA' },
                        use: { type: 'string', example: 'sig' },
                        kid: { type: 'string', example: 'taler-id-rsa' },
                        alg: { type: 'string', example: 'RS256' },
                        n: { type: 'string' },
                        e: { type: 'string' },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  };
  document.paths['/oauth/.well-known/openid-configuration'] = {
    get: {
      tags: ['oauth'],
      summary: 'OpenID Connect Discovery',
      description:
        'Returns the OpenID Connect provider configuration. All endpoints, supported scopes, claims, and algorithms.',
      responses: {
        '200': { description: 'OIDC Discovery document' },
      },
    },
  };
  document.paths['/oauth/session/end'] = {
    get: {
      tags: ['oauth'],
      summary: 'End Session (Logout)',
      description:
        'Terminates the OIDC session. Accepts id_token_hint and post_logout_redirect_uri.',
      parameters: [
        {
          name: 'id_token_hint',
          in: 'query',
          schema: { type: 'string' },
          description: 'Previously issued id_token',
        },
        {
          name: 'post_logout_redirect_uri',
          in: 'query',
          schema: { type: 'string' },
          description: 'URL to redirect after logout',
        },
      ],
      responses: {
        '200': { description: 'Session ended' },
        '303': { description: 'Redirect to post_logout_redirect_uri' },
      },
    },
  };

  // Add Basic Auth security scheme for token endpoint
  if (!document.components) document.components = {};
  if (!document.components.securitySchemes)
    document.components.securitySchemes = {};
  (document.components.securitySchemes as any).basicAuth = {
    type: 'http',
    scheme: 'basic',
    description: 'Client credentials: client_id:client_secret',
  };

  SwaggerModule.setup('docs', app, document, {
    customSiteTitle: 'Taler ID API Docs',
    customfavIcon: 'https://taler.tirol/favicon.ico',
    customCss: '.swagger-ui .topbar { display: none }',
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
      docExpansion: 'list',
      filter: true,
      showExtensions: true,
      tryItOutEnabled: true,
    },
  });

  // Security headers (Flutter Web + Google Fonts + Swagger UI)
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: [
            "'self'",
            "'unsafe-inline'",
            "'wasm-unsafe-eval'",
            'https://static.sumsub.com',
            'https://www.gstatic.com',
            'https://cdn.jsdelivr.net',
          ],
          scriptSrcAttr: ["'unsafe-inline'"],
          styleSrc: [
            "'self'",
            "'unsafe-inline'",
            'https://fonts.googleapis.com',
          ],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
          connectSrc: [
            "'self'",
            'wss://id.taler.tirol',
            'wss://staging.id.taler.tirol',
            'https://api.sumsub.com',
            'wss://api.sumsub.com',
            'https://www.gstatic.com',
            'https://fonts.gstatic.com',
            'https://travel-n8n.up.railway.app',
            'https://cdn.jsdelivr.net',
          ],
          frameSrc: [
            "'self'",
            'https://api.sumsub.com',
            'https://*.sumsub.com',
          ],
          mediaSrc: ["'self'", 'blob:', 'https://*.sumsub.com'],
          workerSrc: ["'self'", 'blob:'],
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
    }),
  );

  // CORS
  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || [
      'http://localhost:3001',
      'http://localhost:8080',
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });

  // Global validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Global exception filter
  app.useGlobalFilters(new HttpExceptionFilter());

  // Audit log interceptor
  const prismaService = app.get(PrismaService);
  app.useGlobalInterceptors(new AuditLogInterceptor(prismaService));

  // Mount oidc-provider at /oauth
  const expressApp = app.getHttpAdapter().getInstance();

  // nginx terminates TLS and forwards to us over loopback (on DO the managed
  // LB and the Selectel RU edge sit in front of nginx, which resolves the real
  // client via real_ip before proxying). Without this Express reports the
  // proxy's own address as req.ip, so the global ThrottlerGuard buckets every
  // client on the planet into a single counter — the per-IP limits never bite
  // — and audit log and session rows record the proxy instead of the caller.
  // Trusting only loopback means an outside client cannot forge
  // X-Forwarded-For: the header is rewritten by our own nginx.
  expressApp.set('trust proxy', process.env.TRUST_PROXY ?? 'loopback');
  const oidcProvider = app.get(OIDC_PROVIDER);
  oidcProvider.proxy = true;

  // Log OIDC provider errors for debugging
  oidcProvider.on('server_error', (_ctx: any, err: any) => {
    Logger.error(
      `OIDC server_error: ${err.message}`,
      err.stack,
      'OidcProvider',
    );
  });
  oidcProvider.on('authorization.error', (_ctx: any, err: any) => {
    Logger.error(
      `OIDC authorization.error: ${err.message}`,
      err.stack,
      'OidcProvider',
    );
  });
  oidcProvider.on('grant.error', (_ctx: any, err: any) => {
    Logger.error(`OIDC grant.error: ${err.message}`, err.stack, 'OidcProvider');
  });

  // DCR registration rate-limit: 10/min per IP (защита от мусорной регистрации клиентов)
  const redisService = app.get(RedisService);
  expressApp.use('/oauth/reg', async (req: any, res: any, next: any) => {
    if (req.method !== 'POST') return next();
    // Use LAST XFF entry — spoof-resistant: appended by our trusted nginx
    // (first entries are client-supplied and can be forged).
    const xff = String(req.headers['x-forwarded-for'] ?? '');
    const ip = xff.split(',').pop()?.trim() || req.ip || 'unknown';
    const key = `dcr_rl:${ip}`;
    try {
      // Atomic pipeline: INCR + EXPIRE in one round-trip — avoids a permanent
      // key (no TTL) if the process dies between the two calls. TTL resets on
      // each request (sliding window) — acceptable for a 10-req/min gate.
      const results = await redisService.getClient().multi().incr(key).expire(key, 60).exec();
      const count = Number(results?.[0]?.[1] ?? 0);
      if (count > 10) {
        return res.status(429).json({ error: 'too_many_requests' });
      }
    } catch (_err) {
      // Redis unavailable — fail-open so DCR registration stays available
      Logger.warn('DCR rate-limit: Redis error, failing open', 'OidcProvider');
    }
    return next();
  });

  const oidcCallback = oidcProvider.callback();
  expressApp.use('/oauth', (req: any, res: any, next: any) => {
    // Let NestJS handle interaction endpoints, self-service client management,
    // and the native-mobile consent endpoints.
    // Note: req.url here is the path AFTER stripping the '/oauth' mount prefix
    // (e.g. '/oauth/register' arrives as '/register').
    if (
      req.url.startsWith('/interaction') ||
      req.url.startsWith('/register') ||
      req.url.startsWith('/clients') ||
      req.url.startsWith('/mobile') ||
      req.url.startsWith('/account')
    ) {
      return next();
    }
    return oidcCallback(req, res);
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  Logger.log(`Taler ID running on port ${port}`, 'Bootstrap');
  Logger.log(
    `Swagger UI available at http://localhost:${port}/docs`,
    'Bootstrap',
  );
  Logger.log(
    `OIDC Provider at ${process.env.OIDC_ISSUER || 'http://localhost:' + port + '/oauth'}`,
    'Bootstrap',
  );
  // --- WebSocket Proxy: /voice/realtime-proxy -> OpenAI Realtime ---
  const voiceGate = app.get(VoiceGateService);
  const ownerVoiceWindowMs = parseFloat(
    process.env.OWNER_VOICE_WINDOW_MS ?? '1000',
  );
  // 16 samples/ms × 2 bytes per int16 = 32 bytes/ms PCM; round to whole sample
  // OpenAI Realtime audio is 24kHz mono int16 PCM: 48 bytes per ms.
  const ownerVoiceWindowBytes = Math.round(ownerVoiceWindowMs * 48);
  const wss = new WebSocketServer({ noServer: true });
  const httpServer = app.getHttpServer();
  const gatingService = app.get(GatingService);

  // Idempotent zombie-session reaper: called from WS cleanup so a network drop
  // / app crash stops the billing cron from draining the wallet forever.
  // See incident 2026-05-26 (vdv): 10 active voice_assistant sessions tickled
  // backend-cron for 5–8 days each because closeVoiceSession HTTP was never
  // hit. Ownership check guards against a client passing someone else's id.
  const closeBillingSession = async (sessionId: string, userId: string) => {
    try {
      const session = await prismaService.aiSession.findUnique({
        where: { id: sessionId },
        select: { userId: true, status: true },
      });
      if (!session || session.userId !== userId) return;
      if (session.status !== 'active') return;
      await gatingService.endSession(sessionId, 'completed');
    } catch (err) {
      Logger.warn(
        `WS-cleanup endSession failed for ${sessionId}: ${String(err)}`,
        'RealtimeProxy',
      );
    }
  };

  httpServer.prependListener('upgrade', (req: any, socket: any, head: any) => {
    console.log('[PROXY] upgrade req:', req.url?.substring(0, 50));
    const urlStr = req.url as string;
    if (!urlStr.startsWith('/voice/realtime-proxy')) {
      // Let Socket.io and other WebSocket handlers manage their own connections
      return;
    }
    const url = new URL(urlStr, 'wss://localhost');
    const token =
      url.searchParams.get('token') ||
      (req.headers.authorization as string | undefined)?.replace(
        'Bearer ',
        '',
      ) ||
      '';
    const jwtPublicKey = fs.readFileSync(
      process.env.JWT_PUBLIC_KEY_PATH as string,
      'utf8',
    );
    let userIdFromToken: string | null = null;
    try {
      const payload = verify(token, jwtPublicKey, {
        algorithms: ['RS256'],
      }) as JwtPayload & { sub?: string };
      // OIDC ID tokens carry the same signature — they must not open the
      // realtime proxy, which spends OpenAI credits on the server key.
      if (!isApiAccessToken(payload)) throw new Error('Not an access token');
      userIdFromToken =
        typeof payload?.sub === 'string' ? payload.sub : null;
    } catch {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    const billingSessionId = url.searchParams.get('billingSessionId');
    wss.handleUpgrade(req, socket, head, (clientWs) => {
      const requestedModel = url.searchParams.get('model');
      if (requestedModel && !ALLOWED_REALTIME_MODELS.has(requestedModel)) {
        Logger.warn(
          `proxy: refused model "${requestedModel}" (userId=${userIdFromToken}), using default`,
          'RealtimeProxy',
        );
      }
      const model =
        requestedModel && ALLOWED_REALTIME_MODELS.has(requestedModel)
          ? requestedModel
          : DEFAULT_REALTIME_MODEL;
      // Per-session voice-gate state
      let ownerEmbedding: number[] = [];
      let responseInFlight = false;
      const pcmWindow = new PcmWindow(ownerVoiceWindowBytes);
      // Anti-flap gating state: silence windows never vote (RMS gate).
      // With 3-sec windows a single speech-energy verdict is reliable
      // (owner ~0.31-0.55, others <0.2 with windowed enrollment), so one
      // non-owner window retracts immediately — with 2 the reaction lagged
      // behind OpenAI's VAD commit and foreign turns slipped through.
      let nonOwnerStreak = 0;
      const VOICE_GATE_MIN_RMS = 400;
      const VOICE_GATE_STREAK = 1;
      // Ring of recently committed user input item ids: on a non-owner
      // verdict the buffer may already be committed, so buffer.clear alone
      // is not enough — delete the committed conversation items too.
      const recentUserItemIds: string[] = [];
      let verifyInFlight = false;

      // Known race: fire-and-forget Prisma.findUnique here means audio frames
      // arriving in the first ~tens of ms have `ownerEmbedding.length === 0`
      // and bypass the gate. Acceptable for the experimental flag — a brief
      // non-owner exposure window is better than blocking the user's first
      // word behind a DB roundtrip.
      if (voiceGate.isEnabled() && userIdFromToken) {
        prismaService.profile
          .findUnique({ where: { userId: userIdFromToken } })
          .then((p) => {
            ownerEmbedding = (p as any)?.ownerEmbedding ?? [];
            if (ownerEmbedding.length === 0) {
              Logger.warn(
                `proxy: owner not enrolled (userId=${userIdFromToken}), gating skipped`,
                'RealtimeProxy',
              );
            }
          })
          .catch((e: any) =>
            Logger.warn(
              `proxy: load ownerEmbedding failed: ${e.message}`,
              'RealtimeProxy',
            ),
          );
      }

      // GA Realtime WS endpoint — the OpenAI-Beta: realtime=v1 header was
      // removed when the API graduated (2026-05-20). Sending it on GA
      // closes the socket immediately after connect.
      const openaiWs = new WebSocket(
        'wss://api.openai.com/v1/realtime?model=' + model,
        {
          headers: {
            Authorization: 'Bearer ' + process.env.OPENAI_API_KEY,
          },
        },
      );
      // Beta→GA session.update shape transform. Shipped 1.0.78 clients still
      // send the flat beta layout (voice, input_audio_format, turn_detection
      // at session root); GA wants everything nested under `audio.input`/
      // `audio.output`. Rewrite on the fly so existing TestFlight/APK builds
      // keep working. A native GA-shape session.update passes through unchanged.
      const transformSessionUpdate = (raw: any): any => {
        if (raw?.type !== 'session.update' || !raw.session) return raw;
        const s = raw.session;
        // Already GA-shape (has `audio` block or `type: 'realtime'`): pass through.
        if (s.audio || s.type === 'realtime' || s.output_modalities) return raw;
        // Detect any beta-only field to decide whether to migrate.
        const hasBetaFields =
          'voice' in s ||
          'input_audio_format' in s ||
          'output_audio_format' in s ||
          'input_audio_transcription' in s ||
          'turn_detection' in s ||
          'modalities' in s;
        if (!hasBetaFields) return raw;
        const ga: any = { type: 'realtime' };
        if (s.instructions) ga.instructions = s.instructions;
        if (s.tools) ga.tools = s.tools;
        if (s.tool_choice) ga.tool_choice = s.tool_choice;
        if (s.temperature !== undefined) ga.temperature = s.temperature;
        if (s.max_response_output_tokens !== undefined) {
          ga.max_response_output_tokens = s.max_response_output_tokens;
        }
        // modalities → output_modalities (audio always present, text optional)
        if (Array.isArray(s.modalities)) {
          ga.output_modalities = s.modalities.includes('audio')
            ? ['audio']
            : ['text'];
        }
        const audio: any = {};
        const inputAudio: any = {};
        if (s.input_audio_format === 'pcm16') {
          inputAudio.format = { type: 'audio/pcm', rate: 24000 };
        }
        if (s.input_audio_transcription) {
          inputAudio.transcription = s.input_audio_transcription;
        }
        if (s.turn_detection) inputAudio.turn_detection = s.turn_detection;
        if (Object.keys(inputAudio).length) audio.input = inputAudio;
        const outputAudio: any = {};
        if (s.output_audio_format === 'pcm16') {
          outputAudio.format = { type: 'audio/pcm', rate: 24000 };
        }
        if (s.voice) outputAudio.voice = s.voice;
        if (Object.keys(outputAudio).length) audio.output = outputAudio;
        if (Object.keys(audio).length) ga.audio = audio;
        return { ...raw, session: ga };
      };

      // Buffer messages from client until OpenAI WS is ready to avoid dropping session.update
      const clientMessageQueue: any[] = [];
      let openaiReady = false;
      let sessionConfigured = false;
      clientWs.on('message', (data: any, isBinary: boolean) => {
        // Apply the beta→GA shim to non-binary JSON events. Binary frames
        // are raw PCM audio and pass through unchanged.
        let outData: any = data;
        let outBin = isBinary;
        // Parse JSON once at the top; reuse for shim, gating, and voice-gate
        // tap downstream. Audio frames at 50/s make per-message work matter.
        let parsedClient: any = null;
        if (!isBinary) {
          try {
            parsedClient = JSON.parse(data.toString());
            const transformed = transformSessionUpdate(parsedClient);
            if (transformed !== parsedClient) {
              outData = JSON.stringify(transformed);
              outBin = false;
            }
          } catch (_) {
            // not JSON, pass through
          }
        }
        const forwardToOpenAI = (d: any, bin: boolean) => {
          if (openaiWs.readyState === WebSocket.OPEN) {
            openaiWs.send(bin ? d : d.toString(), { binary: bin });
          }
        };
        if (openaiReady) {
          if (sessionConfigured) {
            forwardToOpenAI(outData, outBin);
          } else {
            // Wait for session.updated before forwarding audio to OpenAI
            try {
              const parsed = JSON.parse(outData.toString());
              if (parsed.type !== 'input_audio_buffer.append') {
                forwardToOpenAI(outData, outBin);
              }
            } catch (_) {
              forwardToOpenAI(outData, outBin);
            }
          }
        } else {
          // Only queue config messages (session.update, etc.), drop audio until OpenAI is ready
          try {
            const parsed = JSON.parse(outData.toString());
            if (parsed.type !== 'input_audio_buffer.append') {
              clientMessageQueue.push({ data: outData, isBinary: outBin });
            }
          } catch (_) {}
        }
        // Voice-gate tap (added in 2.3): extract base64 PCM from
        // input_audio_buffer.append frames, accumulate into a 1-sec window,
        // verify against owner embedding via the local sidecar. On non-owner
        // verdict, inject retract events into the OpenAI socket.
        if (
          voiceGate.isEnabled() &&
          ownerEmbedding.length > 0 &&
          parsedClient &&
          !verifyInFlight
        ) {
          try {
            if (
              parsedClient.type === 'input_audio_buffer.append' &&
              typeof parsedClient.audio === 'string'
            ) {
              const window = pcmWindow.appendBase64(parsedClient.audio);
              if (window && pcmRms16(window) >= VOICE_GATE_MIN_RMS) {
                verifyInFlight = true;
                const wav = wrapWavMono(window, 24_000);
                voiceGate
                  .verify(wav, ownerEmbedding)
                  .then((verdict) => {
                    verifyInFlight = false;
                    Logger.log(
                      JSON.stringify({
                        ns: 'voice-gate.verify',
                        userId: userIdFromToken,
                        cosine: verdict.similarity ?? null,
                        verdict:
                          verdict.isOwner === true
                            ? 'owner'
                            : verdict.isOwner === false
                            ? 'non_owner'
                            : 'fail_open',
                        audioSec: verdict.audioSec ?? null,
                        embedLatencyMs: verdict.manaxLatencyMs ?? null,
                      }),
                      'voice-gate.verify',
                    );
                    if (verdict.isOwner === true) {
                      nonOwnerStreak = 0;
                    } else if (verdict.isOwner === false) {
                      nonOwnerStreak += 1;
                      if (
                        nonOwnerStreak >= VOICE_GATE_STREAK &&
                        openaiWs.readyState === WebSocket.OPEN
                      ) {
                        nonOwnerStreak = 0;
                        openaiWs.send(
                          JSON.stringify({ type: 'input_audio_buffer.clear' }),
                        );
                        if (responseInFlight) {
                          openaiWs.send(
                            JSON.stringify({ type: 'response.cancel' }),
                          );
                        }
                        // Retract turns OpenAI already committed from this
                        // foreign speech — buffer.clear only covers the
                        // uncommitted tail.
                        while (recentUserItemIds.length > 0) {
                          const itemId = recentUserItemIds.pop();
                          openaiWs.send(
                            JSON.stringify({
                              type: 'conversation.item.delete',
                              item_id: itemId,
                            }),
                          );
                        }
                        Logger.log(
                          JSON.stringify({
                            ns: 'voice-gate.retract',
                            userId: userIdFromToken,
                          }),
                          'voice-gate.retract',
                        );
                      }
                    }
                  })
                  .catch((e: any) => {
                    verifyInFlight = false;
                    Logger.warn(
                      `voice-gate verify exception: ${e.message}`,
                      'RealtimeProxy',
                    );
                  });
              }
            }
          } catch {
            // ignore parse errors; not all messages are JSON we care about
          }
        }
      });
      openaiWs.on('open', () => {
        openaiReady = true;
        // Flush buffered messages (e.g. session.update sent before OpenAI WS opened)
        while (clientMessageQueue.length > 0) {
          const item = clientMessageQueue.shift();
          if (openaiWs.readyState === WebSocket.OPEN) {
            openaiWs.send(item.isBinary ? item.data : item.data.toString(), {
              binary: item.isBinary,
            });
          }
        }
        openaiWs.on('message', (data: any, isBinary: boolean) => {
          let outData = data;
          let outBin = isBinary;
          try {
            const ev = JSON.parse(data.toString());
            if (ev.type === 'session.updated') {
              sessionConfigured = true;
              Logger.log('session.updated received from OpenAI', 'RealtimeProxy');
            }
            if (ev.type === 'response.created') responseInFlight = true;
            if (
              ev.type === 'conversation.item.created' &&
              ev.item?.role === 'user' &&
              typeof ev.item?.id === 'string'
            ) {
              recentUserItemIds.push(ev.item.id);
              if (recentUserItemIds.length > 4) recentUserItemIds.shift();
            }
            if (
              ev.type === 'response.done' ||
              ev.type === 'response.cancelled'
            ) {
              responseInFlight = false;
            }
            if (ev.type === 'session.created') {
              Logger.log(
                'session.created from OpenAI (model=' + (ev.session?.model || '?') + ')',
                'RealtimeProxy',
              );
            }
            if (ev.type === 'error') {
              Logger.warn(
                'OpenAI WS error event: ' + JSON.stringify(ev.error || ev),
                'RealtimeProxy',
              );
            }
            // GA → beta event name rewrite for shipped 1.0.78 clients. GA
            // renamed the audio/transcript response stream events; the mobile
            // handler still listens on the beta names.
            const GA_TO_BETA_EVENT_RENAME: Record<string, string> = {
              'response.output_audio.delta': 'response.audio.delta',
              'response.output_audio.done': 'response.audio.done',
              'response.output_audio_transcript.delta':
                'response.audio_transcript.delta',
              'response.output_audio_transcript.done':
                'response.audio_transcript.done',
            };
            const renamed = GA_TO_BETA_EVENT_RENAME[ev.type];
            if (renamed) {
              ev.type = renamed;
              outData = JSON.stringify(ev);
              outBin = false;
            }
          } catch (_) {}
          if (clientWs.readyState === WebSocket.OPEN)
            clientWs.send(outBin ? outData : outData.toString(), {
              binary: outBin,
            });
        });
      });
      const cleanup = () => {
        try {
          if (openaiWs.readyState === WebSocket.OPEN) openaiWs.close();
        } catch (e) {}
        try {
          if (clientWs.readyState === WebSocket.OPEN) clientWs.close();
        } catch (e) {}
        if (billingSessionId && userIdFromToken) {
          void closeBillingSession(billingSessionId, userIdFromToken);
        }
      };
      clientWs.on('close', cleanup);
      openaiWs.on('close', cleanup);
      openaiWs.on('error', (err: Error) => {
        Logger.error('OpenAI WS error: ' + err.message, 'RealtimeProxy');
        cleanup();
      });
      clientWs.on('error', (err: Error) => {
        Logger.error('Client WS error: ' + err.message, 'RealtimeProxy');
        cleanup();
      });
    });
  });
  Logger.log(
    'WebSocket Realtime Proxy ready at /voice/realtime-proxy',
    'Bootstrap',
  );
}

bootstrap();
