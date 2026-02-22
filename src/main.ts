import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { AuditLogInterceptor } from './common/interceptors/audit-log.interceptor';
import { PrismaService } from './prisma/prisma.service';
import { OIDC_PROVIDER } from './oidc/oidc.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['log', 'warn', 'error'],
    rawBody: true,
  });

  // Swagger/OpenAPI Configuration
  const config = new DocumentBuilder()
    .setTitle('Taler ID API')
    .setDescription('Identity Provider API - Authentication, KYC/KYB, and OAuth 2.0 Provider')
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
    .addTag('oauth-interaction', 'OAuth interaction endpoints (login & consent)')
    .build();

  const document = SwaggerModule.createDocument(app, config);

  // Add oidc-provider endpoints (served by Express middleware, not NestJS controllers)
  document.paths['/oauth/auth'] = {
    get: {
      tags: ['oauth'],
      summary: 'Authorization Endpoint',
      description: 'Initiates the OAuth 2.0 Authorization Code + PKCE flow. Redirects to the login/consent interaction page.',
      parameters: [
        { name: 'client_id', in: 'query', required: true, schema: { type: 'string' }, description: 'Registered OAuth client ID', example: 'walletx' },
        { name: 'response_type', in: 'query', required: true, schema: { type: 'string', enum: ['code'] }, description: 'Must be "code"' },
        { name: 'scope', in: 'query', required: true, schema: { type: 'string' }, description: 'Space-separated scopes', example: 'openid profile email kyc wallet' },
        { name: 'redirect_uri', in: 'query', required: true, schema: { type: 'string' }, description: 'Must match one of client\'s registered redirect URIs' },
        { name: 'code_challenge', in: 'query', required: true, schema: { type: 'string' }, description: 'PKCE code challenge (BASE64URL(SHA256(code_verifier)))' },
        { name: 'code_challenge_method', in: 'query', required: true, schema: { type: 'string', enum: ['S256'] }, description: 'Must be "S256"' },
        { name: 'state', in: 'query', required: false, schema: { type: 'string' }, description: 'Opaque value for CSRF protection' },
        { name: 'nonce', in: 'query', required: false, schema: { type: 'string' }, description: 'Random value included in id_token' },
      ],
      responses: {
        '303': { description: 'Redirect to interaction page for login/consent' },
        '400': { description: 'Invalid request parameters' },
      },
    },
  };
  document.paths['/oauth/token'] = {
    post: {
      tags: ['oauth'],
      summary: 'Token Endpoint',
      description: 'Exchange authorization code for tokens, or refresh an access token.',
      requestBody: {
        required: true,
        content: {
          'application/x-www-form-urlencoded': {
            schema: {
              type: 'object',
              properties: {
                grant_type: { type: 'string', enum: ['authorization_code', 'refresh_token'], description: 'Grant type' },
                code: { type: 'string', description: 'Authorization code (for authorization_code grant)' },
                redirect_uri: { type: 'string', description: 'Must match the redirect_uri used in /oauth/auth' },
                code_verifier: { type: 'string', description: 'PKCE code verifier (plain random string, 43-128 chars)' },
                refresh_token: { type: 'string', description: 'Refresh token (for refresh_token grant)' },
                client_id: { type: 'string', description: 'Client ID (if not using Basic auth)' },
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
                  id_token: { type: 'string', description: 'JWT with user claims' },
                  refresh_token: { type: 'string' },
                  scope: { type: 'string' },
                },
              },
            },
          },
        },
        '400': { description: 'Invalid grant, expired code, or invalid code_verifier' },
        '401': { description: 'Invalid client credentials' },
      },
      security: [{ basicAuth: [] }],
    },
  };
  document.paths['/oauth/me'] = {
    get: {
      tags: ['oauth'],
      summary: 'UserInfo Endpoint',
      description: 'Returns claims about the authenticated user based on the scopes granted.',
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
                  name: { type: 'string', description: 'Full name (scope: profile)' },
                  given_name: { type: 'string', description: 'First name (scope: profile)' },
                  family_name: { type: 'string', description: 'Last name (scope: profile)' },
                  email: { type: 'string', description: 'Email address (scope: email)' },
                  email_verified: { type: 'boolean', description: 'Email verified (scope: email)' },
                  phone_number: { type: 'string', description: 'Phone number (scope: phone)' },
                  phone_number_verified: { type: 'boolean', description: 'Phone verified (scope: phone)' },
                  kyc_status: { type: 'string', enum: ['NONE', 'PENDING', 'APPROVED', 'REJECTED'], description: 'KYC status (scope: kyc)' },
                  kyc_type: { type: 'string', description: 'KYC type (scope: kyc)' },
                  kyc_verified_at: { type: 'string', format: 'date-time', description: 'KYC verification date (scope: kyc)' },
                  wallet_address: { type: 'string', description: 'Blockchain wallet (scope: wallet)' },
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
                token_type_hint: { type: 'string', enum: ['access_token', 'refresh_token'] },
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
      description: 'Returns the public keys used to verify JWT signatures (id_token, access_token).',
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
      description: 'Returns the OpenID Connect provider configuration. All endpoints, supported scopes, claims, and algorithms.',
      responses: {
        '200': { description: 'OIDC Discovery document' },
      },
    },
  };
  document.paths['/oauth/session/end'] = {
    get: {
      tags: ['oauth'],
      summary: 'End Session (Logout)',
      description: 'Terminates the OIDC session. Accepts id_token_hint and post_logout_redirect_uri.',
      parameters: [
        { name: 'id_token_hint', in: 'query', schema: { type: 'string' }, description: 'Previously issued id_token' },
        { name: 'post_logout_redirect_uri', in: 'query', schema: { type: 'string' }, description: 'URL to redirect after logout' },
      ],
      responses: {
        '200': { description: 'Session ended' },
        '303': { description: 'Redirect to post_logout_redirect_uri' },
      },
    },
  };

  // Add Basic Auth security scheme for token endpoint
  if (!document.components) document.components = {};
  if (!document.components.securitySchemes) document.components.securitySchemes = {};
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
          scriptSrc: ["'self'", "'unsafe-inline'", "'wasm-unsafe-eval'", 'https://static.sumsub.com', 'https://www.gstatic.com'],
          scriptSrcAttr: ["'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
          connectSrc: ["'self'", 'https://api.sumsub.com', 'wss://api.sumsub.com', 'https://www.gstatic.com', 'https://fonts.gstatic.com', 'https://travel-n8n.up.railway.app'],
          frameSrc: ["'self'", 'https://api.sumsub.com', 'https://*.sumsub.com'],
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
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3001', 'http://localhost:8080'],
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
  const oidcProvider = app.get(OIDC_PROVIDER);
  oidcProvider.proxy = true;

  // Log OIDC provider errors for debugging
  oidcProvider.on('server_error', (_ctx: any, err: any) => {
    Logger.error(`OIDC server_error: ${err.message}`, err.stack, 'OidcProvider');
  });
  oidcProvider.on('authorization.error', (_ctx: any, err: any) => {
    Logger.error(`OIDC authorization.error: ${err.message}`, err.stack, 'OidcProvider');
  });
  oidcProvider.on('grant.error', (_ctx: any, err: any) => {
    Logger.error(`OIDC grant.error: ${err.message}`, err.stack, 'OidcProvider');
  });

  const oidcCallback = oidcProvider.callback();
  expressApp.use('/oauth', (req: any, res: any, next: any) => {
    // Let NestJS handle interaction endpoints
    if (req.url.startsWith('/interaction')) {
      return next();
    }
    return oidcCallback(req, res);
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  Logger.log(`Taler ID running on port ${port}`, 'Bootstrap');
  Logger.log(`Swagger UI available at http://localhost:${port}/docs`, 'Bootstrap');
  Logger.log(`OIDC Provider at ${process.env.OIDC_ISSUER || 'http://localhost:' + port + '/oauth'}`, 'Bootstrap');
}

bootstrap();
