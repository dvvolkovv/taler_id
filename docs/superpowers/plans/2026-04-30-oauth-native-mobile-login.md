# OAuth Native Mobile Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перехват `https://id.taler.tirol/oauth/authorize` мобильным приложением Taler ID через Universal Links/App Links, с нативным consent UI и graceful fallback на браузерный flow если app не установлен.

**Architecture:** Backend получает 2 новых endpoint в новом модуле `oauth-mobile/` для нативной выдачи authorization code в обход HTML interactions. Mobile app получает новую feature `oauth/` с экраном consent, bloc, и pending-state singleton для resume-after-login. Native config: AASA file на бэкенде + два intent-filter в Android manifest.

**Tech Stack:** NestJS 10, oidc-provider 9, Prisma. Flutter 3.6+, BLoC, GetIt, Freezed, go_router, app_links, flutter_secure_storage. nginx (для AASA MIME).

**Repos:**
- Backend: `~/taler-id/` (branch `main`, прямой push в `main` — конвенция backend репо)
- Mobile: `~/Downloads/taler_id_mobile/` (branch **`dev`** — никогда не коммитим в `main`)

**Spec:** `docs/superpowers/specs/2026-04-30-oauth-native-mobile-login-design.md`

---

## File Structure

### Backend (new files)
```
src/oauth-mobile/
├── oauth-mobile.module.ts             # Module wiring (imports OidcModule, AuthModule)
├── oauth-mobile.controller.ts         # GET /oauth/mobile/grant-info, POST /oauth/mobile/approve
├── oauth-mobile.service.ts            # getGrantInfo, approve
├── scope-descriptors.ts               # Static map: scope key → {label, description}
├── dto/
│   ├── oauth-authorize-query.dto.ts   # Query DTO for grant-info
│   └── oauth-approve.dto.ts           # Body DTO for approve
└── oauth-mobile.service.spec.ts       # Unit tests

test/oauth-mobile.e2e-spec.ts          # E2E test: approve → exchange code via /oauth/token

public/.well-known/apple-app-site-association  # AASA, no extension
```

### Backend (modify)
- `src/app.module.ts` — register `OAuthMobileModule`
- nginx site config DEV (`89.169.55.217`) + PROD (`138.124.61.221`)

### Mobile (new files)
```
lib/features/oauth/
├── domain/
│   ├── entities/
│   │   ├── oauth_authorize_params.dart      # Freezed
│   │   ├── grant_info.dart                  # Freezed
│   │   └── scope_descriptor.dart            # Freezed
│   └── repositories/
│       └── oauth_repository.dart            # abstract
├── data/
│   ├── datasources/
│   │   └── oauth_remote_datasource.dart     # Dio
│   ├── repositories/
│   │   └── oauth_repository_impl.dart
│   └── oauth_pending_request.dart           # Singleton with secure_storage backing
└── presentation/
    ├── bloc/
    │   ├── oauth_authorize_bloc.dart
    │   ├── oauth_authorize_event.dart
    │   └── oauth_authorize_state.dart
    └── screens/
        └── oauth_authorize_screen.dart

test/features/oauth/
├── oauth_authorize_bloc_test.dart
├── oauth_authorize_screen_test.dart
└── oauth_pending_request_test.dart
```

### Mobile (modify)
- `lib/core/router/deep_link_handler.dart` — branch для `/oauth/authorize`
- `lib/core/router/app_router.dart` — новый GoRoute + `_globalRedirect` логика
- `lib/core/utils/constants.dart` — `RouteConstants.oauthAuthorize`
- `lib/core/di/dependencies.dart` — DI registration
- `lib/features/auth/presentation/bloc/auth_bloc.dart` — resume after login
- `android/app/src/main/AndroidManifest.xml` — два intent-filter

---

## Pre-flight

### Task 0: Verify clean working state in both repos

**Files:** none (state check only)

- [ ] **Step 1: Check backend working tree clean**

```bash
cd ~/taler-id && git status --short && git branch --show-current
```
Expected: empty status, branch `main`. If not clean, stash or commit before proceeding.

- [ ] **Step 2: Check mobile repo state**

```bash
cd ~/Downloads/taler_id_mobile && git status --short && git branch --show-current
```
Expected: empty status, branch `dev`. **If branch is not `dev` — `git checkout dev` first.** Mobile app commits go on `dev`, never `main`.

- [ ] **Step 3: Pull latest in both repos**

```bash
cd ~/taler-id && git pull origin main
cd ~/Downloads/taler_id_mobile && git pull origin dev
```

---

## Phase I: Backend foundation

### Task 1: Scope descriptors (static metadata for consent UI)

**Files:**
- Create: `~/taler-id/src/oauth-mobile/scope-descriptors.ts`
- Test: `~/taler-id/src/oauth-mobile/scope-descriptors.spec.ts`

- [ ] **Step 1: Write the failing test**

Create `~/taler-id/src/oauth-mobile/scope-descriptors.spec.ts`:
```typescript
import { describeScopes, KNOWN_SCOPES } from './scope-descriptors';

describe('scope-descriptors', () => {
  it('returns descriptors for known scopes', () => {
    const result = describeScopes(['profile', 'email']);
    expect(result).toEqual([
      { key: 'profile', label: 'Профиль', description: 'Имя, фамилия, аватар' },
      { key: 'email', label: 'Email', description: 'Email адрес' },
    ]);
  });

  it('falls back to capitalised key for unknown scopes', () => {
    const result = describeScopes(['custom_scope']);
    expect(result).toEqual([
      { key: 'custom_scope', label: 'custom_scope', description: 'Доступ к custom_scope' },
    ]);
  });

  it('preserves order of input', () => {
    const result = describeScopes(['email', 'profile', 'openid']);
    expect(result.map((s) => s.key)).toEqual(['email', 'profile', 'openid']);
  });

  it('exposes KNOWN_SCOPES constant for tests', () => {
    expect(Object.keys(KNOWN_SCOPES)).toEqual(
      expect.arrayContaining(['openid', 'profile', 'email', 'offline_access']),
    );
  });
});
```

- [ ] **Step 2: Verify test fails**

```bash
cd ~/taler-id && npx jest src/oauth-mobile/scope-descriptors.spec.ts
```
Expected: FAIL with "Cannot find module './scope-descriptors'".

- [ ] **Step 3: Implement**

Create `~/taler-id/src/oauth-mobile/scope-descriptors.ts`:
```typescript
export interface ScopeDescriptor {
  key: string;
  label: string;
  description: string;
}

export const KNOWN_SCOPES: Record<string, Omit<ScopeDescriptor, 'key'>> = {
  openid: { label: 'OpenID', description: 'Идентификатор аккаунта' },
  profile: { label: 'Профиль', description: 'Имя, фамилия, аватар' },
  email: { label: 'Email', description: 'Email адрес' },
  offline_access: { label: 'Offline доступ', description: 'Поддержка работы без сети (refresh token)' },
};

export function describeScopes(scopes: string[]): ScopeDescriptor[] {
  return scopes.map((key) => {
    const known = KNOWN_SCOPES[key];
    if (known) return { key, ...known };
    return { key, label: key, description: `Доступ к ${key}` };
  });
}
```

- [ ] **Step 4: Run test**

```bash
cd ~/taler-id && npx jest src/oauth-mobile/scope-descriptors.spec.ts
```
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
cd ~/taler-id && git add src/oauth-mobile/scope-descriptors.ts src/oauth-mobile/scope-descriptors.spec.ts && git commit -m "$(cat <<'EOF'
feat(oauth-mobile): add scope descriptors for consent UI

Maps OAuth scope keys to user-facing labels in Russian. Used by mobile
flow to render consent screen.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: DTOs for grant-info query and approve body

**Files:**
- Create: `~/taler-id/src/oauth-mobile/dto/oauth-authorize-query.dto.ts`
- Create: `~/taler-id/src/oauth-mobile/dto/oauth-approve.dto.ts`

(No tests — DTOs are validated indirectly via controller e2e in Task 6.)

- [ ] **Step 1: Create OAuthAuthorizeQueryDto**

Create `~/taler-id/src/oauth-mobile/dto/oauth-authorize-query.dto.ts`:
```typescript
import { IsIn, IsNotEmpty, IsOptional, IsString, IsUrl } from 'class-validator';

export class OAuthAuthorizeQueryDto {
  @IsString()
  @IsNotEmpty()
  client_id!: string;

  @IsString()
  @IsNotEmpty()
  @IsUrl({ require_tld: false, protocols: ['http', 'https'], require_protocol: true })
  redirect_uri!: string;

  @IsString()
  @IsNotEmpty()
  scope!: string;

  @IsString()
  @IsIn(['code'])
  response_type!: 'code';

  @IsOptional()
  @IsString()
  state?: string;

  @IsOptional()
  @IsString()
  code_challenge?: string;

  @IsOptional()
  @IsString()
  @IsIn(['S256'])
  code_challenge_method?: 'S256';

  @IsOptional()
  @IsString()
  nonce?: string;
}
```

- [ ] **Step 2: Create OAuthApproveDto**

Create `~/taler-id/src/oauth-mobile/dto/oauth-approve.dto.ts`:
```typescript
import { IsIn, IsNotEmpty, IsOptional, IsString, IsUrl } from 'class-validator';

export class OAuthApproveDto {
  @IsString()
  @IsNotEmpty()
  client_id!: string;

  @IsString()
  @IsNotEmpty()
  @IsUrl({ require_tld: false, protocols: ['http', 'https'], require_protocol: true })
  redirect_uri!: string;

  @IsString()
  @IsNotEmpty()
  scope!: string;

  @IsString()
  @IsIn(['code'])
  response_type!: 'code';

  @IsString()
  @IsIn(['S256'])
  code_challenge_method!: 'S256';

  @IsString()
  @IsNotEmpty()
  code_challenge!: string;

  @IsOptional()
  @IsString()
  state?: string;

  @IsOptional()
  @IsString()
  nonce?: string;
}
```

Note: For `approve`, `code_challenge` and `code_challenge_method` are required (PKCE-only enforcement). For `grant-info` they're optional because the call only renders consent UI.

- [ ] **Step 3: Verify DTOs compile**

```bash
cd ~/taler-id && npx tsc --noEmit
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
cd ~/taler-id && git add src/oauth-mobile/dto/ && git commit -m "$(cat <<'EOF'
feat(oauth-mobile): add DTOs for grant-info and approve endpoints

OAuthAuthorizeQueryDto for GET /oauth/mobile/grant-info, OAuthApproveDto
for POST /oauth/mobile/approve. PKCE enforcement: approve requires
code_challenge with S256.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: OAuthMobileService.getGrantInfo

**Files:**
- Create: `~/taler-id/src/oauth-mobile/oauth-mobile.service.ts`
- Create: `~/taler-id/src/oauth-mobile/oauth-mobile.service.spec.ts`

- [ ] **Step 1: Write the failing test**

Create `~/taler-id/src/oauth-mobile/oauth-mobile.service.spec.ts`:
```typescript
import { Test } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { OAuthMobileService } from './oauth-mobile.service';
import { OidcService } from '../oidc/oidc.service';
import { PrismaService } from '../prisma/prisma.service';

describe('OAuthMobileService.getGrantInfo', () => {
  let svc: OAuthMobileService;
  let oidc: jest.Mocked<OidcService>;
  let prisma: jest.Mocked<PrismaService>;
  let providerMock: any;

  beforeEach(async () => {
    providerMock = {
      Client: { find: jest.fn() },
    };
    oidc = { getProvider: jest.fn(() => providerMock) } as any;
    prisma = { oAuthGrant: { findFirst: jest.fn() } } as any;
    const moduleRef = await Test.createTestingModule({
      providers: [
        OAuthMobileService,
        { provide: OidcService, useValue: oidc },
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();
    svc = moduleRef.get(OAuthMobileService);
  });

  const baseParams = {
    client_id: 'mybook',
    redirect_uri: 'https://example.com/cb',
    scope: 'profile email',
    response_type: 'code' as const,
  };

  it('throws NotFoundException when client not found', async () => {
    providerMock.Client.find.mockResolvedValue(undefined);
    await expect(svc.getGrantInfo('user-1', baseParams)).rejects.toThrow(NotFoundException);
  });

  it('throws BadRequestException when redirect_uri not in registered list', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://other.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    await expect(svc.getGrantInfo('user-1', baseParams)).rejects.toThrow(/redirect_uri/);
  });

  it('throws BadRequestException when scope not subset of allowed', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile',
      tokenEndpointAuthMethod: 'none',
    });
    await expect(svc.getGrantInfo('user-1', baseParams)).rejects.toThrow(/invalid_scope/);
  });

  it('throws BadRequestException for confidential client', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
    await expect(svc.getGrantInfo('user-1', baseParams)).rejects.toThrow(
      /confidential_client_not_supported_via_mobile/,
    );
  });

  it('returns grant info with remembered=false when no existing grant', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      logoUri: 'https://example.com/logo.png',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue(null);

    const result = await svc.getGrantInfo('user-1', baseParams);
    expect(result).toEqual({
      client_name: 'MyBook',
      client_logo: 'https://example.com/logo.png',
      scopes: [
        { key: 'profile', label: 'Профиль', description: 'Имя, фамилия, аватар' },
        { key: 'email', label: 'Email', description: 'Email адрес' },
      ],
      remembered: false,
    });
  });

  it('returns remembered=true when existing grant covers requested scopes', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email openid',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue({
      scope: 'profile email openid',
    });

    const result = await svc.getGrantInfo('user-1', baseParams);
    expect(result.remembered).toBe(true);
  });

  it('returns remembered=false when existing grant has narrower scope', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    (prisma.oAuthGrant as any).findFirst.mockResolvedValue({
      scope: 'profile',
    });

    const result = await svc.getGrantInfo('user-1', baseParams);
    expect(result.remembered).toBe(false);
  });
});
```

- [ ] **Step 2: Verify test fails**

```bash
cd ~/taler-id && npx jest src/oauth-mobile/oauth-mobile.service.spec.ts
```
Expected: FAIL with "Cannot find module './oauth-mobile.service'".

- [ ] **Step 3: Add `OAuthGrant` model to Prisma schema (preflight check)**

The test uses `prisma.oAuthGrant.findFirst`. Check if it exists:
```bash
grep -n "model OAuthGrant\|oAuthGrant" ~/taler-id/prisma/schema.prisma
```

If `OAuthGrant` model does **not exist**, add it to `~/taler-id/prisma/schema.prisma` (after the `OAuthClient` model). The grant tracks which scopes a user has approved per client (used by `remembered` logic):

```prisma
model OAuthGrant {
  id        String   @id @default(uuid())
  userId    String
  clientId  String
  scope     String   // space-separated scopes
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  @@unique([userId, clientId])
  @@index([userId])
  @@index([clientId])
}
```

Generate migration:
```bash
cd ~/taler-id && npx prisma migrate dev --name add_oauth_grant
```
Expected: migration created in `prisma/migrations/`, prisma client regenerated.

If `OAuthGrant` already exists with different schema — adapt the test to match existing schema and ignore this step.

- [ ] **Step 4: Implement `getGrantInfo`**

Create `~/taler-id/src/oauth-mobile/oauth-mobile.service.ts`:
```typescript
import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { OidcService } from '../oidc/oidc.service';
import { PrismaService } from '../prisma/prisma.service';
import { describeScopes, ScopeDescriptor } from './scope-descriptors';
import type { OAuthAuthorizeQueryDto } from './dto/oauth-authorize-query.dto';

export interface GrantInfo {
  client_name: string;
  client_logo?: string;
  scopes: ScopeDescriptor[];
  remembered: boolean;
}

@Injectable()
export class OAuthMobileService {
  constructor(
    private readonly oidc: OidcService,
    private readonly prisma: PrismaService,
  ) {}

  async getGrantInfo(userId: string, params: OAuthAuthorizeQueryDto): Promise<GrantInfo> {
    const client = await this.findAndValidateClient(params);
    const requestedScopes = params.scope.trim().split(/\s+/).filter(Boolean);

    const grant = await (this.prisma as any).oAuthGrant.findFirst({
      where: { userId, clientId: params.client_id },
    });

    let remembered = false;
    if (grant) {
      const grantedScopes = new Set(
        (grant.scope as string).trim().split(/\s+/).filter(Boolean),
      );
      remembered = requestedScopes.every((s) => grantedScopes.has(s));
    }

    return {
      client_name: client.client_name,
      client_logo: client.logo_uri ?? undefined,
      scopes: describeScopes(requestedScopes),
      remembered,
    };
  }

  private async findAndValidateClient(params: {
    client_id: string;
    redirect_uri: string;
    scope: string;
  }): Promise<any> {
    const provider = this.oidc.getProvider();
    const client = await provider.Client.find(params.client_id);
    if (!client) {
      throw new NotFoundException({ error: 'unknown_client' });
    }

    const allowedRedirectUris: string[] = client.redirectUris ?? [];
    if (!allowedRedirectUris.includes(params.redirect_uri)) {
      throw new BadRequestException({ error: 'redirect_uri_mismatch' });
    }

    const allowedScopes = ((client.scope ?? '') as string).split(/\s+/).filter(Boolean);
    const requestedScopes = params.scope.trim().split(/\s+/).filter(Boolean);
    if (requestedScopes.length === 0) {
      throw new BadRequestException({ error: 'invalid_scope' });
    }
    const invalid = requestedScopes.filter((s) => !allowedScopes.includes(s));
    if (invalid.length > 0) {
      throw new BadRequestException({
        error: 'invalid_scope',
        error_description: `Scope not allowed: ${invalid.join(' ')}`,
      });
    }

    if (client.tokenEndpointAuthMethod !== 'none') {
      throw new BadRequestException({
        error: 'confidential_client_not_supported_via_mobile',
        error_description: 'This client requires client_secret; only public PKCE clients are supported in mobile flow.',
      });
    }

    return client;
  }
}
```

Note: The `oidc-provider`'s `Client.find()` returns the client metadata in oidc-provider naming (e.g., `client_name`, `redirect_uris`, `token_endpoint_auth_method`). However our `PrismaClientAdapter.find()` returns those exact snake_case keys (see `~/taler-id/src/oidc/adapters/prisma-client-adapter.ts`). The oidc-provider then **wraps** that into a Client instance with camelCase getters: `clientId`, `clientName`, `redirectUris`, `tokenEndpointAuthMethod`, `scope`.

If field access fails at runtime, log `Object.keys(client)` and adjust property names. The test mocks expose what we're targeting.

- [ ] **Step 5: Run test**

```bash
cd ~/taler-id && npx jest src/oauth-mobile/oauth-mobile.service.spec.ts
```
Expected: PASS, 6 tests for `getGrantInfo`.

- [ ] **Step 6: Commit**

```bash
cd ~/taler-id && git add src/oauth-mobile/oauth-mobile.service.ts src/oauth-mobile/oauth-mobile.service.spec.ts prisma/ && git commit -m "$(cat <<'EOF'
feat(oauth-mobile): add OAuthMobileService.getGrantInfo

Validates client_id, redirect_uri, scope, PKCE-only requirement, and
returns consent UI metadata. remembered=true when existing OAuthGrant
covers all requested scopes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: OAuthMobileService.approve

**Files:**
- Modify: `~/taler-id/src/oauth-mobile/oauth-mobile.service.ts`
- Modify: `~/taler-id/src/oauth-mobile/oauth-mobile.service.spec.ts`

- [ ] **Step 1: Add failing tests for approve**

Append to `~/taler-id/src/oauth-mobile/oauth-mobile.service.spec.ts`:
```typescript
describe('OAuthMobileService.approve', () => {
  let svc: OAuthMobileService;
  let oidc: jest.Mocked<OidcService>;
  let prisma: any;
  let providerMock: any;

  const baseParams = {
    client_id: 'mybook',
    redirect_uri: 'https://example.com/cb',
    scope: 'profile email',
    response_type: 'code' as const,
    code_challenge: 'CHALLENGE_ABC',
    code_challenge_method: 'S256' as const,
    state: 'state-123',
    nonce: 'nonce-456',
  };

  beforeEach(async () => {
    const grantSaveSpy = jest.fn().mockResolvedValue('grant-jti-789');
    const grantInstance = {
      addOIDCScope: jest.fn(),
      save: grantSaveSpy,
      jti: 'grant-jti-789',
    };
    const codeSaveSpy = jest.fn().mockResolvedValue('code-value-XYZ');
    const codeInstance = { save: codeSaveSpy };

    providerMock = {
      Client: {
        find: jest.fn().mockResolvedValue({
          clientId: 'mybook',
          clientName: 'MyBook',
          redirectUris: ['https://example.com/cb'],
          scope: 'profile email openid',
          tokenEndpointAuthMethod: 'none',
        }),
      },
      Grant: jest.fn(() => grantInstance),
      AuthorizationCode: jest.fn(() => codeInstance),
      _grantSpy: grantSaveSpy,
      _codeSpy: codeSaveSpy,
      _grantInstance: grantInstance,
      _codeInstance: codeInstance,
    };
    oidc = { getProvider: jest.fn(() => providerMock) } as any;
    prisma = {
      oAuthGrant: {
        findFirst: jest.fn().mockResolvedValue(null),
        upsert: jest.fn().mockResolvedValue({ id: 'grant-row-1' }),
      },
    };
    const moduleRef = await Test.createTestingModule({
      providers: [
        OAuthMobileService,
        { provide: OidcService, useValue: oidc },
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();
    svc = moduleRef.get(OAuthMobileService);
  });

  it('creates grant and authorization code, returns redirect_uri with code+state', async () => {
    const result = await svc.approve('user-1', baseParams);

    expect(providerMock.Grant).toHaveBeenCalledWith({
      accountId: 'user-1',
      clientId: 'mybook',
    });
    expect(providerMock._grantInstance.addOIDCScope).toHaveBeenCalledWith('profile email');
    expect(providerMock._grantSpy).toHaveBeenCalled();

    expect(providerMock.AuthorizationCode).toHaveBeenCalledWith(
      expect.objectContaining({
        accountId: 'user-1',
        clientId: 'mybook',
        redirectUri: 'https://example.com/cb',
        scope: 'profile email',
        grantId: 'grant-jti-789',
        codeChallenge: 'CHALLENGE_ABC',
        codeChallengeMethod: 'S256',
        nonce: 'nonce-456',
      }),
    );
    expect(providerMock._codeSpy).toHaveBeenCalled();

    expect(result.redirect_uri).toBe(
      'https://example.com/cb?code=code-value-XYZ&state=state-123',
    );
  });

  it('persists grant in OAuthGrant table for remembered logic', async () => {
    await svc.approve('user-1', baseParams);
    expect(prisma.oAuthGrant.upsert).toHaveBeenCalledWith({
      where: { userId_clientId: { userId: 'user-1', clientId: 'mybook' } },
      create: { userId: 'user-1', clientId: 'mybook', scope: 'profile email' },
      update: { scope: expect.stringMatching(/profile|email/) },
    });
  });

  it('merges scopes with existing grant on repeat approve', async () => {
    prisma.oAuthGrant.findFirst.mockResolvedValue({ scope: 'profile' });
    await svc.approve('user-1', { ...baseParams, scope: 'email' });
    expect(prisma.oAuthGrant.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: { scope: expect.stringMatching(/profile.*email|email.*profile/) },
      }),
    );
  });

  it('omits state from redirect_uri when not provided', async () => {
    const { state, ...paramsNoState } = baseParams;
    const result = await svc.approve('user-1', paramsNoState as any);
    expect(result.redirect_uri).toBe('https://example.com/cb?code=code-value-XYZ');
  });

  it('rejects confidential client', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
    await expect(svc.approve('user-1', baseParams)).rejects.toThrow(
      /confidential_client_not_supported_via_mobile/,
    );
  });

  it('rejects invalid redirect_uri', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://other.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    await expect(svc.approve('user-1', baseParams)).rejects.toThrow(/redirect_uri/);
  });
});
```

- [ ] **Step 2: Verify tests fail**

```bash
cd ~/taler-id && npx jest src/oauth-mobile/oauth-mobile.service.spec.ts -t approve
```
Expected: FAIL with "svc.approve is not a function".

- [ ] **Step 3: Implement `approve`**

Append to `~/taler-id/src/oauth-mobile/oauth-mobile.service.ts` (inside the class):
```typescript
  async approve(
    userId: string,
    params: import('./dto/oauth-approve.dto').OAuthApproveDto,
  ): Promise<{ redirect_uri: string }> {
    await this.findAndValidateClient(params);
    const requestedScope = params.scope.trim().split(/\s+/).filter(Boolean).join(' ');

    const provider = this.oidc.getProvider();

    const grant = new provider.Grant({
      accountId: userId,
      clientId: params.client_id,
    });
    grant.addOIDCScope(requestedScope);
    await grant.save();

    const code = new provider.AuthorizationCode({
      accountId: userId,
      clientId: params.client_id,
      redirectUri: params.redirect_uri,
      scope: requestedScope,
      grantId: grant.jti,
      codeChallenge: params.code_challenge,
      codeChallengeMethod: params.code_challenge_method,
      nonce: params.nonce,
    });
    const codeValue = await code.save();

    const existing = await (this.prisma as any).oAuthGrant.findFirst({
      where: { userId, clientId: params.client_id },
    });
    const mergedScopes = mergeScopes(existing?.scope ?? '', requestedScope);
    await (this.prisma as any).oAuthGrant.upsert({
      where: { userId_clientId: { userId, clientId: params.client_id } },
      create: { userId, clientId: params.client_id, scope: mergedScopes },
      update: { scope: mergedScopes },
    });

    const url = new URL(params.redirect_uri);
    url.searchParams.set('code', codeValue);
    if (params.state) url.searchParams.set('state', params.state);
    return { redirect_uri: url.toString() };
  }
}

function mergeScopes(existing: string, added: string): string {
  const set = new Set([
    ...existing.split(/\s+/).filter(Boolean),
    ...added.split(/\s+/).filter(Boolean),
  ]);
  return Array.from(set).join(' ');
}
```

Also at the top of the file, change:
```typescript
import type { OAuthAuthorizeQueryDto } from './dto/oauth-authorize-query.dto';
```
to:
```typescript
import type { OAuthAuthorizeQueryDto } from './dto/oauth-authorize-query.dto';
import type { OAuthApproveDto } from './dto/oauth-approve.dto';
```
And update the `findAndValidateClient` parameter type to a union (or keep as inline structural type, which is what the current shape already is — both DTOs share `client_id`, `redirect_uri`, `scope`).

- [ ] **Step 4: Run tests**

```bash
cd ~/taler-id && npx jest src/oauth-mobile/oauth-mobile.service.spec.ts
```
Expected: PASS, 11 tests total (6 getGrantInfo + 5 approve).

- [ ] **Step 5: Commit**

```bash
cd ~/taler-id && git add src/oauth-mobile/oauth-mobile.service.ts src/oauth-mobile/oauth-mobile.service.spec.ts && git commit -m "$(cat <<'EOF'
feat(oauth-mobile): add OAuthMobileService.approve

Creates oidc-provider Grant + AuthorizationCode for authenticated user,
upserts OAuthGrant row for remembered tracking, returns redirect_uri
with code+state. PKCE-only enforcement via DTO + service-level check.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Controller + module registration

**Files:**
- Create: `~/taler-id/src/oauth-mobile/oauth-mobile.controller.ts`
- Create: `~/taler-id/src/oauth-mobile/oauth-mobile.module.ts`
- Modify: `~/taler-id/src/app.module.ts`

- [ ] **Step 1: Implement controller**

Create `~/taler-id/src/oauth-mobile/oauth-mobile.controller.ts`:
```typescript
import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { OAuthAuthorizeQueryDto } from './dto/oauth-authorize-query.dto';
import { OAuthApproveDto } from './dto/oauth-approve.dto';
import { OAuthMobileService } from './oauth-mobile.service';

@Controller('oauth/mobile')
@UseGuards(JwtAuthGuard)
export class OAuthMobileController {
  constructor(private readonly svc: OAuthMobileService) {}

  @Get('grant-info')
  grantInfo(@CurrentUser() user: any, @Query() query: OAuthAuthorizeQueryDto) {
    return this.svc.getGrantInfo(user.sub, query);
  }

  @Post('approve')
  @Throttle({ short: { limit: 10, ttl: 60_000 } })
  approve(@CurrentUser() user: any, @Body() body: OAuthApproveDto) {
    return this.svc.approve(user.sub, body);
  }
}
```

- [ ] **Step 2: Implement module**

Create `~/taler-id/src/oauth-mobile/oauth-mobile.module.ts`:
```typescript
import { Module } from '@nestjs/common';
import { OidcModule } from '../oidc/oidc.module';
import { AuthModule } from '../auth/auth.module';
import { OAuthMobileController } from './oauth-mobile.controller';
import { OAuthMobileService } from './oauth-mobile.service';

@Module({
  imports: [OidcModule, AuthModule],
  controllers: [OAuthMobileController],
  providers: [OAuthMobileService],
})
export class OAuthMobileModule {}
```

- [ ] **Step 3: Register in AppModule**

Open `~/taler-id/src/app.module.ts`. Find the `imports: [...]` array. Add `OAuthMobileModule`:
```typescript
import { OAuthMobileModule } from './oauth-mobile/oauth-mobile.module';
// ...
@Module({
  imports: [
    // ...existing imports
    OAuthMobileModule,
  ],
})
```

- [ ] **Step 4: Verify backend compiles and starts**

```bash
cd ~/taler-id && npm run build
```
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
cd ~/taler-id && git add src/oauth-mobile/oauth-mobile.controller.ts src/oauth-mobile/oauth-mobile.module.ts src/app.module.ts && git commit -m "$(cat <<'EOF'
feat(oauth-mobile): wire controller and module

GET /oauth/mobile/grant-info, POST /oauth/mobile/approve.
Both under JwtAuthGuard. Approve throttled to 10/min/user.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: E2E test — approve → exchange code via /oauth/token

**Files:**
- Create: `~/taler-id/test/oauth-mobile.e2e-spec.ts`

- [ ] **Step 1: Write the e2e test**

Create `~/taler-id/test/oauth-mobile.e2e-spec.ts`:
```typescript
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { createHash, randomBytes } from 'crypto';

describe('OAuth Mobile E2E', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let userJwt: string;
  let userId: string;
  const clientId = 'e2e-mobile-' + Date.now();
  const redirectUri = 'https://e2e.example.com/cb';

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleRef.createNestApplication();
    await app.init();

    prisma = app.get(PrismaService);
    const jwt = app.get(JwtService);

    // Seed test user
    userId = 'e2e-user-' + Date.now();
    await prisma.user.create({
      data: {
        id: userId,
        email: `${userId}@test.com`,
        passwordHash: 'x',
        emailVerified: true,
      },
    });
    userJwt = jwt.sign({ sub: userId, email: `${userId}@test.com` });

    // Seed test client (public PKCE-only)
    await prisma.oAuthClient.create({
      data: {
        clientId,
        clientSecret: '',
        name: 'E2E Test Client',
        redirectUris: [redirectUri],
        allowedScopes: ['profile', 'email'],
        userId,
      },
    });
    // Mark as public for PrismaClientAdapter (it currently hardcodes
    // taler-id-developers; for the e2e to work we need to extend that
    // logic to consider clientSecret='' as public, OR use the
    // taler-id-developers client_id directly).
  });

  afterAll(async () => {
    await prisma.oAuthClient.deleteMany({ where: { clientId } });
    await prisma.user.deleteMany({ where: { id: userId } });
    await app.close();
  });

  it('grant-info → approve → exchange code via /oauth/token end-to-end', async () => {
    // PKCE: generate verifier + challenge
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');

    const params = {
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'profile email',
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 'e2e-state',
    };

    // 1. grant-info
    const grantInfoRes = await request(app.getHttpServer())
      .get('/oauth/mobile/grant-info')
      .query(params)
      .set('Authorization', `Bearer ${userJwt}`)
      .expect(200);
    expect(grantInfoRes.body.client_name).toBe('E2E Test Client');
    expect(grantInfoRes.body.remembered).toBe(false);

    // 2. approve
    const approveRes = await request(app.getHttpServer())
      .post('/oauth/mobile/approve')
      .send(params)
      .set('Authorization', `Bearer ${userJwt}`)
      .expect(200);
    const callbackUrl = new URL(approveRes.body.redirect_uri);
    expect(callbackUrl.searchParams.get('state')).toBe('e2e-state');
    const code = callbackUrl.searchParams.get('code');
    expect(code).toBeTruthy();

    // 3. Exchange via /oauth/token
    const tokenRes = await request(app.getHttpServer())
      .post('/oauth/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      })
      .expect(200);
    expect(tokenRes.body.access_token).toBeTruthy();
    expect(tokenRes.body.token_type).toBe('Bearer');

    // 4. Second grant-info → remembered=true
    const repeatRes = await request(app.getHttpServer())
      .get('/oauth/mobile/grant-info')
      .query(params)
      .set('Authorization', `Bearer ${userJwt}`)
      .expect(200);
    expect(repeatRes.body.remembered).toBe(true);
  });
});
```

- [ ] **Step 2: Extend PrismaClientAdapter to recognise empty clientSecret as public**

Currently `~/taler-id/src/oidc/adapters/prisma-client-adapter.ts` hardcodes `taler-id-developers` as the only public client. Extend to make any client with empty `clientSecret` public:

```typescript
const isPublicClient = c.clientId === 'taler-id-developers' || !c.clientSecret;
```

Without this change, the e2e seeded client would be treated as confidential and rejected by the approve endpoint.

- [ ] **Step 3: Run e2e test**

```bash
cd ~/taler-id && npx jest --config test/jest-e2e.json test/oauth-mobile.e2e-spec.ts --runInBand
```
Expected: PASS, 1 test. **If oidc-provider's Grant/AuthorizationCode API doesn't match assumptions** (e.g., constructor signature differs in v9), this is where we discover it. Adjust `oauth-mobile.service.ts` accordingly. Common fixes:
- `provider.AuthorizationCode` may need `claims` field (set to `{}`)
- `code.save()` may return an object instead of string — use `String(value)` if needed
- `Grant.find` may exist with different signature — for the test we don't need it

- [ ] **Step 4: Commit**

```bash
cd ~/taler-id && git add test/oauth-mobile.e2e-spec.ts src/oidc/adapters/prisma-client-adapter.ts && git commit -m "$(cat <<'EOF'
test(oauth-mobile): e2e — approve issues code redeemable via /oauth/token

End-to-end: seeded user → grant-info → approve → exchange with PKCE
verifier → access_token. Repeat grant-info shows remembered=true.

Treat any OAuthClient with empty clientSecret as public PKCE-only —
required for tests and future self-registered public clients via
Developer Portal.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Deploy backend to DEV

**Files:** none (deployment only)

- [ ] **Step 1: Push backend to remote**

```bash
cd ~/taler-id && git push origin main
```

- [ ] **Step 2: Deploy on DEV server**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm install && npx prisma migrate deploy && npm run build && pm2 restart taler-id-dev'
```
Expected: prisma migration applied (`add_oauth_grant`), `taler-id-dev` restarted online.

- [ ] **Step 3: Smoke endpoints with curl**

Get a JWT for `integration_test@taler-test.com` first (login):
```bash
curl -s -X POST https://staging.id.taler.tirol/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"integration_test@taler-test.com","password":"IntegrationTest123!"}' \
  | jq -r '.accessToken'
```

Then test `grant-info` with `taler-id-developers` (existing public client):
```bash
TOKEN="<paste from above>"
curl -s "https://staging.id.taler.tirol/oauth/mobile/grant-info?client_id=taler-id-developers&redirect_uri=https%3A%2F%2Fstaging.id.taler.tirol%2Fdevelopers%2F&scope=openid+profile&response_type=code" \
  -H "Authorization: Bearer $TOKEN" | jq
```
Expected: `{client_name, scopes: [...], remembered: false}`.

If 401 → check JWT, if 400 → check redirect_uri matches client's registered list, if 500 → `pm2 logs taler-id-dev` for the error.

---

## Phase II: Native config

### Task 8: Apple App Site Association file + nginx MIME

**Files:**
- Create: `~/taler-id/public/.well-known/apple-app-site-association`

- [ ] **Step 1: Create AASA file**

```bash
mkdir -p ~/taler-id/public/.well-known
```

Create `~/taler-id/public/.well-known/apple-app-site-association` (no extension):
```json
{
  "applinks": {
    "details": [
      {
        "appIDs": [
          "MG58MDUNZ2.tirol.taler.talerIdMobile",
          "MG58MDUNZ2.tirol.taler.talerIdMobile.dev"
        ],
        "components": [
          { "/": "/oauth/authorize", "?": { "*": "*" } },
          { "/": "/room/*" },
          { "/": "/ui/invite*" }
        ]
      }
    ]
  }
}
```

- [ ] **Step 2: Validate JSON locally**

```bash
cat ~/taler-id/public/.well-known/apple-app-site-association | jq .
```
Expected: parses without errors.

- [ ] **Step 3: Commit**

```bash
cd ~/taler-id && git add public/.well-known/apple-app-site-association && git commit -m "$(cat <<'EOF'
feat(oauth-mobile): add apple-app-site-association for Universal Links

Registers /oauth/authorize, /room/*, /ui/invite* paths for both prod
and dev iOS app IDs. Activates Universal Links interception on iPhone.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 4: Deploy AASA to DEV server**

```bash
cd ~/taler-id && git push origin main
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull'
```

The file lives in `~/taler-id/public/.well-known/`, but nginx serves from `/var/www/html/`. Copy:
```bash
ssh dvolkov@89.169.55.217 'sudo cp ~/taler-id/public/.well-known/apple-app-site-association /var/www/html/.well-known/apple-app-site-association && sudo chmod 644 /var/www/html/.well-known/apple-app-site-association'
```

- [ ] **Step 5: Configure nginx MIME for AASA on DEV**

SSH to DEV:
```bash
ssh dvolkov@89.169.55.217
```
Edit nginx site config (likely at `/etc/nginx/sites-available/staging.id.taler.tirol` or similar — list with `ls /etc/nginx/sites-enabled/`). Inside the `server { ... listen 443 ssl; ... }` block, add:
```nginx
location = /.well-known/apple-app-site-association {
    default_type application/json;
    add_header Content-Type application/json;
    try_files $uri =404;
}
```

Test config and reload:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

- [ ] **Step 6: Verify AASA reachable with correct MIME**

From your local machine:
```bash
curl -I https://staging.id.taler.tirol/.well-known/apple-app-site-association
```
Expected:
- `HTTP/2 200`
- `Content-Type: application/json`
- No redirect

```bash
curl -s https://staging.id.taler.tirol/.well-known/apple-app-site-association | jq .
```
Expected: the JSON we wrote.

---

### Task 9: Android intent-filters for `/oauth/authorize`

**Files:**
- Modify: `~/Downloads/taler_id_mobile/android/app/src/main/AndroidManifest.xml`

- [ ] **Step 1: Confirm we're on `dev` branch**

```bash
cd ~/Downloads/taler_id_mobile && git branch --show-current
```
Expected: `dev`. If not, `git checkout dev`.

- [ ] **Step 2: Add intent-filters**

Open `~/Downloads/taler_id_mobile/android/app/src/main/AndroidManifest.xml`. Find the existing `<intent-filter android:autoVerify="true">` block for `pathPrefix="/room/"`. **After** that block (and after the `/ui/invite` block), add two new intent-filter entries inside the same `<activity android:name=".MainActivity">`:

```xml
<!-- Deep links: https://id.taler.tirol/oauth/authorize -->
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="id.taler.tirol" android:pathPrefix="/oauth/authorize"/>
</intent-filter>
<!-- Deep links: https://staging.id.taler.tirol/oauth/authorize -->
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="staging.id.taler.tirol" android:pathPrefix="/oauth/authorize"/>
</intent-filter>
```

- [ ] **Step 3: Verify XML is well-formed**

```bash
cd ~/Downloads/taler_id_mobile && xmllint --noout android/app/src/main/AndroidManifest.xml
```
Expected: no output (well-formed). If `xmllint` not installed: `flutter pub get` and `flutter build apk --debug --flavor dev -t lib/main_dev.dart --dart-define=FLAVOR=dev` will fail loud on malformed XML.

- [ ] **Step 4: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add android/app/src/main/AndroidManifest.xml && git commit -m "$(cat <<'EOF'
feat(oauth): register /oauth/authorize Android App Links

Two intent-filters with autoVerify=true for id.taler.tirol and
staging.id.taler.tirol /oauth/authorize paths. Pairs with backend AASA
file for cross-platform Universal/App Links support.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase III: Mobile feature

### Task 10: Mobile entities (params, grant_info, scope_descriptor)

**Files:**
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/domain/entities/scope_descriptor.dart`
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/domain/entities/grant_info.dart`
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/domain/entities/oauth_authorize_params.dart`

- [ ] **Step 1: Check Freezed/json_serializable already in pubspec**

```bash
cd ~/Downloads/taler_id_mobile && grep -E "freezed|json_serializable|build_runner" pubspec.yaml
```
Expected: `freezed`, `freezed_annotation`, `json_serializable`, `json_annotation`, `build_runner` all listed (used by other features).

- [ ] **Step 2: Create scope_descriptor.dart**

Create `~/Downloads/taler_id_mobile/lib/features/oauth/domain/entities/scope_descriptor.dart`:
```dart
import 'package:freezed_annotation/freezed_annotation.dart';

part 'scope_descriptor.freezed.dart';
part 'scope_descriptor.g.dart';

@freezed
class ScopeDescriptor with _$ScopeDescriptor {
  const factory ScopeDescriptor({
    required String key,
    required String label,
    required String description,
  }) = _ScopeDescriptor;

  factory ScopeDescriptor.fromJson(Map<String, dynamic> json) =>
      _$ScopeDescriptorFromJson(json);
}
```

- [ ] **Step 3: Create grant_info.dart**

Create `~/Downloads/taler_id_mobile/lib/features/oauth/domain/entities/grant_info.dart`:
```dart
import 'package:freezed_annotation/freezed_annotation.dart';
import 'scope_descriptor.dart';

part 'grant_info.freezed.dart';
part 'grant_info.g.dart';

@freezed
class GrantInfo with _$GrantInfo {
  const factory GrantInfo({
    @JsonKey(name: 'client_name') required String clientName,
    @JsonKey(name: 'client_logo') String? clientLogo,
    required List<ScopeDescriptor> scopes,
    required bool remembered,
  }) = _GrantInfo;

  factory GrantInfo.fromJson(Map<String, dynamic> json) =>
      _$GrantInfoFromJson(json);
}
```

- [ ] **Step 4: Create oauth_authorize_params.dart**

Create `~/Downloads/taler_id_mobile/lib/features/oauth/domain/entities/oauth_authorize_params.dart`:
```dart
import 'package:freezed_annotation/freezed_annotation.dart';

part 'oauth_authorize_params.freezed.dart';

@freezed
class OAuthAuthorizeParams with _$OAuthAuthorizeParams {
  const factory OAuthAuthorizeParams({
    required String clientId,
    required String redirectUri,
    required String scope,
    required String responseType,
    String? state,
    String? codeChallenge,
    String? codeChallengeMethod,
    String? nonce,
  }) = _OAuthAuthorizeParams;

  const OAuthAuthorizeParams._();

  factory OAuthAuthorizeParams.fromUri(Uri uri) {
    final q = uri.queryParameters;
    return OAuthAuthorizeParams(
      clientId: q['client_id'] ?? '',
      redirectUri: q['redirect_uri'] ?? '',
      scope: q['scope'] ?? '',
      responseType: q['response_type'] ?? 'code',
      state: q['state'],
      codeChallenge: q['code_challenge'],
      codeChallengeMethod: q['code_challenge_method'],
      nonce: q['nonce'],
    );
  }

  Map<String, String> toQueryParameters() {
    final m = <String, String>{
      'client_id': clientId,
      'redirect_uri': redirectUri,
      'scope': scope,
      'response_type': responseType,
    };
    if (state != null) m['state'] = state!;
    if (codeChallenge != null) m['code_challenge'] = codeChallenge!;
    if (codeChallengeMethod != null) m['code_challenge_method'] = codeChallengeMethod!;
    if (nonce != null) m['nonce'] = nonce!;
    return m;
  }
}
```

- [ ] **Step 5: Run build_runner**

```bash
cd ~/Downloads/taler_id_mobile && dart run build_runner build --delete-conflicting-outputs
```
Expected: Generates `*.freezed.dart` and `*.g.dart` files. Watch for errors — common one is `freezed` version mismatch.

- [ ] **Step 6: Verify Flutter analyzer is clean for new files**

```bash
cd ~/Downloads/taler_id_mobile && flutter analyze lib/features/oauth/
```
Expected: no issues.

- [ ] **Step 7: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add lib/features/oauth/domain/ && git commit -m "$(cat <<'EOF'
feat(oauth): add domain entities for native OAuth login

Freezed: ScopeDescriptor, GrantInfo, OAuthAuthorizeParams.
fromUri/toQueryParameters helpers for routing.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: OAuth pending request singleton (with tests)

**Files:**
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/data/oauth_pending_request.dart`
- Create: `~/Downloads/taler_id_mobile/test/features/oauth/oauth_pending_request_test.dart`

- [ ] **Step 1: Write the failing tests**

Create `~/Downloads/taler_id_mobile/test/features/oauth/oauth_pending_request_test.dart`:
```dart
import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/oauth/data/oauth_pending_request.dart';

class _FakeStorage implements OAuthPendingStorage {
  String? _value;

  @override
  Future<String?> read() async => _value;

  @override
  Future<void> write(String value) async {
    _value = value;
  }

  @override
  Future<void> clear() async {
    _value = null;
  }
}

void main() {
  group('OAuthPendingRequest', () {
    late _FakeStorage storage;
    late OAuthPendingRequest pending;
    late DateTime fakeNow;

    setUp(() {
      storage = _FakeStorage();
      fakeNow = DateTime.utc(2026, 4, 30, 12, 0, 0);
      pending = OAuthPendingRequest(storage: storage, now: () => fakeNow);
    });

    test('save persists params to storage with timestamp', () async {
      final uri = Uri.parse('https://id.taler.tirol/oauth/authorize?client_id=mybook');
      await pending.save(uri);
      expect(await storage.read(), isNotNull);
    });

    test('consume returns saved uri and clears storage', () async {
      final uri = Uri.parse('https://id.taler.tirol/oauth/authorize?client_id=mybook');
      await pending.save(uri);
      final result = await pending.consume();
      expect(result, uri);
      expect(await storage.read(), isNull);
    });

    test('consume returns null when nothing stored', () async {
      final result = await pending.consume();
      expect(result, isNull);
    });

    test('consume returns null and clears storage when TTL exceeded', () async {
      final uri = Uri.parse('https://id.taler.tirol/oauth/authorize?client_id=mybook');
      await pending.save(uri);

      fakeNow = fakeNow.add(const Duration(minutes: 6));
      final result = await pending.consume();
      expect(result, isNull);
      expect(await storage.read(), isNull);
    });

    test('consume within TTL returns uri', () async {
      final uri = Uri.parse('https://id.taler.tirol/oauth/authorize?client_id=mybook');
      await pending.save(uri);

      fakeNow = fakeNow.add(const Duration(minutes: 4));
      final result = await pending.consume();
      expect(result, uri);
    });

    test('save overwrites previous value', () async {
      await pending.save(Uri.parse('https://id.taler.tirol/oauth/authorize?client_id=A'));
      await pending.save(Uri.parse('https://id.taler.tirol/oauth/authorize?client_id=B'));
      final result = await pending.consume();
      expect(result!.queryParameters['client_id'], 'B');
    });
  });
}
```

- [ ] **Step 2: Verify test fails**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/features/oauth/oauth_pending_request_test.dart
```
Expected: FAIL — file `oauth_pending_request.dart` doesn't exist.

- [ ] **Step 3: Implement OAuthPendingRequest**

Create `~/Downloads/taler_id_mobile/lib/features/oauth/data/oauth_pending_request.dart`:
```dart
import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

abstract class OAuthPendingStorage {
  Future<String?> read();
  Future<void> write(String value);
  Future<void> clear();
}

class SecureStorageOAuthPending implements OAuthPendingStorage {
  static const _key = 'oauth_pending_v1';
  final FlutterSecureStorage _storage;
  SecureStorageOAuthPending([FlutterSecureStorage? storage])
      : _storage = storage ?? const FlutterSecureStorage();

  @override
  Future<String?> read() => _storage.read(key: _key);

  @override
  Future<void> write(String value) => _storage.write(key: _key, value: value);

  @override
  Future<void> clear() => _storage.delete(key: _key);
}

class OAuthPendingRequest {
  static const _ttl = Duration(minutes: 5);

  final OAuthPendingStorage _storage;
  final DateTime Function() _now;

  OAuthPendingRequest({
    required OAuthPendingStorage storage,
    DateTime Function()? now,
  })  : _storage = storage,
        _now = now ?? DateTime.now;

  Future<void> save(Uri uri) async {
    final payload = jsonEncode({
      'uri': uri.toString(),
      'savedAt': _now().toIso8601String(),
    });
    await _storage.write(payload);
  }

  Future<Uri?> consume() async {
    final raw = await _storage.read();
    if (raw == null) return null;
    try {
      final payload = jsonDecode(raw) as Map<String, dynamic>;
      final savedAt = DateTime.parse(payload['savedAt'] as String);
      if (_now().difference(savedAt) > _ttl) {
        await _storage.clear();
        return null;
      }
      await _storage.clear();
      return Uri.parse(payload['uri'] as String);
    } catch (_) {
      await _storage.clear();
      return null;
    }
  }
}
```

- [ ] **Step 4: Run test**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/features/oauth/oauth_pending_request_test.dart
```
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add lib/features/oauth/data/oauth_pending_request.dart test/features/oauth/oauth_pending_request_test.dart && git commit -m "$(cat <<'EOF'
feat(oauth): add OAuthPendingRequest with 5-minute TTL

Persists OAuth params across cold-start and login redirect via
flutter_secure_storage. Used by deep_link_handler when app is opened
via Universal Link while user is logged out.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: Repository contract + remote datasource

**Files:**
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/domain/repositories/oauth_repository.dart`
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/data/datasources/oauth_remote_datasource.dart`
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/data/repositories/oauth_repository_impl.dart`

- [ ] **Step 1: Define repository interface**

Create `~/Downloads/taler_id_mobile/lib/features/oauth/domain/repositories/oauth_repository.dart`:
```dart
import '../entities/grant_info.dart';
import '../entities/oauth_authorize_params.dart';

class OAuthApproveResult {
  final String redirectUri;
  const OAuthApproveResult(this.redirectUri);
}

abstract class OAuthRepository {
  Future<GrantInfo> getGrantInfo(OAuthAuthorizeParams params);
  Future<OAuthApproveResult> approve(OAuthAuthorizeParams params);
}
```

- [ ] **Step 2: Create remote datasource**

Reference an existing datasource for the `Dio` injection pattern. Look at `~/Downloads/taler_id_mobile/lib/features/profile/data/datasources/profile_remote_datasource.dart`:
```bash
ls ~/Downloads/taler_id_mobile/lib/features/profile/data/datasources/
```

Mirror the pattern. Create `~/Downloads/taler_id_mobile/lib/features/oauth/data/datasources/oauth_remote_datasource.dart`:
```dart
import 'package:dio/dio.dart';
import '../../domain/entities/grant_info.dart';
import '../../domain/entities/oauth_authorize_params.dart';

class OAuthRemoteDatasource {
  final Dio _dio;
  OAuthRemoteDatasource(this._dio);

  Future<GrantInfo> getGrantInfo(OAuthAuthorizeParams params) async {
    final response = await _dio.get<Map<String, dynamic>>(
      '/oauth/mobile/grant-info',
      queryParameters: params.toQueryParameters(),
    );
    return GrantInfo.fromJson(response.data!);
  }

  Future<String> approve(OAuthAuthorizeParams params) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/oauth/mobile/approve',
      data: params.toQueryParameters(),
    );
    return response.data!['redirect_uri'] as String;
  }
}
```

- [ ] **Step 3: Create repository implementation**

Create `~/Downloads/taler_id_mobile/lib/features/oauth/data/repositories/oauth_repository_impl.dart`:
```dart
import '../../domain/entities/grant_info.dart';
import '../../domain/entities/oauth_authorize_params.dart';
import '../../domain/repositories/oauth_repository.dart';
import '../datasources/oauth_remote_datasource.dart';

class OAuthRepositoryImpl implements OAuthRepository {
  final OAuthRemoteDatasource _remote;
  OAuthRepositoryImpl(this._remote);

  @override
  Future<GrantInfo> getGrantInfo(OAuthAuthorizeParams params) =>
      _remote.getGrantInfo(params);

  @override
  Future<OAuthApproveResult> approve(OAuthAuthorizeParams params) async {
    final redirectUri = await _remote.approve(params);
    return OAuthApproveResult(redirectUri);
  }
}
```

- [ ] **Step 4: Verify analyzer clean**

```bash
cd ~/Downloads/taler_id_mobile && flutter analyze lib/features/oauth/
```
Expected: no issues.

- [ ] **Step 5: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add lib/features/oauth/domain/repositories/ lib/features/oauth/data/datasources/ lib/features/oauth/data/repositories/ && git commit -m "$(cat <<'EOF'
feat(oauth): add repository + Dio remote datasource

OAuthRepository contract + OAuthRemoteDatasource hitting
/oauth/mobile/grant-info and /oauth/mobile/approve endpoints.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 13: OAuthAuthorizeBloc (events, states, logic)

**Files:**
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/presentation/bloc/oauth_authorize_event.dart`
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/presentation/bloc/oauth_authorize_state.dart`
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/presentation/bloc/oauth_authorize_bloc.dart`
- Create: `~/Downloads/taler_id_mobile/test/features/oauth/oauth_authorize_bloc_test.dart`

- [ ] **Step 1: Define events and states**

Create `~/Downloads/taler_id_mobile/lib/features/oauth/presentation/bloc/oauth_authorize_event.dart`:
```dart
import 'package:equatable/equatable.dart';
import '../../domain/entities/oauth_authorize_params.dart';

abstract class OAuthAuthorizeEvent extends Equatable {
  const OAuthAuthorizeEvent();
  @override
  List<Object?> get props => [];
}

class LoadGrantInfo extends OAuthAuthorizeEvent {
  final OAuthAuthorizeParams params;
  const LoadGrantInfo(this.params);
  @override
  List<Object?> get props => [params];
}

class ApprovePressed extends OAuthAuthorizeEvent {
  const ApprovePressed();
}

class CancelPressed extends OAuthAuthorizeEvent {
  const CancelPressed();
}
```

Create `~/Downloads/taler_id_mobile/lib/features/oauth/presentation/bloc/oauth_authorize_state.dart`:
```dart
import 'package:equatable/equatable.dart';
import '../../domain/entities/grant_info.dart';
import '../../domain/entities/oauth_authorize_params.dart';

abstract class OAuthAuthorizeState extends Equatable {
  const OAuthAuthorizeState();
  @override
  List<Object?> get props => [];
}

class OAuthInitial extends OAuthAuthorizeState {
  const OAuthInitial();
}

class OAuthLoading extends OAuthAuthorizeState {
  const OAuthLoading();
}

class OAuthConsentRequired extends OAuthAuthorizeState {
  final GrantInfo grantInfo;
  final OAuthAuthorizeParams params;
  const OAuthConsentRequired(this.grantInfo, this.params);
  @override
  List<Object?> get props => [grantInfo, params];
}

class OAuthApproving extends OAuthAuthorizeState {
  final GrantInfo grantInfo;
  final OAuthAuthorizeParams params;
  const OAuthApproving(this.grantInfo, this.params);
  @override
  List<Object?> get props => [grantInfo, params];
}

class OAuthAutoApproving extends OAuthAuthorizeState {
  const OAuthAutoApproving();
}

class OAuthSuccess extends OAuthAuthorizeState {
  final String redirectUri;
  const OAuthSuccess(this.redirectUri);
  @override
  List<Object?> get props => [redirectUri];
}

class OAuthCancelled extends OAuthAuthorizeState {
  final String redirectUri;
  const OAuthCancelled(this.redirectUri);
  @override
  List<Object?> get props => [redirectUri];
}

class OAuthFailure extends OAuthAuthorizeState {
  final String message;
  final OAuthAuthorizeParams params;
  const OAuthFailure(this.message, this.params);
  @override
  List<Object?> get props => [message, params];
}
```

- [ ] **Step 2: Write failing bloc tests**

Create `~/Downloads/taler_id_mobile/test/features/oauth/oauth_authorize_bloc_test.dart`:
```dart
import 'package:bloc_test/bloc_test.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/features/oauth/domain/entities/grant_info.dart';
import 'package:taler_id_mobile/features/oauth/domain/entities/oauth_authorize_params.dart';
import 'package:taler_id_mobile/features/oauth/domain/entities/scope_descriptor.dart';
import 'package:taler_id_mobile/features/oauth/domain/repositories/oauth_repository.dart';
import 'package:taler_id_mobile/features/oauth/presentation/bloc/oauth_authorize_bloc.dart';
import 'package:taler_id_mobile/features/oauth/presentation/bloc/oauth_authorize_event.dart';
import 'package:taler_id_mobile/features/oauth/presentation/bloc/oauth_authorize_state.dart';

class _MockRepo extends Mock implements OAuthRepository {}

const _params = OAuthAuthorizeParams(
  clientId: 'mybook',
  redirectUri: 'https://example.com/cb',
  scope: 'profile email',
  responseType: 'code',
  state: 'xyz',
  codeChallenge: 'abc',
  codeChallengeMethod: 'S256',
);

const _grantInfoFresh = GrantInfo(
  clientName: 'MyBook',
  scopes: [ScopeDescriptor(key: 'profile', label: 'Профиль', description: '...')],
  remembered: false,
);

const _grantInfoRemembered = GrantInfo(
  clientName: 'MyBook',
  scopes: [ScopeDescriptor(key: 'profile', label: 'Профиль', description: '...')],
  remembered: true,
);

void main() {
  setUpAll(() {
    registerFallbackValue(_params);
  });

  group('OAuthAuthorizeBloc', () {
    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'LoadGrantInfo (remembered=false) → Loading → ConsentRequired',
      build: () {
        final repo = _MockRepo();
        when(() => repo.getGrantInfo(any())).thenAnswer((_) async => _grantInfoFresh);
        return OAuthAuthorizeBloc(repo);
      },
      act: (bloc) => bloc.add(const LoadGrantInfo(_params)),
      expect: () => [
        const OAuthLoading(),
        const OAuthConsentRequired(_grantInfoFresh, _params),
      ],
    );

    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'LoadGrantInfo (remembered=true) → Loading → AutoApproving → Success',
      build: () {
        final repo = _MockRepo();
        when(() => repo.getGrantInfo(any())).thenAnswer((_) async => _grantInfoRemembered);
        when(() => repo.approve(any())).thenAnswer(
          (_) async => const OAuthApproveResult('https://example.com/cb?code=AUTO&state=xyz'),
        );
        return OAuthAuthorizeBloc(repo);
      },
      act: (bloc) => bloc.add(const LoadGrantInfo(_params)),
      expect: () => [
        const OAuthLoading(),
        const OAuthAutoApproving(),
        const OAuthSuccess('https://example.com/cb?code=AUTO&state=xyz'),
      ],
    );

    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'ApprovePressed from ConsentRequired → Approving → Success',
      build: () {
        final repo = _MockRepo();
        when(() => repo.approve(any())).thenAnswer(
          (_) async => const OAuthApproveResult('https://example.com/cb?code=USER&state=xyz'),
        );
        return OAuthAuthorizeBloc(repo);
      },
      seed: () => const OAuthConsentRequired(_grantInfoFresh, _params),
      act: (bloc) => bloc.add(const ApprovePressed()),
      expect: () => [
        const OAuthApproving(_grantInfoFresh, _params),
        const OAuthSuccess('https://example.com/cb?code=USER&state=xyz'),
      ],
    );

    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'CancelPressed from ConsentRequired → Cancelled with error redirect',
      build: () => OAuthAuthorizeBloc(_MockRepo()),
      seed: () => const OAuthConsentRequired(_grantInfoFresh, _params),
      act: (bloc) => bloc.add(const CancelPressed()),
      expect: () => [
        const OAuthCancelled(
          'https://example.com/cb?error=access_denied&state=xyz',
        ),
      ],
    );

    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'getGrantInfo error → Failure with retry hint',
      build: () {
        final repo = _MockRepo();
        when(() => repo.getGrantInfo(any())).thenThrow(Exception('network'));
        return OAuthAuthorizeBloc(repo);
      },
      act: (bloc) => bloc.add(const LoadGrantInfo(_params)),
      expect: () => [
        const OAuthLoading(),
        isA<OAuthFailure>(),
      ],
    );

    blocTest<OAuthAuthorizeBloc, OAuthAuthorizeState>(
      'approve error → returns to ConsentRequired',
      build: () {
        final repo = _MockRepo();
        when(() => repo.approve(any())).thenThrow(Exception('500'));
        return OAuthAuthorizeBloc(repo);
      },
      seed: () => const OAuthConsentRequired(_grantInfoFresh, _params),
      act: (bloc) => bloc.add(const ApprovePressed()),
      expect: () => [
        const OAuthApproving(_grantInfoFresh, _params),
        const OAuthConsentRequired(_grantInfoFresh, _params),
      ],
    );
  });
}
```

- [ ] **Step 3: Verify tests fail**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/features/oauth/oauth_authorize_bloc_test.dart
```
Expected: FAIL — `oauth_authorize_bloc.dart` doesn't exist.

- [ ] **Step 4: Implement bloc**

Create `~/Downloads/taler_id_mobile/lib/features/oauth/presentation/bloc/oauth_authorize_bloc.dart`:
```dart
import 'package:flutter_bloc/flutter_bloc.dart';
import '../../domain/entities/grant_info.dart';
import '../../domain/entities/oauth_authorize_params.dart';
import '../../domain/repositories/oauth_repository.dart';
import 'oauth_authorize_event.dart';
import 'oauth_authorize_state.dart';

class OAuthAuthorizeBloc extends Bloc<OAuthAuthorizeEvent, OAuthAuthorizeState> {
  final OAuthRepository _repo;
  OAuthAuthorizeParams? _currentParams;
  GrantInfo? _currentGrantInfo;

  OAuthAuthorizeBloc(this._repo) : super(const OAuthInitial()) {
    on<LoadGrantInfo>(_onLoad);
    on<ApprovePressed>(_onApprove);
    on<CancelPressed>(_onCancel);
  }

  Future<void> _onLoad(LoadGrantInfo event, Emitter<OAuthAuthorizeState> emit) async {
    _currentParams = event.params;
    emit(const OAuthLoading());
    try {
      final grantInfo = await _repo.getGrantInfo(event.params);
      _currentGrantInfo = grantInfo;
      if (grantInfo.remembered) {
        emit(const OAuthAutoApproving());
        final result = await _repo.approve(event.params);
        emit(OAuthSuccess(result.redirectUri));
      } else {
        emit(OAuthConsentRequired(grantInfo, event.params));
      }
    } catch (e) {
      emit(OAuthFailure(e.toString(), event.params));
    }
  }

  Future<void> _onApprove(ApprovePressed event, Emitter<OAuthAuthorizeState> emit) async {
    final params = _currentParams;
    final grantInfo = _currentGrantInfo;
    if (params == null || grantInfo == null) return;
    emit(OAuthApproving(grantInfo, params));
    try {
      final result = await _repo.approve(params);
      emit(OAuthSuccess(result.redirectUri));
    } catch (_) {
      emit(OAuthConsentRequired(grantInfo, params));
    }
  }

  void _onCancel(CancelPressed event, Emitter<OAuthAuthorizeState> emit) {
    final params = _currentParams;
    if (params == null) return;
    final uri = Uri.parse(params.redirectUri).replace(queryParameters: {
      'error': 'access_denied',
      if (params.state != null) 'state': params.state!,
    });
    emit(OAuthCancelled(uri.toString()));
  }
}
```

- [ ] **Step 5: Run tests**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/features/oauth/oauth_authorize_bloc_test.dart
```
Expected: PASS, 6 tests.

- [ ] **Step 6: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add lib/features/oauth/presentation/bloc/ test/features/oauth/oauth_authorize_bloc_test.dart && git commit -m "$(cat <<'EOF'
feat(oauth): add OAuthAuthorizeBloc with consent + auto-approve flows

Events: LoadGrantInfo, ApprovePressed, CancelPressed.
States: Initial, Loading, ConsentRequired, Approving, AutoApproving,
Success, Cancelled, Failure.

remembered=true triggers AutoApproving without UI; cancel formulates
access_denied callback locally without backend call.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: OAuthAuthorizeScreen (UI + widget tests)

**Files:**
- Create: `~/Downloads/taler_id_mobile/lib/features/oauth/presentation/screens/oauth_authorize_screen.dart`
- Create: `~/Downloads/taler_id_mobile/test/features/oauth/oauth_authorize_screen_test.dart`

- [ ] **Step 1: Write the failing widget tests**

Create `~/Downloads/taler_id_mobile/test/features/oauth/oauth_authorize_screen_test.dart`:
```dart
import 'package:bloc_test/bloc_test.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/features/oauth/domain/entities/grant_info.dart';
import 'package:taler_id_mobile/features/oauth/domain/entities/oauth_authorize_params.dart';
import 'package:taler_id_mobile/features/oauth/domain/entities/scope_descriptor.dart';
import 'package:taler_id_mobile/features/oauth/presentation/bloc/oauth_authorize_bloc.dart';
import 'package:taler_id_mobile/features/oauth/presentation/bloc/oauth_authorize_event.dart';
import 'package:taler_id_mobile/features/oauth/presentation/bloc/oauth_authorize_state.dart';
import 'package:taler_id_mobile/features/oauth/presentation/screens/oauth_authorize_screen.dart';

class _MockBloc extends MockBloc<OAuthAuthorizeEvent, OAuthAuthorizeState>
    implements OAuthAuthorizeBloc {}

const _params = OAuthAuthorizeParams(
  clientId: 'mybook',
  redirectUri: 'https://example.com/cb',
  scope: 'profile',
  responseType: 'code',
);

const _grantInfo = GrantInfo(
  clientName: 'MyBook',
  scopes: [
    ScopeDescriptor(key: 'profile', label: 'Профиль', description: 'Имя, фамилия'),
  ],
  remembered: false,
);

Widget _harness(OAuthAuthorizeBloc bloc) => MaterialApp(
      home: BlocProvider<OAuthAuthorizeBloc>.value(
        value: bloc,
        child: OAuthAuthorizeScreen(params: _params, onLaunchUrl: (_) async {}),
      ),
    );

void main() {
  setUpAll(() {
    registerFallbackValue(const LoadGrantInfo(_params));
  });

  testWidgets('ConsentRequired renders client name, scope list, buttons',
      (tester) async {
    final bloc = _MockBloc();
    when(() => bloc.state).thenReturn(const OAuthConsentRequired(_grantInfo, _params));
    when(() => bloc.stream).thenAnswer((_) => const Stream.empty());

    await tester.pumpWidget(_harness(bloc));
    await tester.pumpAndSettle();

    expect(find.textContaining('MyBook'), findsWidgets);
    expect(find.textContaining('Профиль'), findsOneWidget);
    expect(find.textContaining('Имя, фамилия'), findsOneWidget);
    expect(find.text('Разрешить'), findsOneWidget);
    expect(find.text('Отмена'), findsOneWidget);
  });

  testWidgets('Tap Разрешить dispatches ApprovePressed', (tester) async {
    final bloc = _MockBloc();
    when(() => bloc.state).thenReturn(const OAuthConsentRequired(_grantInfo, _params));
    when(() => bloc.stream).thenAnswer((_) => const Stream.empty());

    await tester.pumpWidget(_harness(bloc));
    await tester.tap(find.text('Разрешить'));
    await tester.pump();

    verify(() => bloc.add(const ApprovePressed())).called(1);
  });

  testWidgets('Tap Отмена dispatches CancelPressed', (tester) async {
    final bloc = _MockBloc();
    when(() => bloc.state).thenReturn(const OAuthConsentRequired(_grantInfo, _params));
    when(() => bloc.stream).thenAnswer((_) => const Stream.empty());

    await tester.pumpWidget(_harness(bloc));
    await tester.tap(find.text('Отмена'));
    await tester.pump();

    verify(() => bloc.add(const CancelPressed())).called(1);
  });

  testWidgets('Loading state shows spinner', (tester) async {
    final bloc = _MockBloc();
    when(() => bloc.state).thenReturn(const OAuthLoading());
    when(() => bloc.stream).thenAnswer((_) => const Stream.empty());

    await tester.pumpWidget(_harness(bloc));
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
  });

  testWidgets('Failure state shows retry + browser fallback buttons', (tester) async {
    final bloc = _MockBloc();
    when(() => bloc.state).thenReturn(const OAuthFailure('Network error', _params));
    when(() => bloc.stream).thenAnswer((_) => const Stream.empty());

    await tester.pumpWidget(_harness(bloc));
    await tester.pumpAndSettle();

    expect(find.textContaining('Network error'), findsOneWidget);
    expect(find.text('Повторить'), findsOneWidget);
    expect(find.text('Открыть в браузере'), findsOneWidget);
  });

  testWidgets('Success state triggers onLaunchUrl with redirect', (tester) async {
    final bloc = _MockBloc();
    String? launched;
    whenListen<OAuthAuthorizeState>(
      bloc,
      Stream.fromIterable([
        const OAuthSuccess('https://example.com/cb?code=ABC&state=xyz'),
      ]),
      initialState: const OAuthLoading(),
    );

    await tester.pumpWidget(MaterialApp(
      home: BlocProvider<OAuthAuthorizeBloc>.value(
        value: bloc,
        child: OAuthAuthorizeScreen(
          params: _params,
          onLaunchUrl: (url) async {
            launched = url;
          },
        ),
      ),
    ));
    await tester.pumpAndSettle();

    expect(launched, 'https://example.com/cb?code=ABC&state=xyz');
  });
}
```

- [ ] **Step 2: Verify tests fail**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/features/oauth/oauth_authorize_screen_test.dart
```
Expected: FAIL — `oauth_authorize_screen.dart` doesn't exist.

- [ ] **Step 3: Implement OAuthAuthorizeScreen**

Create `~/Downloads/taler_id_mobile/lib/features/oauth/presentation/screens/oauth_authorize_screen.dart`:
```dart
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:url_launcher/url_launcher.dart';
import '../../domain/entities/oauth_authorize_params.dart';
import '../bloc/oauth_authorize_bloc.dart';
import '../bloc/oauth_authorize_event.dart';
import '../bloc/oauth_authorize_state.dart';

typedef LaunchUrlFn = Future<void> Function(String url);

Future<void> _defaultLaunch(String url) async {
  await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
}

class OAuthAuthorizeScreen extends StatefulWidget {
  final OAuthAuthorizeParams params;
  final LaunchUrlFn? onLaunchUrl;

  const OAuthAuthorizeScreen({
    super.key,
    required this.params,
    this.onLaunchUrl,
  });

  @override
  State<OAuthAuthorizeScreen> createState() => _OAuthAuthorizeScreenState();
}

class _OAuthAuthorizeScreenState extends State<OAuthAuthorizeScreen> {
  bool _loadDispatched = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_loadDispatched) {
        _loadDispatched = true;
        context.read<OAuthAuthorizeBloc>().add(LoadGrantInfo(widget.params));
      }
    });
  }

  Future<void> _handleLaunch(String url) async {
    final fn = widget.onLaunchUrl ?? _defaultLaunch;
    await fn(url);
    if (mounted && Navigator.canPop(context)) {
      Navigator.pop(context);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Вход через Taler ID')),
      body: BlocConsumer<OAuthAuthorizeBloc, OAuthAuthorizeState>(
        listener: (context, state) async {
          if (state is OAuthSuccess) {
            await _handleLaunch(state.redirectUri);
          } else if (state is OAuthCancelled) {
            await _handleLaunch(state.redirectUri);
          }
        },
        builder: (context, state) {
          if (state is OAuthLoading || state is OAuthInitial) {
            return const Center(child: CircularProgressIndicator());
          }
          if (state is OAuthAutoApproving) {
            return const Center(child: CircularProgressIndicator());
          }
          if (state is OAuthApproving) {
            return _buildConsent(context, state.grantInfo, busy: true);
          }
          if (state is OAuthConsentRequired) {
            return _buildConsent(context, state.grantInfo, busy: false);
          }
          if (state is OAuthFailure) {
            return _buildFailure(context, state.message);
          }
          if (state is OAuthSuccess || state is OAuthCancelled) {
            return const Center(child: CircularProgressIndicator());
          }
          return const SizedBox.shrink();
        },
      ),
    );
  }

  Widget _buildConsent(BuildContext context, dynamic grantInfo, {required bool busy}) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (grantInfo.clientLogo != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 16),
              child: Image.network(
                grantInfo.clientLogo,
                height: 64,
                errorBuilder: (_, __, ___) => const SizedBox.shrink(),
              ),
            ),
          Text(
            '${grantInfo.clientName} запрашивает доступ',
            style: Theme.of(context).textTheme.titleLarge,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          ...grantInfo.scopes.map<Widget>((s) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 8),
                child: ListTile(
                  leading: const Icon(Icons.check_circle_outline),
                  title: Text(s.label),
                  subtitle: Text(s.description),
                  contentPadding: EdgeInsets.zero,
                ),
              )),
          const Spacer(),
          ElevatedButton(
            onPressed: busy
                ? null
                : () => context.read<OAuthAuthorizeBloc>().add(const ApprovePressed()),
            child: busy
                ? const SizedBox(
                    height: 20,
                    width: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Text('Разрешить'),
          ),
          const SizedBox(height: 12),
          TextButton(
            onPressed: busy
                ? null
                : () => context.read<OAuthAuthorizeBloc>().add(const CancelPressed()),
            child: const Text('Отмена'),
          ),
        ],
      ),
    );
  }

  Widget _buildFailure(BuildContext context, String message) {
    final fallback = Uri.parse('https://id.taler.tirol/oauth/authorize').replace(
      queryParameters: widget.params.toQueryParameters(),
    );
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.error_outline, size: 64),
          const SizedBox(height: 16),
          Text(message, textAlign: TextAlign.center),
          const SizedBox(height: 24),
          ElevatedButton(
            onPressed: () => context
                .read<OAuthAuthorizeBloc>()
                .add(LoadGrantInfo(widget.params)),
            child: const Text('Повторить'),
          ),
          const SizedBox(height: 12),
          TextButton(
            onPressed: () => _handleLaunch(fallback.toString()),
            child: const Text('Открыть в браузере'),
          ),
        ],
      ),
    );
  }
}
```

- [ ] **Step 4: Run tests**

```bash
cd ~/Downloads/taler_id_mobile && flutter test test/features/oauth/oauth_authorize_screen_test.dart
```
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add lib/features/oauth/presentation/screens/oauth_authorize_screen.dart test/features/oauth/oauth_authorize_screen_test.dart && git commit -m "$(cat <<'EOF'
feat(oauth): add OAuthAuthorizeScreen with consent UI

Renders client name+logo+scopes, handles approve/cancel taps, shows
spinner during loading/auto-approve, shows retry + browser fallback on
failure. Auto-launches redirect_uri on Success/Cancelled state.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: DI registration

**Files:**
- Modify: `~/Downloads/taler_id_mobile/lib/core/di/dependencies.dart`

- [ ] **Step 1: Inspect existing DI structure**

```bash
grep -n "registerLazySingleton\|registerFactory" ~/Downloads/taler_id_mobile/lib/core/di/dependencies.dart | head -20
```

Reference an existing feature DI block (profile, auth) to mirror naming conventions.

- [ ] **Step 2: Register OAuth bindings**

In `~/Downloads/taler_id_mobile/lib/core/di/dependencies.dart`, add the imports near the top:
```dart
import 'package:taler_id_mobile/features/oauth/data/datasources/oauth_remote_datasource.dart';
import 'package:taler_id_mobile/features/oauth/data/oauth_pending_request.dart';
import 'package:taler_id_mobile/features/oauth/data/repositories/oauth_repository_impl.dart';
import 'package:taler_id_mobile/features/oauth/domain/repositories/oauth_repository.dart';
import 'package:taler_id_mobile/features/oauth/presentation/bloc/oauth_authorize_bloc.dart';
```

Inside the `setupDependencies()` function, add (typically grouped with feature bindings):
```dart
// OAuth (native mobile login)
sl.registerLazySingleton<OAuthRemoteDatasource>(
  () => OAuthRemoteDatasource(sl<DioClient>().dio),
);
sl.registerLazySingleton<OAuthRepository>(
  () => OAuthRepositoryImpl(sl<OAuthRemoteDatasource>()),
);
sl.registerLazySingleton<OAuthPendingRequest>(
  () => OAuthPendingRequest(storage: SecureStorageOAuthPending()),
);
sl.registerFactory<OAuthAuthorizeBloc>(
  () => OAuthAuthorizeBloc(sl<OAuthRepository>()),
);
```

(If `DioClient` is not the type — it's likely `DioClient` based on `lib/core/api/`. Check with `grep -n "class DioClient" lib/core/api/`.)

- [ ] **Step 3: Verify compilation**

```bash
cd ~/Downloads/taler_id_mobile && flutter analyze lib/
```
Expected: no issues.

- [ ] **Step 4: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add lib/core/di/dependencies.dart && git commit -m "$(cat <<'EOF'
feat(oauth): register native OAuth feature in GetIt DI

OAuthRemoteDatasource, OAuthRepository (Impl), OAuthPendingRequest,
OAuthAuthorizeBloc all wired. Bloc registered as factory so each route
push gets a fresh instance.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 16: RouteConstants + GoRoute + globalRedirect

**Files:**
- Modify: `~/Downloads/taler_id_mobile/lib/core/utils/constants.dart`
- Modify: `~/Downloads/taler_id_mobile/lib/core/router/app_router.dart`

- [ ] **Step 1: Add route constant**

In `~/Downloads/taler_id_mobile/lib/core/utils/constants.dart`, inside the `RouteConstants` class, add (next to other auth-related routes):
```dart
  static const oauthAuthorize = '/oauth/authorize';
```

- [ ] **Step 2: Add GoRoute outside ShellRoute**

Open `~/Downloads/taler_id_mobile/lib/core/router/app_router.dart`. Find the existing top-level `GoRoute(path: RouteConstants.invite, ...)` (it's outside the ShellRoute since it bypasses bottom nav). Add similarly above or below it:
```dart
GoRoute(
  path: RouteConstants.oauthAuthorize,
  builder: (context, state) => BlocProvider(
    create: (_) => sl<OAuthAuthorizeBloc>(),
    child: OAuthAuthorizeScreen(
      params: OAuthAuthorizeParams.fromUri(state.uri),
    ),
  ),
),
```

Add imports:
```dart
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:taler_id_mobile/features/oauth/domain/entities/oauth_authorize_params.dart';
import 'package:taler_id_mobile/features/oauth/presentation/bloc/oauth_authorize_bloc.dart';
import 'package:taler_id_mobile/features/oauth/presentation/screens/oauth_authorize_screen.dart';
```

- [ ] **Step 3: Wire `_globalRedirect` to save pending OAuth on logged-out access**

In the same `app_router.dart`, modify the `_globalRedirect` function. Find the section that checks if user has refresh token; when route is `/oauth/authorize` and user is not logged in, save params before redirecting to login:

```dart
Future<String?> _globalRedirect(BuildContext context, GoRouterState state) async {
  // ... existing publicRoutes / room handling ...

  // Native OAuth flow: if user not authenticated, save params for resume after login
  if (state.matchedLocation == RouteConstants.oauthAuthorize) {
    try {
      final storage = sl<SecureStorageService>();
      final hasToken = await storage.hasRefreshToken;
      if (!hasToken) {
        await sl<OAuthPendingRequest>().save(state.uri);
        return RouteConstants.login;
      }
    } catch (_) {
      // If storage is briefly unavailable, just let it through —
      // the screen will fail-fast with a friendly error.
    }
    return null;
  }

  // ... existing token-check logic stays below ...
}
```

Add import:
```dart
import 'package:taler_id_mobile/features/oauth/data/oauth_pending_request.dart';
```

- [ ] **Step 4: Verify analyzer**

```bash
cd ~/Downloads/taler_id_mobile && flutter analyze lib/core/router/ lib/core/utils/constants.dart
```
Expected: no issues.

- [ ] **Step 5: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add lib/core/utils/constants.dart lib/core/router/app_router.dart && git commit -m "$(cat <<'EOF'
feat(oauth): wire /oauth/authorize route + logged-out redirect

GoRoute outside ShellRoute (bypasses bottom nav, full-screen consent).
_globalRedirect saves OAuth params via OAuthPendingRequest before
redirecting to /login when user is logged out.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 17: Deep link handler — branch for `/oauth/authorize`

**Files:**
- Modify: `~/Downloads/taler_id_mobile/lib/core/router/deep_link_handler.dart`

- [ ] **Step 1: Add branch for OAuth authorize**

Open `~/Downloads/taler_id_mobile/lib/core/router/deep_link_handler.dart`. In the `_handleUri` static method, add a branch for `/oauth/authorize` **before** the existing branches (more specific matches first):

```dart
static void _handleUri(GoRouter router, Uri uri) {
  debugPrint('Deep link received: $uri');

  // OAuth native login (Universal Links / App Links):
  // https://id.taler.tirol/oauth/authorize?...
  // https://staging.id.taler.tirol/oauth/authorize?...
  if (uri.path == '/oauth/authorize' &&
      (uri.host == 'id.taler.tirol' || uri.host == 'staging.id.taler.tirol')) {
    final query = uri.query.isEmpty ? '' : '?${uri.query}';
    router.push('/oauth/authorize$query');
    return;
  }

  // ... existing branches (invite, room, talerid://user) stay as-is ...
}
```

- [ ] **Step 2: Verify analyzer**

```bash
cd ~/Downloads/taler_id_mobile && flutter analyze lib/core/router/deep_link_handler.dart
```
Expected: no issues.

- [ ] **Step 3: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add lib/core/router/deep_link_handler.dart && git commit -m "$(cat <<'EOF'
feat(oauth): route /oauth/authorize Universal Link to native screen

Deep link handler pushes /oauth/authorize route (preserving query)
when receiving https://id.taler.tirol/oauth/authorize or staging.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 18: Resume after login

**Files:**
- Modify: `~/Downloads/taler_id_mobile/lib/features/auth/presentation/bloc/auth_bloc.dart`

The exact integration depends on existing auth bloc structure. Two acceptable patterns:

**Pattern A — auth_bloc:** After emitting `LoginSuccess`, check `OAuthPendingRequest.consume()`. If non-null, expose a property on the success state (or emit a `LoginSuccessWithPendingOAuth` state) so the listener at the screen layer can navigate.

**Pattern B — login screen listener:** Keep auth bloc unchanged, do the consume in the login screen's `BlocListener<AuthBloc, AuthState>` for `LoginSuccess`.

We use Pattern B because it requires no auth-domain changes.

- [ ] **Step 1: Find login screen BlocListener**

```bash
grep -rn "LoginSuccess\|GoRouter.of\|context.go" ~/Downloads/taler_id_mobile/lib/features/auth/presentation/screens/login_screen.dart 2>/dev/null | head -20
```

- [ ] **Step 2: Patch login_screen to consume pending OAuth on success**

In `~/Downloads/taler_id_mobile/lib/features/auth/presentation/screens/login_screen.dart` (or whichever file holds the post-login navigation), find where the login success navigates to dashboard. Replace the navigation block with:

```dart
// After successful login
final pending = await sl<OAuthPendingRequest>().consume();
if (pending != null) {
  if (!mounted) return;
  context.go('${RouteConstants.oauthAuthorize}?${pending.query}');
} else {
  if (!mounted) return;
  context.go(RouteConstants.dashboard);
}
```

Required imports:
```dart
import 'package:taler_id_mobile/core/di/dependencies.dart';
import 'package:taler_id_mobile/core/utils/constants.dart';
import 'package:taler_id_mobile/features/oauth/data/oauth_pending_request.dart';
```

If login navigation lives somewhere else (e.g., handled by `_globalRedirect` after `splash` screen reads token), adapt: in `splash_screen.dart` after auth check, before navigating to dashboard, check `OAuthPendingRequest.consume()` similarly.

- [ ] **Step 3: Verify analyzer**

```bash
cd ~/Downloads/taler_id_mobile && flutter analyze lib/features/auth/
```
Expected: no issues.

- [ ] **Step 4: Run all unit tests**

```bash
cd ~/Downloads/taler_id_mobile && flutter test
```
Expected: all green (existing + new).

- [ ] **Step 5: Commit**

```bash
cd ~/Downloads/taler_id_mobile && git add lib/features/auth/presentation/screens/login_screen.dart && git commit -m "$(cat <<'EOF'
feat(oauth): resume pending OAuth flow after login

Post-login navigation consumes OAuthPendingRequest. If a pending OAuth
authorize Uri exists (saved by _globalRedirect when user hit
/oauth/authorize while logged out), routes there; otherwise to
dashboard.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase IV: Smoke + deploy

### Task 19: Build dev APK locally + install on Android

**Files:** none

- [ ] **Step 1: Build local dev APK**

```bash
cd ~/Downloads/taler_id_mobile && flutter build apk --flavor dev --release -t lib/main_dev.dart --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol
```
Expected: builds to `build/app/outputs/flutter-apk/app-dev-release.apk`. Reasoning for local build: per `feedback_local_apk_builds.md` ad-hoc smoke uses local builds, not server-built APKs.

- [ ] **Step 2: Install on connected Android device**

```bash
~/Library/Android/sdk/platform-tools/adb devices
~/Library/Android/sdk/platform-tools/adb install -r ~/Downloads/taler_id_mobile/build/app/outputs/flutter-apk/app-dev-release.apk
```

- [ ] **Step 3: Verify App Links registered**

```bash
~/Library/Android/sdk/platform-tools/adb shell pm get-app-links tirol.taler.taler_id_mobile.dev
```
Expected: at least one verified domain `id.taler.tirol` and `staging.id.taler.tirol` with `legacy_user_decision_state: always` (or `verified`). If domains show as `none`, it usually means `assetlinks.json` isn't reachable — check `curl https://id.taler.tirol/.well-known/assetlinks.json` and `curl https://staging.id.taler.tirol/.well-known/assetlinks.json`.

- [ ] **Step 4: Manual smoke (Android)**

On the test device, open Chrome and navigate to: `https://staging.id.taler.tirol/oauth/authorize?client_id=taler-id-developers&redirect_uri=https%3A%2F%2Fstaging.id.taler.tirol%2Fdevelopers%2F&scope=openid+profile&response_type=code&state=smoke&code_challenge=test_challenge_must_be_43chars_minimum_AAAAAAAAA&code_challenge_method=S256`.

Expected: Taler ID Dev app opens, shows consent screen with "Taler ID Developer Portal" client_name and scopes "OpenID" + "Профиль". Tap "Разрешить" → returns to Chrome which lands on `staging.id.taler.tirol/developers/?code=...&state=smoke` (the SPA shows itself).

If app doesn't intercept and Chrome loads the HTML form: App Links not verified, retry assetlinks.json check.

---

### Task 20: Build dev iOS + install on iPhone

**Files:** none

- [ ] **Step 1: Build dev iOS to physical iPhone**

```bash
cd ~/Downloads/taler_id_mobile && flutter run --flavor dev -t lib/main_dev.dart --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol -d 00008101-000E21100202001E
```

- [ ] **Step 2: Force AASA fetch by reinstalling the app**

iOS fetches `apple-app-site-association` at app install time. Since we deployed AASA to the server **after** the app was already installed, iOS still has the empty/missing AASA cached.

Force a fresh fetch:
1. Uninstall Taler ID Dev from iPhone (long-press → Remove App).
2. Re-run `flutter run --flavor dev ...` (or re-install the existing build via Xcode/TestFlight).

After fresh install, iOS sends a request to `https://id.taler.tirol/.well-known/apple-app-site-association` (and staging) within a few seconds. Verify in nginx access log on DEV:
```bash
ssh dvolkov@89.169.55.217 'sudo tail -50 /var/log/nginx/access.log | grep apple-app-site-association'
```
Expected: a line like `... GET /.well-known/apple-app-site-association HTTP/2.0 200 ... AASA-Bot/1.0`.

If no such request appears within 30 seconds of install, iOS device is still on the old cache — physically reboot the iPhone, then reinstall once more.

- [ ] **Step 3: Manual smoke (iPhone)**

Open Safari on iPhone, navigate to:
```
https://staging.id.taler.tirol/oauth/authorize?client_id=taler-id-developers&redirect_uri=https%3A%2F%2Fstaging.id.taler.tirol%2Fdevelopers%2F&scope=openid+profile&response_type=code&state=smoke&code_challenge=test_challenge_must_be_43chars_minimum_AAAAAAAAA&code_challenge_method=S256
```

Expected: Safari shows banner "Open in Taler ID Dev" or directly opens the app (depends on iOS version + first-time interaction). Tap to open. Consent screen appears. Tap "Разрешить". Returns to Safari, SPA logged in.

If Safari just renders the HTML form: AASA cache not yet active. Force-restart device, retry.

- [ ] **Step 4: Document any AASA cache issues observed**

Note in commit message or release notes if iPhone needed reboot for first activation.

---

### Task 21: Full smoke checklist

Run through each scenario from spec section "Testing → E2E (manual smoke checklist)":

- [ ] **iPhone, app installed, logged in:** redirected to consent → approve → back to Safari with code, SPA logged in
- [ ] **iPhone, app installed, logged out:** PIN/login first, then resume on consent → approve → success
- [ ] **iPhone, app NOT installed:** uninstall app, retry — Safari renders HTML form, browser fallback works
- [ ] **iPhone, second login (remembered=true):** consent screen does NOT appear, instant callback
- [ ] **Android (dev flavor):** all four iPhone scenarios work
- [ ] **iPhone, cancel:** tap "Отмена" → Safari shows `?error=access_denied`, SPA shows error
- [ ] **iPhone, in-call:** during voice call, trigger /oauth/authorize externally → consent opens on top, can cancel and resume call
- [ ] **iPhone, cold-start:** kill app, tap Universal Link in Safari → app cold-starts, consent appears (via pending storage)

Document any failures and revise tasks above before proceeding to PROD deploy.

---

### Task 22: PROD deploy (only after explicit user approval)

**Per project CLAUDE.md: PROD deploy ONLY when user explicitly says so.** Do NOT proceed automatically after DEV smoke passes.

When user gives green light:

- [ ] **Step 1: Backend PROD**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler-id && git pull && npm install && npx prisma migrate deploy && npm run build && pm2 restart taler-id'
```

- [ ] **Step 2: AASA file PROD**

```bash
ssh dvolkov@138.124.61.221 'sudo cp ~/taler-id/public/.well-known/apple-app-site-association /var/www/html/.well-known/apple-app-site-association && sudo chmod 644 /var/www/html/.well-known/apple-app-site-association'
```

- [ ] **Step 3: nginx config PROD**

SSH to PROD, edit `/etc/nginx/sites-available/id.taler.tirol` (or wherever the prod config lives), add the same `location = /.well-known/apple-app-site-association` block as in Task 8 step 5, then `sudo nginx -t && sudo systemctl reload nginx`.

- [ ] **Step 4: Verify AASA on PROD**

```bash
curl -I https://id.taler.tirol/.well-known/apple-app-site-association
curl -s https://id.taler.tirol/.well-known/apple-app-site-association | jq .
```

- [ ] **Step 5: Mobile PROD APK**

```bash
ssh dvolkov@138.124.61.221 'cd ~/taler_id_mobile && git checkout main && git merge dev && git push origin main && flutter build apk --flavor prod --release --dart-define=FLAVOR=prod && cp build/app/outputs/flutter-apk/app-prod-release.apk /var/www/downloads/taler-id.apk'
```

- [ ] **Step 6: Mobile PROD iOS (TestFlight)**

Local build:
```bash
cd ~/Downloads/taler_id_mobile && git checkout main && git pull && flutter build ipa --release --export-options-plist ios/ExportOptions.plist && xcrun altool --upload-app --type ios -f build/ios/ipa/*.ipa --apiKey J3P22V4URD --apiIssuer 44b87272-3052-40ea-a48a-6c6f88a2df11
```

After upload — set TestFlight release notes per project conventions (CLAUDE.md "ОБЯЗАТЕЛЬНО после загрузки в TestFlight").

- [ ] **Step 7: Run full mandatory test suite from CLAUDE.md**

```bash
cd ~/Downloads/taler_id_tests && npm run test:prod && npm run test:voice:prod && npm run test:assistant:prod && npm run test:files:prod && npm run test:channels:prod && npm run test:billing:prod
```

---

## Self-Review

**Spec coverage:**
- ✅ Universal Links / App Links interception (Tasks 8, 9, 17, 19, 20)
- ✅ Graceful browser fallback (no code changes — existing oidc-provider HTML form, just don't break it)
- ✅ Consent screen with remember-per-client (Tasks 13, 14)
- ✅ PKCE-only enforcement (Tasks 2, 3, 4)
- ✅ Backend `/oauth/mobile/grant-info` + `/approve` (Tasks 3-6)
- ✅ Mobile screen + bloc + DI + routing (Tasks 10-18)
- ✅ Resume-after-login via OAuthPendingRequest (Tasks 11, 16, 18)
- ✅ Cancel returns access_denied per OAuth spec (Task 13)
- ✅ Manual browser fallback button on errors (Task 14)
- ✅ Smoke testing checklist (Tasks 19-21)
- ✅ PROD deploy gated on explicit approval (Task 22)

**Type/method consistency:**
- `OAuthAuthorizeParams.fromUri/toQueryParameters` — matches names in remote datasource and `app_router.dart`
- `OAuthRepository.getGrantInfo / approve` — matches bloc dispatch
- `OAuthApproveResult.redirectUri` — used consistently in bloc → screen → launchUrl
- `OAuthPendingRequest.save / consume` — matches usage in `_globalRedirect` and `login_screen`
- `OAuthMobileService.getGrantInfo / approve` — matches controller's two endpoints
- All Russian UI strings consistent: "Разрешить", "Отмена", "Повторить", "Открыть в браузере"

**Placeholder scan:**
- No "TBD"/"TODO" in any task
- All test code is concrete (real assertions, not "test the function")
- All commands are exact (file paths, npm/flutter args)
- Edge case "AASA cache" documented as Task 20 step 2 with concrete workaround

**Single-spec scope:** Yes — touches two repos but one logical feature, sequential dependencies, single rollout window.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-30-oauth-native-mobile-login.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task with two-stage review (spec compliance, then code quality). Faster iteration, same session.

**2. Inline Execution** — Execute tasks in this session via `superpowers:executing-plans`, batched with checkpoints for your review.

Which approach?
