# OAuth UI Kit — Phase 4: Developer Portal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a self-service developer portal at `https://id.taler.tirol/developers/` so OAuth integrators can register, edit, rotate secrets for, and delete their OAuth clients without contacting the maintainer.

**Architecture:** New React+Vite SPA in `~/taler-id/developers/` builds to `~/taler-id/public/developers/` (existing `ServeStaticModule` serves `public/` at `/`). Auth via Phase 2 SDK consumed as a local `file:` dependency. Plus one new backend endpoint (`POST /oauth/clients/:clientId/rotate-secret`) and a one-time SQL seed for the `taler-id-developers` system OAuth client.

**Tech Stack:** React 18 · Vite 5 · TypeScript 5.5 strict · `@taler-id/oauth-client` (Phase 2 SDK, local file: dep) · Vitest 2 + jsdom + `@testing-library/react` · pnpm.

**Spec:** `~/taler-id/docs/superpowers/specs/2026-04-30-oauth-ui-kit-phase-4-developer-portal.md`

**Working directory:** `~/taler-id` for backend changes (Tasks 1-2) and the new `~/taler-id/developers/` directory for the SPA (Tasks 3-12). Deploy hits `dvolkov@89.169.55.217` (DEV) and `dvolkov@138.124.61.221` (PROD).

**Phase 2 SDK precondition:** the developers/ project consumes `@taler-id/oauth-client` via a relative `file:` dep at `../../taler-id-sdk-js`. This requires `~/taler-id-sdk-js` to exist with a built `dist/`. Already true on Dmitry's local machine (Phase 3 work confirmed `~/taler-id-sdk-js/dist/` exists). For a fresh clone or CI, run `cd ~/taler-id-sdk-js && pnpm install && pnpm build` first.

**Parallel-work warning:** `~/taler-id` has substantial uncommitted work in `src/` (~94 files from the user's parallel branches at the time of Phase 2). Each task in this plan must `git add` only its specific files (never `git add -A` / `git add .`).

---

## File Structure (final state after Task 13)

```
~/taler-id/
├── developers/                                    # T3 — Vite project (NEW)
│   ├── package.json
│   ├── pnpm-lock.yaml
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── vitest.config.ts
│   ├── eslint.config.js
│   ├── index.html
│   ├── src/
│   │   ├── main.tsx                               # T5
│   │   ├── App.tsx                                # T5
│   │   ├── api.ts                                 # T4
│   │   ├── styles.css                             # T3
│   │   ├── pages/
│   │   │   ├── ClientsList.tsx                    # T6
│   │   │   └── LoginGate.tsx                      # T5
│   │   └── modals/
│   │       ├── CreateClientModal.tsx              # T7
│   │       ├── EditClientModal.tsx                # T8
│   │       ├── DeleteClientModal.tsx              # T9
│   │       ├── RotateSecretModal.tsx              # T10
│   │       └── SecretRevealModal.tsx              # T11
│   └── tests/
│       ├── api.test.ts                            # T4
│       ├── App.test.tsx                           # T5
│       ├── ClientsList.test.tsx                   # T6
│       ├── CreateClientModal.test.tsx             # T7
│       ├── EditClientModal.test.tsx               # T8
│       ├── DeleteClientModal.test.tsx             # T9
│       ├── RotateSecretModal.test.tsx             # T10
│       └── SecretRevealModal.test.tsx             # T11
├── public/developers/                             # T12 — built SPA, committed for deploy
│   ├── index.html
│   └── assets/...
├── prisma/migrations/2026_seed_taler_id_developers_client.sql  # T2
└── src/
    ├── oauth-registration/
    │   ├── oauth-registration.controller.ts       # T1 — modify (add @Post(rotate-secret))
    │   ├── oauth-registration.service.ts          # T1 — modify (add rotateSecret method)
    │   └── oauth-registration.service.spec.ts     # T1 — modify (add 3 tests)
    └── oidc/
        └── adapters/
            └── prisma-client-adapter.ts           # T2 — modify (post-logout for taler-id-developers)
```

---

## Task 1: Backend — `rotateSecret` endpoint + service method + spec

**Files:**
- Modify: `~/taler-id/src/oauth-registration/oauth-registration.service.ts` (add method)
- Modify: `~/taler-id/src/oauth-registration/oauth-registration.controller.ts` (add @Post)
- Modify: `~/taler-id/src/oauth-registration/oauth-registration.service.spec.ts` (add 3 tests)

- [ ] **Step 1: Add the failing tests**

Append a new `describe('rotateSecret', ...)` block at the end of the existing `~/taler-id/src/oauth-registration/oauth-registration.service.spec.ts` (after the last `});` of the file's main `describe`):

```ts
  describe('rotateSecret', () => {
    it('returns new secret + audit logs success', async () => {
      const userId = 'u-1';
      const clientId = 'cli-1';
      prisma.oAuthClient.findFirst.mockResolvedValue({
        id: 1, clientId, userId, clientSecret: 'OLD',
        name: 'app', redirectUris: ['app://cb'],
        allowedScopes: ['openid'], logoUri: null,
        createdAt: new Date(), updatedAt: new Date(),
      } as any);
      prisma.oAuthClient.update.mockResolvedValue({ clientSecret: 'NEW' } as any);
      prisma.auditLog.create.mockResolvedValue({} as any);

      const result = await service.rotateSecret(userId, clientId, '127.0.0.1', 'ua');

      expect(result.client_id).toBe(clientId);
      expect(result.client_secret).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(result.client_secret).not.toBe('OLD');
      expect(result.client_secret_rotated_at).toBeGreaterThan(0);
      expect(prisma.oAuthClient.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ clientSecret: expect.any(String) }),
        }),
      );
      expect(prisma.auditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            action: 'OAUTH_CLIENT_ROTATED',
            userId,
          }),
        }),
      );
    });

    it('throws NotFoundException when caller does not own client', async () => {
      prisma.oAuthClient.findFirst.mockResolvedValue(null);
      await expect(
        service.rotateSecret('u-1', 'someone-elses-client', '127.0.0.1', 'ua'),
      ).rejects.toThrow(NotFoundException);
    });

    it('generates a 32-byte base64url secret each rotation', async () => {
      prisma.oAuthClient.findFirst.mockResolvedValue({
        id: 1, clientId: 'c', userId: 'u', clientSecret: 'OLD',
        name: 'a', redirectUris: ['x'], allowedScopes: [], logoUri: null,
        createdAt: new Date(), updatedAt: new Date(),
      } as any);
      prisma.oAuthClient.update.mockImplementation(({ data }: any) =>
        Promise.resolve({ clientSecret: data.clientSecret }),
      );
      prisma.auditLog.create.mockResolvedValue({} as any);

      const a = await service.rotateSecret('u', 'c', '1.2.3.4', 'ua');
      const b = await service.rotateSecret('u', 'c', '1.2.3.4', 'ua');
      // base64url of 32 bytes is 43 chars (no padding)
      expect(a.client_secret.length).toBeGreaterThanOrEqual(43);
      expect(a.client_secret).not.toBe(b.client_secret);
    });
  });
```

If the existing spec file imports `NotFoundException`, reuse the import. Otherwise add `import { NotFoundException } from '@nestjs/common';` at the top.

- [ ] **Step 2: Run tests to verify failure**

```bash
cd ~/taler-id
npm run test -- oauth-registration.service.spec 2>&1 | tail -20
```

Expected: 3 new tests fail with "service.rotateSecret is not a function".

- [ ] **Step 3: Add the service method**

Append to the existing `OAuthRegistrationService` class in `~/taler-id/src/oauth-registration/oauth-registration.service.ts` (e.g. after `deleteMine`):

```ts
  async rotateSecret(userId: string, clientId: string, ip: string, userAgent: string) {
    const existing = await this.prisma.oAuthClient.findFirst({
      where: { clientId, userId },
    });
    if (!existing) {
      throw new NotFoundException({ error: 'client_not_found' });
    }

    const newSecret = randomBytes(32).toString('base64url');
    await this.prisma.oAuthClient.update({
      where: { id: existing.id },
      data: { clientSecret: newSecret },
    });

    await this.writeAuditLog(userId, 'OAUTH_CLIENT_ROTATED', ip, userAgent, {
      clientId,
    });

    return {
      client_id: clientId,
      client_secret: newSecret,
      client_secret_rotated_at: Math.floor(Date.now() / 1000),
    };
  }
```

`randomBytes` and `NotFoundException` are already imported at the top of the file (verify; if not, add them).

- [ ] **Step 4: Add the controller route**

Append to the existing `OAuthRegistrationController` in `~/taler-id/src/oauth-registration/oauth-registration.controller.ts` (e.g. after the `@Delete('clients/:clientId')` handler):

```ts
  @Post('clients/:clientId/rotate-secret')
  @Throttle({ short: { limit: 3, ttl: 60_000 } })
  rotateSecret(
    @CurrentUser() user: any,
    @Param('clientId') clientId: string,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.svc.rotateSecret(user.sub, clientId, ip, userAgent ?? '');
  }
```

`@Post`, `@Throttle`, `@Param`, `@Ip`, `@Headers`, `@CurrentUser` are already imported.

- [ ] **Step 5: Run tests + typecheck**

```bash
cd ~/taler-id
npm run test -- oauth-registration.service.spec 2>&1 | tail -10
npx tsc --noEmit --project tsconfig.json 2>&1 | tail -5
```

Expected: 3 new tests pass; typecheck clean.

- [ ] **Step 6: Commit**

```bash
cd ~/taler-id
git add src/oauth-registration/oauth-registration.service.ts \
        src/oauth-registration/oauth-registration.controller.ts \
        src/oauth-registration/oauth-registration.service.spec.ts
git commit -m "feat(oauth-registration): rotateSecret endpoint with throttle + audit log"
```

---

## Task 2: Backend — system client `taler-id-developers` (adapter + seed SQL)

**Files:**
- Modify: `~/taler-id/src/oidc/adapters/prisma-client-adapter.ts` (extend post-logout URI hardcoding)
- Create: `~/taler-id/prisma/migrations/2026_seed_taler_id_developers_client.sql`

The adapter currently hardcodes post-logout redirect URIs only for `taler-id-demo` (line 17). We extend that to also cover `taler-id-developers`.

- [ ] **Step 1: Modify the adapter**

In `~/taler-id/src/oidc/adapters/prisma-client-adapter.ts`, replace the hardcoded `postLogoutRedirectUris` block. Current code (lines 14-22):

```ts
    // Hardcoded post-logout redirect URIs for the demo client until the
    // OAuthClient model gains a postLogoutRedirectUris column (planned for
    // Phase 4 — developer portal).
    const postLogoutRedirectUris =
      c.clientId === 'taler-id-demo'
        ? [
            'https://staging.id.taler.tirol/demo/',
            'https://id.taler.tirol/demo/',
          ]
        : undefined;
```

Replace with:

```ts
    // Hardcoded post-logout redirect URIs for system clients until the
    // OAuthClient model gains a postLogoutRedirectUris column.
    let postLogoutRedirectUris: string[] | undefined;
    if (c.clientId === 'taler-id-demo') {
      postLogoutRedirectUris = [
        'https://staging.id.taler.tirol/demo/',
        'https://id.taler.tirol/demo/',
      ];
    } else if (c.clientId === 'taler-id-developers') {
      postLogoutRedirectUris = [
        'https://staging.id.taler.tirol/developers/',
        'https://id.taler.tirol/developers/',
      ];
    }
```

- [ ] **Step 2: Write the seed SQL**

Create `~/taler-id/prisma/migrations/2026_seed_taler_id_developers_client.sql` (note: this is NOT a real Prisma migration — it's a manual one-time seed kept alongside migrations for findability):

```sql
-- One-time seed for the Taler ID Developer Portal's own OAuth client.
-- The SPA at /developers/ uses this clientId for its own login flow (dogfood).
-- Run once per database (DEV: taler_id_dev, PROD: taler_id) at first deploy
-- of Phase 4. Idempotent via ON CONFLICT.
--
-- Phase 4 spec: docs/superpowers/specs/2026-04-30-oauth-ui-kit-phase-4-developer-portal.md

INSERT INTO "OAuthClient" (
  "clientId",
  "clientSecret",
  "name",
  "redirectUris",
  "allowedScopes",
  "userId",
  "createdAt",
  "updatedAt"
)
VALUES (
  'taler-id-developers',
  encode(gen_random_bytes(32), 'base64'),
  'Taler ID Developer Portal',
  ARRAY[
    'https://id.taler.tirol/developers/',
    'https://staging.id.taler.tirol/developers/'
  ],
  ARRAY['openid', 'profile', 'email', 'offline_access'],
  NULL,
  now(),
  now()
)
ON CONFLICT ("clientId") DO NOTHING;
```

PKCE flow doesn't actually consume `clientSecret` for public clients, but the column is `NOT NULL` per Phase 1's schema. We seed a random throwaway value.

- [ ] **Step 3: Verify TypeScript compiles**

```bash
cd ~/taler-id
npx tsc --noEmit --project tsconfig.json 2>&1 | tail -5
```

Expected: 0 errors.

- [ ] **Step 4: Commit**

```bash
cd ~/taler-id
git add src/oidc/adapters/prisma-client-adapter.ts \
        prisma/migrations/2026_seed_taler_id_developers_client.sql
git commit -m "feat(oidc): post-logout URIs + seed SQL for taler-id-developers system client"
```

---

## Task 3: SPA bootstrap

**Files (all created):**
- `~/taler-id/developers/package.json`
- `~/taler-id/developers/vite.config.ts`
- `~/taler-id/developers/tsconfig.json`
- `~/taler-id/developers/vitest.config.ts`
- `~/taler-id/developers/eslint.config.js`
- `~/taler-id/developers/index.html`
- `~/taler-id/developers/src/styles.css`
- `~/taler-id/developers/src/main.tsx` (placeholder)
- `~/taler-id/developers/src/App.tsx` (placeholder)
- `~/taler-id/developers/.gitignore`

- [ ] **Step 1: Create directory and `.gitignore`**

```bash
mkdir -p ~/taler-id/developers/src/pages ~/taler-id/developers/src/modals ~/taler-id/developers/tests
cd ~/taler-id/developers
```

Write `~/taler-id/developers/.gitignore`:

```
node_modules
dist
.dart_tool
*.log
.env
.env.local
coverage
```

(Note: `dist/` is gitignored INSIDE `developers/`. The build output goes to `~/taler-id/public/developers/` via Vite's `outDir: '../public/developers'` — that path is OUTSIDE `developers/` so it doesn't match this gitignore.)

- [ ] **Step 2: Write `package.json`**

```json
{
  "name": "taler-id-developers-portal",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "eslint src tests",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "@taler-id/oauth-client": "file:../../taler-id-sdk-js",
    "react": "^18.3.0",
    "react-dom": "^18.3.0"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.4.0",
    "@testing-library/react": "^16.0.0",
    "@types/react": "^18.3.0",
    "@types/react-dom": "^18.3.0",
    "@typescript-eslint/eslint-plugin": "^8.0.0",
    "@typescript-eslint/parser": "^8.0.0",
    "@vitejs/plugin-react": "^4.3.0",
    "eslint": "^9.0.0",
    "jsdom": "^25.0.0",
    "typescript": "^5.5.0",
    "vite": "^5.0.0",
    "vitest": "^2.0.0"
  }
}
```

- [ ] **Step 3: Write `vite.config.ts`**

```ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/developers/',
  build: {
    outDir: '../public/developers',
    emptyOutDir: true,
    sourcemap: true,
  },
});
```

- [ ] **Step 4: Write `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "jsx": "react-jsx",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "isolatedModules": true,
    "verbatimModuleSyntax": true,
    "resolveJsonModule": true,
    "outDir": "dist"
  },
  "include": ["src/**/*", "tests/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

- [ ] **Step 5: Write `vitest.config.ts`**

```ts
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: false,
    include: ['tests/**/*.test.{ts,tsx}'],
    setupFiles: ['./tests/setup.ts'],
  },
});
```

- [ ] **Step 6: Write `tests/setup.ts`**

```ts
import '@testing-library/jest-dom/vitest';
```

- [ ] **Step 7: Write `eslint.config.js`**

```js
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

export default [
  {
    files: ['src/**/*.{ts,tsx}', 'tests/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsparser,
      parserOptions: { ecmaVersion: 2022, sourceType: 'module', ecmaFeatures: { jsx: true } },
    },
    plugins: { '@typescript-eslint': tseslint },
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
      'no-console': 'warn',
    },
  },
  { ignores: ['dist', 'node_modules', 'coverage'] },
];
```

- [ ] **Step 8: Write `index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <title>Taler ID — Developer Portal</title>
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/main.tsx"></script>
</body>
</html>
```

- [ ] **Step 9: Write `src/styles.css` (Phase 0 design tokens)**

```css
:root {
  --primary: #167EF2;
  --primary-dark: #1570D6;
  --accent: #FBBF24;
  --bg: #0A0E1A;
  --bg-elevated: #161B2C;
  --bg-deep: #11162A;
  --fg: #F5F7FA;
  --fg-muted: #8A92A6;
  --border: #232A40;
  --danger: #EF4444;
}

* { box-sizing: border-box; }

html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  min-height: 100vh;
}

#root { min-height: 100vh; }

a { color: var(--primary); text-decoration: none; }
a:hover { text-decoration: underline; }

code, pre {
  font-family: 'JetBrains Mono', ui-monospace, monospace;
}

button {
  font-family: inherit;
  cursor: pointer;
}

button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-primary {
  background: var(--primary);
  color: #fff;
  border: 1px solid var(--primary);
  padding: 8px 16px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 13px;
}
.btn-primary:hover { background: var(--primary-dark); }

.btn-secondary {
  background: transparent;
  color: var(--fg);
  border: 1px solid var(--border);
  padding: 8px 16px;
  border-radius: 6px;
  font-size: 13px;
}
.btn-secondary:hover { border-color: var(--primary); }

.btn-danger {
  background: var(--danger);
  color: #fff;
  border: 1px solid var(--danger);
  padding: 8px 16px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 13px;
}

.modal-backdrop {
  position: fixed; inset: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex; align-items: center; justify-content: center;
  z-index: 100;
}
.modal {
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
  max-width: 540px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}
.modal-title {
  font-size: 18px;
  font-weight: 600;
  margin: 0 0 12px;
}
.modal-actions {
  margin-top: 24px;
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}

.field { display: block; margin-bottom: 16px; }
.field label { display: block; font-size: 13px; color: var(--fg-muted); margin-bottom: 6px; }
.field input, .field textarea, .field select {
  display: block;
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--fg);
  border-radius: 6px;
  padding: 8px 12px;
  font-size: 13px;
  font-family: inherit;
}
.field textarea { font-family: 'JetBrains Mono', monospace; resize: vertical; min-height: 70px; }
.field-error { color: var(--danger); font-size: 12px; margin-top: 4px; }
```

- [ ] **Step 10: Write placeholder `src/main.tsx` and `src/App.tsx`**

`src/main.tsx`:
```tsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import { App } from './App';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

`src/App.tsx`:
```tsx
export function App() {
  return <div>Loading…</div>;
}
```

(These are placeholders that Tasks 5-11 fill out.)

- [ ] **Step 11: Install + verify the toolchain**

The Phase 2 SDK at `~/taler-id-sdk-js/dist/` must already exist. If not:
```bash
cd ~/taler-id-sdk-js && pnpm install && pnpm build
```

Then in our SPA project:
```bash
cd ~/taler-id/developers
corepack enable
pnpm install
pnpm typecheck
pnpm build
ls ../public/developers/
```

Expected: `pnpm install` resolves the file: dep to `~/taler-id-sdk-js/dist/`. `pnpm build` writes `index.html` + `assets/` to `~/taler-id/public/developers/`. No errors.

- [ ] **Step 12: Commit**

```bash
cd ~/taler-id
git add developers/
git commit -m "chore(developers): bootstrap Vite + React + TypeScript SPA"
```

(The `dist/` and `node_modules/` inside `developers/` are gitignored — only source is committed. The `public/developers/` build output is committed in Task 12, not now.)

---

## Task 4: `api.ts` fetch wrappers

**Files:**
- Create: `~/taler-id/developers/src/api.ts`
- Create: `~/taler-id/developers/tests/api.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// tests/api.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { listClients, registerClient, updateClient, deleteClient, rotateSecret } from '../src/api';

describe('api', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;
  const getToken = async () => 'AT';

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify([]), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
  });

  it('listClients GETs /oauth/clients with Bearer header', async () => {
    await listClients(getToken);
    expect(fetchSpy).toHaveBeenCalledWith('/oauth/clients', expect.objectContaining({
      headers: expect.objectContaining({ authorization: 'Bearer AT' }),
    }));
  });

  it('registerClient POSTs JSON body', async () => {
    fetchSpy.mockResolvedValue(new Response(JSON.stringify({ client_id: 'cid', client_secret: 'sec' }), { status: 200 }));
    const result = await registerClient(getToken, {
      client_name: 'a',
      redirect_uris: ['app://cb'],
      scope: 'openid',
    });
    expect(result.client_id).toBe('cid');
    const call = fetchSpy.mock.calls[0]!;
    expect(call[0]).toBe('/oauth/register');
    expect((call[1] as RequestInit).method).toBe('POST');
    const body = JSON.parse((call[1] as RequestInit).body as string);
    expect(body.client_name).toBe('a');
  });

  it('updateClient PATCHes /oauth/clients/:id', async () => {
    await updateClient(getToken, 'cid-1', { client_name: 'newname' });
    const call = fetchSpy.mock.calls[0]!;
    expect(call[0]).toBe('/oauth/clients/cid-1');
    expect((call[1] as RequestInit).method).toBe('PATCH');
  });

  it('deleteClient DELETEs /oauth/clients/:id', async () => {
    await deleteClient(getToken, 'cid-1');
    const call = fetchSpy.mock.calls[0]!;
    expect(call[0]).toBe('/oauth/clients/cid-1');
    expect((call[1] as RequestInit).method).toBe('DELETE');
  });

  it('rotateSecret POSTs to /oauth/clients/:id/rotate-secret', async () => {
    fetchSpy.mockResolvedValue(new Response(JSON.stringify({ client_id: 'cid', client_secret: 'NEW' }), { status: 200 }));
    const result = await rotateSecret(getToken, 'cid-1');
    expect(result.client_secret).toBe('NEW');
    const call = fetchSpy.mock.calls[0]!;
    expect(call[0]).toBe('/oauth/clients/cid-1/rotate-secret');
    expect((call[1] as RequestInit).method).toBe('POST');
  });

  it('throws Error on non-2xx response', async () => {
    fetchSpy.mockResolvedValue(new Response('{"error":"bad"}', { status: 400 }));
    await expect(listClients(getToken)).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify failure**

```bash
cd ~/taler-id/developers
pnpm test 2>&1 | tail -10
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```ts
// src/api.ts

/** A function that returns a fresh access token (handles refresh internally). */
export type GetToken = () => Promise<string>;

export interface OAuthClient {
  client_id: string;
  client_id_issued_at: number;
  client_name: string;
  redirect_uris: string[];
  scope: string;
  logo_uri?: string;
  token_endpoint_auth_method: string;
  grant_types: string[];
  response_types: string[];
}

export interface RegisterResponse extends OAuthClient {
  client_secret: string;
  client_secret_expires_at: number;
}

export interface RegisterPayload {
  client_name: string;
  redirect_uris: string[];
  scope?: string;
  logo_uri?: string;
}

export interface UpdatePayload {
  client_name?: string;
  redirect_uris?: string[];
  scope?: string;
  logo_uri?: string;
}

export interface RotateResponse {
  client_id: string;
  client_secret: string;
  client_secret_rotated_at: number;
}

async function call<T>(getToken: GetToken, path: string, init: RequestInit = {}): Promise<T> {
  const token = await getToken();
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      authorization: `Bearer ${token}`,
      ...(init.body ? { 'content-type': 'application/json' } : {}),
    },
  });
  if (!response.ok) {
    let detail: unknown;
    try { detail = await response.json(); } catch { detail = await response.text(); }
    throw new Error(`HTTP ${response.status}: ${JSON.stringify(detail)}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const listClients = (getToken: GetToken) =>
  call<OAuthClient[]>(getToken, '/oauth/clients');

export const registerClient = (getToken: GetToken, payload: RegisterPayload) =>
  call<RegisterResponse>(getToken, '/oauth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

export const updateClient = (getToken: GetToken, clientId: string, payload: UpdatePayload) =>
  call<OAuthClient>(getToken, `/oauth/clients/${clientId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });

export const deleteClient = (getToken: GetToken, clientId: string) =>
  call<void>(getToken, `/oauth/clients/${clientId}`, { method: 'DELETE' });

export const rotateSecret = (getToken: GetToken, clientId: string) =>
  call<RotateResponse>(getToken, `/oauth/clients/${clientId}/rotate-secret`, {
    method: 'POST',
  });
```

- [ ] **Step 4: Run tests + typecheck**

```bash
pnpm test 2>&1 | tail -10
pnpm typecheck 2>&1 | tail -3
```

Expected: 6 tests pass; typecheck clean.

- [ ] **Step 5: Commit**

```bash
cd ~/taler-id
git add developers/src/api.ts developers/tests/api.test.ts
git commit -m "feat(developers): typed fetch helpers for /oauth/clients endpoints"
```

---

## Task 5: Auth gate — `App.tsx`, `LoginGate.tsx`, `main.tsx`

**Files:**
- Modify: `~/taler-id/developers/src/main.tsx`
- Modify: `~/taler-id/developers/src/App.tsx`
- Create: `~/taler-id/developers/src/pages/LoginGate.tsx`
- Create: `~/taler-id/developers/tests/App.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// tests/App.test.tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { App } from '../src/App';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return {
    ...actual,
    useTalerIdAuth: vi.fn(),
  };
});

describe('App', () => {
  it('renders LoginGate when not authenticated', () => {
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn(),
    });
    render(<App />);
    expect(screen.getByRole('button', { name: /Sign in with Taler ID/i })).toBeInTheDocument();
  });

  it('renders ClientsList when authenticated', () => {
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: { sub: 'u1' },
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    });
    // ClientsList fetches on mount — mock fetch
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    render(<App />);
    expect(screen.queryByRole('button', { name: /Sign in with Taler ID/i })).not.toBeInTheDocument();
  });

  it('renders loading state when isLoading', () => {
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: null,
      isAuthenticated: false,
      isLoading: true,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn(),
    });
    render(<App />);
    expect(screen.getByText(/Loading/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify failure**

```bash
cd ~/taler-id/developers
pnpm test App 2>&1 | tail -10
```

Expected: FAIL — `App` doesn't yet branch on auth state.

- [ ] **Step 3: Write `LoginGate`**

```tsx
// src/pages/LoginGate.tsx
import { useTalerIdAuth } from '@taler-id/oauth-client/react';

export function LoginGate() {
  const { login } = useTalerIdAuth();
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ textAlign: 'center', maxWidth: 360 }}>
        <h1 style={{ fontSize: 28, marginBottom: 8 }}>Taler ID Developer Portal</h1>
        <p style={{ color: 'var(--fg-muted)', marginBottom: 32 }}>
          Manage your OAuth clients. Sign in with your Taler ID account (email-verified accounts only).
        </p>
        <button className="btn-primary" style={{ padding: '12px 24px', fontSize: 15 }} onClick={() => login()}>
          Sign in with Taler ID
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Update `App.tsx`**

```tsx
// src/App.tsx
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { LoginGate } from './pages/LoginGate';
import { ClientsList } from './pages/ClientsList';

export function App() {
  const { isAuthenticated, isLoading } = useTalerIdAuth();
  if (isLoading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fg-muted)' }}>
        Loading…
      </div>
    );
  }
  if (!isAuthenticated) return <LoginGate />;
  return <ClientsList />;
}
```

- [ ] **Step 5: Update `main.tsx`**

```tsx
// src/main.tsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { TalerIdProvider } from '@taler-id/oauth-client/react';
import './styles.css';
import { App } from './App';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TalerIdProvider
      clientId="taler-id-developers"
      redirectUri={window.location.origin + '/developers/'}
    >
      <App />
    </TalerIdProvider>
  </StrictMode>,
);
```

- [ ] **Step 6: Stub `ClientsList` so the import resolves**

Create `src/pages/ClientsList.tsx` as a placeholder (filled in Task 6):

```tsx
// src/pages/ClientsList.tsx (placeholder — Task 6 implements it)
export function ClientsList() {
  return <div>Clients list — implemented in Task 6</div>;
}
```

- [ ] **Step 7: Run tests + typecheck**

```bash
pnpm test 2>&1 | tail -10
pnpm typecheck 2>&1 | tail -3
```

Expected: 9 tests pass total (6 api + 3 App). The "renders ClientsList" test currently asserts only the absence of the LoginGate button — passes against the placeholder.

- [ ] **Step 8: Commit**

```bash
cd ~/taler-id
git add developers/src/main.tsx developers/src/App.tsx developers/src/pages/LoginGate.tsx \
        developers/src/pages/ClientsList.tsx developers/tests/App.test.tsx
git commit -m "feat(developers): auth gate + LoginGate; TalerIdProvider in main"
```

---

## Task 6: `ClientsList` page

**Files:**
- Modify: `~/taler-id/developers/src/pages/ClientsList.tsx`
- Create: `~/taler-id/developers/tests/ClientsList.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// tests/ClientsList.test.tsx
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ClientsList } from '../src/pages/ClientsList';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return { ...actual, useTalerIdAuth: vi.fn() };
});

describe('ClientsList', () => {
  beforeEach(() => {
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: { sub: 'u1', email: 'u@example.com' },
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    });
  });

  it('renders rows from the API', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify([
        {
          client_id: '4f3c-abc',
          client_name: 'my-app',
          redirect_uris: ['app://cb', 'app://cb2'],
          scope: 'openid profile',
          client_id_issued_at: Math.floor(Date.now() / 1000) - 86400,
          token_endpoint_auth_method: 'client_secret_basic',
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
        },
      ]), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    render(<ClientsList />);
    await waitFor(() => expect(screen.getByText('my-app')).toBeInTheDocument());
    expect(screen.getByText(/2 URIs/i)).toBeInTheDocument();
    expect(screen.getByText(/4f3c-abc/i)).toBeInTheDocument();
  });

  it('shows empty state with CTA when no clients', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    render(<ClientsList />);
    await waitFor(() => expect(screen.getByText(/No OAuth clients yet/i)).toBeInTheDocument());
  });
});
```

(The third test — that clicking "Register new client" opens the create modal — is added in Task 7 once the real `CreateClientModal` exists. With only a stub it would always fail.)

Note: `userEvent` requires `@testing-library/user-event` — add to dev deps if not yet:

```bash
cd ~/taler-id/developers
pnpm add -D @testing-library/user-event
```

- [ ] **Step 2: Run test to verify failure**

```bash
pnpm test ClientsList 2>&1 | tail -10
```

Expected: FAIL — placeholder `ClientsList` doesn't fetch or render rows.

- [ ] **Step 3: Implement `ClientsList`**

```tsx
// src/pages/ClientsList.tsx
import { useEffect, useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { listClients, type OAuthClient } from '../api';
import { CreateClientModal } from '../modals/CreateClientModal';
import { EditClientModal } from '../modals/EditClientModal';
import { DeleteClientModal } from '../modals/DeleteClientModal';
import { RotateSecretModal } from '../modals/RotateSecretModal';
import { SecretRevealModal } from '../modals/SecretRevealModal';

export function ClientsList() {
  const { user, logout, getAccessToken } = useTalerIdAuth();
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<OAuthClient | null>(null);
  const [deleting, setDeleting] = useState<OAuthClient | null>(null);
  const [rotating, setRotating] = useState<OAuthClient | null>(null);
  const [secret, setSecret] = useState<{ client_id: string; client_secret: string } | null>(null);

  const refresh = async () => {
    try {
      const data = await listClients(getAccessToken);
      setClients(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load clients');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); /* eslint-disable-next-line */ }, []);

  const formatRelative = (issuedAt: number) => {
    const ago = Math.floor((Date.now() / 1000) - issuedAt);
    if (ago < 60) return 'just now';
    if (ago < 3600) return `${Math.floor(ago / 60)}m ago`;
    if (ago < 86400) return `${Math.floor(ago / 3600)}h ago`;
    return `${Math.floor(ago / 86400)} days ago`;
  };

  return (
    <div style={{ minHeight: '100vh' }}>
      {/* Nav */}
      <div style={{ background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)', padding: '16px 24px' }}>
        <div style={{ maxWidth: 960, margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <strong style={{ fontSize: 16 }}>Taler ID — Developer Portal</strong>
          <div style={{ fontSize: 13, color: 'var(--fg-muted)' }}>
            <span style={{ marginRight: 16 }}>{user?.email as string ?? user?.sub}</span>
            <button className="btn-secondary" onClick={() => logout({ returnTo: window.location.origin + '/developers/' })}>Logout</button>
          </div>
        </div>
      </div>

      <div style={{ maxWidth: 960, margin: '0 auto', padding: '32px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <div>
            <h1 style={{ margin: 0, fontSize: 22 }}>Your OAuth clients</h1>
            <p style={{ color: 'var(--fg-muted)', marginTop: 4, marginBottom: 0, fontSize: 13 }}>
              {clients.length} of 10 used. Email-verified accounts only.
            </p>
          </div>
          <button className="btn-primary" onClick={() => setCreateOpen(true)}>+ Register new client</button>
        </div>

        {loading && <div style={{ color: 'var(--fg-muted)' }}>Loading…</div>}
        {error && <div style={{ color: 'var(--danger)', padding: 12, background: 'var(--bg-elevated)', borderRadius: 6 }}>{error}</div>}

        {!loading && !error && clients.length === 0 && (
          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: 32, textAlign: 'center' }}>
            <p style={{ marginTop: 0 }}>No OAuth clients yet.</p>
            <button className="btn-primary" onClick={() => setCreateOpen(true)}>Register your first client</button>
          </div>
        )}

        {!loading && clients.length > 0 && (
          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1fr 1fr 160px', gap: 12, padding: '12px 16px', background: 'var(--bg-deep)', fontSize: 11, color: 'var(--fg-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              <div>Name</div><div>Client ID</div><div>Redirect URIs</div><div>Created</div><div>Actions</div>
            </div>
            {clients.map((c) => (
              <ClientRow
                key={c.client_id}
                client={c}
                formatRelative={formatRelative}
                onEdit={() => setEditing(c)}
                onDelete={() => setDeleting(c)}
                onRotate={() => setRotating(c)}
              />
            ))}
          </div>
        )}

        <div style={{ marginTop: 32, padding: 16, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 13, color: 'var(--fg-muted)' }}>
          <strong style={{ color: 'var(--fg)' }}>Need help integrating?</strong>
          {' '}
          <a href="/oauth-guide.html">Integration guide →</a>
          {' · '}
          <a href="/brand">Brand assets →</a>
          {' · '}
          <a href="https://www.npmjs.com/package/@taler-id/oauth-client" target="_blank" rel="noopener">JS SDK →</a>
          {' · '}
          <a href="https://pub.dev/packages/talerid_oauth" target="_blank" rel="noopener">Flutter SDK →</a>
        </div>
      </div>

      {createOpen && (
        <CreateClientModal
          onClose={() => setCreateOpen(false)}
          onCreated={(secret) => { setCreateOpen(false); setSecret(secret); refresh(); }}
        />
      )}
      {editing && (
        <EditClientModal client={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); refresh(); }} />
      )}
      {deleting && (
        <DeleteClientModal client={deleting} onClose={() => setDeleting(null)} onDeleted={() => { setDeleting(null); refresh(); }} />
      )}
      {rotating && (
        <RotateSecretModal
          client={rotating}
          onClose={() => setRotating(null)}
          onRotated={(secret) => { setRotating(null); setSecret(secret); }}
        />
      )}
      {secret && (
        <SecretRevealModal
          clientId={secret.client_id}
          clientSecret={secret.client_secret}
          onClose={() => setSecret(null)}
        />
      )}
    </div>
  );
}

function ClientRow({
  client, formatRelative, onEdit, onDelete, onRotate,
}: {
  client: OAuthClient;
  formatRelative: (n: number) => string;
  onEdit: () => void;
  onDelete: () => void;
  onRotate: () => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 1fr 1fr 160px', gap: 12, padding: '14px 16px', borderTop: '1px solid var(--border)', alignItems: 'center', fontSize: 13, position: 'relative' }}>
      <div><strong>{client.client_name}</strong></div>
      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--fg-muted)' }}>{client.client_id}</div>
      <div style={{ color: 'var(--fg-muted)' }}>{client.redirect_uris.length} URIs</div>
      <div style={{ color: 'var(--fg-muted)' }}>{formatRelative(client.client_id_issued_at)}</div>
      <div style={{ display: 'flex', gap: 6, position: 'relative' }}>
        <button className="btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }} onClick={onEdit}>Edit</button>
        <button className="btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }} onClick={() => setMenuOpen((v) => !v)} aria-label="More actions">⋯</button>
        {menuOpen && (
          <div style={{ position: 'absolute', top: '100%', right: 0, marginTop: 4, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, padding: 4, zIndex: 10, minWidth: 140 }}>
            <button className="btn-secondary" style={{ display: 'block', width: '100%', textAlign: 'left', border: 'none' }} onClick={() => { setMenuOpen(false); onRotate(); }}>Rotate secret</button>
            <button className="btn-secondary" style={{ display: 'block', width: '100%', textAlign: 'left', border: 'none', color: 'var(--danger)' }} onClick={() => { setMenuOpen(false); onDelete(); }}>Delete</button>
          </div>
        )}
      </div>
    </div>
  );
}
```

The five modal imports reference files that Tasks 7-11 create. For now, create stub files so the imports resolve:

```tsx
// src/modals/CreateClientModal.tsx (Task 7 implements)
import type { RegisterResponse } from '../api';
export function CreateClientModal(_: { onClose: () => void; onCreated: (s: RegisterResponse) => void }) { return null; }
```

```tsx
// src/modals/EditClientModal.tsx (Task 8 implements)
import type { OAuthClient } from '../api';
export function EditClientModal(_: { client: OAuthClient; onClose: () => void; onSaved: () => void }) { return null; }
```

```tsx
// src/modals/DeleteClientModal.tsx (Task 9 implements)
import type { OAuthClient } from '../api';
export function DeleteClientModal(_: { client: OAuthClient; onClose: () => void; onDeleted: () => void }) { return null; }
```

```tsx
// src/modals/RotateSecretModal.tsx (Task 10 implements)
import type { OAuthClient, RotateResponse } from '../api';
export function RotateSecretModal(_: { client: OAuthClient; onClose: () => void; onRotated: (r: RotateResponse) => void }) { return null; }
```

```tsx
// src/modals/SecretRevealModal.tsx (Task 11 implements)
export function SecretRevealModal(_: { clientId: string; clientSecret: string; onClose: () => void }) { return null; }
```

These stubs make imports type-check. Tasks 7-11 replace each with the real implementation.

Wait — the test at the top of this task expects clicking "Register new client" to open a modal that has a heading "Register new OAuth client". Our stub doesn't render anything. The test will fail. We need to either:
- Make the stubs render minimal markup (e.g. CreateClientModal renders `<div role="heading">Register new OAuth client</div>`), OR
- Move the "create modal opens" test to Task 7 (when CreateClientModal is real)

Pick option 2 — move the create-modal-opens test to Task 7. Remove the third test from `tests/ClientsList.test.tsx` for now; we'll re-add it in Task 7.

- [ ] **Step 4: Run tests + typecheck**

```bash
pnpm test 2>&1 | tail -10
pnpm typecheck 2>&1 | tail -3
```

Expected: 11 tests pass total (6 api + 3 App + 2 ClientsList — empty state + render rows). Typecheck clean.

- [ ] **Step 5: Commit**

```bash
cd ~/taler-id
git add developers/src/pages/ClientsList.tsx \
        developers/src/modals/*.tsx \
        developers/tests/ClientsList.test.tsx \
        developers/package.json developers/pnpm-lock.yaml
git commit -m "feat(developers): ClientsList page with table + actions menu + modal stubs"
```

---

## Task 7: `CreateClientModal`

**Files:**
- Modify: `~/taler-id/developers/src/modals/CreateClientModal.tsx`
- Create: `~/taler-id/developers/tests/CreateClientModal.test.tsx`

- [ ] **Step 1: Write the failing tests**

```tsx
// tests/CreateClientModal.test.tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CreateClientModal } from '../src/modals/CreateClientModal';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return { ...actual, useTalerIdAuth: vi.fn() };
});

describe('CreateClientModal', () => {
  beforeEach(() => {
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: { sub: 'u1' },
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    });
  });

  it('renders form fields', () => {
    render(<CreateClientModal onClose={() => {}} onCreated={() => {}} />);
    expect(screen.getByRole('heading', { name: /Register new OAuth client/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Client name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Redirect URIs/i)).toBeInTheDocument();
  });

  it('submits and calls onCreated with client_id + client_secret', async () => {
    const onCreated = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({
        client_id: 'cid', client_secret: 'sec',
      }), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    const user = userEvent.setup();
    render(<CreateClientModal onClose={() => {}} onCreated={onCreated} />);
    await user.type(screen.getByLabelText(/Client name/i), 'my-app');
    await user.type(screen.getByLabelText(/Redirect URIs/i), 'app://cb');
    await user.click(screen.getByRole('button', { name: /Register/i }));
    await waitFor(() =>
      expect(onCreated).toHaveBeenCalledWith(expect.objectContaining({ client_id: 'cid', client_secret: 'sec' })),
    );
  });

  it('shows error when API fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'bad' }), { status: 400 }),
    );
    const user = userEvent.setup();
    render(<CreateClientModal onClose={() => {}} onCreated={() => {}} />);
    await user.type(screen.getByLabelText(/Client name/i), 'x');
    await user.type(screen.getByLabelText(/Redirect URIs/i), 'app://cb');
    await user.click(screen.getByRole('button', { name: /Register/i }));
    await waitFor(() => expect(screen.getByText(/HTTP 400/i)).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Run test to verify failure**

```bash
pnpm test CreateClient 2>&1 | tail -10
```

Expected: FAIL — stub renders null.

- [ ] **Step 3: Replace the stub**

```tsx
// src/modals/CreateClientModal.tsx
import { useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { registerClient, type RegisterResponse } from '../api';

const ALLOWED_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

export function CreateClientModal({
  onClose, onCreated,
}: { onClose: () => void; onCreated: (resp: RegisterResponse) => void }) {
  const { getAccessToken } = useTalerIdAuth();
  const [name, setName] = useState('');
  const [redirectUris, setRedirectUris] = useState('');
  const [logoUri, setLogoUri] = useState('');
  const [scopes, setScopes] = useState<string[]>(['openid', 'profile', 'email']);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      const result = await registerClient(getAccessToken, {
        client_name: name.trim(),
        redirect_uris: redirectUris.split('\n').map((s) => s.trim()).filter(Boolean),
        scope: scopes.join(' '),
        logo_uri: logoUri.trim() || undefined,
      });
      onCreated(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally {
      setSubmitting(false);
    }
  };

  const toggleScope = (s: string) => {
    setScopes((cur) => cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]);
  };

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <h2 className="modal-title">Register new OAuth client</h2>
        <div className="field">
          <label htmlFor="cc-name">Client name</label>
          <input id="cc-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
        </div>
        <div className="field">
          <label htmlFor="cc-uris">Redirect URIs (one per line)</label>
          <textarea id="cc-uris" value={redirectUris} onChange={(e) => setRedirectUris(e.target.value)} rows={3} />
        </div>
        <div className="field">
          <label htmlFor="cc-logo">Logo URL (optional)</label>
          <input id="cc-logo" value={logoUri} onChange={(e) => setLogoUri(e.target.value)} placeholder="https://example.com/logo.png" />
        </div>
        <div className="field">
          <label>Scopes</label>
          {ALLOWED_SCOPES.map((s) => (
            <label key={s} style={{ display: 'inline-flex', alignItems: 'center', marginRight: 12, fontSize: 13 }}>
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggleScope(s)} />
              <code style={{ marginLeft: 4 }}>{s}</code>
            </label>
          ))}
        </div>
        {error && <div className="field-error">{error}</div>}
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose} disabled={submitting}>Cancel</button>
          <button
            className="btn-primary"
            onClick={submit}
            disabled={submitting || !name.trim() || !redirectUris.trim()}
          >
            {submitting ? 'Registering…' : 'Register'}
          </button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Add the deferred ClientsList integration test**

In `~/taler-id/developers/tests/ClientsList.test.tsx`, append the third test that was deferred from Task 6:

```tsx
  it('clicking "Register new client" opens the create modal', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    const user = userEvent.setup();
    render(<ClientsList />);
    await waitFor(() => expect(screen.getByText(/Register new client/i)).toBeInTheDocument());
    await user.click(screen.getByText(/Register new client/i));
    expect(screen.getByRole('heading', { name: /Register new OAuth client/i })).toBeInTheDocument();
  });
```

- [ ] **Step 5: Run tests + typecheck**

```bash
pnpm test 2>&1 | tail -10
pnpm typecheck 2>&1 | tail -3
```

Expected: 14 tests pass (6 api + 3 App + 3 ClientsList + 3 CreateClient).

- [ ] **Step 6: Commit**

```bash
cd ~/taler-id
git add developers/src/modals/CreateClientModal.tsx \
        developers/tests/CreateClientModal.test.tsx \
        developers/tests/ClientsList.test.tsx
git commit -m "feat(developers): CreateClientModal with form validation + scope picker"
```

---

## Task 8: `EditClientModal`

**Files:**
- Modify: `~/taler-id/developers/src/modals/EditClientModal.tsx`
- Create: `~/taler-id/developers/tests/EditClientModal.test.tsx`

- [ ] **Step 1: Write failing test**

```tsx
// tests/EditClientModal.test.tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EditClientModal } from '../src/modals/EditClientModal';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return { ...actual, useTalerIdAuth: vi.fn() };
});

const fakeClient = {
  client_id: 'cid', client_name: 'old', redirect_uris: ['app://cb'],
  scope: 'openid', client_id_issued_at: 0,
  token_endpoint_auth_method: 'client_secret_basic',
  grant_types: [], response_types: [],
};

describe('EditClientModal', () => {
  beforeEach(() => {
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: { sub: 'u1' }, isAuthenticated: true, isLoading: false,
      login: vi.fn(), logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    });
  });

  it('pre-populates form from client', () => {
    render(<EditClientModal client={fakeClient as any} onClose={() => {}} onSaved={() => {}} />);
    expect((screen.getByLabelText(/Client name/i) as HTMLInputElement).value).toBe('old');
    expect((screen.getByLabelText(/Redirect URIs/i) as HTMLTextAreaElement).value).toContain('app://cb');
  });

  it('submits PATCH and calls onSaved', async () => {
    const onSaved = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    const user = userEvent.setup();
    render(<EditClientModal client={fakeClient as any} onClose={() => {}} onSaved={onSaved} />);
    await user.clear(screen.getByLabelText(/Client name/i));
    await user.type(screen.getByLabelText(/Client name/i), 'new');
    await user.click(screen.getByRole('button', { name: /Save/i }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
  });
});
```

- [ ] **Step 2: Verify failure**

```bash
pnpm test EditClient 2>&1 | tail -10
```

Expected: FAIL.

- [ ] **Step 3: Replace stub**

```tsx
// src/modals/EditClientModal.tsx
import { useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { updateClient, type OAuthClient } from '../api';

const ALLOWED_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

export function EditClientModal({
  client, onClose, onSaved,
}: { client: OAuthClient; onClose: () => void; onSaved: () => void }) {
  const { getAccessToken } = useTalerIdAuth();
  const [name, setName] = useState(client.client_name);
  const [redirectUris, setRedirectUris] = useState(client.redirect_uris.join('\n'));
  const [logoUri, setLogoUri] = useState(client.logo_uri ?? '');
  const [scopes, setScopes] = useState<string[]>(client.scope.split(' ').filter(Boolean));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await updateClient(getAccessToken, client.client_id, {
        client_name: name.trim(),
        redirect_uris: redirectUris.split('\n').map((s) => s.trim()).filter(Boolean),
        scope: scopes.join(' '),
        logo_uri: logoUri.trim() || undefined,
      });
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally {
      setSubmitting(false);
    }
  };

  const toggleScope = (s: string) => {
    setScopes((cur) => cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]);
  };

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <h2 className="modal-title">Edit {client.client_name}</h2>
        <div style={{ fontSize: 12, color: 'var(--fg-muted)', marginBottom: 16 }}>
          Client ID: <code>{client.client_id}</code>
        </div>
        <div className="field">
          <label htmlFor="ec-name">Client name</label>
          <input id="ec-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
        </div>
        <div className="field">
          <label htmlFor="ec-uris">Redirect URIs (one per line)</label>
          <textarea id="ec-uris" value={redirectUris} onChange={(e) => setRedirectUris(e.target.value)} rows={3} />
        </div>
        <div className="field">
          <label htmlFor="ec-logo">Logo URL (optional)</label>
          <input id="ec-logo" value={logoUri} onChange={(e) => setLogoUri(e.target.value)} />
        </div>
        <div className="field">
          <label>Scopes</label>
          {ALLOWED_SCOPES.map((s) => (
            <label key={s} style={{ display: 'inline-flex', alignItems: 'center', marginRight: 12, fontSize: 13 }}>
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggleScope(s)} />
              <code style={{ marginLeft: 4 }}>{s}</code>
            </label>
          ))}
        </div>
        {error && <div className="field-error">{error}</div>}
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose} disabled={submitting}>Cancel</button>
          <button className="btn-primary" onClick={submit} disabled={submitting}>
            {submitting ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 4: Run tests**

```bash
pnpm test 2>&1 | tail -5
pnpm typecheck 2>&1 | tail -3
```

Expected: 16 tests pass.

- [ ] **Step 5: Commit**

```bash
cd ~/taler-id
git add developers/src/modals/EditClientModal.tsx developers/tests/EditClientModal.test.tsx
git commit -m "feat(developers): EditClientModal with pre-populated fields"
```

---

## Task 9: `DeleteClientModal`

**Files:**
- Modify: `~/taler-id/developers/src/modals/DeleteClientModal.tsx`
- Create: `~/taler-id/developers/tests/DeleteClientModal.test.tsx`

- [ ] **Step 1: Write failing test**

```tsx
// tests/DeleteClientModal.test.tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeleteClientModal } from '../src/modals/DeleteClientModal';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return { ...actual, useTalerIdAuth: vi.fn() };
});

const fakeClient = {
  client_id: 'cid', client_name: 'my-app', redirect_uris: [], scope: '',
  client_id_issued_at: 0, token_endpoint_auth_method: 'client_secret_basic',
  grant_types: [], response_types: [],
};

describe('DeleteClientModal', () => {
  beforeEach(() => {
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: { sub: 'u' }, isAuthenticated: true, isLoading: false,
      login: vi.fn(), logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    });
  });

  it('Delete button is disabled until user types client name', async () => {
    const user = userEvent.setup();
    render(<DeleteClientModal client={fakeClient as any} onClose={() => {}} onDeleted={() => {}} />);
    const btn = screen.getByRole('button', { name: /Delete forever/i });
    expect(btn).toBeDisabled();
    await user.type(screen.getByLabelText(/Type the client name/i), 'my-app');
    expect(btn).toBeEnabled();
  });

  it('submits DELETE and calls onDeleted', async () => {
    const onDeleted = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 204 }));
    const user = userEvent.setup();
    render(<DeleteClientModal client={fakeClient as any} onClose={() => {}} onDeleted={onDeleted} />);
    await user.type(screen.getByLabelText(/Type the client name/i), 'my-app');
    await user.click(screen.getByRole('button', { name: /Delete forever/i }));
    await waitFor(() => expect(onDeleted).toHaveBeenCalled());
  });
});
```

- [ ] **Step 2: Replace stub**

```tsx
// src/modals/DeleteClientModal.tsx
import { useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { deleteClient, type OAuthClient } from '../api';

export function DeleteClientModal({
  client, onClose, onDeleted,
}: { client: OAuthClient; onClose: () => void; onDeleted: () => void }) {
  const { getAccessToken } = useTalerIdAuth();
  const [confirmText, setConfirmText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true); setError(null);
    try {
      await deleteClient(getAccessToken, client.client_id);
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally { setSubmitting(false); }
  };

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <h2 className="modal-title">Delete {client.client_name}?</h2>
        <p style={{ color: 'var(--fg-muted)' }}>
          This permanently deletes the OAuth client. Any deployed integration using <code>{client.client_id}</code> will immediately stop working.
        </p>
        <div className="field">
          <label htmlFor="del-conf">Type the client name to confirm: <code>{client.client_name}</code></label>
          <input id="del-conf" value={confirmText} onChange={(e) => setConfirmText(e.target.value)} />
        </div>
        {error && <div className="field-error">{error}</div>}
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose} disabled={submitting}>Cancel</button>
          <button className="btn-danger" onClick={submit} disabled={submitting || confirmText !== client.client_name}>
            {submitting ? 'Deleting…' : 'Delete forever'}
          </button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Run + commit**

```bash
pnpm test 2>&1 | tail -5
git add developers/src/modals/DeleteClientModal.tsx developers/tests/DeleteClientModal.test.tsx
git commit -m "feat(developers): DeleteClientModal with type-name-to-confirm safety"
```

---

## Task 10: `RotateSecretModal`

**Files:**
- Modify: `~/taler-id/developers/src/modals/RotateSecretModal.tsx`
- Create: `~/taler-id/developers/tests/RotateSecretModal.test.tsx`

- [ ] **Step 1: Write failing test**

```tsx
// tests/RotateSecretModal.test.tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RotateSecretModal } from '../src/modals/RotateSecretModal';
import * as sdk from '@taler-id/oauth-client/react';

vi.mock('@taler-id/oauth-client/react', async (importOriginal) => {
  const actual = await importOriginal<typeof sdk>();
  return { ...actual, useTalerIdAuth: vi.fn() };
});

const fakeClient = {
  client_id: 'cid', client_name: 'my-app', redirect_uris: [], scope: '',
  client_id_issued_at: 0, token_endpoint_auth_method: 'client_secret_basic',
  grant_types: [], response_types: [],
};

describe('RotateSecretModal', () => {
  beforeEach(() => {
    vi.mocked(sdk.useTalerIdAuth).mockReturnValue({
      user: { sub: 'u' }, isAuthenticated: true, isLoading: false,
      login: vi.fn(), logout: vi.fn(),
      getAccessToken: vi.fn().mockResolvedValue('AT'),
    });
  });

  it('warns about old secret invalidation', () => {
    render(<RotateSecretModal client={fakeClient as any} onClose={() => {}} onRotated={() => {}} />);
    expect(screen.getByText(/old secret will fail/i)).toBeInTheDocument();
  });

  it('on confirm calls API and onRotated with new secret', async () => {
    const onRotated = vi.fn();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ client_id: 'cid', client_secret: 'NEW_SECRET' }), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    const user = userEvent.setup();
    render(<RotateSecretModal client={fakeClient as any} onClose={() => {}} onRotated={onRotated} />);
    await user.click(screen.getByRole('button', { name: /Rotate secret/i }));
    await waitFor(() => expect(onRotated).toHaveBeenCalledWith(expect.objectContaining({ client_secret: 'NEW_SECRET' })));
  });
});
```

- [ ] **Step 2: Replace stub**

```tsx
// src/modals/RotateSecretModal.tsx
import { useState } from 'react';
import { useTalerIdAuth } from '@taler-id/oauth-client/react';
import { rotateSecret, type OAuthClient, type RotateResponse } from '../api';

export function RotateSecretModal({
  client, onClose, onRotated,
}: { client: OAuthClient; onClose: () => void; onRotated: (resp: RotateResponse) => void }) {
  const { getAccessToken } = useTalerIdAuth();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setSubmitting(true); setError(null);
    try {
      const result = await rotateSecret(getAccessToken, client.client_id);
      onRotated(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed');
    } finally { setSubmitting(false); }
  };

  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <h2 className="modal-title">Rotate secret for {client.client_name}?</h2>
        <p style={{ color: 'var(--fg-muted)' }}>
          Rotating invalidates the current secret immediately. Any deployed app using the old secret will fail until you update it with the new one.
        </p>
        <p style={{ color: 'var(--fg-muted)' }}>
          You'll see the new secret only once on the next screen. Copy it before closing.
        </p>
        {error && <div className="field-error">{error}</div>}
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose} disabled={submitting}>Cancel</button>
          <button className="btn-primary" onClick={submit} disabled={submitting}>
            {submitting ? 'Rotating…' : 'Rotate secret'}
          </button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Run + commit**

```bash
pnpm test 2>&1 | tail -5
git add developers/src/modals/RotateSecretModal.tsx developers/tests/RotateSecretModal.test.tsx
git commit -m "feat(developers): RotateSecretModal with warning + confirmation"
```

---

## Task 11: `SecretRevealModal`

**Files:**
- Modify: `~/taler-id/developers/src/modals/SecretRevealModal.tsx`
- Create: `~/taler-id/developers/tests/SecretRevealModal.test.tsx`

- [ ] **Step 1: Write failing test**

```tsx
// tests/SecretRevealModal.test.tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SecretRevealModal } from '../src/modals/SecretRevealModal';

describe('SecretRevealModal', () => {
  it('shows the secret in monospace', () => {
    render(<SecretRevealModal clientId="cid" clientSecret="SECRET123" onClose={() => {}} />);
    expect(screen.getByText('SECRET123')).toBeInTheDocument();
  });

  it('Done button is disabled until checkbox is ticked', async () => {
    const user = userEvent.setup();
    render(<SecretRevealModal clientId="cid" clientSecret="S" onClose={() => {}} />);
    const done = screen.getByRole('button', { name: /Done/i });
    expect(done).toBeDisabled();
    await user.click(screen.getByLabelText(/I've copied the secret/i));
    expect(done).toBeEnabled();
  });

  it('clicking Copy fires the clipboard API', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    const user = userEvent.setup();
    render(<SecretRevealModal clientId="cid" clientSecret="S123" onClose={() => {}} />);
    await user.click(screen.getByRole('button', { name: /Copy/i }));
    expect(writeText).toHaveBeenCalledWith('S123');
  });

  it('Done button calls onClose', async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(<SecretRevealModal clientId="cid" clientSecret="S" onClose={onClose} />);
    await user.click(screen.getByLabelText(/I've copied the secret/i));
    await user.click(screen.getByRole('button', { name: /Done/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Replace stub**

```tsx
// src/modals/SecretRevealModal.tsx
import { useState } from 'react';

export function SecretRevealModal({
  clientId, clientSecret, onClose,
}: { clientId: string; clientSecret: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const [acked, setAcked] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(clientSecret);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // ignore — user can manually select+copy
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal" style={{ borderColor: 'var(--accent)' }}>
        <h2 className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>⚠️</span>
          Save this client_secret now
        </h2>
        <p style={{ color: 'var(--accent)', fontSize: 13 }}>
          This is the only time you'll see this secret. Once you close this dialog it's gone — you'll need to rotate to get a new one.
        </p>
        <div style={{ fontSize: 12, color: 'var(--fg-muted)', marginBottom: 8 }}>Client ID</div>
        <div style={{ background: '#05070D', border: '1px solid var(--border)', borderRadius: 6, padding: 10, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, marginBottom: 16, wordBreak: 'break-all' }}>
          {clientId}
        </div>
        <div style={{ fontSize: 12, color: 'var(--fg-muted)', marginBottom: 8 }}>Client Secret</div>
        <div style={{ background: '#05070D', border: '1px solid var(--border)', borderRadius: 6, padding: 10, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, marginBottom: 8, wordBreak: 'break-all' }}>
          {clientSecret}
        </div>
        <button className="btn-primary" onClick={copy} style={{ fontSize: 12 }}>
          {copied ? '✓ Copied!' : '📋 Copy to clipboard'}
        </button>
        <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <input type="checkbox" checked={acked} onChange={(e) => setAcked(e.target.checked)} />
            <span>I've copied the secret to a safe place</span>
          </label>
        </div>
        <div className="modal-actions">
          <button className="btn-primary" onClick={onClose} disabled={!acked}>Done</button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Run + commit**

```bash
pnpm test 2>&1 | tail -5
pnpm typecheck 2>&1 | tail -3
pnpm lint 2>&1 | tail -3
git add developers/src/modals/SecretRevealModal.tsx developers/tests/SecretRevealModal.test.tsx
git commit -m "feat(developers): SecretRevealModal with copy + acknowledge gate"
```

Expected: ~24 tests pass total.

---

## Task 12: Build SPA + commit `public/developers/`

**Files:**
- Create: `~/taler-id/public/developers/index.html` and `~/taler-id/public/developers/assets/*` (Vite output)

- [ ] **Step 1: Build**

```bash
cd ~/taler-id/developers
pnpm build 2>&1 | tail -10
```

Expected: `dist` folder OR — because of `outDir: '../public/developers'` — the build output appears at `~/taler-id/public/developers/`. Verify:

```bash
ls ~/taler-id/public/developers/
```

Should show `index.html` and an `assets/` directory.

- [ ] **Step 2: Smoke-test the build locally**

Backend has a static dev server already on `localhost:3000` (NestJS). Or use Vite preview:

```bash
cd ~/taler-id/developers
pnpm preview 2>&1 &  # serves the build output
sleep 3
curl -fI http://localhost:4173/developers/ 2>&1 | head -3
kill %1
```

Expected: `HTTP 200`. (Port 4173 is Vite's preview default.)

- [ ] **Step 3: Commit the build output**

```bash
cd ~/taler-id
git add public/developers/
git status --short  # confirm only public/developers/ files staged
git commit -m "build(developers): v1.0 production bundle"
```

This commit's diff is large (the bundled JS), but is needed because the backend deploy is `git pull` — the SPA is served as static files, the server doesn't run a build.

---

## Task 13: Deploy to DEV + smoke

**Files:** none (deploy + verification only).

- [ ] **Step 1: Push the entire phase to origin/main**

```bash
cd ~/taler-id
git push origin main
```

Expected: pushes Tasks 1-12's commits.

- [ ] **Step 2: Deploy DEV**

```bash
ssh dvolkov@89.169.55.217 "cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev"
```

Expected: pulls all new commits, backend re-builds (only TypeScript backend, not the SPA — it's pre-built), pm2 restarts.

- [ ] **Step 3: Run the seed SQL on the DEV database**

```bash
ssh dvolkov@89.169.55.217 "psql taler_id_dev -f ~/taler-id/prisma/migrations/2026_seed_taler_id_developers_client.sql 2>&1 | tail -3"
```

Expected: `INSERT 0 1` (or `INSERT 0 0` if a previous run already inserted). Idempotent.

- [ ] **Step 4: Verify the SPA is served**

```bash
curl -fI https://staging.id.taler.tirol/developers/ 2>&1 | head -3
```

Expected: `HTTP/2 200` with `content-type: text/html`.

- [ ] **Step 5: Manual smoke test**

Open `https://staging.id.taler.tirol/developers/` in a browser:

1. Click "Sign in with Taler ID" → goes through Phase 2 SDK redirect → completes login → returns to portal authenticated.
2. Click "+ Register new client" → fill form → submit → SecretRevealModal shows client_id + client_secret.
3. Copy secret to clipboard, tick checkbox, click Done → secret modal closes, new client appears in table.
4. Click "Edit" on the new client → change name → Save → table reflects new name.
5. Click "⋯" → "Rotate secret" → confirm → SecretRevealModal shows new secret.
6. Click "⋯" → "Delete" → type client name → confirm → row vanishes.
7. Click Logout → redirects to `/oauth/session/end` → returns to LoginGate.

If any step fails, fix locally and redeploy. Do NOT deploy PROD if DEV smoke fails.

- [ ] **Step 6: PROD deployment is OUT OF SCOPE for this plan**

PROD goes only on explicit user instruction. To deploy to PROD when ready:

```bash
ssh dvolkov@138.124.61.221 "cd ~/taler-id && git pull && npm run build && pm2 restart taler-id"
ssh dvolkov@138.124.61.221 "psql taler_id -f ~/taler-id/prisma/migrations/2026_seed_taler_id_developers_client.sql"
```

Then run the same manual smoke test against `https://id.taler.tirol/developers/`.

---

## Out of Scope — Do Not Do

- **PROD deployment** — Phase 4 v1 only ships to DEV. Wait for explicit user instruction.
- **Usage stats / rate-limit dashboard** (Phase 4.5) — needs backend instrumentation (counter middleware + Redis state).
- **Audit history view** (Phase 4.5) — `GET /oauth/audit-log?clientId=X` endpoint not built; data exists in `AuditLog` but no read API.
- **Multi-org / team management** — `Tenant` model exists but unused.
- **Custom OAuth scopes beyond `openid/profile/email/offline_access`** — would need review queue.
- **Logo file upload** — current accept-URL is sufficient.
- **Onboarding wizard / first-time UX** — let real users tell us what's missing.
- **i18n** — UI is English-only for MVP.
- **react-router** — single page, no routing needed.
- **TanStack Query** — `useState` is enough for the small client list.
- **Touching `~/taler-id-sdk-js`** — Phase 2's repo. We consume it as a `file:` dep but don't modify it here.
