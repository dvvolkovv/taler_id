# OAuth UI Kit — Phase 4: Developer Portal

**Status:** Design approved 2026-04-30
**Decomposition parent:** `taler_id_mobile/docs/superpowers/specs/2026-04-28-oauth-ui-kit-decomposition.md`
**Sibling specs:** Phase 0 (`2026-04-29-oauth-ui-kit-phase-0-brand.md`), Phase 1 (`2026-04-28-oauth-rfc7591-registration-design.md`), Phase 2 (`2026-04-29-oauth-ui-kit-phase-2-js-sdk.md`), Phase 3 (`2026-04-29-oauth-ui-kit-phase-3-flutter-sdk.md`)

## Goal

Ship a self-service Developer Portal at `https://id.taler.tirol/developers/` so OAuth integrators can register, edit, rotate secrets for, and delete their OAuth clients without contacting the maintainer. Closes the OAuth UI Kit decomposition.

## Scope

**In scope (MVP):**
- Single-page React + Vite + TypeScript SPA hosted at `id.taler.tirol/developers/`
- Auth via dogfooded `@taler-id/oauth-client@0.1.0` (Phase 2 SDK — see "Phase 2 SDK dependency" note in Architecture)
- Five operations on OAuth clients: list, create, edit (`client_name` / `redirect_uris` / `logo_uri` / `scope`), delete, rotate `client_secret`
- One-time `client_secret` reveal modal after creation and after rotation, with copy-to-clipboard and mandatory acknowledgement checkbox
- Deep-links from the portal to existing assets: `/oauth-guide.html`, `/brand`, JS SDK npm page, Flutter SDK pub.dev page
- One new backend endpoint: `POST /oauth/clients/:clientId/rotate-secret`
- One new system OAuth client `taler-id-developers` registered in the DB at deploy time
- Vitest + jsdom + Testing Library tests for the SPA; spec extension on the backend service for the new method

**Out of scope (deferred):**
- API usage stats / rate-limit dashboard (Phase 4.5 if demand emerges; needs backend instrumentation)
- Audit history view (data exists in `AuditLog` from Phase 1 — frontend deferred)
- Multi-org / team management (`Tenant` model exists but Phase 1 doesn't use it)
- Custom OAuth scopes beyond `openid/profile/email/offline_access` (would need review queue)
- Logo file upload (current accept-URL flow is sufficient for MVP)
- Onboarding wizard / first-time UX
- i18n / Russian translation (developer audience uses English)
- Audit log endpoint (`GET /oauth/audit-log?clientId=X`) — Phase 4.5

## Architecture

The SPA lives in a new directory in the existing backend repo and builds to the existing static-serve tree:

```
~/taler-id/
├── developers/                         # NEW — Vite project
│   ├── package.json
│   ├── vite.config.ts                  # base: '/developers/', outDir: '../public/developers'
│   ├── tsconfig.json                   # strict, ES2022
│   ├── index.html                      # Vite entry
│   ├── src/
│   │   ├── main.tsx                    # TalerIdProvider wraps App
│   │   ├── App.tsx                     # auth gate → ClientsList
│   │   ├── api.ts                      # fetch wrappers around /oauth/clients/*
│   │   ├── pages/
│   │   │   ├── ClientsList.tsx
│   │   │   └── LoginGate.tsx
│   │   ├── modals/
│   │   │   ├── CreateClientModal.tsx
│   │   │   ├── EditClientModal.tsx
│   │   │   ├── DeleteClientModal.tsx
│   │   │   ├── RotateSecretModal.tsx
│   │   │   └── SecretRevealModal.tsx
│   │   └── styles.css                  # imports Phase 0 colors + Inter
│   └── tests/                          # vitest + @testing-library/react
└── public/developers/                  # build output, COMMITTED to git for deploy
    ├── index.html
    └── assets/
```

The backend's existing `ServeStaticModule` (`rootPath: public/`, `serveRoot: '/'`) already serves `public/developers/` at the URL `/developers/` without any code change. SPA-style fallback (deep link refresh → `/developers/index.html`) is unnecessary because we use a single-page app with no client-side routing — the only valid path is `/developers/`.

**Stack:** React 18 · Vite 5 · TypeScript 5.5 (strict) · `@taler-id/oauth-client@^0.1.0` · `vitest` + `jsdom` + `@testing-library/react`. No Redux / TanStack Query — `useState` and a small `api.ts` are sufficient for ~10 clients per user.

**Phase 2 SDK dependency:** Phase 2's npm publish was deferred (npm account 2FA blocker not resolved at the time of Phase 4 design). The package source lives in `~/taler-id-sdk-js/` (a separate repo at `github.com:dvvolkovv/taler-id-sdk-js`). Phase 4 consumes it via a git URL in `package.json`:

```json
"@taler-id/oauth-client": "github:dvvolkovv/taler-id-sdk-js#v0.1.0"
```

This pins to the existing `v0.1.0` git tag. When Phase 2's npm publish unblocks, swap the entry to `"@taler-id/oauth-client": "^0.1.0"` (no other code changes needed — same package, same exports). The SPA build runs `pnpm install` which clones from GitHub, runs the SDK's `prepublishOnly` (lint/typecheck/test/build), and produces a usable `dist/` for the Vite consumer.

**Internal organisation (per-file responsibility):**

- `api.ts` — typed fetch helpers for the five OAuth-client endpoints. Reads access token from the `TalerIdClient` (passed in via context).
- `App.tsx` — single component that gates `ClientsList` behind `useTalerIdAuth()`'s `isAuthenticated`.
- `pages/ClientsList.tsx` — fetches `/oauth/clients` on mount, renders a 5-column table, owns the modal-open state for the five modals.
- Each modal in `modals/` — controlled component with `open`, `client?` and `onClose` props. Forms are managed via `useState` (no react-hook-form for MVP).
- `pages/LoginGate.tsx` — single button styled per `/brand` calling `client.login()` from Phase 2 SDK.
- `styles.css` — global styles inheriting from Phase 0's design tokens (Taler Blue `#167EF2`, Gold `#FBBF24`, dark bg `#0A0E1A`, Inter, JetBrains Mono).

## UI structure and visual style

The portal is a single page at `/developers/` with five modals. Visual style matches `/brand` and `/oauth-guide`: Inter sans-serif, JetBrains Mono for code, dark background `#0A0E1A`, elevated panels `#161B2C`, Taler Blue `#167EF2` for primary actions, Taler Gold `#FBBF24` for warnings, muted foreground `#8A92A6`.

**Main page (`ClientsList`):**

```
┌──────────────────────────────────────────────────────────────────┐
│  Taler ID — Developer Portal             u@example.com · Logout  │
├──────────────────────────────────────────────────────────────────┤
│  Your OAuth clients              3 of 10 used    [+ Register]    │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ NAME          │ CLIENT ID    │ URIs │ CREATED   │ ACTIONS   │
│  │ my-app        │ 4f3c-…       │  2   │ 2 days ago│ [Edit][⋯] │
│  │ internal-tool │ b8e9-…       │  1   │ 1 wk ago  │ [Edit][⋯] │
│  │ demo-bot      │ c2a1-…       │  1   │ 3 wk ago  │ [Edit][⋯] │
│  └────────────────────────────────────────────────────────────┘  │
│  Need help integrating? Integration guide · Brand · JS · Flutter │
└──────────────────────────────────────────────────────────────────┘
```

The `[⋯]` menu opens a dropdown with `Rotate secret` and `Delete` (rare/destructive actions hidden one click deep). `[Edit]` is the common action and stays visible.

**Five modals:**

1. **`CreateClientModal`** — fields: `client_name` (required, max 100 chars), `redirect_uris` (textarea, one per line, validated as URL), `logo_uri` (optional URL), `scope` (multi-select of 4 allowed scopes). Submit → `POST /oauth/register` → on success, close this modal and open `SecretRevealModal` with the returned `client_id` + `client_secret`.

2. **`EditClientModal`** — same fields as create, pre-populated from the client. Submit → `PATCH /oauth/clients/:id`. Note: `client_secret` is NOT visible here. Returned response (no secret) only refreshes the list.

3. **`DeleteClientModal`** — confirmation dialog with the client's name typed by the user (Stripe-style) before `DELETE /oauth/clients/:id`.

4. **`RotateSecretModal`** — confirmation: "Rotating invalidates the current secret immediately. Any deployed app using the old secret will fail. Continue?" → `POST /oauth/clients/:id/rotate-secret` → close, open `SecretRevealModal` with the new secret.

5. **`SecretRevealModal`** — gold-bordered, mono-font, copy-to-clipboard button, mandatory checkbox "I've copied the secret to a safe place" before the Done button enables. Closing without checking is impossible (X-button is hidden / no-op until checkbox).

## Auth flow

The portal is an OAuth client of itself (dogfood). Handled by Phase 2 SDK:

```tsx
// main.tsx
import { TalerIdProvider } from '@taler-id/oauth-client/react';

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

```tsx
// App.tsx
function App() {
  const { isAuthenticated, isLoading } = useTalerIdAuth();
  if (isLoading) return <CenteredSpinner />;
  if (!isAuthenticated) return <LoginGate />;
  return <ClientsList />;
}
```

The provider auto-handles `?code=` callback on mount (Phase 2 SDK behaviour). Tokens live in `sessionStorage` (Phase 2 default). Access tokens are fetched on every backend call via `client.getAccessToken()` (auto-refreshes if near expiry).

**System client `taler-id-developers`:** must exist in the database before the first user logs in. Registered like the existing `taler-id-demo` system client — `userId = NULL`, `clientId = 'taler-id-developers'`, redirect URIs list both staging and prod portal URLs, scopes `openid profile email offline_access`. Hardcoded post-logout redirect URIs in `prisma-client-adapter.ts` so RP-initiated logout returns to the portal.

## Backend additions

### New endpoint

`POST /oauth/clients/:clientId/rotate-secret` in the existing `OAuthRegistrationController`:

- JWT-auth via existing `JwtAuthGuard`
- Throttled at 3 rotations per minute per IP via `@Throttle({ short: { limit: 3, ttl: 60_000 } })`
- Body: empty
- Response: `{ client_id: string, client_secret: string, client_secret_rotated_at: number }`

### Service method

`OAuthRegistrationService.rotateSecret(userId, clientId, ip, userAgent)`:

1. `findFirst({ where: { clientId, userId } })` → if null, throw `NotFoundException({ error: 'client_not_found' })`
2. Generate `newSecret = randomBytes(32).toString('base64url')` (matches Phase 1 register)
3. `prisma.oAuthClient.update({ where: { id: existing.id }, data: { clientSecret: newSecret } })`
4. `writeAuditLog(userId, 'OAUTH_CLIENT_ROTATED', ip, userAgent, { clientId })`
5. Return `{ client_id, client_secret: newSecret, client_secret_rotated_at: Math.floor(Date.now() / 1000) }`

The old secret is **immediately invalidated** — any in-flight token exchange using the old secret will fail. Documented in the rotate-confirmation modal.

### System client seed

A one-time SQL inserted on each server (DEV + PROD) at first deploy:

```sql
INSERT INTO "OAuthClient" ("clientId", "clientSecret", "name", "redirectUris", "allowedScopes", "userId", "createdAt", "updatedAt")
VALUES (
  'taler-id-developers',
  encode(gen_random_bytes(32), 'base64'),
  'Taler ID Developer Portal',
  ARRAY['https://id.taler.tirol/developers/', 'https://staging.id.taler.tirol/developers/'],
  ARRAY['openid', 'profile', 'email', 'offline_access'],
  NULL, now(), now()
)
ON CONFLICT ("clientId") DO NOTHING;
```

The PKCE flow doesn't actually use the system client's `clientSecret` (PKCE replaces it for public clients), but oidc-provider requires the field non-null. We generate a random one at insert time; nobody ever uses it.

`prisma-client-adapter.ts` extended to recognise `taler-id-developers` and return the same hardcoded post-logout redirect URIs as `taler-id-demo`.

## Testing

**Frontend (Vitest + jsdom + Testing Library):**

- `api.test.ts` — fetch helpers: correct URL + Authorization header for each of the five backend calls.
- `App.test.tsx` — auth gate: with `useTalerIdAuth` mocked, asserts `LoginGate` renders when `!isAuthenticated`, `ClientsList` when authenticated.
- `ClientsList.test.tsx` — renders rows from a mocked client list, click `[+ Register]` opens `CreateClientModal`, click `[Edit]` opens `EditClientModal`.
- `CreateClientModal.test.tsx` — required-field validation, submit → calls api + opens `SecretRevealModal` on success.
- `SecretRevealModal.test.tsx` — Done button disabled by default, enables when checkbox is ticked, click Copy fires the clipboard API.
- The other three modals (Edit, Delete, Rotate) — one happy-path test each.

**Backend:**

- `oauth-registration.service.spec.ts` — extend with a `rotateSecret` group: ownership 404, success path (secret changed + returned + audit log written), throttle is implicitly tested by Phase 1's existing throttle tests on `register`.

**Manual e2e:** before each deploy, register an OAuth client through the portal against staging, complete a login round-trip, rotate, delete. Documented in the deploy step of the plan.

## Deployment

1. Local build: `cd developers && pnpm build` → outputs `public/developers/`.
2. Commit `public/developers/` (build artifacts) and `developers/` (source) to the backend repo.
3. Deploy DEV first: `ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev'`. The `npm run build` here is for the backend, not the SPA; the SPA is pre-built and committed.
4. Run the system-client SQL once on DEV's `taler_id_dev` database (idempotent via `ON CONFLICT DO NOTHING`).
5. Manual smoke test: open `https://staging.id.taler.tirol/developers/`, login with a test account (must have email verified), register a client, rotate, delete.
6. PROD only on explicit user instruction: same flow on `dvolkov@138.124.61.221`, system-client SQL on `taler_id` database.

## Acceptance Criteria

Phase 4 v1 is "done" when all of the following are true:

1. `https://id.taler.tirol/developers/` returns HTTP 200 with the React SPA.
2. The Phase 2 SDK's login flow successfully authenticates a real user against `taler-id-developers`.
3. All five operations (list, create, edit, delete, rotate-secret) work end-to-end against PROD with a real OAuth integrator user account.
4. `client_secret` is shown only at creation and after rotation; nowhere else in the UI.
5. `vitest run` passes locally and adds at least 8 new frontend tests; backend service spec adds 3 new tests for `rotateSecret`.
6. The five footer deep-links (`/oauth-guide.html`, `/brand`, npmjs.com/.../oauth-client, pub.dev/packages/talerid_oauth) all resolve.
7. The decomposition spec's "Phase 4 — Developer Portal" section can be ticked off (MVP scope; Phase 4.5 features remain explicitly deferred).
