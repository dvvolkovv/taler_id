# OAuth UI Kit — Phase 2: JavaScript SDK

**Status:** Design approved 2026-04-29
**Decomposition parent:** `taler_id_mobile/docs/superpowers/specs/2026-04-28-oauth-ui-kit-decomposition.md`
**Sibling specs:** Phase 0 (`2026-04-29-oauth-ui-kit-phase-0-brand.md`), Phase 1 (`2026-04-28-oauth-rfc7591-registration-design.md`)

## Goal

Ship `@taler-id/oauth-client` — a TypeScript SDK for browser SPAs that reduces "Sign in with Taler ID" integration from ~30 lines of `openid-client` + PKCE wiring to roughly five lines of configuration. Includes an opt-in React adapter (`<TalerIdProvider>` + `useTalerIdAuth()`).

## Scope

**In scope:**
- One npm package `@taler-id/oauth-client` published from a new repo `taler-id-sdk-js`
- Browser-only Authorization Code + PKCE redirect flow
- Vanilla TypeScript core class `TalerIdClient`
- React adapter at `@taler-id/oauth-client/react` subpath export
- Storage adapters for `sessionStorage` (default) / `localStorage` / in-memory
- On-demand token refresh via `getAccessToken()`
- Single error class `TalerIdAuthError` with `code` discriminator
- Vitest+jsdom test suite with mocked OAuth endpoints
- README quickstart + minimal `examples/vanilla-html/` and `examples/react-vite/`
- GitHub Actions CI: lint, typecheck, test on PR; `npm publish` on `v*` tag push

**Out of scope (Phase 2 v1):**
- Server-side Node.js use case (potential Phase 2.5 if integrators ask)
- Popup login flow (only redirect)
- Vue / Svelte / Solid adapters
- Login-button component in code (lives in `/brand` as HTML/CSS — Phase 0)
- Background auto-refresh timers (refresh is on-demand at `getAccessToken()` only)
- Dev portal / client management UI (Phase 4)
- Rewriting the existing `~/taler-id/src/demo/` to use the SDK (separate follow-up commit after publish)

## Architecture

A single npm package shipped in two entry-points so non-React integrators don't pull in React-related code:

| Subpath                          | Exports                                          |
| -------------------------------- | ------------------------------------------------ |
| `@taler-id/oauth-client`         | `TalerIdClient`, `TalerIdAuthError`, types       |
| `@taler-id/oauth-client/react`   | `TalerIdProvider`, `useTalerIdAuth`              |

Both entry-points are emitted as ESM + CJS with separate `.d.ts` files via `tsup`. `react` subpath declares `react@>=17 <20` as `peerDependency`, never `dependency` — integrators bring their own React.

**Repo:** new GitHub repo `taler-id-sdk-js` (separate from `taler_id` backend) for independent versioning, CI pipeline, and `npm publish` lifecycle. Backend updates that change OAuth surface (new scopes, claim shapes) will require a corresponding SDK release; the spec/plan in this repo lives next to Phase 0/1 specs as the central design history.

**Stack:**
- TypeScript 5.x with strict mode
- `tsup` for bundling (output: ESM + CJS + types in `dist/`)
- Vitest + jsdom + `@testing-library/react` for tests
- ESLint with `@typescript-eslint` recommended
- GitHub Actions (Node 20.x matrix); on tag `v*`: build, test, `npm publish --access public`
- Versioning: start at `0.1.0`, promote to `1.0.0` once a real third-party integrator adopts and confirms the API is stable

## Core API — `TalerIdClient`

```ts
import { TalerIdClient } from '@taler-id/oauth-client';

const client = new TalerIdClient({
  clientId: 'your-client-id',                    // required
  redirectUri: 'https://yourapp.com/callback',   // required
  scope: 'openid profile email',                 // optional, default 'openid profile email'
  storage: 'session',                            // optional, 'session' (default) | 'local' | 'memory'
  issuer: 'https://id.taler.tirol/oauth',        // optional, default points to PROD
  onLog: (level, msg, meta) => {},               // optional debug hook
});
```

The seven-method surface:

```ts
await client.loginWithRedirect();                // generates PKCE+state, navigates to /oauth/auth
await client.handleRedirectCallback();           // exchanges ?code= for tokens, cleans URL
const user = await client.getUser();             // fetched once from /oauth/me, cached
const token = await client.getAccessToken();     // auto-refreshes if <30s to expiry
const isAuthed = client.isAuthenticated();       // sync, no network
const unsub = client.onAuthStateChange(cb);      // emits { user, isAuthenticated, isLoading }
await client.logout({ returnTo: '/' });          // POST revoke, clear storage, navigate to /oauth/session/end
```

PKCE generation, state parameters, and storage are entirely internal — integrators never touch them. `handleRedirectCallback()` validates the `state` parameter against the value stashed pre-redirect; mismatch throws `TalerIdAuthError({ code: 'state_mismatch' })`.

### Internal modules (one file per responsibility)

```
src/
├── index.ts          # public re-exports
├── client.ts         # TalerIdClient class (<300 lines)
├── pkce.ts           # generateCodeVerifier(), generateCodeChallenge()
├── storage.ts        # SessionStorageAdapter, LocalStorageAdapter, MemoryStorageAdapter
├── errors.ts         # TalerIdAuthError
├── state.ts          # internal AuthState type + emitter (typed pub/sub for the seven-arg subset)
└── react/
    ├── index.ts      # public re-exports for the subpath
    ├── provider.tsx  # TalerIdProvider
    └── hook.ts       # useTalerIdAuth
```

Each module has one responsibility. The client class composes pkce + storage + state + fetch — no logic inside `client.ts` that another module could own.

## React API

```tsx
import { TalerIdProvider, useTalerIdAuth } from '@taler-id/oauth-client/react';

// At the app root
<TalerIdProvider
  clientId="your-client-id"
  redirectUri="https://yourapp.com/callback"
>
  <App />
</TalerIdProvider>

// In any component
function Profile() {
  const { user, isAuthenticated, isLoading, login, logout, getAccessToken } = useTalerIdAuth();

  if (isLoading) return <p>Loading…</p>;
  if (!isAuthenticated) return <button onClick={() => login()}>Sign in with Taler ID</button>;

  return <p>Hello {user.name} <button onClick={() => logout()}>Logout</button></p>;
}
```

**`TalerIdProvider` behaviour:**
- Constructs the `TalerIdClient` once, memoised by config props
- On mount: if `window.location.search` contains `?code=`, calls `handleRedirectCallback()` and removes the query string from the URL via `history.replaceState`. Integrators don't need a separate callback route — the same component handles both the launch and the return.
- Subscribes to `client.onAuthStateChange()`, propagates state into React Context
- Unsubscribes on unmount

**`useTalerIdAuth()` returns:**
- Reactive: `user`, `isAuthenticated`, `isLoading`
- Methods (stable references via `useCallback`): `login`, `logout`, `getAccessToken`

Single hook; no `useUser` / `useAccessToken` proliferation.

## Storage Layer

Three adapters implement the same interface:

```ts
interface Storage {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}
```

Picked at construction by `storage` option. Keys are prefixed `talerid:` to avoid collisions when multiple OAuth SDKs coexist on a page.

**Persisted keys:**
- `talerid:access_token` — current access token JWT
- `talerid:refresh_token` — current refresh token (opaque)
- `talerid:id_token` — current id_token JWT
- `talerid:expires_at` — epoch ms when access_token expires
- `talerid:user` — JSON-stringified userinfo from `/oauth/me`

**Transient keys (during login flow only, removed in `handleRedirectCallback`):**
- `talerid:pkce_verifier`
- `talerid:oauth_state`

`MemoryStorageAdapter` is a `Map<string, string>` that lives for the lifetime of the page — no persistence across reloads.

## Token Refresh

On `getAccessToken()`:
1. Read `expires_at` from storage. If `expires_at - Date.now() > 30_000`, return cached `access_token`.
2. Otherwise POST to `/oauth/token` with `grant_type=refresh_token`, `client_id`, `refresh_token`. Store new tokens, recompute `expires_at` from `expires_in`.
3. Return the new access_token.
4. If refresh fails (HTTP 4xx / network), clear all storage, emit `unauthenticated` state, throw `TalerIdAuthError({ code: 'login_required' })`.

**Concurrent refresh guard:** an internal `Map<'refresh', Promise<string>>` ensures that two callers awaiting `getAccessToken()` simultaneously share a single in-flight refresh request. Cleared once the promise settles.

No background timers — refresh happens at the moment the integrator asks for a token. Simpler, no orphaned `setTimeout` after page navigation, plays nicely with hot-reload during development.

## Errors

One class with a discriminator field. Avoids subclass proliferation while preserving narrowing.

```ts
type TalerIdErrorCode =
  | 'login_required'
  | 'consent_required'
  | 'network'
  | 'config'
  | 'state_mismatch'
  | 'invalid_grant';

class TalerIdAuthError extends Error {
  readonly code: TalerIdErrorCode;
  readonly cause?: unknown;
  constructor(args: { code: TalerIdErrorCode; message?: string; cause?: unknown });
}
```

Integrators check `if (err instanceof TalerIdAuthError && err.code === 'login_required')`. The `cause` field carries the underlying network or HTTP error for debugging.

## Logging

The SDK never writes to `console`. Integrators wanting diagnostics pass `onLog: (level, message, meta) => void` in the config:

```ts
new TalerIdClient({
  clientId, redirectUri,
  onLog: (level, msg, meta) => {
    if (level === 'error') Sentry.captureMessage(msg, { extra: meta });
  },
});
```

Levels: `'debug' | 'info' | 'warn' | 'error'`.

## Testing

**Vitest config** with `jsdom` environment. Test layout mirrors source layout (`tests/client.test.ts`, `tests/pkce.test.ts`, etc.).

**Unit:**
- `pkce.test.ts` — verifier length, challenge is base64url(sha256(verifier)), per RFC 7636
- `storage.test.ts` — round-trip get/set/remove for all three adapters; key prefixing
- `errors.test.ts` — `instanceof` checks, `code` narrowing

**Integration:**
- `client.test.ts` — full flow with mocked endpoints. Tools: `vi.spyOn(window.location, 'assign')` for redirect, `fetch` mock returning canned `/oauth/token` and `/oauth/me` responses. Verify storage state at each step. Verify state-mismatch error path.
- `refresh.test.ts` — concurrent `getAccessToken()` calls share one refresh; expired refresh produces `login_required`

**React:**
- `provider.test.tsx` — `@testing-library/react`. Mount provider with mocked client, simulate `?code=` in URL, assert `useTalerIdAuth()` transitions through `isLoading: true` → `isAuthenticated: true`.

**E2E (manual, not CI):**
- `npm run e2e:staging` — uses the live `taler-id-demo` client against `staging.id.taler.tirol`. Run before each release tag. Not in CI because the demo client secret is not appropriate to ship to GitHub Actions.

## Project Structure

```
taler-id-sdk-js/
├── package.json              # exports map for both entry points; "type": "module"
├── tsconfig.json             # strict
├── tsup.config.ts            # dual ESM/CJS build, two entry points
├── vitest.config.ts          # jsdom env
├── eslint.config.js
├── .github/workflows/
│   ├── ci.yml                # lint + typecheck + test on push/PR
│   └── release.yml           # build + npm publish on v* tag
├── src/
│   ├── index.ts
│   ├── client.ts
│   ├── pkce.ts
│   ├── storage.ts
│   ├── errors.ts
│   ├── state.ts
│   └── react/
│       ├── index.ts
│       ├── provider.tsx
│       └── hook.ts
├── tests/
│   ├── pkce.test.ts
│   ├── storage.test.ts
│   ├── errors.test.ts
│   ├── client.test.ts
│   ├── refresh.test.ts
│   └── provider.test.tsx
├── examples/
│   ├── vanilla-html/         # zero-bundler HTML using esm.sh CDN to load the package
│   │   └── index.html
│   └── react-vite/           # minimal Vite + React app (~30 lines)
│       ├── package.json
│       ├── index.html
│       └── src/main.tsx
└── README.md                 # 5-line quickstart + framework examples + API reference
```

## Out of Scope (explicit deferrals)

These were considered and rejected for Phase 2 v1 — listed here so future contributors don't reopen the discussion without cause:

- **Node.js server-side variant.** `openid-client` already exists; the README will link to it.
- **Popup login flow.** Adds `postMessage` complexity, blocked by some browsers, broken on iOS Safari. Defer until at least one integrator asks.
- **Vue / Svelte / Solid adapters.** Vanilla SDK + 10 lines of glue covers each. Add per-framework adapters when adoption justifies maintenance.
- **`<TalerIdLoginButton />` component.** Phase 0 ships HTML/CSS buttons at `/brand`. Duplicating those in JSX risks divergence.
- **Background refresh timers.** On-demand refresh is enough; timers complicate hot-reload and SPA route changes.
- **Demo rewrite.** The `~/taler-id/src/demo/` controller will be rewritten to consume the published SDK — but in a separate follow-up commit after `0.1.0` is on npm. Not part of Phase 2 v1.
- **Telemetry / analytics SDK-side.** Integrators add their own via `onLog`.

## Acceptance Criteria

Phase 2 v1 is "done" when all of the following are true:

1. `taler-id-sdk-js` repo exists on GitHub with the structure above.
2. `npm install @taler-id/oauth-client@0.1.0` works publicly.
3. `vitest run` passes locally and in GitHub Actions CI on push.
4. `examples/react-vite/` runs (`npm run dev`) and successfully completes login → callback → user → logout against `staging.id.taler.tirol` using the `taler-id-demo` client_id.
5. README's 5-line quickstart accurately describes the API.
6. The decomposition spec's "Phase 2 — JavaScript SDK" section can be ticked off.
