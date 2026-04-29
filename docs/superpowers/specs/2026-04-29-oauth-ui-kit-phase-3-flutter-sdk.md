# OAuth UI Kit — Phase 3: Flutter SDK

**Status:** Design approved 2026-04-29
**Decomposition parent:** `taler_id_mobile/docs/superpowers/specs/2026-04-28-oauth-ui-kit-decomposition.md`
**Sibling specs:** Phase 0 (`2026-04-29-oauth-ui-kit-phase-0-brand.md`), Phase 1 (`2026-04-28-oauth-rfc7591-registration-design.md`), Phase 2 (`2026-04-29-oauth-ui-kit-phase-2-js-sdk.md`)

## Goal

Ship `talerid_oauth` — a Flutter package on pub.dev that lets iOS/Android Flutter apps add "Sign in with Taler ID" by wrapping `flutter_appauth` with Taler ID defaults. Reduces a typical OAuth integration from ~80 lines of `flutter_appauth` plumbing + token storage + refresh logic to roughly five lines of configuration.

## Scope

**In scope:**
- One Flutter package `talerid_oauth` published to pub.dev from a new repo `taler_id_sdk_flutter`
- iOS + Android only (uses `flutter_appauth` which wraps native `AppAuth-iOS` / `AppAuth-Android`)
- Authorization Code + PKCE redirect flow via `flutter_appauth.authorizeAndExchangeCode()` (single call — no separate callback handler)
- `TalerIdClient` Dart class with `create()` factory, `login()`, `logout()`, `getUser()`, `getAccessToken()`, `isAuthenticated`, and `authState` (`ValueListenable<AuthState>`)
- Pluggable storage interface with `SecureStorage` (default, wraps `flutter_secure_storage`), `MemoryStorage` (for tests), and `Storage` abstract class for custom adapters
- On-demand token refresh with concurrent-call guard
- Single `TalerIdAuthError` with `TalerIdErrorCode` enum (incl. `userCancelled` for browser dismiss)
- `flutter_test`-based test suite with mocked platform channels for `flutter_appauth` and a `MockClient` for HTTP
- `example/` Flutter app demonstrating end-to-end login against staging
- README quickstart + API reference + configuration table
- GitHub Actions CI: `flutter analyze`, `flutter test`, `dart pub publish --dry-run` on PR/push

**Out of scope (v1):**
- macOS / Linux / Windows / Flutter Web — only iOS + Android
- Login button widget with Phase 0 styles (buttons live as HTML/CSS at `id.taler.tirol/brand`)
- Riverpod / Provider / Bloc helper packages (ValueListenable works with all)
- Background token refresh timers
- `TalerIdProvider` widget wrapping `MaterialApp`
- iOS Swift Package or Android Kotlin standalone library (defer to Phase 3.5 if demand emerges)
- Automated `dart pub publish` from CI (first release done interactively; OIDC trusted publishing on pub.dev configured in v0.2 if desired)

## Architecture

A standalone Flutter package shipped from a new repo:

| Component | Path / location |
| --------- | -------------- |
| Repo | `git@github.com:dvvolkovv/taler_id_sdk_flutter.git` |
| Package name (pub.dev) | `talerid_oauth` |
| Library entry point | `lib/talerid_oauth.dart` |

**Stack:**
- Dart 3.5+ / Flutter 3.24+ (avoids bleeding edge to maximise integrator adoption)
- Runtime deps:
  - `flutter_appauth: ^9.0.0` — native AppAuth bindings for iOS/Android
  - `flutter_secure_storage: ^9.0.0` — encrypted storage (Keychain on iOS, Keystore on Android)
  - `http: ^1.0.0` — userinfo + revocation requests (flutter_appauth handles `/oauth/token` directly)
- Dev deps:
  - `flutter_test` (SDK)
  - `mocktail: ^1.0.0` for HTTP and platform mocking
  - `equatable: ^2.0.0` for `AuthState` value equality

**Versioning:** Start at `0.1.0` (pre-1.0 to signal API may evolve). Promote to `1.0.0` once at least one external integrator validates the API in production.

## Public API — `TalerIdClient`

```dart
import 'package:talerid_oauth/talerid_oauth.dart';

final client = await TalerIdClient.create(
  clientId: 'your-client-id',                     // required
  redirectUri: 'com.yourapp://oauth/callback',    // required, must match scheme registered in app
  scope: 'openid profile email',                  // optional, default 'openid profile email'
  storage: SecureStorage(),                       // optional, default SecureStorage()
  issuer: 'https://id.taler.tirol/oauth',         // optional, override for staging
  onLog: (level, message, [meta]) {},             // optional debug hook
);
```

The async `create()` factory hydrates internal state from storage (reads existing tokens if present and seeds the `authState` ValueListenable). Synchronous getters (`isAuthenticated`, `authState.value`) read the in-memory cache.

Six public members:

```dart
// 1. Login: opens ASWebAuthenticationSession (iOS) / Custom Tab (Android),
//    user authenticates + consents, returns when tokens are stored.
//    Throws TalerIdAuthError on user cancel / network failure / state mismatch.
await client.login();

// 2. Logout: revoke tokens, clear storage, optionally end OIDC session in browser.
await client.logout();                  // silent local logout
await client.logout(endSession: true);  // RP-initiated: opens browser to /oauth/session/end

// 3. Get current user (cached from /oauth/me, fetched once)
final UserInfo user = await client.getUser();

// 4. Get access token (auto-refreshes if <30s to expiry)
final String token = await client.getAccessToken();

// 5. Sync check (no I/O, no network)
final bool authed = client.isAuthenticated;

// 6. Reactive state
final ValueListenable<AuthState> state = client.authState;
```

PKCE generation, state nonces, and browser launching happen entirely inside `flutter_appauth`. No separate `handleRedirectCallback` step exists — `authorizeAndExchangeCode` is a single Future that resolves with tokens or throws.

### Internal modules (one file per responsibility)

```
lib/
├── talerid_oauth.dart              # public re-exports
├── src/
│   ├── client.dart                 # TalerIdClient class (<300 lines)
│   ├── auth_state.dart             # AuthState (Equatable) + UserInfo
│   ├── errors.dart                 # TalerIdAuthError, TalerIdErrorCode enum
│   ├── storage.dart                # Storage abstract, SecureStorage, MemoryStorage
│   └── refresh.dart                # token refresh logic + concurrent guard
```

`client.dart` composes storage + refresh + flutter_appauth + http; no logic inside the class that another module could own.

## AuthState and UserInfo

```dart
class AuthState extends Equatable {
  final UserInfo? user;
  final bool isAuthenticated;
  final bool isLoading;

  const AuthState({this.user, required this.isAuthenticated, required this.isLoading});

  @override
  List<Object?> get props => [user, isAuthenticated, isLoading];
}

class UserInfo extends Equatable {
  final String sub;
  final Map<String, Object?> claims;

  const UserInfo({required this.sub, required this.claims});

  String? get email => claims['email'] as String?;
  String? get name => claims['name'] as String?;
  T? claim<T>(String key) => claims[key] as T?;

  @override
  List<Object?> get props => [sub, claims];
}
```

Equatable equality ensures `ValueListenable` notifies listeners only when the state genuinely changes (not on every internal write that produces a structurally-identical value).

## Storage

Three implementations of one interface:

```dart
abstract class Storage {
  Future<String?> get(String key);
  Future<void> set(String key, String value);
  Future<void> remove(String key);
}

class SecureStorage implements Storage {
  // wraps flutter_secure_storage with talerid: key prefix
  // configures iOS accessibility = first_unlock_this_device
}

class MemoryStorage implements Storage {
  final Map<String, String> _map = {};
  // ...
}
```

Picked at construction by passing an instance to `TalerIdClient.create(storage: ...)`. Default is `SecureStorage()`.

**Persisted keys** (all prefixed `talerid:`):
- `talerid:access_token`, `talerid:refresh_token`, `talerid:id_token`
- `talerid:expires_at` — epoch ms as string
- `talerid:user` — JSON-encoded userinfo

**Async note:** unlike the JS SDK, all `Storage` operations are `Future`-returning because `flutter_secure_storage` makes platform-channel calls. `client.isAuthenticated` and `client.authState.value` remain synchronous by reading an in-memory mirror that is kept in sync after every successful storage write.

## Token Refresh

On `getAccessToken()`:

1. Read `expiresAt` from in-memory cache (synced from storage at create-time and on every refresh).
2. If `expiresAt - now > 30_000` ms, return cached `access_token`.
3. Otherwise call `flutter_appauth.token(grant_type: 'refresh_token', ...)` to obtain a new pair, persist to storage, update memory.
4. Return the new access token.
5. On failure (HTTP 4xx, network, revoked token): clear all storage, set `authState` to unauthenticated, throw `TalerIdAuthError(code: TalerIdErrorCode.loginRequired)`.

**Concurrent refresh guard:** an internal `Completer<String>?` field stores the pending refresh future. Concurrent callers `await` the same Future; cleared on settlement.

No background timers — refresh happens at the moment the integrator asks for a token.

## Errors

```dart
enum TalerIdErrorCode {
  loginRequired,
  consentRequired,
  network,
  config,
  userCancelled,    // user dismissed the browser tab — Flutter-only
  invalidGrant,
}

class TalerIdAuthError implements Exception {
  final TalerIdErrorCode code;
  final String message;
  final Object? cause;
  // ...
}
```

`flutter_appauth` throws `PlatformException` on user cancel; we catch and re-throw as `TalerIdAuthError(code: userCancelled)`. Network errors become `TalerIdErrorCode.network` with the underlying error in `cause`.

## Logging

```dart
TalerIdClient.create(
  clientId: ..., redirectUri: ...,
  onLog: (String level, String message, [Object? meta]) {
    if (level == 'error') Sentry.captureMessage(message, extra: {'meta': meta});
  },
);
```

Optional callback, default no-op. Levels: `'debug'`, `'info'`, `'warn'`, `'error'` — same as JS SDK for cross-SDK consistency.

## Testing

`flutter_test` with the standard Flutter testing harness.

**Unit:**
- `storage_test.dart` — `MemoryStorage` round-trip; `SecureStorage` via `flutter_secure_storage`'s built-in `MethodChannel` mock.
- `errors_test.dart` — `TalerIdAuthError` codes, message defaulting from code, cause chain.
- `auth_state_test.dart` — Equatable equality, listener fires only on real change.

**Integration (mocked):**
- `client_test.dart` — full flow with `flutter_appauth` mocked via `MethodChannel.setMockMethodCallHandler`. HTTP mocked via `MockClient` from `package:http/testing.dart`. Verifies: `create()` hydrates state, `login()` stores tokens + emits authenticated state, `getUser()` calls `/oauth/me`, `logout()` clears storage.
- `refresh_test.dart` — concurrent `getAccessToken()` calls share one refresh; refresh failure → `loginRequired` and storage clear.
- `state_test.dart` — `client.authState` mirrors actual state; listeners fire on login/logout.

**Manual e2e (not CI):**
- Run `example/` against `staging.id.taler.tirol` with the `taler-id-demo` client. Run before each release tag.

## Project Structure

```
taler_id_sdk_flutter/
├── pubspec.yaml                # Flutter package manifest
├── analysis_options.yaml       # lints
├── README.md                   # quickstart + API reference
├── CHANGELOG.md                # required by pub.dev
├── LICENSE                     # MIT
├── .github/
│   └── workflows/ci.yml        # flutter analyze + test + publish dry-run
├── lib/
│   ├── talerid_oauth.dart
│   └── src/
│       ├── client.dart
│       ├── auth_state.dart
│       ├── errors.dart
│       ├── storage.dart
│       └── refresh.dart
├── test/
│   ├── storage_test.dart
│   ├── errors_test.dart
│   ├── auth_state_test.dart
│   ├── client_test.dart
│   ├── refresh_test.dart
│   └── state_test.dart
└── example/                    # Flutter app demonstrating the SDK
    ├── pubspec.yaml
    ├── lib/main.dart
    ├── ios/ (Runner.xcodeproj with Info.plist URL scheme)
    └── android/ (AndroidManifest.xml with intent-filter)
```

## Side-PR in `taler_id_mobile`

The mobile app's `lib/core/router/deep_link_handler.dart:60-69` contains a stale OAuth-callback skeleton (`// Handle OAuth code exchange` with no implementation). Phase 3 includes a separate single-commit PR removing that branch:

```dart
// REMOVE this block:
if (uri.path.contains('oauth/callback')) {
  final code = uri.queryParameters['code'];
  if (code != null) {
    debugPrint('OAuth callback code: $code');
    // Handle OAuth code exchange
  }
  return;
}
```

The `talerid://` URL scheme registration in `Info.plist` and `AndroidManifest.xml` stays — it serves `talerid://invite` and `talerid://user/{id}` deep links. Only the dead `oauth/callback` branch is removed.

## Acceptance Criteria

Phase 3 v0.1.0 is "done" when all of the following are true:

1. `taler_id_sdk_flutter` repo exists publicly on GitHub.
2. `dart pub publish` placed `talerid_oauth: 0.1.0` on pub.dev.
3. `flutter test` passes locally and in GitHub Actions CI.
4. `example/` runs (`flutter run`) and successfully completes login → user → logout against `staging.id.taler.tirol` using the `taler-id-demo` client.
5. README's quickstart accurately describes the API.
6. The dead OAuth-callback branch in `taler_id_mobile/lib/core/router/deep_link_handler.dart` is removed.
7. Decomposition spec's "Phase 3 — Mobile SDK" section can be ticked off (Flutter portion at least; native iOS / Android packages remain explicitly deferred).
