# OAuth UI Kit — Phase 3: Flutter SDK — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `talerid_oauth@0.1.0` on pub.dev — a Flutter package that wraps `flutter_appauth` with Taler ID defaults so iOS/Android apps add "Sign in with Taler ID" with ~5 lines of config.

**Architecture:** New repo `taler_id_sdk_flutter` containing one Flutter package. Single library entry (`package:talerid_oauth/talerid_oauth.dart`). Mobile-only (iOS+Android) via `flutter_appauth` native AppAuth bindings. Pluggable storage with `flutter_secure_storage` default. On-demand token refresh, single `TalerIdAuthError` with `TalerIdErrorCode` enum. `flutter_test`-based test suite using a fake `OAuthBackend` (no platform-channel mocking) plus `MockClient` for HTTP. CI on GitHub Actions.

**Tech Stack:** Dart 3.5+ / Flutter 3.24+ · `flutter_appauth: ^9.0.0` · `flutter_secure_storage: ^9.0.0` · `http: ^1.0.0` · `equatable: ^2.0.0` · `mocktail: ^1.0.0` · `flutter_lints: ^5.0.0` · `flutter_test` (sdk).

**Spec:** `~/taler-id/docs/superpowers/specs/2026-04-29-oauth-ui-kit-phase-3-flutter-sdk.md`

**Working directory:** New repo at `~/taler_id_sdk_flutter/` (does not exist yet — created in Task 1). Do NOT do work inside `~/taler-id` (backend) or `~/Downloads/taler_id_mobile` (mobile app), except for Task 13's small side-PR which lives in the mobile-app repo.

**Backend integration target:** OAuth endpoints at `https://id.taler.tirol/oauth/*` (production) and `https://staging.id.taler.tirol/oauth/*` (staging). The `taler-id-demo` system client is what `example/` uses against staging. The mobile-app skeleton cleanup uses neither.

**About `flutter_appauth` version pinning:** the plan's pubspec uses `^9.0.0` as a placeholder. Before Task 1's `flutter pub get`, run `flutter pub deps --no-dev | grep flutter_appauth` against an empty test project OR check pub.dev/packages/flutter_appauth — if `^9.0.0` doesn't resolve, fall back to the latest 8.x. Same for `flutter_secure_storage` (try 9.x first, fallback 8.x).

---

## Human Prerequisites (one-time, before Task 14)

Two steps require Dmitry's interactive participation — they block ONLY the publish step (Task 14); Tasks 1-13 build the entire package without needing them.

1. **pub.dev account** — Dmitry already has a Google account; pub.dev uses it directly. Run `dart pub login` once (opens a browser, OAuth consent, done). No pre-publish action required.
2. **First publish requires `dart pub publish`** interactively from the local terminal — pub.dev verifies the publisher via the same OAuth login. Subsequent releases can be automated via pub.dev's OIDC trusted publishers (configured per-package after the first publish lands).

There is no pub.dev equivalent of npm's "scope ownership" complication — the package name `talerid_oauth` just needs to be free at first-publish time. Task 1 verifies that.

---

## File Structure (final state after Task 14)

```
~/taler_id_sdk_flutter/
├── .github/workflows/ci.yml        # T12 — flutter analyze + test + publish dry-run
├── .gitignore                      # T1
├── analysis_options.yaml           # T1
├── CHANGELOG.md                    # T11
├── LICENSE                         # T1 (MIT)
├── README.md                       # T11
├── pubspec.yaml                    # T1 — package manifest
├── lib/
│   ├── talerid_oauth.dart          # T6 — public re-exports
│   └── src/
│       ├── auth_state.dart         # T3 — AuthState + UserInfo (Equatable)
│       ├── client.dart             # T6, T7, T8, T9, T10 — TalerIdClient class
│       ├── errors.dart             # T2 — TalerIdAuthError + TalerIdErrorCode enum
│       ├── oauth_backend.dart      # T5 — OAuthBackend abstract + FlutterAppAuthBackend impl
│       └── storage.dart            # T4 — Storage abstract + SecureStorage + MemoryStorage
├── test/
│   ├── auth_state_test.dart        # T3
│   ├── client_test.dart            # T6, T7, T8 — incremental coverage
│   ├── errors_test.dart            # T2
│   ├── refresh_test.dart           # T9
│   ├── logout_test.dart            # T10
│   └── storage_test.dart           # T4
└── example/                        # T11 — Flutter app demonstrating the SDK
    ├── pubspec.yaml
    ├── lib/main.dart
    ├── ios/Runner/Info.plist       # URL scheme registration
    └── android/app/src/main/AndroidManifest.xml  # intent-filter
```

`client.dart` grows over five tasks (T6 → T10). All other source files are touched by exactly one task.

---

## Task 1: Bootstrap the repo

**Files (all created):**
- `~/taler_id_sdk_flutter/.gitignore`
- `~/taler_id_sdk_flutter/pubspec.yaml`
- `~/taler_id_sdk_flutter/analysis_options.yaml`
- `~/taler_id_sdk_flutter/LICENSE`
- `~/taler_id_sdk_flutter/README.md` (placeholder — full content in Task 11)
- `~/taler_id_sdk_flutter/lib/talerid_oauth.dart` (placeholder export)

- [ ] **Step 1: Verify the package name is available on pub.dev**

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://pub.dev/packages/talerid_oauth"
```

`200` → name is taken; STOP and escalate.
`404` → name is free; proceed.

- [ ] **Step 2: Create the directory and init git**

```bash
mkdir -p ~/taler_id_sdk_flutter
cd ~/taler_id_sdk_flutter
git init
git branch -m main
```

- [ ] **Step 3: Write `.gitignore`**

```
.dart_tool/
.flutter-plugins
.flutter-plugins-dependencies
.packages
.pub-cache/
.pub/
build/
.idea/
.vscode/
*.iml
ios/Pods/
ios/.symlinks/
ios/Flutter/Flutter.framework
ios/Flutter/Flutter.podspec
android/.gradle/
android/local.properties
.DS_Store
*.log
.env
.env.local
coverage/
```

- [ ] **Step 4: Write `pubspec.yaml`**

```yaml
name: talerid_oauth
description: Flutter SDK for Sign in with Taler ID — Authorization Code + PKCE for iOS and Android apps via flutter_appauth.
version: 0.1.0
homepage: https://id.taler.tirol/oauth-guide.html
repository: https://github.com/dvvolkovv/taler_id_sdk_flutter

environment:
  sdk: ^3.5.0
  flutter: ">=3.24.0"

dependencies:
  flutter:
    sdk: flutter
  flutter_appauth: ^9.0.0
  flutter_secure_storage: ^9.0.0
  http: ^1.0.0
  equatable: ^2.0.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^5.0.0
  mocktail: ^1.0.0
```

If `flutter pub get` (next step) fails to resolve `^9.0.0` for either `flutter_appauth` or `flutter_secure_storage`, fall back to `^8.0.0` for that package and retry.

- [ ] **Step 5: Write `analysis_options.yaml`**

```yaml
include: package:flutter_lints/flutter.yaml

linter:
  rules:
    avoid_print: true
    prefer_const_constructors: true
    public_member_api_docs: true
    always_declare_return_types: true
```

- [ ] **Step 6: Write `LICENSE`**

```
MIT License

Copyright (c) 2026 Dmitry Volkov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 7: Write placeholder `lib/talerid_oauth.dart`**

```dart
/// Flutter SDK for Sign in with Taler ID. Full library in later tasks.
library talerid_oauth;
```

- [ ] **Step 8: Write `README.md` placeholder**

```markdown
# talerid_oauth

Flutter SDK for Sign in with Taler ID. Full README in Task 11.

[Spec](https://github.com/dvvolkovv/taler_id/blob/main/docs/superpowers/specs/2026-04-29-oauth-ui-kit-phase-3-flutter-sdk.md)
```

- [ ] **Step 9: Resolve dependencies**

```bash
cd ~/taler_id_sdk_flutter
flutter pub get
```

Expected: `.dart_tool/`, `pubspec.lock` produced. No resolution errors.

- [ ] **Step 10: Verify analyzer + test scaffolding works (empty placeholders)**

```bash
cd ~/taler_id_sdk_flutter
flutter analyze
flutter test 2>&1 | tail -3
```

Expected: `flutter analyze` reports 0 issues. `flutter test` reports "No tests were found." (since `test/` is empty) — this is fine, it's a non-zero exit but the tooling works.

- [ ] **Step 11: Create the GitHub repo and push**

```bash
cd ~/taler_id_sdk_flutter
gh repo create dvvolkovv/taler_id_sdk_flutter --public \
  --description "Flutter SDK for Sign in with Taler ID — Authorization Code + PKCE for iOS and Android via flutter_appauth." \
  --source=. --remote=origin
git add .
git commit -m "chore: bootstrap talerid_oauth package"
git push -u origin main
```

Expected: repo at <https://github.com/dvvolkovv/taler_id_sdk_flutter> exists; initial commit on `main`.

---

## Task 2: Errors module

**Files:**
- Create: `~/taler_id_sdk_flutter/lib/src/errors.dart`
- Create: `~/taler_id_sdk_flutter/test/errors_test.dart`

- [ ] **Step 1: Write the failing test**

```dart
// test/errors_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:talerid_oauth/src/errors.dart';

void main() {
  group('TalerIdAuthError', () {
    test('is an Exception with code, message, and optional cause', () {
      final inner = StateError('boom');
      final err = TalerIdAuthError(
        code: TalerIdErrorCode.network,
        message: 'OAuth token request failed',
        cause: inner,
      );
      expect(err, isA<Exception>());
      expect(err.code, TalerIdErrorCode.network);
      expect(err.message, 'OAuth token request failed');
      expect(err.cause, inner);
    });

    test('uses code name as default message when none given', () {
      final err = TalerIdAuthError(code: TalerIdErrorCode.userCancelled);
      expect(err.message, 'userCancelled');
    });

    test('toString includes the code name', () {
      final err = TalerIdAuthError(code: TalerIdErrorCode.invalidGrant);
      expect(err.toString(), contains('invalidGrant'));
    });

    test('all error codes are present', () {
      const expected = {
        TalerIdErrorCode.loginRequired,
        TalerIdErrorCode.consentRequired,
        TalerIdErrorCode.network,
        TalerIdErrorCode.config,
        TalerIdErrorCode.userCancelled,
        TalerIdErrorCode.invalidGrant,
      };
      expect(TalerIdErrorCode.values.toSet(), expected);
    });
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/taler_id_sdk_flutter
flutter test test/errors_test.dart 2>&1 | tail -5
```

Expected: FAIL — file `lib/src/errors.dart` not found.

- [ ] **Step 3: Write the implementation**

```dart
// lib/src/errors.dart

/// Discriminator for [TalerIdAuthError] — every error has one.
enum TalerIdErrorCode {
  /// No active session; integrator should call `login()`.
  loginRequired,

  /// Granted consent has expired or never existed; integrator should call `login()`.
  consentRequired,

  /// Network-level failure (connection refused, timeout, DNS, etc.).
  network,

  /// Misconfiguration — missing or malformed `clientId`/`redirectUri`/etc.
  config,

  /// User dismissed the in-app browser before completing OAuth.
  userCancelled,

  /// Token endpoint returned 4xx (typically `invalid_grant`/`invalid_request`).
  invalidGrant,
}

/// Single error class for all SDK error paths. Discriminate via [code].
class TalerIdAuthError implements Exception {
  final TalerIdErrorCode code;
  final String message;
  final Object? cause;

  TalerIdAuthError({
    required this.code,
    String? message,
    this.cause,
  }) : message = message ?? code.name;

  @override
  String toString() => 'TalerIdAuthError(code: ${code.name}, message: $message)';
}
```

- [ ] **Step 4: Run tests**

```bash
flutter test test/errors_test.dart 2>&1 | tail -5
```

Expected: PASS — 4 tests.

- [ ] **Step 5: Commit**

```bash
git add lib/src/errors.dart test/errors_test.dart
git commit -m "feat(errors): TalerIdAuthError with TalerIdErrorCode enum"
```

---

## Task 3: AuthState + UserInfo

**Files:**
- Create: `~/taler_id_sdk_flutter/lib/src/auth_state.dart`
- Create: `~/taler_id_sdk_flutter/test/auth_state_test.dart`

- [ ] **Step 1: Write the failing test**

```dart
// test/auth_state_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:talerid_oauth/src/auth_state.dart';

void main() {
  group('UserInfo', () {
    test('exposes sub and arbitrary claims', () {
      final user = UserInfo(sub: 'u-1', claims: {'email': 'u@example.com', 'name': 'Alice'});
      expect(user.sub, 'u-1');
      expect(user.email, 'u@example.com');
      expect(user.name, 'Alice');
      expect(user.claim<String>('email'), 'u@example.com');
      expect(user.claim<String>('missing'), isNull);
    });

    test('equality is value-based', () {
      final a = UserInfo(sub: 'u-1', claims: {'email': 'a'});
      final b = UserInfo(sub: 'u-1', claims: {'email': 'a'});
      expect(a, equals(b));
    });

    test('serializes to and from JSON', () {
      final user = UserInfo(sub: 'u-1', claims: {'email': 'u@x.com'});
      final json = user.toJson();
      final restored = UserInfo.fromJson(json);
      expect(restored, equals(user));
    });
  });

  group('AuthState', () {
    test('equality reflects all fields', () {
      const a = AuthState(user: null, isAuthenticated: false, isLoading: true);
      const b = AuthState(user: null, isAuthenticated: false, isLoading: true);
      const c = AuthState(user: null, isAuthenticated: false, isLoading: false);
      expect(a, equals(b));
      expect(a, isNot(equals(c)));
    });
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
flutter test test/auth_state_test.dart 2>&1 | tail -5
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```dart
// lib/src/auth_state.dart
import 'dart:convert';
import 'package:equatable/equatable.dart';

/// User info from `/oauth/me`, with arbitrary OIDC claims.
class UserInfo extends Equatable {
  final String sub;
  final Map<String, Object?> claims;

  const UserInfo({required this.sub, required this.claims});

  String? get email => claims['email'] as String?;
  String? get name => claims['name'] as String?;

  T? claim<T>(String key) => claims[key] as T?;

  Map<String, Object?> toJson() => {'sub': sub, ...claims};

  factory UserInfo.fromJson(Map<String, Object?> json) {
    final claims = Map<String, Object?>.from(json);
    final sub = claims.remove('sub') as String;
    return UserInfo(sub: sub, claims: claims);
  }

  String toJsonString() => jsonEncode(toJson());

  factory UserInfo.fromJsonString(String s) =>
      UserInfo.fromJson(jsonDecode(s) as Map<String, Object?>);

  @override
  List<Object?> get props => [sub, claims];
}

/// Reactive auth state exposed by `TalerIdClient.authState`.
class AuthState extends Equatable {
  final UserInfo? user;
  final bool isAuthenticated;
  final bool isLoading;

  const AuthState({
    this.user,
    required this.isAuthenticated,
    required this.isLoading,
  });

  /// Default unauthenticated, idle state.
  static const AuthState initial = AuthState(
    user: null,
    isAuthenticated: false,
    isLoading: false,
  );

  AuthState copyWith({
    UserInfo? user,
    bool? isAuthenticated,
    bool? isLoading,
    bool clearUser = false,
  }) =>
      AuthState(
        user: clearUser ? null : (user ?? this.user),
        isAuthenticated: isAuthenticated ?? this.isAuthenticated,
        isLoading: isLoading ?? this.isLoading,
      );

  @override
  List<Object?> get props => [user, isAuthenticated, isLoading];
}
```

- [ ] **Step 4: Run tests**

```bash
flutter test test/auth_state_test.dart 2>&1 | tail -5
```

Expected: PASS — 4 tests.

- [ ] **Step 5: Commit**

```bash
git add lib/src/auth_state.dart test/auth_state_test.dart
git commit -m "feat(state): AuthState + UserInfo with Equatable equality and JSON codec"
```

---

## Task 4: Storage adapters

**Files:**
- Create: `~/taler_id_sdk_flutter/lib/src/storage.dart`
- Create: `~/taler_id_sdk_flutter/test/storage_test.dart`

- [ ] **Step 1: Write the failing test**

```dart
// test/storage_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:talerid_oauth/src/storage.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('MemoryStorage', () {
    test('round-trips get/set/remove', () async {
      final s = MemoryStorage();
      expect(await s.get('talerid:k'), isNull);
      await s.set('talerid:k', 'v');
      expect(await s.get('talerid:k'), 'v');
      await s.remove('talerid:k');
      expect(await s.get('talerid:k'), isNull);
    });

    test('isolated per instance', () async {
      final a = MemoryStorage();
      final b = MemoryStorage();
      await a.set('talerid:k', 'v');
      expect(await b.get('talerid:k'), isNull);
    });
  });

  group('SecureStorage', () {
    setUp(() {
      // flutter_secure_storage uses a method channel — mock it.
      const channel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
      final store = <String, String>{};
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        final args = (call.arguments as Map?)?.cast<String, Object?>() ?? const {};
        switch (call.method) {
          case 'write':
            store[args['key'] as String] = args['value'] as String;
            return null;
          case 'read':
            return store[args['key'] as String];
          case 'delete':
            store.remove(args['key'] as String);
            return null;
          case 'readAll':
            return Map<String, String>.from(store);
          case 'deleteAll':
            store.clear();
            return null;
        }
        return null;
      });
    });

    test('round-trips get/set/remove via flutter_secure_storage channel', () async {
      final s = SecureStorage();
      expect(await s.get('talerid:k'), isNull);
      await s.set('talerid:k', 'v');
      expect(await s.get('talerid:k'), 'v');
      await s.remove('talerid:k');
      expect(await s.get('talerid:k'), isNull);
    });
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
flutter test test/storage_test.dart 2>&1 | tail -5
```

Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```dart
// lib/src/storage.dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Pluggable token storage. Implementations must persist the value verbatim.
/// All operations are async because production storages hit platform channels.
abstract class Storage {
  Future<String?> get(String key);
  Future<void> set(String key, String value);
  Future<void> remove(String key);
}

/// Default storage. Wraps flutter_secure_storage — Keychain on iOS, Keystore on Android.
class SecureStorage implements Storage {
  final FlutterSecureStorage _inner;

  SecureStorage()
      : _inner = const FlutterSecureStorage(
          iOptions: IOSOptions(
            accessibility: KeychainAccessibility.first_unlock_this_device,
          ),
          aOptions: AndroidOptions(encryptedSharedPreferences: true),
        );

  @override
  Future<String?> get(String key) => _inner.read(key: key);

  @override
  Future<void> set(String key, String value) =>
      _inner.write(key: key, value: value);

  @override
  Future<void> remove(String key) => _inner.delete(key: key);
}

/// In-memory adapter — useful for tests or environments where persistence is undesired.
class MemoryStorage implements Storage {
  final Map<String, String> _store = {};

  @override
  Future<String?> get(String key) async => _store[key];

  @override
  Future<void> set(String key, String value) async {
    _store[key] = value;
  }

  @override
  Future<void> remove(String key) async {
    _store.remove(key);
  }
}
```

- [ ] **Step 4: Run tests**

```bash
flutter test test/storage_test.dart 2>&1 | tail -5
```

Expected: PASS — 3 tests.

- [ ] **Step 5: Commit**

```bash
git add lib/src/storage.dart test/storage_test.dart
git commit -m "feat(storage): Storage abstract + SecureStorage + MemoryStorage"
```

---

## Task 5: OAuthBackend abstraction + FlutterAppAuthBackend implementation

**Files:**
- Create: `~/taler_id_sdk_flutter/lib/src/oauth_backend.dart`

The abstraction lets `TalerIdClient` be tested with a fake without mocking platform channels. The real `FlutterAppAuthBackend` is a thin wrapper around `flutter_appauth`'s API surface that we use; it has no behaviour worth unit-testing on its own (would just be testing the package). We test it indirectly via `client_test.dart` (Task 6+) using the fake.

- [ ] **Step 1: Write the implementation directly (no test for this file)**

```dart
// lib/src/oauth_backend.dart
import 'package:flutter_appauth/flutter_appauth.dart';

/// Result of an authorization-code-with-PKCE token exchange.
class OAuthTokens {
  final String accessToken;
  final String? refreshToken;
  final String? idToken;
  final DateTime? expiresAt;

  OAuthTokens({
    required this.accessToken,
    this.refreshToken,
    this.idToken,
    this.expiresAt,
  });
}

/// Internal port — abstracts `flutter_appauth` so tests can use a fake.
abstract class OAuthBackend {
  /// Run the full authorize-and-exchange flow. Throws on cancel / network / state mismatch.
  Future<OAuthTokens> authorizeAndExchangeCode({
    required String clientId,
    required String redirectUri,
    required String issuer,
    required List<String> scopes,
  });

  /// Exchange a refresh token for new tokens.
  Future<OAuthTokens> refresh({
    required String clientId,
    required String issuer,
    required String refreshToken,
  });

  /// End the OIDC session in the browser (RP-initiated logout).
  /// Throws on user cancel; does NOT throw on browser dismiss after success.
  Future<void> endSession({
    required String issuer,
    required String idTokenHint,
    required String postLogoutRedirectUri,
  });
}

/// Production backend — wraps `flutter_appauth`.
class FlutterAppAuthBackend implements OAuthBackend {
  final FlutterAppAuth _appAuth = const FlutterAppAuth();

  @override
  Future<OAuthTokens> authorizeAndExchangeCode({
    required String clientId,
    required String redirectUri,
    required String issuer,
    required List<String> scopes,
  }) async {
    final result = await _appAuth.authorizeAndExchangeCode(
      AuthorizationTokenRequest(
        clientId,
        redirectUri,
        issuer: issuer,
        scopes: scopes,
        promptValues: const [],
      ),
    );
    if (result == null) {
      throw StateError('flutter_appauth returned null AuthorizationTokenResponse');
    }
    return OAuthTokens(
      accessToken: result.accessToken!,
      refreshToken: result.refreshToken,
      idToken: result.idToken,
      expiresAt: result.accessTokenExpirationDateTime,
    );
  }

  @override
  Future<OAuthTokens> refresh({
    required String clientId,
    required String issuer,
    required String refreshToken,
  }) async {
    final result = await _appAuth.token(
      TokenRequest(
        clientId,
        '', // redirectUri unused for refresh grant
        issuer: issuer,
        refreshToken: refreshToken,
        grantType: 'refresh_token',
      ),
    );
    if (result == null) {
      throw StateError('flutter_appauth returned null TokenResponse');
    }
    return OAuthTokens(
      accessToken: result.accessToken!,
      refreshToken: result.refreshToken,
      idToken: result.idToken,
      expiresAt: result.accessTokenExpirationDateTime,
    );
  }

  @override
  Future<void> endSession({
    required String issuer,
    required String idTokenHint,
    required String postLogoutRedirectUri,
  }) async {
    await _appAuth.endSession(
      EndSessionRequest(
        idTokenHint: idTokenHint,
        postLogoutRedirectUri: postLogoutRedirectUri,
        issuer: issuer,
      ),
    );
  }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
flutter analyze lib/src/oauth_backend.dart 2>&1 | tail -3
```

Expected: 0 issues.

If `flutter_appauth`'s API differs slightly (the field names or method shapes might shift across major versions), adjust the wrapper accordingly. The contract — `authorizeAndExchangeCode`, `refresh`, `endSession` — stays the same regardless.

- [ ] **Step 3: Commit**

```bash
git add lib/src/oauth_backend.dart
git commit -m "feat(backend): OAuthBackend abstraction over flutter_appauth"
```

---

## Task 6: TalerIdClient skeleton — config validation, create() factory, isAuthenticated, authState

**Files:**
- Create: `~/taler_id_sdk_flutter/lib/src/client.dart`
- Modify: `~/taler_id_sdk_flutter/lib/talerid_oauth.dart` (replace placeholder)
- Create: `~/taler_id_sdk_flutter/test/client_test.dart`

- [ ] **Step 1: Write the failing test**

```dart
// test/client_test.dart
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:talerid_oauth/talerid_oauth.dart';
import 'package:talerid_oauth/src/oauth_backend.dart';

class FakeOAuthBackend implements OAuthBackend {
  OAuthTokens? nextAuthorizeResult;
  Object? nextAuthorizeError;
  OAuthTokens? nextRefreshResult;
  Object? nextRefreshError;
  bool endSessionCalled = false;

  @override
  Future<OAuthTokens> authorizeAndExchangeCode({
    required String clientId,
    required String redirectUri,
    required String issuer,
    required List<String> scopes,
  }) async {
    if (nextAuthorizeError != null) throw nextAuthorizeError!;
    return nextAuthorizeResult!;
  }

  @override
  Future<OAuthTokens> refresh({
    required String clientId,
    required String issuer,
    required String refreshToken,
  }) async {
    if (nextRefreshError != null) throw nextRefreshError!;
    return nextRefreshResult!;
  }

  @override
  Future<void> endSession({
    required String issuer,
    required String idTokenHint,
    required String postLogoutRedirectUri,
  }) async {
    endSessionCalled = true;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('TalerIdClient — skeleton', () {
    late MemoryStorage storage;
    late FakeOAuthBackend backend;

    setUp(() {
      storage = MemoryStorage();
      backend = FakeOAuthBackend();
    });

    test('create() throws config when clientId empty', () async {
      expect(
        () => TalerIdClient.create(
          clientId: '',
          redirectUri: 'app://cb',
          storage: storage,
          backend: backend,
        ),
        throwsA(isA<TalerIdAuthError>()
            .having((e) => e.code, 'code', TalerIdErrorCode.config)),
      );
    });

    test('create() throws config when redirectUri empty', () async {
      expect(
        () => TalerIdClient.create(
          clientId: 'c',
          redirectUri: '',
          storage: storage,
          backend: backend,
        ),
        throwsA(isA<TalerIdAuthError>()
            .having((e) => e.code, 'code', TalerIdErrorCode.config)),
      );
    });

    test('isAuthenticated false on empty storage', () async {
      final client = await TalerIdClient.create(
        clientId: 'c',
        redirectUri: 'app://cb',
        storage: storage,
        backend: backend,
      );
      expect(client.isAuthenticated, isFalse);
    });

    test('isAuthenticated true when access_token + future expires_at present', () async {
      await storage.set('talerid:access_token', 'AT');
      await storage.set(
        'talerid:expires_at',
        DateTime.now().add(const Duration(minutes: 1)).millisecondsSinceEpoch.toString(),
      );
      final client = await TalerIdClient.create(
        clientId: 'c',
        redirectUri: 'app://cb',
        storage: storage,
        backend: backend,
      );
      expect(client.isAuthenticated, isTrue);
    });

    test('authState is a ValueListenable<AuthState>', () async {
      final client = await TalerIdClient.create(
        clientId: 'c',
        redirectUri: 'app://cb',
        storage: storage,
        backend: backend,
      );
      expect(client.authState, isA<ValueListenable<AuthState>>());
      expect(client.authState.value.isAuthenticated, isFalse);
    });
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
flutter test test/client_test.dart 2>&1 | tail -5
```

Expected: FAIL — `TalerIdClient` not found.

- [ ] **Step 3: Write the implementation**

```dart
// lib/src/client.dart
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import 'auth_state.dart';
import 'errors.dart';
import 'oauth_backend.dart';
import 'storage.dart';

const String _kPrefix = 'talerid:';
const String _kAccess = '${_kPrefix}access_token';
const String _kRefresh = '${_kPrefix}refresh_token';
const String _kId = '${_kPrefix}id_token';
const String _kExpires = '${_kPrefix}expires_at';
const String _kUser = '${_kPrefix}user';

const String _defaultIssuer = 'https://id.taler.tirol/oauth';
const String _defaultScope = 'openid profile email';

typedef LogCallback = void Function(String level, String message, [Object? meta]);

/// Browser SDK for Sign in with Taler ID.
class TalerIdClient {
  final String clientId;
  final String redirectUri;
  final String scope;
  final String issuer;
  final Storage storage;
  final OAuthBackend _backend;
  final http.Client _http;
  final LogCallback _log;

  final ValueNotifier<AuthState> _state;
  ValueListenable<AuthState> get authState => _state;

  TalerIdClient._({
    required this.clientId,
    required this.redirectUri,
    required this.scope,
    required this.issuer,
    required this.storage,
    required OAuthBackend backend,
    http.Client? httpClient,
    LogCallback? onLog,
    required AuthState initialState,
  })  : _backend = backend,
        _http = httpClient ?? http.Client(),
        _log = onLog ?? ((_, __, [___]) {}),
        _state = ValueNotifier<AuthState>(initialState);

  /// Async factory: validates config, hydrates state from storage, returns a ready client.
  static Future<TalerIdClient> create({
    required String clientId,
    required String redirectUri,
    String scope = _defaultScope,
    String issuer = _defaultIssuer,
    Storage? storage,
    OAuthBackend? backend,
    http.Client? httpClient,
    LogCallback? onLog,
  }) async {
    if (clientId.isEmpty) {
      throw TalerIdAuthError(
          code: TalerIdErrorCode.config, message: 'clientId is required');
    }
    if (redirectUri.isEmpty) {
      throw TalerIdAuthError(
          code: TalerIdErrorCode.config, message: 'redirectUri is required');
    }
    final s = storage ?? SecureStorage();
    final b = backend ?? FlutterAppAuthBackend();

    final access = await s.get(_kAccess);
    final expiresRaw = await s.get(_kExpires);
    final userJson = await s.get(_kUser);

    final expiresAt = int.tryParse(expiresRaw ?? '');
    final isAuthed = access != null &&
        expiresAt != null &&
        expiresAt > DateTime.now().millisecondsSinceEpoch;

    final user = (userJson != null) ? UserInfo.fromJsonString(userJson) : null;

    final initial = AuthState(
      user: user,
      isAuthenticated: isAuthed,
      isLoading: false,
    );

    return TalerIdClient._(
      clientId: clientId,
      redirectUri: redirectUri,
      scope: scope,
      issuer: issuer,
      storage: s,
      backend: b,
      httpClient: httpClient,
      onLog: onLog,
      initialState: initial,
    );
  }

  /// Sync — reads from in-memory cache derived from the most recent storage write.
  bool get isAuthenticated => _state.value.isAuthenticated;

  /// Internal helper used by future tasks.
  void _emit(AuthState next) {
    if (next != _state.value) _state.value = next;
  }
}
```

```dart
// lib/talerid_oauth.dart (replace placeholder)
/// Flutter SDK for Sign in with Taler ID.
library talerid_oauth;

export 'src/auth_state.dart' show AuthState, UserInfo;
export 'src/errors.dart' show TalerIdAuthError, TalerIdErrorCode;
export 'src/storage.dart' show Storage, SecureStorage, MemoryStorage;
export 'src/client.dart' show TalerIdClient, LogCallback;
```

- [ ] **Step 4: Run tests + analyzer**

```bash
flutter test 2>&1 | tail -5
flutter analyze 2>&1 | tail -3
```

Expected: 5 client tests pass; all other tests still pass; `flutter analyze` reports 0 issues.

- [ ] **Step 5: Commit**

```bash
git add lib/src/client.dart lib/talerid_oauth.dart test/client_test.dart
git commit -m "feat(client): TalerIdClient skeleton — create() factory, isAuthenticated, authState"
```

---

## Task 7: TalerIdClient — login()

**Files:**
- Modify: `~/taler_id_sdk_flutter/lib/src/client.dart` (add method)
- Modify: `~/taler_id_sdk_flutter/test/client_test.dart` (append tests)

- [ ] **Step 1: Append the failing tests to `test/client_test.dart`**

Append at the end (after the last `});`):

```dart
  group('TalerIdClient — login', () {
    late MemoryStorage storage;
    late FakeOAuthBackend backend;
    late TalerIdClient client;

    setUp(() async {
      storage = MemoryStorage();
      backend = FakeOAuthBackend();
      client = await TalerIdClient.create(
        clientId: 'c',
        redirectUri: 'app://cb',
        storage: storage,
        backend: backend,
      );
    });

    test('stores tokens, emits authenticated state, returns when done', () async {
      backend.nextAuthorizeResult = OAuthTokens(
        accessToken: 'AT',
        refreshToken: 'RT',
        idToken: 'IT',
        expiresAt: DateTime.now().add(const Duration(minutes: 15)),
      );

      await client.login();

      expect(client.isAuthenticated, isTrue);
      expect(client.authState.value.isAuthenticated, isTrue);
      expect(await storage.get('talerid:access_token'), 'AT');
      expect(await storage.get('talerid:refresh_token'), 'RT');
      expect(await storage.get('talerid:id_token'), 'IT');
      final expires = int.parse((await storage.get('talerid:expires_at'))!);
      expect(expires, greaterThan(DateTime.now().millisecondsSinceEpoch));
    });

    test('maps backend cancellation to userCancelled error', () async {
      backend.nextAuthorizeError = StateError('User cancelled flow');
      await expectLater(
        client.login(),
        throwsA(isA<TalerIdAuthError>()),
      );
      // Even on error, state stays unauthenticated.
      expect(client.isAuthenticated, isFalse);
    });

    test('isLoading is true during login flow', () async {
      var sawLoading = false;
      client.authState.addListener(() {
        if (client.authState.value.isLoading) sawLoading = true;
      });
      backend.nextAuthorizeResult = OAuthTokens(
        accessToken: 'AT',
        expiresAt: DateTime.now().add(const Duration(minutes: 15)),
      );
      await client.login();
      expect(sawLoading, isTrue);
      expect(client.authState.value.isLoading, isFalse);
    });
  });
```

- [ ] **Step 2: Run test to verify it fails**

```bash
flutter test test/client_test.dart 2>&1 | tail -10
```

Expected: 3 new tests fail with "method not found".

- [ ] **Step 3: Add the implementation**

Add to `lib/src/client.dart` (inside the `TalerIdClient` class, e.g. after the constructor's helpers):

```dart
  /// Run the full authorize-and-exchange-code flow.
  /// Opens an in-app browser, returns when tokens are stored.
  Future<void> login() async {
    _emit(_state.value.copyWith(isLoading: true));
    try {
      final tokens = await _backend.authorizeAndExchangeCode(
        clientId: clientId,
        redirectUri: redirectUri,
        issuer: issuer,
        scopes: scope.split(' '),
      );
      await _persistTokens(tokens);
      _emit(AuthState(
        user: _state.value.user,
        isAuthenticated: true,
        isLoading: false,
      ));
      _log('info', 'login complete', {'scope': scope});
    } on TalerIdAuthError {
      _emit(_state.value.copyWith(isLoading: false));
      rethrow;
    } catch (err) {
      _emit(_state.value.copyWith(isLoading: false));
      // Map underlying error to a TalerIdAuthError. Users dismissing the in-app browser
      // surfaces here as a PlatformException; we attribute anything we can't classify
      // as `userCancelled` since it is by far the most common cause.
      throw TalerIdAuthError(
        code: TalerIdErrorCode.userCancelled,
        message: 'login failed',
        cause: err,
      );
    }
  }

  Future<void> _persistTokens(OAuthTokens tokens) async {
    await storage.set(_kAccess, tokens.accessToken);
    if (tokens.refreshToken != null) {
      await storage.set(_kRefresh, tokens.refreshToken!);
    }
    if (tokens.idToken != null) {
      await storage.set(_kId, tokens.idToken!);
    }
    if (tokens.expiresAt != null) {
      await storage.set(
        _kExpires,
        tokens.expiresAt!.millisecondsSinceEpoch.toString(),
      );
    }
  }
```

- [ ] **Step 4: Run tests + analyzer**

```bash
flutter test 2>&1 | tail -5
flutter analyze 2>&1 | tail -3
```

Expected: all tests pass (5 prior + 3 new); analyzer clean.

- [ ] **Step 5: Commit**

```bash
git add lib/src/client.dart test/client_test.dart
git commit -m "feat(client): login() runs flutter_appauth flow, stores tokens, emits state"
```

---

## Task 8: TalerIdClient — getUser + getAccessToken (no refresh yet)

**Files:**
- Modify: `~/taler_id_sdk_flutter/lib/src/client.dart` (add methods)
- Modify: `~/taler_id_sdk_flutter/test/client_test.dart` (append tests)

- [ ] **Step 1: Append the failing tests**

Append at the end of `test/client_test.dart`:

```dart
  group('TalerIdClient — getAccessToken / getUser', () {
    late MemoryStorage storage;
    late FakeOAuthBackend backend;

    Future<TalerIdClient> makeClient({http.Client? httpClient}) =>
        TalerIdClient.create(
          clientId: 'c',
          redirectUri: 'app://cb',
          storage: storage,
          backend: backend,
          httpClient: httpClient,
        );

    setUp(() async {
      storage = MemoryStorage();
      backend = FakeOAuthBackend();
      await storage.set('talerid:access_token', 'AT');
      await storage.set(
        'talerid:expires_at',
        DateTime.now().add(const Duration(minutes: 1)).millisecondsSinceEpoch.toString(),
      );
    });

    test('getAccessToken returns cached token when not near expiry', () async {
      final client = await makeClient();
      expect(await client.getAccessToken(), 'AT');
    });

    test('getAccessToken throws loginRequired when no token in storage', () async {
      await storage.remove('talerid:access_token');
      await storage.remove('talerid:expires_at');
      final client = await makeClient();
      await expectLater(
        client.getAccessToken(),
        throwsA(isA<TalerIdAuthError>()
            .having((e) => e.code, 'code', TalerIdErrorCode.loginRequired)),
      );
    });

    test('getUser fetches /oauth/me with Bearer header, caches result', () async {
      var calls = 0;
      final mockHttp = MockClient((req) async {
        calls += 1;
        expect(req.url.toString(), 'https://id.taler.tirol/oauth/me');
        expect(req.headers['authorization'], 'Bearer AT');
        return http.Response(
          jsonEncode({'sub': 'user-1', 'email': 'u@x.com'}),
          200,
          headers: {'content-type': 'application/json'},
        );
      });
      final client = await makeClient(httpClient: mockHttp);
      final user = await client.getUser();
      expect(user.sub, 'user-1');
      expect(user.email, 'u@x.com');
      expect(calls, 1);

      // second call hits cache
      final user2 = await client.getUser();
      expect(user2, equals(user));
      expect(calls, 1);
    });

    test('getUser throws network on fetch failure', () async {
      final mockHttp = MockClient((req) async {
        throw http.ClientException('Failed to fetch');
      });
      final client = await makeClient(httpClient: mockHttp);
      await expectLater(
        client.getUser(),
        throwsA(isA<TalerIdAuthError>()
            .having((e) => e.code, 'code', TalerIdErrorCode.network)),
      );
    });
  });
```

Add these imports at the top of `test/client_test.dart` (alongside existing imports):

```dart
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
```

- [ ] **Step 2: Run test to verify it fails**

```bash
flutter test test/client_test.dart 2>&1 | tail -10
```

Expected: 4 new tests fail with method-not-found.

- [ ] **Step 3: Add the implementation**

Add to `lib/src/client.dart` (inside the class):

```dart
  /// Returns the current access token. Refresh logic added in Task 9.
  Future<String> getAccessToken() async {
    final token = await storage.get(_kAccess);
    final expiresRaw = await storage.get(_kExpires);
    if (token == null || expiresRaw == null) {
      throw TalerIdAuthError(
        code: TalerIdErrorCode.loginRequired,
        message: 'No active session',
      );
    }
    return token;
  }

  /// Fetches userinfo from `/oauth/me`. First call hits the network and caches in storage;
  /// subsequent calls return the cached value.
  Future<UserInfo> getUser() async {
    final cachedJson = await storage.get(_kUser);
    if (cachedJson != null) return UserInfo.fromJsonString(cachedJson);

    final token = await getAccessToken();
    http.Response response;
    try {
      response = await _http.get(
        Uri.parse('$issuer/me'),
        headers: {'authorization': 'Bearer $token'},
      );
    } catch (err) {
      throw TalerIdAuthError(
        code: TalerIdErrorCode.network,
        message: 'userinfo request failed',
        cause: err,
      );
    }
    if (response.statusCode != 200) {
      throw TalerIdAuthError(
        code: TalerIdErrorCode.loginRequired,
        message: 'userinfo returned ${response.statusCode}',
      );
    }
    final json = jsonDecode(response.body) as Map<String, Object?>;
    final user = UserInfo.fromJson(json);
    await storage.set(_kUser, user.toJsonString());
    _emit(_state.value.copyWith(user: user));
    return user;
  }
```

Also add the imports at the top of `lib/src/client.dart` if missing:

```dart
import 'dart:convert';  // already there if jsonEncode used
import 'package:http/http.dart' as http;  // already there
```

- [ ] **Step 4: Run tests + analyzer**

```bash
flutter test 2>&1 | tail -5
flutter analyze 2>&1 | tail -3
```

Expected: 12 client tests pass total; analyzer clean.

- [ ] **Step 5: Commit**

```bash
git add lib/src/client.dart test/client_test.dart
git commit -m "feat(client): getAccessToken (no refresh) + getUser with caching"
```

---

## Task 9: Token refresh + concurrent guard

**Files:**
- Modify: `~/taler_id_sdk_flutter/lib/src/client.dart` (extend getAccessToken, add helpers)
- Create: `~/taler_id_sdk_flutter/test/refresh_test.dart`

- [ ] **Step 1: Write the failing test (NEW file)**

```dart
// test/refresh_test.dart
import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:talerid_oauth/talerid_oauth.dart';
import 'package:talerid_oauth/src/oauth_backend.dart';

import 'client_test.dart' show FakeOAuthBackend;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('TalerIdClient — refresh', () {
    late MemoryStorage storage;
    late FakeOAuthBackend backend;

    Future<TalerIdClient> makeClient() => TalerIdClient.create(
          clientId: 'c',
          redirectUri: 'app://cb',
          storage: storage,
          backend: backend,
        );

    setUp(() async {
      storage = MemoryStorage();
      backend = FakeOAuthBackend();
      await storage.set('talerid:access_token', 'OLD');
      await storage.set('talerid:refresh_token', 'RT');
      await storage.set(
        'talerid:expires_at',
        DateTime.now().add(const Duration(seconds: 5)).millisecondsSinceEpoch.toString(),
      );
    });

    test('refreshes when access_token is within 30s of expiry', async () {
      backend.nextRefreshResult = OAuthTokens(
        accessToken: 'NEW',
        refreshToken: 'RT2',
        expiresAt: DateTime.now().add(const Duration(minutes: 15)),
      );
      final client = await makeClient();
      final token = await client.getAccessToken();
      expect(token, 'NEW');
      expect(await storage.get('talerid:access_token'), 'NEW');
      expect(await storage.get('talerid:refresh_token'), 'RT2');
    });

    test('two concurrent getAccessToken calls share one refresh', () async {
      final completer = Completer<OAuthTokens>();
      backend = _BlockingBackend(completer);
      final client = await makeClient();

      final p1 = client.getAccessToken();
      final p2 = client.getAccessToken();

      completer.complete(OAuthTokens(
        accessToken: 'NEW',
        expiresAt: DateTime.now().add(const Duration(minutes: 15)),
      ));

      final results = await Future.wait([p1, p2]);
      expect(results, ['NEW', 'NEW']);
      expect((backend as _BlockingBackend).refreshCalls, 1);
    });

    test('refresh failure clears storage and throws loginRequired', () async {
      backend.nextRefreshError = StateError('invalid_grant');
      final client = await makeClient();
      await expectLater(
        client.getAccessToken(),
        throwsA(isA<TalerIdAuthError>()
            .having((e) => e.code, 'code', TalerIdErrorCode.loginRequired)),
      );
      expect(await storage.get('talerid:access_token'), isNull);
      expect(await storage.get('talerid:refresh_token'), isNull);
      expect(client.authState.value.isAuthenticated, isFalse);
    });

    test('does NOT refresh when access_token has >30s of life left', () async {
      await storage.set(
        'talerid:expires_at',
        DateTime.now().add(const Duration(minutes: 1)).millisecondsSinceEpoch.toString(),
      );
      final client = await makeClient();
      final token = await client.getAccessToken();
      expect(token, 'OLD');
    });
  });
}

class _BlockingBackend extends FakeOAuthBackend {
  final Completer<OAuthTokens> _completer;
  int refreshCalls = 0;

  _BlockingBackend(this._completer);

  @override
  Future<OAuthTokens> refresh({
    required String clientId,
    required String issuer,
    required String refreshToken,
  }) {
    refreshCalls += 1;
    return _completer.future;
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
flutter test test/refresh_test.dart 2>&1 | tail -10
```

Expected: 4 tests fail (current `getAccessToken` returns 'OLD' regardless).

- [ ] **Step 3: Replace `getAccessToken` and add `_refreshAccessToken` + `_clearSession` in `lib/src/client.dart`**

Replace the body of `getAccessToken()` and add a `_refreshInFlight` field, a `_refreshAccessToken()` method, and a `_clearSession()` method. Approximate placement: keep them near `getAccessToken`.

```dart
  Completer<String>? _refreshInFlight;

  Future<String> getAccessToken() async {
    final token = await storage.get(_kAccess);
    final expiresRaw = await storage.get(_kExpires);
    if (token == null || expiresRaw == null) {
      throw TalerIdAuthError(
        code: TalerIdErrorCode.loginRequired,
        message: 'No active session',
      );
    }
    final expiresAt = int.tryParse(expiresRaw) ?? 0;
    if (expiresAt - DateTime.now().millisecondsSinceEpoch > 30_000) {
      return token;
    }
    return _refreshAccessToken();
  }

  Future<String> _refreshAccessToken() {
    if (_refreshInFlight != null) return _refreshInFlight!.future;
    final completer = Completer<String>();
    _refreshInFlight = completer;

    () async {
      final refreshToken = await storage.get(_kRefresh);
      if (refreshToken == null) {
        await _clearSession();
        completer.completeError(TalerIdAuthError(
          code: TalerIdErrorCode.loginRequired,
          message: 'No refresh token',
        ));
        return;
      }
      try {
        final tokens = await _backend.refresh(
          clientId: clientId,
          issuer: issuer,
          refreshToken: refreshToken,
        );
        await _persistTokens(tokens);
        completer.complete(tokens.accessToken);
      } catch (err) {
        await _clearSession();
        completer.completeError(TalerIdAuthError(
          code: TalerIdErrorCode.loginRequired,
          message: 'Refresh request failed',
          cause: err,
        ));
      } finally {
        _refreshInFlight = null;
      }
    }();

    return completer.future;
  }

  Future<void> _clearSession() async {
    await storage.remove(_kAccess);
    await storage.remove(_kRefresh);
    await storage.remove(_kId);
    await storage.remove(_kExpires);
    await storage.remove(_kUser);
    _emit(const AuthState(user: null, isAuthenticated: false, isLoading: false));
  }
```

Also add `import 'dart:async';` to `lib/src/client.dart` if not already imported (needed for `Completer`).

- [ ] **Step 4: Run tests + analyzer**

```bash
flutter test 2>&1 | tail -5
flutter analyze 2>&1 | tail -3
```

Expected: all tests pass (12 + 4 = 16 client+refresh, plus errors/storage/auth_state); analyzer clean.

- [ ] **Step 5: Commit**

```bash
git add lib/src/client.dart test/refresh_test.dart
git commit -m "feat(client): on-demand token refresh with concurrent-call guard"
```

---

## Task 10: TalerIdClient — logout

**Files:**
- Modify: `~/taler_id_sdk_flutter/lib/src/client.dart` (add method)
- Create: `~/taler_id_sdk_flutter/test/logout_test.dart`

- [ ] **Step 1: Write the failing test (NEW file)**

```dart
// test/logout_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:talerid_oauth/talerid_oauth.dart';

import 'client_test.dart' show FakeOAuthBackend;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('TalerIdClient — logout', () {
    late MemoryStorage storage;
    late FakeOAuthBackend backend;

    setUp(() async {
      storage = MemoryStorage();
      backend = FakeOAuthBackend();
      await storage.set('talerid:access_token', 'AT');
      await storage.set('talerid:refresh_token', 'RT');
      await storage.set('talerid:id_token', 'IT');
      await storage.set(
        'talerid:expires_at',
        DateTime.now().add(const Duration(minutes: 1)).millisecondsSinceEpoch.toString(),
      );
      await storage.set('talerid:user', '{"sub":"u"}');
    });

    test('silent logout clears storage and emits unauthenticated state', () async {
      final client = await TalerIdClient.create(
        clientId: 'c',
        redirectUri: 'app://cb',
        storage: storage,
        backend: backend,
      );
      expect(client.isAuthenticated, isTrue);

      await client.logout();

      expect(client.isAuthenticated, isFalse);
      expect(await storage.get('talerid:access_token'), isNull);
      expect(await storage.get('talerid:user'), isNull);
      expect(backend.endSessionCalled, isFalse);
    });

    test('logout(endSession: true) calls backend.endSession with id_token_hint', () async {
      final client = await TalerIdClient.create(
        clientId: 'c',
        redirectUri: 'app://cb',
        storage: storage,
        backend: backend,
      );
      await client.logout(endSession: true);
      expect(backend.endSessionCalled, isTrue);
      // Storage still cleared.
      expect(await storage.get('talerid:access_token'), isNull);
    });

    test('logout when not authenticated is a no-op (idempotent)', () async {
      // Drain storage first.
      await storage.remove('talerid:access_token');
      await storage.remove('talerid:refresh_token');
      await storage.remove('talerid:id_token');
      await storage.remove('talerid:expires_at');
      await storage.remove('talerid:user');

      final client = await TalerIdClient.create(
        clientId: 'c',
        redirectUri: 'app://cb',
        storage: storage,
        backend: backend,
      );
      await client.logout();
      expect(client.isAuthenticated, isFalse);
    });
  });
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
flutter test test/logout_test.dart 2>&1 | tail -10
```

Expected: 3 tests fail with `client.logout` not found.

- [ ] **Step 3: Add the implementation**

Add to `lib/src/client.dart` (inside the class):

```dart
  /// Logs the user out. Always clears local storage and emits unauthenticated state.
  /// If `endSession: true`, opens an in-app browser to the OIDC `session/end` endpoint
  /// (RP-initiated logout). On a fresh-installed device or after data clear, this is a no-op.
  Future<void> logout({bool endSession = false}) async {
    final idToken = await storage.get(_kId);
    await _clearSession();
    if (endSession && idToken != null) {
      try {
        await _backend.endSession(
          issuer: issuer,
          idTokenHint: idToken,
          postLogoutRedirectUri: redirectUri,
        );
      } catch (err) {
        // Logout must succeed locally even if the browser flow fails.
        _log('warn', 'endSession failed; local logout already complete', err);
      }
    }
  }
```

- [ ] **Step 4: Run tests + analyzer**

```bash
flutter test 2>&1 | tail -5
flutter analyze 2>&1 | tail -3
```

Expected: 19 tests total pass (16 + 3 logout); analyzer clean.

- [ ] **Step 5: Commit**

```bash
git add lib/src/client.dart test/logout_test.dart
git commit -m "feat(client): logout clears storage; logout(endSession:) does RP-initiated browser flow"
```

---

## Task 11: README + CHANGELOG + example app

**Files:**
- Modify: `~/taler_id_sdk_flutter/README.md`
- Create: `~/taler_id_sdk_flutter/CHANGELOG.md`
- Create: `~/taler_id_sdk_flutter/example/pubspec.yaml`
- Create: `~/taler_id_sdk_flutter/example/lib/main.dart`
- Create: `~/taler_id_sdk_flutter/example/ios/Runner/Info.plist` (URL scheme)
- Create: `~/taler_id_sdk_flutter/example/android/app/src/main/AndroidManifest.xml` (intent-filter)

The example app's iOS/Android scaffolding is mostly generated by `flutter create`. We start with that and override only the URL-scheme files. Keep the example minimal — one button, one userinfo display.

- [ ] **Step 1: Generate the example app skeleton**

```bash
cd ~/taler_id_sdk_flutter
flutter create example --platforms=ios,android --org com.talerid.example --project-name talerid_oauth_example
```

This creates `example/` with full iOS + Android scaffolds. We'll selectively override files in subsequent steps.

- [ ] **Step 2: Replace `example/pubspec.yaml`**

```yaml
name: talerid_oauth_example
description: Example app for the talerid_oauth SDK.
publish_to: none
version: 0.0.1+1

environment:
  sdk: ^3.5.0
  flutter: ">=3.24.0"

dependencies:
  flutter:
    sdk: flutter
  talerid_oauth:
    path: ..

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^5.0.0

flutter:
  uses-material-design: true
```

- [ ] **Step 3: Replace `example/lib/main.dart`**

```dart
import 'package:flutter/material.dart';
import 'package:talerid_oauth/talerid_oauth.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final client = await TalerIdClient.create(
    clientId: 'taler-id-demo',
    redirectUri: 'com.talerid.example://oauth/callback',
    issuer: 'https://staging.id.taler.tirol/oauth',
  );
  runApp(MyApp(client: client));
}

class MyApp extends StatelessWidget {
  final TalerIdClient client;
  const MyApp({super.key, required this.client});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Taler ID — Example',
      theme: ThemeData(useMaterial3: true, colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF167EF2))),
      home: HomePage(client: client),
    );
  }
}

class HomePage extends StatelessWidget {
  final TalerIdClient client;
  const HomePage({super.key, required this.client});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Sign in with Taler ID')),
      body: ValueListenableBuilder<AuthState>(
        valueListenable: client.authState,
        builder: (ctx, state, _) {
          if (state.isLoading) {
            return const Center(child: CircularProgressIndicator());
          }
          if (!state.isAuthenticated) {
            return Center(
              child: ElevatedButton.icon(
                icon: const Icon(Icons.login),
                label: const Text('Sign in with Taler ID'),
                onPressed: () => client.login(),
              ),
            );
          }
          return _AuthenticatedView(client: client);
        },
      ),
    );
  }
}

class _AuthenticatedView extends StatelessWidget {
  final TalerIdClient client;
  const _AuthenticatedView({required this.client});

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<UserInfo>(
      future: client.getUser(),
      builder: (ctx, snap) {
        if (!snap.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final user = snap.data!;
        return Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text('Hello, ${user.name ?? user.sub}', style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 8),
              if (user.email != null) Text(user.email!),
              const SizedBox(height: 24),
              SelectableText('sub: ${user.sub}'),
              const Spacer(),
              OutlinedButton(
                onPressed: () => client.logout(),
                child: const Text('Logout'),
              ),
            ],
          ),
        );
      },
    );
  }
}
```

- [ ] **Step 4: Add the iOS URL scheme to `example/ios/Runner/Info.plist`**

Open `example/ios/Runner/Info.plist`. Inside the top-level `<dict>`, before the closing `</dict>`, insert:

```xml
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLName</key>
			<string>com.talerid.example.oauth</string>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>com.talerid.example</string>
			</array>
		</dict>
	</array>
```

(Tab indentation, matching the existing file style.)

- [ ] **Step 5: Add the Android intent-filter to `example/android/app/src/main/AndroidManifest.xml`**

Open `example/android/app/src/main/AndroidManifest.xml`. Inside the existing `<activity android:name=".MainActivity" ...>` element (after the existing intent-filter for `MAIN`/`LAUNCHER`), insert this additional intent-filter:

```xml
            <intent-filter android:autoVerify="false">
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="com.talerid.example" />
            </intent-filter>
```

- [ ] **Step 6: Replace `README.md`**

```markdown
# talerid_oauth

Flutter SDK for **Sign in with Taler ID**. iOS + Android via `flutter_appauth`. Authorization Code + PKCE in ~5 lines.

## Install

```bash
flutter pub add talerid_oauth
```

## Quickstart

```dart
import 'package:talerid_oauth/talerid_oauth.dart';

final client = await TalerIdClient.create(
  clientId: 'your-client-id',
  redirectUri: 'com.yourapp://oauth/callback',
);

await client.login();          // opens in-app browser, returns when authenticated
final user = await client.getUser();
final token = await client.getAccessToken();
await client.logout();
```

Use `client.authState` (`ValueListenable<AuthState>`) inside `ValueListenableBuilder` to react to login/logout.

## Platform setup

### iOS — `ios/Runner/Info.plist`

Add a URL type matching your `redirectUri` scheme:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array><string>com.yourapp</string></array>
  </dict>
</array>
```

### Android — `android/app/src/main/AndroidManifest.xml`

Add an intent-filter to the main activity:

```xml
<intent-filter android:autoVerify="false">
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="com.yourapp" />
</intent-filter>
```

## Configuration

| Option        | Default                              | Description                                            |
| ------------- | ------------------------------------ | ------------------------------------------------------ |
| `clientId`    | (required)                           | OAuth client_id from your Taler ID registration        |
| `redirectUri` | (required)                           | Custom URL scheme registered in your iOS/Android app   |
| `scope`       | `'openid profile email'`             | Space-separated scopes                                 |
| `storage`     | `SecureStorage()`                    | Pluggable; `MemoryStorage` for tests, custom for Hive  |
| `issuer`      | `'https://id.taler.tirol/oauth'`     | Override for staging                                   |
| `onLog`       | `(_, __, [___]) => {}`               | Diagnostic callback `(level, message, [meta])`         |

## API

| Member                                  | Description                                              |
| --------------------------------------- | -------------------------------------------------------- |
| `await TalerIdClient.create(...)`       | Async factory; hydrates state from storage               |
| `await client.login()`                  | Opens browser, waits, stores tokens                      |
| `await client.logout({endSession?})`    | Clears storage; with `endSession:true` opens RP logout    |
| `await client.getUser()`                | Fetch and cache `/oauth/me` userinfo                     |
| `await client.getAccessToken()`         | Returns access_token, auto-refreshes if near expiry      |
| `client.isAuthenticated`                | Sync, no I/O                                             |
| `client.authState`                      | `ValueListenable<AuthState>` for reactive UI             |

## Errors

```dart
import 'package:talerid_oauth/talerid_oauth.dart';

try {
  await client.login();
} on TalerIdAuthError catch (err) {
  if (err.code == TalerIdErrorCode.userCancelled) { /* user dismissed browser */ }
}
```

Codes: `loginRequired` · `consentRequired` · `network` · `config` · `userCancelled` · `invalidGrant`.

## See also

- Live integration guide: <https://id.taler.tirol/oauth-guide.html>
- Brand assets and buttons: <https://id.taler.tirol/brand>
- JavaScript SDK: [`@taler-id/oauth-client`](https://www.npmjs.com/package/@taler-id/oauth-client) (browser SPAs)
- Source: <https://github.com/dvvolkovv/taler_id_sdk_flutter>

## License

MIT
```

- [ ] **Step 7: Write `CHANGELOG.md`**

```markdown
## 0.1.0

- Initial release
- iOS + Android support via `flutter_appauth`
- `TalerIdClient.create()` async factory + `login`/`logout`/`getUser`/`getAccessToken`/`isAuthenticated`/`authState`
- Pluggable storage (`SecureStorage` default, `MemoryStorage` for tests)
- On-demand token refresh with concurrent-call guard
- `TalerIdAuthError` with `TalerIdErrorCode` enum
```

- [ ] **Step 8: Verify the example builds**

```bash
cd ~/taler_id_sdk_flutter/example
flutter pub get
flutter build apk --debug 2>&1 | tail -5  # Android first — no Xcode needed
```

Expected: APK builds. iOS build is optional in CI but a sanity-check locally if Xcode is installed:

```bash
cd ~/taler_id_sdk_flutter/example
flutter build ios --debug --no-codesign 2>&1 | tail -5
```

If iOS build fails because of a CocoaPods issue (`pod install` is invoked automatically), run:

```bash
cd ~/taler_id_sdk_flutter/example/ios
pod install --repo-update
cd ..
flutter build ios --debug --no-codesign
```

If both fail, report DONE_WITH_CONCERNS — the example apk smoke is informational; the package itself is what matters for pub.dev.

- [ ] **Step 9: Commit**

```bash
cd ~/taler_id_sdk_flutter
git add README.md CHANGELOG.md example/
git commit -m "docs(example): minimal Flutter app + README + CHANGELOG"
```

---

## Task 12: GitHub Actions CI

**Files:**
- Create: `~/taler_id_sdk_flutter/.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          channel: stable
          flutter-version: 3.24.x
      - run: flutter pub get
      - run: dart format --set-exit-if-changed .
      - run: flutter analyze
      - run: flutter test --coverage
      - run: flutter pub publish --dry-run
```

- [ ] **Step 2: Commit and push**

```bash
cd ~/taler_id_sdk_flutter
git add .github/workflows/ci.yml
git commit -m "ci: flutter analyze + test + publish dry-run"
git push origin main
```

- [ ] **Step 3: Verify CI runs and is green**

```bash
gh run list --branch main --limit 1
gh run watch
```

Expected: workflow completes with green checks. If `dart format --set-exit-if-changed .` fails, fix formatting locally with `dart format .`, push, watch again.

If `flutter pub publish --dry-run` fails, the failure tells you exactly what's wrong (pubspec issue, missing CHANGELOG, etc.). Fix + push + retry.

---

## Task 13: Side-PR — remove dead OAuth-callback skeleton in `taler_id_mobile`

**Files (in a DIFFERENT repository):**
- Modify: `~/Downloads/taler_id_mobile/lib/core/router/deep_link_handler.dart` (remove lines 60-69 of the current file)

**Repository:** `~/Downloads/taler_id_mobile` (a different repo from `~/taler_id_sdk_flutter`). This task is a small drive-by cleanup, not part of the SDK package itself.

- [ ] **Step 1: Confirm the working copy is clean**

```bash
cd ~/Downloads/taler_id_mobile
git status --short
git branch --show-current
```

Expected: working copy is clean OR has only unrelated changes; current branch is `dev` per the project's branching rule. If the branch is `main`, switch to `dev`:

```bash
git checkout dev
git pull
```

- [ ] **Step 2: Remove the dead code**

Open `lib/core/router/deep_link_handler.dart`. Delete the entire OAuth-callback branch — the spec block currently at approx. lines 60-69:

```dart
    // Handle OAuth callback:
    // talerid://oauth/callback?code=X
    if (uri.path.contains('oauth/callback')) {
      final code = uri.queryParameters['code'];
      if (code != null) {
        debugPrint('OAuth callback code: $code');
        // Handle OAuth code exchange
      }
      return;
    }
```

After deletion, the function ends with the `talerid://user/{userId}` handler (currently lines 52-58).

- [ ] **Step 3: Verify the file still parses + tests still pass**

```bash
cd ~/Downloads/taler_id_mobile
flutter analyze lib/core/router/deep_link_handler.dart
flutter test test/ 2>&1 | tail -5
```

Expected: 0 issues. Tests still green.

- [ ] **Step 4: Commit and push**

```bash
git add lib/core/router/deep_link_handler.dart
git commit -m "chore(deep-links): remove unused OAuth callback skeleton

This block was a leftover stub from an early prototype with no consumer
in the codebase. Phase 3 of the OAuth UI Kit decomposition concluded the
mobile app is the identity provider, not an OAuth integrator, so this
skeleton has no use case. URL scheme registration in Info.plist /
AndroidManifest.xml is preserved — it serves talerid://invite and
talerid://user/{id} deep links."
git push origin dev
```

The mobile app will pick this up on its next deploy via the project's standard pull/build workflow.

---

## Task 14: First release — v0.1.0 to pub.dev

**Files:** none (publish only).

This task requires Dmitry's interactive `dart pub login` (one-time) and `dart pub publish` (per-release). The implementer subagent triggers the publish; Dmitry confirms in browser when prompted.

- [ ] **Step 1: Verify pub.dev login is active**

```bash
cd ~/taler_id_sdk_flutter
dart pub token list 2>&1 | head -5
```

If output shows credentials for `https://pub.dev`: proceed.
If output is empty / says not logged in: STOP and ask Dmitry to run `dart pub login` (opens browser). Re-run this check after.

- [ ] **Step 2: Final dry-run**

```bash
cd ~/taler_id_sdk_flutter
flutter pub publish --dry-run 2>&1 | tail -10
```

Expected: `Package has 0 warnings.` (or similar). If warnings, fix them — common culprits: missing `description`, missing `homepage`, `LICENSE` not present, `.gitignore` rules accidentally excluding `lib/`.

- [ ] **Step 3: Tag the release**

```bash
cd ~/taler_id_sdk_flutter
git tag -a v0.1.0 -m "Initial release of talerid_oauth"
git push origin v0.1.0
```

- [ ] **Step 4: Publish**

```bash
cd ~/taler_id_sdk_flutter
flutter pub publish
```

The CLI prints a summary, asks "Do you want to publish talerid_oauth 0.1.0 (y/N)?" — Dmitry types `y` interactively. The CLI then prints `Publishing successful!` and a link to the package page.

If the implementer is operating in a context that can't accept interactive input, they STOP here and report BLOCKED with the dry-run output. Dmitry runs the publish command from his terminal.

- [ ] **Step 5: Verify it's live**

```bash
sleep 30  # let pub.dev index propagate
curl -fI https://pub.dev/api/packages/talerid_oauth 2>&1 | head -3
curl -s https://pub.dev/api/packages/talerid_oauth | head -50
```

Expected: HTTP 200; JSON with `version: 0.1.0`.

- [ ] **Step 6: Smoke test by adding into a scratch project**

```bash
rm -rf /tmp/talerid-flutter-smoke
flutter create /tmp/talerid-flutter-smoke --platforms=ios,android
cd /tmp/talerid-flutter-smoke
flutter pub add talerid_oauth
grep talerid_oauth pubspec.yaml
flutter pub get
flutter analyze 2>&1 | tail -3
```

Expected: `talerid_oauth: ^0.1.0` line in pubspec; `flutter pub get` resolves successfully; `flutter analyze` reports 0 issues.

- [ ] **Step 7: Create a GitHub release**

```bash
cd ~/taler_id_sdk_flutter
gh release create v0.1.0 --title "v0.1.0 — initial release" --notes-file - <<'EOF'
First public release of `talerid_oauth`.

- iOS + Android Flutter SDK for Sign in with Taler ID
- Authorization Code + PKCE via `flutter_appauth`
- `TalerIdClient.create()` async factory + 6 public members
- Pluggable storage (`SecureStorage` default, `MemoryStorage` for tests)
- On-demand token refresh with concurrent-call guard
- Single `TalerIdAuthError` with `TalerIdErrorCode` enum

See [README](https://github.com/dvvolkovv/taler_id_sdk_flutter#readme), [pub.dev page](https://pub.dev/packages/talerid_oauth), and the [integration guide](https://id.taler.tirol/oauth-guide.html).
EOF
```

Expected: GitHub release page is visible at `https://github.com/dvvolkovv/taler_id_sdk_flutter/releases/tag/v0.1.0`.

---

## Out of Scope — Do Not Do

- **Native iOS Swift Package** or **Android Kotlin standalone library** — defer to a Phase 3.5 follow-up.
- **macOS / Linux / Windows / Flutter Web** support — only iOS + Android.
- **Login button widget** with Phase 0 styles — buttons live as HTML/CSS at `id.taler.tirol/brand`; this SDK is logic only.
- **Riverpod / Provider / BLoC helper packages** — `ValueListenable<AuthState>` works with all of them.
- **Background token refresh timers** — refresh is on-demand only.
- **Automating `dart pub publish` from CI via OIDC** — possible but deferred until v0.2; first release is interactive.
- **Touching `~/taler-id` (backend) beyond reading docs** — backend is a different repo. Phase 3 work happens entirely in `~/taler_id_sdk_flutter/`. Task 13 (mobile-app cleanup) is a small drive-by in `~/Downloads/taler_id_mobile/`, also a different repo.
