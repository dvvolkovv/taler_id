# OAuth Native Mobile Login — Design

**Date:** 2026-04-30
**Status:** Spec, awaiting plan
**Goal:** Перехват `https://id.taler.tirol/oauth/authorize?...` Taler ID мобильным приложением через Universal Links / App Links, с нативным consent UI, выдачей authorization code из app, и graceful fallback на браузерный flow если app не установлен.

## Context

Сейчас весь OAuth login flow рендерится backend'ом как HTML страницы oidc-provider library. Когда юзер на iPhone в Safari тапает «Sign in with Taler ID» в стороннем сайте/приложении, открывается `id.taler.tirol/oauth/authorize` в браузере, юзер вводит email/password, видит consent, происходит redirect на `redirect_uri?code=...`.

Это работает, но даёт фрикции (ввод пароля), не использует уже-аутентифицированный state Taler ID app, и не даёт нативного UX уровня «Sign in with Apple».

Decomposition парент: `taler_id_mobile/docs/superpowers/specs/2026-04-28-oauth-ui-kit-decomposition.md` (Phase 5 / Native Login).

## Driving Use Cases

**A. Web на iPhone:** Юзер на сайте example.com (открыт в Safari) тапает «Sign in with Taler ID». Сейчас — открывается HTML-форма. С новой фичей — открывается Taler ID app, юзер видит consent, app возвращает code обратно в Safari вкладку example.com.

**B. Native integrator app:** Будущий native iOS integrator app (например awakening-bot mobile) открывает OAuth через `ASWebAuthenticationSession` или Universal Link. С новой фичей — открывается Taler ID app, app возвращает code в integrator app через custom scheme или Universal Link integrator-а.

Оба сценария единый дизайн.

## Decisions

- **App-not-installed fallback: graceful** — тот же URL `/oauth/authorize` обрабатывается двумя способами в зависимости от наличия Taler ID app. Если app установлен → перехват, нативный UX. Если нет → URL открывается в браузере, oidc-provider рендерит HTML-форму как сейчас. Никаких install promptов или ошибок.
- **Consent: один раз на клиента** (industry standard, oidc-provider default). Первый login — показываем consent screen. Backend сохраняет `Grant` в БД. Последующие — auto-approve без UI. Соответствует поведению Sign in with Apple/Google.
- **Биометрия:** не дополнительная — существующий PIN/Face ID gate Taler ID app срабатывает при cold open и так. Не добавляем второй confirmation gesture для OAuth.
- **PKCE-only:** мобильный flow выдаёт code только public клиентам с `token_endpoint_auth_method: 'none'` + S256. Confidential клиенты (с client_secret) идут через браузерный flow.
- **Multi-account:** не поддерживаем (app один аккаунт за раз; multi-account — отдельная фича).

## Architecture

```
┌──────────────┐  https://id.taler.tirol/oauth/authorize?...    ┌─────────────────┐
│   Safari /   │ ────────────────────────────────────────────►  │ iOS / Android   │
│  Native App  │  Universal Link / App Link path match           │ link routing    │
└──────────────┘                                                 └────────┬────────┘
                                                                          │
                                                              ┌───────────┴───────────┐
                                                  app installed                 app NOT installed
                                                              │                       │
                                                              ▼                       ▼
                                                   ┌────────────────────┐    ┌──────────────────┐
                                                   │ Taler ID app       │    │ Browser loads    │
                                                   │ /oauth/authorize   │    │ id.taler.tirol/  │
                                                   │ screen             │    │ oauth/authorize  │
                                                   └─────────┬──────────┘    │ (HTML, current)  │
                                                             │               └──────────────────┘
                                                  GET /oauth/mobile/grant-info
                                                             │
                                                             ▼
                                                  ┌────────────────────┐
                                                  │ Consent UI (skip   │
                                                  │ if remembered)     │
                                                  └─────────┬──────────┘
                                                  POST /oauth/mobile/approve
                                                             │
                                                             ▼
                                                  launchUrl(redirect_uri?code=...)
                                                             │
                                                  ┌──────────┴───────────┐
                                                  ▼                      ▼
                                          Safari example.com    Native integrator app
                                          (web initiator)       (custom scheme / UL)
```

**Принципы:**
- Тот же `/oauth/authorize` URL — два способа обработки. Браузерный flow не модифицируется (это и есть наш fallback).
- Backend получает 2 новых endpoint исключительно для нативного flow (в обход HTML interactions).
- Mobile app получает один новый screen + route + два data source method.
- Universal Links / App Links инфраструктура частично уже есть; дособираем недостающее.

## Data Flow

### Сценарий A — web initiator на iPhone

1. Safari открывает `example.com/login`. Юзер тапает «Sign in with Taler ID».
2. Safari navigates → `https://id.taler.tirol/oauth/authorize?client_id=mybook&redirect_uri=https://example.com/cb&scope=profile+email&state=xyz&response_type=code&code_challenge=ABC&code_challenge_method=S256&nonce=N1`.
3. iOS видит `applinks:id.taler.tirol` в entitlement Taler ID app + path `/oauth/authorize` в AASA → открывает app, передаёт URL. Safari **не загружает** страницу.
4. Mobile app: `DeepLinkHandler` получает URI, видит path `/oauth/authorize` → `router.push('/oauth/authorize?...')`.
5. `_globalRedirect` проверяет: юзер залогинен? Если нет — сохраняет params в `OAuthPendingRequest` (in-memory + `flutter_secure_storage` ключ `oauth_pending_v1`, TTL 5 минут), редиректит на `/login`. После `LoginSuccess` listener в `auth_bloc` достаёт pending, push на `/oauth/authorize`.
6. `OAuthAuthorizeScreen` парсит params, вызывает `LoadGrantInfo` event.
7. Bloc → `GET /oauth/mobile/grant-info?{params}` (Bearer JWT). Backend валидирует, возвращает:
   ```json
   {
     "client_name": "MyBook.com",
     "client_logo": "https://...",
     "scopes": [
       { "key": "profile", "label": "Профиль", "description": "Имя, фамилия, аватар" },
       { "key": "email", "label": "Email", "description": "Email адрес" }
     ],
     "remembered": false
   }
   ```
8. Если `remembered: true` → bloc сразу диспатчит `ApprovePressed` без UI. Иначе показывает consent screen.
9. Юзер тапает «Разрешить» → `POST /oauth/mobile/approve` body = `{client_id, redirect_uri, scope, state, response_type, code_challenge, code_challenge_method, nonce}`. Backend:
   - Создаёт/находит `Session` для juzera.
   - Создаёт/дополняет `Grant` (юзер + клиент + scopes).
   - Создаёт `AuthorizationCode` через `provider.AuthorizationCode.save()`.
   - Возвращает `{ "redirect_uri": "https://example.com/cb?code=abc123&state=xyz" }`.
10. App вызывает `launchUrl(redirectUri, mode: LaunchMode.externalApplication)`.
11. iOS открывает Safari (вкладка с example.com уже жива) → SPA капчит callback → exchange code на token → done.

### Сценарий B — native integrator app

Идентично сценарию A. Отличие только на шаге 11: `redirect_uri` имеет custom scheme (`mybook://callback?code=...`) или Universal Link integrator-а. ОС роутит в integrator app. Backend и Taler ID app не различают сценарии — единая логика.

### Cancel

Юзер тап «Отмена» на consent → bloc формирует локально `redirect_uri + "?error=access_denied&state=xyz"` → `launchUrl(...)`. Backend не вовлечён (валидно по OAuth 2.1 spec).

## Components

### Backend — `src/oauth-mobile/`

**Файлы (новые):**
- `oauth-mobile.module.ts` — `imports: [OidcModule, AuthModule]`, `controllers: [OAuthMobileController]`, `providers: [OAuthMobileService]`
- `oauth-mobile.controller.ts` — два endpoint, оба под `@UseGuards(JwtAuthGuard)`:
  - `@Get('mobile/grant-info')` — query из `OAuthAuthorizeQueryDto`
  - `@Post('mobile/approve')` — body из `OAuthApproveDto`, `@Throttle({ short: { limit: 10, ttl: 60_000 } })`
- `oauth-mobile.service.ts` — основная логика:
  - `getGrantInfo(userId, params): GrantInfoDto`
  - `approve(userId, params): { redirect_uri: string }`
- `dto/oauth-authorize-query.dto.ts`, `dto/oauth-approve.dto.ts` — class-validator
- `oauth-mobile.service.spec.ts` — unit тесты

**Регистрация:**
- `app.module.ts` — добавить `OAuthMobileModule` в `imports`

**Endpoint contract:**

`GET /oauth/mobile/grant-info?client_id=...&redirect_uri=...&scope=...&response_type=code` (Bearer JWT)
- 200: `{client_name, client_logo, scopes: [{key, label, description}], remembered}`
- 400: invalid params (mirror oidc-provider validation)
- 401: missing/invalid JWT
- 404: client not found

`POST /oauth/mobile/approve` (Bearer JWT, body = OAuth params)
- 200: `{redirect_uri: <full URL with code+state>}`
- 400: invalid params, confidential client (PKCE-only enforcement), redirect_uri mismatch, scope не в `allowedScopes`
- 401: missing/invalid JWT
- 429: throttle exceeded

**Логика `getGrantInfo`:**
```
1. const client = await provider.Client.find(client_id) → 404 если нет
2. validate redirect_uri ∈ client.redirectUris → 400
3. validate scopes ⊆ client.allowedScopes → 400
4. if client.token_endpoint_auth_method !== 'none' → 400 'confidential_client_not_supported_via_mobile'
5. const grant = await prisma.findGrant(userId, client_id) (или provider.Grant.find если будет нужно)
6. const remembered = grant && requestedScopes ⊆ grant.scopes
7. return { client_name, client_logo, scopes: scopeDescriptors, remembered }
```

**Логика `approve`:**
```
1. Re-validate (тот же набор что getGrantInfo)
2. Создать/найти Session для userId через provider.Session.find(...)
3. Создать/дополнить Grant: provider.Grant.find или new provider.Grant({accountId, clientId})
   grant.addOIDCScope(scope); await grant.save();
4. Создать AuthorizationCode:
   const code = new provider.AuthorizationCode({
     accountId: userId,
     clientId,
     redirectUri,
     scope,
     grantId: grant.jti,
     codeChallenge,
     codeChallengeMethod,
     nonce,
     state,
     resource: undefined,
   });
   const value = await code.save();
5. return { redirect_uri: `${redirectUri}?code=${value}&state=${state}` }
```

**Validation rules:**
- `code_challenge_method`: только `S256` (отвергаем `plain`)
- `response_type`: только `code` (отвергаем `token`, `id_token`)
- `redirect_uri`: exact match (не prefix) с `client.redirectUris`
- `scope`: пробельно-разделённый список, каждый в `client.allowedScopes`

### Mobile app — `lib/features/oauth/`

**Файлы (новые):**
- `domain/entities/oauth_authorize_params.dart` — Freezed модель с полями `clientId`, `redirectUri`, `scope`, `state`, `responseType`, `codeChallenge`, `codeChallengeMethod`, `nonce`
- `domain/entities/grant_info.dart` — `clientName`, `clientLogo`, `scopes: List<ScopeDescriptor>`, `remembered`
- `domain/entities/scope_descriptor.dart` — `key`, `label`, `description`
- `domain/repositories/oauth_repository.dart` — abstract: `getGrantInfo`, `approve`, `cancel`
- `data/datasources/oauth_remote_datasource.dart` — Dio calls
- `data/repositories/oauth_repository_impl.dart`
- `presentation/bloc/oauth_authorize_bloc.dart` (+ events, states)
- `presentation/screens/oauth_authorize_screen.dart` — UI consent
- Тесты: `test/features/oauth/oauth_authorize_bloc_test.dart`, widget test

**Состояния bloc:**
- `Initial`
- `Loading` (загрузка grant-info)
- `ConsentRequired(GrantInfo)` (показать UI)
- `AutoApproving` (remembered=true, без UI, сразу POST)
- `Approving` (POST в полёте)
- `Success(redirectUri)` (закрытие через launchUrl)
- `Cancelled(redirectUri)` (то же самое, redirect_uri с ошибкой)
- `Failure(message)` (ошибка с retry / fallback кнопкой)

**Изменения существующих файлов:**
- `lib/core/router/deep_link_handler.dart` — добавить ветку для `/oauth/authorize` path (не `talerid://`, а HTTPS path):
  ```dart
  if (uri.host == 'id.taler.tirol' || uri.host == 'staging.id.taler.tirol') {
    if (uri.path == '/oauth/authorize') {
      router.push('/oauth/authorize${uri.hasQuery ? '?${uri.query}' : ''}');
      return;
    }
  }
  ```
- `lib/core/router/app_router.dart` — новый GoRoute `/oauth/authorize` (вне ShellRoute, чтобы открывался поверх bottom nav)
- `lib/core/router/app_router.dart:_globalRedirect` — если route = `/oauth/authorize` и юзер не залогинен, сохранить params в `OAuthPendingRequest` (singleton провайдер), редирект на `/login`
- `lib/features/auth/presentation/bloc/auth_bloc.dart` — после `LoginSuccess` проверить `OAuthPendingRequest.consume()`, push на `/oauth/authorize` если есть
- `lib/core/di/dependencies.dart` — register `OAuthRepository`, `OAuthRemoteDatasource`, `OAuthAuthorizeBloc`, `OAuthPendingRequest`

**Pending state (cold-start safety):**
- `OAuthPendingRequest` — синглтон с in-memory current + `flutter_secure_storage`-backed snapshot
- TTL 5 минут (timestamp при сохранении). Истёкшие записи игнорируются и удаляются.
- Цель: если cold-start через Universal Link до auth gate → params не теряются

### Native config

**iOS — новый файл `~/taler-id/public/.well-known/apple-app-site-association`:**
```json
{
  "applinks": {
    "details": [{
      "appIDs": ["MG58MDUNZ2.tirol.taler.talerIdMobile", "MG58MDUNZ2.tirol.taler.talerIdMobile.dev"],
      "components": [
        { "/": "/oauth/authorize", "?": { "*": "*" } },
        { "/": "/room/*" },
        { "/": "/ui/invite*" }
      ]
    }]
  }
}
```

Файл без расширения, MIME `application/json`. Размещение `/var/www/html/.well-known/` на DEV/PROD nginx host.

**nginx config (для обоих серверов):**
```
location = /.well-known/apple-app-site-association {
  default_type application/json;
  add_header Content-Type application/json;
  try_files $uri =404;
}
```

(Не редиректить, не требовать auth, отдавать с правильным MIME.)

**Android — `~/Downloads/taler_id_mobile/android/app/src/main/AndroidManifest.xml`:**
Добавить два intent-filter (для `id.taler.tirol` и `staging.id.taler.tirol`):
```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="id.taler.tirol" android:pathPrefix="/oauth/authorize"/>
</intent-filter>
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="https" android:host="staging.id.taler.tirol" android:pathPrefix="/oauth/authorize"/>
</intent-filter>
```

`assetlinks.json` уже существует с обоими package_name (`tirol.taler.taler_id_mobile` и `tirol.taler.taler_id_mobile.dev`) и нужными SHA fingerprintами — модифицировать не нужно.

## Error Handling

**Backend errors:**
| Сценарий | HTTP | Body |
|---------|------|------|
| Invalid `client_id` | 404 | `{ error: 'unknown_client' }` |
| `redirect_uri` mismatch | 400 | `{ error: 'redirect_uri_mismatch' }` |
| Unknown scope | 400 | `{ error: 'invalid_scope' }` |
| `code_challenge_method ≠ S256` | 400 | `{ error: 'invalid_code_challenge_method' }` |
| Confidential client | 400 | `{ error: 'confidential_client_not_supported_via_mobile' }` |
| Throttle exceeded | 429 | (default NestJS throttle response) |
| JWT missing/invalid | 401 | (default JwtAuthGuard) |

**App errors:**
| Сценарий | UI |
|---------|------|
| `getGrantInfo` HTTP error | Screen с «Не удалось загрузить» + кнопки [Повторить] [Открыть в браузере] |
| `approve` 4xx | Toast с error + остаёмся на consent (юзер ретрайнет или cancel'ит) |
| `approve` 5xx | Toast «Серверная ошибка» + кнопка [Открыть в браузере] (manual fallback) |
| User cancel | `launchUrl(redirect_uri + ?error=access_denied&state=...)`, back-stack pop |
| Cold-start без auth | `_globalRedirect` сохраняет params, редирект на `/login`. После login — resume |
| App уже на critical screen (звонок, KYC) | Push поверх через go_router. Юзер может cancel и вернуться |

**Manual browser fallback button** — на error states. Делает `launchUrl('https://id.taler.tirol/oauth/authorize?...', LaunchMode.externalApplication)`. ОС открывает Safari (Universal Link не сработает в external, потому что инициатор — то же app), oidc-provider рендерит HTML-форму. Безотказный fallback.

## Testing

### Backend

`oauth-mobile.service.spec.ts`:
- ✓ `getGrantInfo` валидный клиент → name+logo+scopes
- ✓ `getGrantInfo` invalid client_id → throws NotFoundException
- ✓ `getGrantInfo` redirect_uri mismatch → throws BadRequestException
- ✓ `getGrantInfo` `remembered: true` если Grant покрывает scope
- ✓ `getGrantInfo` `remembered: false` если scope шире
- ✓ `approve` создаёт code, redirect_uri корректен
- ✓ `approve` отвергает confidential client
- ✓ `approve` отвергает invalid redirect_uri
- ✓ `approve` идемпотентен на repeat call (создаёт новый code, не конфликтует)

`oauth-mobile.controller.e2e.spec.ts`:
- ✓ Full integration: `POST /approve` → returned code обменивается на токен через `/oauth/token` с PKCE verifier

### Mobile

`oauth_authorize_bloc_test.dart`:
- ✓ `LoadGrantInfo` → `Loading` → `ConsentRequired` (remembered:false)
- ✓ `LoadGrantInfo` → `Loading` → `AutoApproving` → `Success` (remembered:true)
- ✓ `ApprovePressed` → POST → `Success(redirectUri)`
- ✓ `CancelPressed` → `Cancelled(redirectUri с error=access_denied)`
- ✓ Error на `getGrantInfo` → `Failure`
- ✓ Error на `approve` → остаёмся в `ConsentRequired` + toast event

`oauth_authorize_screen_test.dart` (widget):
- ✓ `ConsentRequired` рендерит client_name, logo, scope list, кнопки
- ✓ Tap на «Разрешить» диспатчит `ApprovePressed`
- ✓ Tap на «Отмена» диспатчит `CancelPressed`
- ✓ `Loading` рендерит spinner
- ✓ `Failure` рендерит retry + browser fallback кнопки

`oauth_pending_request_test.dart`:
- ✓ `save` записывает params + timestamp
- ✓ `consume` возвращает params и удаляет
- ✓ `consume` возвращает null если истёк TTL (>5 мин)
- ✓ `consume` возвращает null если ничего не сохранено

### E2E (manual smoke checklist)

- [ ] **iPhone, app installed, logged in:** `staging.id.taler.tirol/developers/` → tap login → app открывается → consent screen → approve → возврат в Safari → Developer Portal SPA logged in
- [ ] **iPhone, app installed, logged out:** то же, но app требует PIN/login сначала → resume на consent → success
- [ ] **iPhone, app NOT installed:** `oauth/authorize` → HTML-форма → login → redirect (browser fallback)
- [ ] **iPhone, second login (remembered):** consent screen НЕ появляется, app мгновенно делает callback
- [ ] **Android (oba flavor):** все четыре сценария выше
- [ ] **iPhone, cancel:** tap «Отмена» → возврат в Safari с `?error=access_denied`, SPA показывает ошибку
- [ ] **iPhone, in-call:** во время звонка на /oauth/authorize → consent открывается поверх, можно cancel и вернуться к звонку
- [ ] **iPhone cold-start:** убить app, тапнуть Universal Link в Safari, app cold-start'ит → попадает на consent (через pending storage)

### Не покрываем тестами

- Multi-tab Safari race conditions (manual smoke достаточен)
- AASA cache на первой установке iOS (известный edge — задокументируем в release notes, не в тестах)
- Параллельные approve calls от того же юзера (throttle 10/min достаточен)

## Out of Scope

- Multi-account switcher на consent screen (нужен только когда у app будет multi-session support)
- Persistence consent на app-side (всё хранится в БД через `Grant` модель)
- Custom scheme `talerid://oauth/authorize` как entry-point (Universal Links покрывают use case; custom scheme — только для return)
- Изменения в существующем браузерном flow (это и есть наш fallback, не трогаем)
- Изменения в OAuth registration / Developer Portal (отдельная фича)

## Deployment

1. Backend: новые endpoint выкатываем сначала на DEV, проверяем ручной curl. Затем PROD.
2. AASA файл: deploy на DEV (`/var/www/html/.well-known/apple-app-site-association`), nginx reload, проверка `curl -I staging.id.taler.tirol/.well-known/apple-app-site-association` на правильный MIME. Затем PROD.
3. Mobile app: ветка `dev`, билд dev APK + dev iOS TestFlight, smoke на staging. Затем merge в `main`, prod APK + prod TestFlight.
4. AASA cache на iOS: после первой установки app **необходимо** зайти в Safari, попробовать Universal Link несколько раз — iOS подтянет AASA асинхронно. Это нормально.
5. App Links на Android: после установки `autoVerify="true"` запускает фоновую проверку `assetlinks.json`. Если успех — app получает default-handler привилегию. Логи: `adb shell pm get-app-links tirol.taler.taler_id_mobile.dev`.

## Open Questions

Нет (закрыты в брейнсторме).

## Files Changed Summary

**Backend (new):**
- `src/oauth-mobile/oauth-mobile.module.ts`
- `src/oauth-mobile/oauth-mobile.controller.ts`
- `src/oauth-mobile/oauth-mobile.service.ts`
- `src/oauth-mobile/dto/oauth-authorize-query.dto.ts`
- `src/oauth-mobile/dto/oauth-approve.dto.ts`
- `src/oauth-mobile/oauth-mobile.service.spec.ts`
- `src/oauth-mobile/oauth-mobile.controller.e2e.spec.ts`

**Backend (modify):**
- `src/app.module.ts` — register `OAuthMobileModule`
- `public/.well-known/apple-app-site-association` (новый файл)
- nginx site config — серверное правило для AASA

**Mobile app (new):**
- `lib/features/oauth/domain/entities/oauth_authorize_params.dart`
- `lib/features/oauth/domain/entities/grant_info.dart`
- `lib/features/oauth/domain/entities/scope_descriptor.dart`
- `lib/features/oauth/domain/repositories/oauth_repository.dart`
- `lib/features/oauth/data/datasources/oauth_remote_datasource.dart`
- `lib/features/oauth/data/repositories/oauth_repository_impl.dart`
- `lib/features/oauth/presentation/bloc/oauth_authorize_bloc.dart`
- `lib/features/oauth/presentation/bloc/oauth_authorize_event.dart`
- `lib/features/oauth/presentation/bloc/oauth_authorize_state.dart`
- `lib/features/oauth/presentation/screens/oauth_authorize_screen.dart`
- `lib/features/oauth/data/oauth_pending_request.dart`
- `test/features/oauth/oauth_authorize_bloc_test.dart`
- `test/features/oauth/oauth_authorize_screen_test.dart`
- `test/features/oauth/oauth_pending_request_test.dart`

**Mobile app (modify):**
- `lib/core/router/deep_link_handler.dart` — branch для `/oauth/authorize`
- `lib/core/router/app_router.dart` — route + `_globalRedirect` логика
- `lib/features/auth/presentation/bloc/auth_bloc.dart` — resume after login
- `lib/core/di/dependencies.dart` — DI registration
- `android/app/src/main/AndroidManifest.xml` — два новых intent-filter

## Approval

Brainstormed and approved by user 2026-04-30 across 4 sections (architecture, data flow, components, error handling + testing).
