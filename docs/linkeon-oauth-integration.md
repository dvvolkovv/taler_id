# Taler ID ↔ Linkeon: разбор ошибок интеграции OAuth

Дата: 2026-08-03. Окружение: PROD (`https://api.talerid.io`).

Ниже — что именно ломается при «Войти через Taler ID», с воспроизведением.
Часть проблем на стороне Linkeon, часть на нашей — разделено явно.

---

## 1. На стороне Linkeon: запрос уходит на несуществующий эндпоинт

**Симптом:** в мобильном приложении — «Не удалось войти через Taler ID (HTTP 404)».

**Причина:** приложение обращается к `/oauth/authorize`. Такого пути у нас нет.
Эндпоинт авторизации — `/oauth/auth`.

```bash
curl -o /dev/null -w '%{http_code}\n' \
  'https://api.talerid.io/oauth/authorize?client_id=linkeon-partner-web&response_type=code'
# 404

curl -o /dev/null -w '%{http_code}\n' \
  'https://api.talerid.io/oauth/auth?client_id=linkeon-partner-web&response_type=code'
# 400 — эндпоинт есть, ругается на неполные параметры
```

То же самое на всех наших окружениях, это не особенность PROD.

Канонический источник правды — discovery-документ, его стоит читать вместо
хардкода путей:

```bash
curl -s https://api.talerid.io/oauth/.well-known/openid-configuration | jq .
```

```json
{
  "authorization_endpoint": "https://api.talerid.io/oauth/auth",
  "token_endpoint":         "https://api.talerid.io/oauth/token",
  "userinfo_endpoint":      "https://api.talerid.io/oauth/me",
  "jwks_uri":               "https://api.talerid.io/oauth/jwks"
}
```

---

## 2. На стороне Linkeon: PKCE обязателен

Это следующая ошибка, в которую вы упрётесь сразу после исправления пути.
Запрос без PKCE не отклоняется на месте — он редиректит на ваш callback с ошибкой:

```
https://my.linkeon.io/webhook/ecosystem/talerid/oauth/callback
  ?error=invalid_request
  &error_description=Authorization+Server+policy+requires+PKCE+to+be+used+for+this+request
  &state=...
```

Требуется `code_challenge` + `code_challenge_method=S256`. Метод `plain` не поддерживается.

---

## 3. Параметры клиента `linkeon-partner-web`

| Параметр | Значение |
|---|---|
| `client_id` | `linkeon-partner-web` |
| `redirect_uri` | `https://my.linkeon.io/webhook/ecosystem/talerid/oauth/callback` |
| Разрешённые scope | `openid`, `profile`, `email` — **только они** |
| `response_type` | `code` |
| PKCE | обязателен, `S256` |
| Аутентификация на `/oauth/token` | `client_secret_basic` или `client_secret_post` (секрет выдан отдельно) |
| Grant types | `authorization_code`, `refresh_token` |

`redirect_uri` сверяется побайтово — любой лишний слэш или другой хост даст ошибку.

Запрос scope за пределами разрешённых (`phone`, `kyc`, `wallet`) будет отклонён,
даже если он есть в `scopes_supported` — этот список общий для всех клиентов,
а не персональный.

---

## 4. Корректный запрос авторизации

```
https://api.talerid.io/oauth/auth
  ?client_id=linkeon-partner-web
  &redirect_uri=https%3A%2F%2Fmy.linkeon.io%2Fwebhook%2Fecosystem%2Ftalerid%2Foauth%2Fcallback
  &response_type=code
  &scope=openid%20profile%20email
  &state=<случайная строка>
  &code_challenge=<base64url(sha256(verifier))>
  &code_challenge_method=S256
```

Обмен кода на токен:

```bash
curl -X POST https://api.talerid.io/oauth/token \
  -u 'linkeon-partner-web:<client_secret>' \
  -d grant_type=authorization_code \
  -d code=<код из callback> \
  -d redirect_uri=https://my.linkeon.io/webhook/ecosystem/talerid/oauth/callback \
  -d code_verifier=<исходный verifier>
```

Код одноразовый и живёт 60 секунд.

---

## 5. На стороне Taler ID: страница согласия не завершает поток

**Это наш баг, чинится у нас — держите в виду, чтобы не искать причину у себя.**

После исправления пути вы дойдёте до нашей страницы согласия и упрётесь в неё:
кнопка «Allow» визуально не делает ничего, редиректа на ваш callback не происходит.

Сам протокол при этом исправен — проверено по шагам, код выдаётся:

```
POST /oauth/interaction/:uid/consent  → 303 /oauth/auth/:uid
GET  /oauth/auth/:uid                 → 303 https://my.linkeon.io/...?code=...&state=...
```

Ломается именно наша страница: она ведёт этот редирект через `fetch`, а последний
переход — на ваш домен, и наш собственный CSP (`connect-src`) его блокирует.
Плюс при любой ошибке страница показывает пустую карточку вместо текста ошибки.

Пока это не исправлено с нашей стороны, поток не завершится, даже если у вас всё
верно. Сообщим, когда выкатим.

---

## Итого

**Ваша часть:**
1. `/oauth/authorize` → `/oauth/auth`.
2. Добавить PKCE (`S256`).
3. Ограничить scope до `openid profile email`.

**Наша часть:**
4. Починить страницу согласия (редирект и отображение ошибок).
