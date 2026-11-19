# Вход через Taler ID от имени компании (scope `companies`)

Для сайтов, которым нужен вход «как физлицо или как компания» и предзаполнение карточки компании проверенными реквизитами. Первый потребитель — trientes.org.

## Что получает сайт

Человек входит через Taler ID (OAuth 2.0 Authorization Code + PKCE). Если сайт запросил scope `companies`, Taler ID при каждом входе показывает выбор:

- **«Войти как»** — сам человек или одна из его компаний;
- **«Передать данные компаний»** — какие компании отдать сайту.

В списке только компании, где человек OWNER или ADMIN и KYB пройден.

## Подключение

| | DEV | TEST | PROD |
|--|--|--|--|
| Issuer | `https://staging.id.taler.tirol/oauth` | `https://id.taler.tirol/oauth` | `https://api.talerid.io/oauth` |

Discovery: `<issuer>/.well-known/openid-configuration`. Scope `companies` выдаётся клиенту вручную (напишите команде Taler ID); через динамическую регистрацию его не получить.

Запрос: `scope=openid profile companies`, PKCE (S256) обязателен. Клиент с секретом аутентифицируется на `<issuer>/token` через `client_secret_basic`.

## `/oauth/me`

Данные компаний приходят только из userinfo (`GET <issuer>/me` с access-токеном), не в ID-токене.

```json
{
  "sub": "8d3c…",
  "acting_as": { "type": "company", "company_id": "6f1c…", "name": "Ромашка" },
  "companies": [{
    "company_id": "6f1c…",
    "name": "Ромашка",
    "legal_name": "ООО «Ромашка»",
    "registration_number": "1027700132195",
    "tax_id": "7701234567",
    "legal_form": "LLC",
    "incorporated_on": "2015-03-02",
    "country": "RUS",
    "city": "Москва",
    "legal_address": "Москва, ул. Пробная, 1",
    "website": "https://romashka.example",
    "logo_url": null,
    "logo_verified": false,
    "kyb_status": "verified",
    "kyb_verified_at": "2026-11-20T10:00:00.000Z",
    "role": "OWNER"
  }]
}
```

- `sub` — всегда человек. Компания — не отдельная учётная запись.
- `acting_as.type`: `person` — вошёл физлицом; `company` — от имени компании `company_id`. `acting_as.name` — название компании в Taler ID, не проверено (как `name` в карточке).
- `acting_as.revoked: true` — с момента входа компания перестала быть доступной (сняли роль, отозвали KYB, удалили). Проверяется заново на каждый запрос `/oauth/me`. Считайте, что человек больше не представляет компанию. Если компанию удалили, `acting_as.name` может быть `null`.
- `companies` — переданные компании, которые доступны сейчас. Компания из `acting_as` в списке есть всегда, пока она не `revoked`; недоступная компания из списка пропадает.
- Проверены KYB: `legal_name`, `registration_number`, `tax_id`, `legal_form`, `incorporated_on`, `country`, `city`, `legal_address`, `website`. **Не проверены:** `name` (название в Taler ID, его меняет владелец) и `logo_url` (поэтому `logo_verified` всегда `false`). `logo_url` может быть `null` — на практике сейчас так у всех компаний.
- Поле, которого не было в анкете KYB, — `null`.
- `country` — страна, как её вернула проверка KYB; обычно код ISO 3166-1 alpha-3 (например, `RUS`). `incorporated_on` — дата `ГГГГ-ММ-ДД`, `kyb_verified_at` — ISO 8601.
- `role` — роль человека в компании: `OWNER` или `ADMIN`.
- `company_id` постоянен — по нему связывайте карточку на сайте.

## Тихий вход (`prompt=none`) и продление

Выбор «войти как» Taler ID показывает на **каждом** входе, если сайт просит `companies`, а у человека есть подходящая компания. Поэтому:

- **`prompt=none` со scope `companies`** у такого человека всегда отвечает `error=consent_required` (в описании — `requested scopes not granted`). Это значит «нужен обычный вход с экраном», а не «человек вышел из Taler ID». Библиотеки тихого продления (например, `signinSilent` / `automaticSilentRenew` в oidc-client-ts) часто трактуют такой ответ как «сессии нет» — не разлогинивайте человека по нему.
- **Продлевайте сессию refresh-токеном**, а не тихим входом. Выбор привязан к согласию и переживает обновление токена: `/oauth/me` с новым access-токеном вернёт тот же `acting_as` (или `revoked`, если компания перестала быть доступной). Refresh-токен выдаётся по scope `offline_access` (включается клиенту по согласованию), а клиенту с секретом — только через явный экран согласия: в браузере добавьте в запрос авторизации `prompt=consent` — без него `offline_access` молча отбрасывается; приложение Taler ID при `offline_access` показывает экран всегда.
- **Согласие живёт 30 дней** с входа, на котором оно дано, и refresh-токеном не продлевается. После этого refresh отвечает `invalid_grant` — человек должен войти заново.
- **Тихий вход без `companies`** пройдёт, но новый токен `acting_as` и `companies` не вернёт. От имени кого человек вошёл — храните у себя с момента входа.
- `revoked` может прийти и при перепроверке через refresh-токен — считайте, что человек больше не представляет компанию, и предложите войти заново.
- **Аккаунт удалён или заблокирован:** `/oauth/me` отвечает 401 (`invalid_token`) даже с неистёкшим access-токеном, refresh — `invalid_grant`. Считайте, что у человека больше нет аккаунта Taler ID: завершите его сессию на сайте и снимите представительство компании. От истёкшего согласия `invalid_grant` по ответу не отличить — в обоих случаях только новый вход.

## Вход с телефона, где стоит приложение Taler ID

Ссылку `<issuer>/auth` на телефоне перехватывает приложение Taler ID и показывает своё окно согласия с тем же выбором компаний. Код возвращается на ваш `redirect_uri` так же, но:

- код всегда приходит **в query** (`?code=…&state=…`) — `response_mode=form_post` и `fragment` в этом пути не поддерживаются; используйте режим по умолчанию;
- приложение передаёт только `client_id`, `redirect_uri`, `scope`, `response_type`, `state`, `code_challenge`(+`_method`) и `nonce`: `prompt`, `max_age`, `login_hint` не учитываются — не стройте на них проверку «человек только что ввёл пароль»;
- PAR (`request_uri` вместо параметров) этим путём не работает — передавайте параметры прямо в ссылке;
- PKCE (S256) обязателен, как и в браузере; обмен кода на токены — как обычно, с секретом клиента.

## Пример (Node.js, openid-client v5, Express + express-session)

Пример на API openid-client **v5** (`Issuer`, `generators`, `client.callback`). В v6 API другой.

```ts
import express from 'express';
import session from 'express-session';
import { Issuer, generators } from 'openid-client';

type ActingAs =
  | { type: 'person' }
  | { type: 'company'; company_id: string; name: string | null; revoked?: true };
type CompanyCard = { company_id: string; legal_name: string | null; tax_id: string | null /* … остальные поля выше */ };

declare module 'express-session' {
  interface SessionData { talerid?: { verifier: string; state: string } }
}

const REDIRECT_URI = 'https://trientes.org/auth/talerid/callback';
const issuer = await Issuer.discover('https://api.talerid.io/oauth');
const client = new issuer.Client({
  client_id: process.env.TALERID_CLIENT_ID!,
  client_secret: process.env.TALERID_CLIENT_SECRET!,
  redirect_uris: [REDIRECT_URI],
  response_types: ['code'],
  token_endpoint_auth_method: 'client_secret_basic',
});

const app = express();
app.use(session({ secret: process.env.SESSION_SECRET!, resave: false, saveUninitialized: false }));

app.get('/auth/talerid', (req, res) => {
  const verifier = generators.codeVerifier();
  const state = generators.state();
  req.session.talerid = { verifier, state }; // храните verifier и state в сессии до колбэка
  res.redirect(client.authorizationUrl({
    scope: 'openid profile companies', // для refresh-токена: + offline_access и prompt: 'consent'
    code_challenge: generators.codeChallenge(verifier),
    code_challenge_method: 'S256',
    state,
  }));
});

app.get('/auth/talerid/callback', async (req, res) => {
  const saved = req.session.talerid;
  delete req.session.talerid;
  if (!saved) return res.status(400).send('Вход не начат');

  const tokens = await client.callback(REDIRECT_URI, client.callbackParams(req), {
    code_verifier: saved.verifier,
    state: saved.state,
  });
  const me = await client.userinfo<{ acting_as?: ActingAs; companies?: CompanyCard[] }>(tokens.access_token!);

  const actingAs = me.acting_as;
  if (actingAs?.type === 'company' && !actingAs.revoked) {
    const card = me.companies?.find((c) => c.company_id === actingAs.company_id);
    // предзаполнить карточку компании из card
  }
  // сохранить me.sub и actingAs в своей сессии
  res.redirect('/');
});
```
