# Вход через Taler ID от имени компании и передача проверенных компаний — Design

**Date:** 2026-11-19
**Status:** Approved (design), pending implementation plan
**Scope:** сторона Taler ID — KYB компании до конца (статус и снимок реквизитов из welID), scope `companies` в OAuth/OIDC, выбор «войти как» и «какие компании передать» на экранах согласия (веб и мобильное приложение), документация для интеграторов. Сайт trientes.org (кнопка входа, предзаполнение карточки компании, вход физлицом или компанией) делается в другой сессии по документации из этого спека.

## Цель

trientes.org ведёт каталог компаний. Человек, который зарегистрировал компанию в Taler ID и прошёл по ней KYB, должен войти на trientes.org через Taler ID и:

- выбрать, **под кем** он входит — как физлицо или как одна из своих компаний;
- выбрать, **данные каких компаний** передать сайту;
- получить на сайте **предзаполненную карточку** компании из проверенных реквизитов.

Передаются только компании, прошедшие KYB.

## Контекст

**OAuth/OIDC в Taler ID сегодня** (`src/oidc/oidc-provider.factory.ts`, oidc-provider 9.6):
- scopes `openid profile email phone kyc wallet offline_access` + MCP-scopes + `messenger` (только партнёрские клиенты);
- все claims берутся из профиля человека в `findAccount`; про компании OIDC не отдаёт ничего;
- согласие: веб — SPA `public/consent.html` через `src/oidc/oidc-interaction.controller.ts` (`POST /oauth/interaction/:uid/consent` принимает `approved_scopes`); мобильное приложение — нативный экран через `src/oauth-mobile/` (`GET /oauth/mobile/grant-info`, `POST /oauth/mobile/approve`);
- согласие запоминается (`Grant`, 30 дней), повторный вход экрана не показывает.

**Компании сегодня:** модель `Tenant` (название, описание, логотип, свободный текст юр. адреса, сайт, контакты, `kybStatus`, `sumsubApplicantId`), участники `TenantMember` с ролями OWNER/ADMIN/OPERATOR/VIEWER. Регистрационного номера, страны, города, ОПФ в базе нет.

**KYB сегодня — ни разу не доходил до конца:**
- `POST /tenant/:id/kyb/start` выдаёт ссылку на WebSDK welID (уровень `prj:taler/kyb-level`, анкета заводится на `externalUserId = tenantId`) и ставит `kybStatus = PENDING`;
- `VERIFIED`/`REJECTED` ставит **только вебхук** (`TenantService.handleKybWebhook`). Вебхуки welID заведены только для TEST; на DEV и PROD работает минутный опросчик, но он смотрит лишь `KycRecord` людей — компания там никогда не станет проверенной;
- реквизиты компании из анкеты welID Taler ID не забирает вообще;
- на 19.11.2026 компаний: DEV 3, TEST 14, PROD 11 — все `UNVERIFIED`, анкет KYB нет ни одной (KYC/KYB обнулены 2026-09-21).

**welID по окружениям:** DEV и PROD — `welid.test.gsmsoft.eu`, TEST — `welid.trientes.com`. Уровень KYB везде `kyb-level`.

## Ключевые решения

| Вопрос | Решение |
|--------|---------|
| Кто что делает | Taler ID — этот спек. trientes.org — другая сессия по `docs/talerid-companies-oauth.md` |
| Откуда данные компании | **Из анкеты KYB в welID.** Передаются только компании со статусом `VERIFIED` |
| Когда забираем данные | **Один раз при одобрении KYB** — снимок в своей таблице. При входе в welID не ходим |
| Кто может войти «как компания» и передать её | **OWNER и ADMIN** компании |
| Как отдаём | **Стандартный OIDC:** новый scope `companies`; `acting_as` в ID-токене и userinfo, `companies` — в userinfo |
| `sub` | Всегда человек. Компания — не отдельная учётная запись |
| Когда показываем выбор | **При каждом входе**, если сайт запросил `companies` и у человека есть хотя бы одна подходящая компания. Нет таких — вход как сейчас |
| Какие компании отмечены | Как в прошлый раз у этого же приложения. Компания из «войти как» отмечена всегда |
| Кому доступен scope | Только клиентам, которым его выдали вручную (`allowedScopes`). Через DCR не получить |

## Архитектура

```
welID (KYB-анкета компании, externalUserId = tenantId)
   │  опросчик раз в минуту (DEV/PROD) / вебхук (TEST)
   ▼
Taler ID
   Tenant.kybStatus = VERIFIED  +  CompanyKybProfile (снимок реквизитов)
   │
   │  OAuth: scope=openid companies …
   ▼
экран согласия (веб consent.html / мобильное приложение)
   «Войти как: Иван Петров ◉ | ООО Ромашка ○»
   «Передать данные: ☑ ООО Ромашка  ☐ ООО Лютик»
   │  act_as, company_ids  → проверка на сервере
   ▼
OAuthCompanySelection (по grantId)
   │
   ▼
ID-токен: acting_as            /oauth/me: acting_as + companies[]
   │
   ▼
trientes.org (другая сессия): вход + предзаполнение карточки
```

### Часть 1. KYB компании до конца

- **Опрос статуса.** Минутный опросчик KYC (`src/kyc/kyc.service.ts`) дополнительно опрашивает компании с `kybStatus = PENDING`: `GET /resources/applicants/-;externalUserId={tenantId}/one`, `reviewResult.reviewAnswer` → `VERIFIED` (GREEN) или `REJECTED`. Вебхук на TEST продолжает работать как есть.
- **Снимок реквизитов.** При переходе в `VERIFIED` (из опросчика или вебхука) Taler ID забирает анкету и сохраняет снимок. Если welID в этот момент недоступен, статус уже `VERIFIED`, а снимка нет — компания не считается подходящей, опросчик повторит запрос на следующем круге.
- **Новая модель `CompanyKybProfile`** (одна запись на компанию, отдельно от редактируемых полей `Tenant`):
  - `tenantId` (unique), `applicantId`, `verifiedAt`;
  - `legalName`, `registrationNumber`, `taxId`, `legalForm`, `incorporatedOn`;
  - `country` (ISO 3166-1 alpha-2), `city`, `legalAddress`, `website`;
  - `raw` (Json) — сырой `info.companyInfo` из welID.
- **Повторный отказ или отзыв KYB:** `kybStatus` меняется, снимок остаётся, но наружу компания не отдаётся.
- **Поля welID не проверены вживую.** Первый шаг реализации — пройти KYB тестовой компанией на DEV и сохранить настоящий ответ welID как фикстуру. Поле, которого в ответе нет, остаётся пустым (город может прийти только строкой адреса — тогда разбираем её, а если не выходит — оставляем пустым).
- Логотипа в KYB нет: в ответе берётся `Tenant.logoUrl` с пометкой «не проверен».

### Часть 2. Scope `companies` и выдача данных

**Подходящая компания** (одно правило на всё — `CompanyEligibility`):
1. человек — OWNER или ADMIN в `TenantMember`;
2. `Tenant.kybStatus = VERIFIED`;
3. есть `CompanyKybProfile`.

Правило проверяется при согласии и при каждой выдаче claims (обмен кода, `/oauth/me`): снятая роль или отозванный KYB убирают компанию из ответа сразу.

**Выбор при входе — модель `OAuthCompanySelection`:**
- `grantId` (PK), `userId`, `clientId`, `actAsTenantId` (null = физлицо), `sharedTenantIds` (массив), `createdAt`;
- новая запись на каждое согласие; привязка к `grantId` разделяет одновременные входы с разных устройств и даёт refresh-токену тот выбор, что был при этом входе;
- последняя запись по (`userId`, `clientId`) — отметки по умолчанию для следующего входа;
- удаляется вместе с согласием при отзыве доступа.

**Каждый вход с экраном.** `loadExistingGrant` возвращает «согласия нет», если запрошен `companies` и у человека есть подходящая компания, — oidc-provider показывает экран согласия. Без подходящих компаний — поведение по умолчанию.

**Claims.** `findAccount(ctx, sub, token)` берёт `token.grantId` → `OAuthCompanySelection`:

`acting_as` — в ID-токене и `/oauth/me`:
```json
{ "type": "person" }
{ "type": "company", "company_id": "6f1c…", "name": "ООО Ромашка" }
{ "type": "company", "company_id": "6f1c…", "name": "ООО Ромашка", "revoked": true }
```
`revoked: true` — только в `/oauth/me`, когда компания с момента входа перестала быть подходящей.

`companies` — только в `/oauth/me` (ID-токен не раздуваем):
```json
[{
  "company_id": "6f1c…",
  "name": "Ромашка",
  "legal_name": "ООО «Ромашка»",
  "registration_number": "1027700132195",
  "tax_id": "7701234567",
  "legal_form": "LLC",
  "incorporated_on": "2015-03-02",
  "country": "RU",
  "city": "Москва",
  "legal_address": "…",
  "website": "https://romashka.example",
  "logo_url": "https://…", "logo_verified": false,
  "kyb_status": "verified",
  "kyb_verified_at": "2026-11-20T10:00:00Z",
  "role": "OWNER"
}]
```
Компания из `acting_as` всегда присутствует в `companies`. Отсутствующее у welID поле — `null`.

`name` (и `acting_as.name`) — название компании в Taler ID (`Tenant.name`), его владелец может менять; проверенное название — `legal_name` из KYB. Как и логотип, `name` сайту следует считать непроверенным.

**Регистрация scope:** `companies` добавляется в `scopes` и `claims` провайдера, в `KNOWN_SCOPES` (описание для экранов согласия), вырезается из DCR-клиентов так же, как `messenger` (`prisma-client-adapter`). Клиенту Trientes выдаётся вручную в `allowedScopes`.

### Часть 3. Экраны согласия

Содержимое одинаковое для веба и приложения:
- **«Войти как»** — радиокнопки: сам человек (имя из профиля) и каждая подходящая компания с отметкой «KYB пройден»;
- **«Передать данные компаний»** — галочки по подходящим компаниям, отмеченные как в последнем выборе; компания из «войти как» отмечена и заблокирована;
- **подсказка** про компании человека с ролью OWNER/ADMIN без KYB: «ООО Лютик не прошла KYB — пройдите проверку в приложении Taler ID».

Блоки показываются только если запрошен `companies` и есть подходящие компании; иначе экран прежний.

- **Веб:** `GET /oauth/interaction/:uid` (JSON для SPA) дополнительно отдаёт `person`, `eligibleCompanies`, `unverifiedCompanies`, `lastSelection`. `POST /oauth/interaction/:uid/consent` принимает `act_as` (`"person"` или `tenantId`) и `company_ids`.
- **Мобильное приложение:** `GET /oauth/mobile/grant-info` и `POST /oauth/mobile/approve` — те же поля. Нативный экран согласия получает оба блока.
- **Сервер не верит клиенту:** каждая компания из `act_as` и `company_ids` проверяется `CompanyEligibility`; хоть одна неподходящая — 400, согласие не создаётся.
- **Старые версии приложения** не присылают выбор → вход физлицом без компаний. Выбор в мобильном приложении появляется со следующим релизом; десктоп — та же кодовая база, получит при пересборке.

### Часть 4. Ошибки, безопасность, аудит

- Подмена выбора — 400 (см. выше).
- Каждая передача компаний пишется в `AuditLog`: `OAUTH_COMPANIES_SHARED`, `meta: { clientId, actAs, companyIds }`.
- Отзыв доступа приложению удаляет и `OAuthCompanySelection`.
- **Известное ограничение:** PROD смотрит в тестовый инстанс welID (`welid.test.gsmsoft.eu`). Пока PROD не переведён на боевой welID, «проверенные» компании на PROD проверены тестовым инстансом. Переезд — вне этого спека.

## Тестирование

- **Юнит (бэкенд):** `CompanyEligibility`; сборка `acting_as`/`companies` (включая `revoked`, отсутствующие поля); проверка выбора на подмену; опрос KYB компаний (PENDING → VERIFIED/REJECTED, повтор снимка); разбор ответа welID — на фикстуре с DEV; `loadExistingGrant` (экран при подходящих компаниях, обычное поведение без них); вырезание `companies` из DCR.
- **E2E — новый набор `test:companies`** в `taler_id_tests`: тестовый OAuth-клиент со scope `companies` → вход с выбором «как компания» → `/oauth/me` → отказ на чужую компанию → снятие роли убирает компанию. Как довести KYB тестовой компании до `VERIFIED` без ручного прохождения в welID — выясняется первым шагом (тестовый метод одобрения у welID; если его нет — DEV-скрипт, заводящий проверенную компанию со снимком из фикстуры).
- **Мобильное приложение:** виджет-тесты экрана выбора (отметки по умолчанию, блокировка компании из «войти как», отправка выбора).

## Выкатка

- Бэкенд DEV → TEST → PROD (PROD — по явной команде), миграция двух новых таблиц.
- На PROD (и DEV/TEST для разработки Trientes) заводится OAuth-клиент Trientes со scope `companies`.
- Мобильное приложение — со следующим релизом.

## Документация для trientes.org

- `docs/talerid-companies-oauth.md`: какой scope запрашивать, формат `acting_as` и `companies`, как отличить вход физлицом от входа компанией, что делать при `revoked`, пример кода (openid-client), адреса DEV/TEST/PROD.
- Раздел «Companies» в публичном руководстве `public/oauth-guide.html`.

## Вне спека

- Сайт trientes.org.
- Переезд PROD на боевой инстанс welID.
- Редактирование компании из приложения и UI самого KYB (они уже есть; правим только если KYB-путь потребует).
- Push-уведомления сайту об изменениях компании (сайт перепроверяет через `/oauth/me` по refresh-токену).
