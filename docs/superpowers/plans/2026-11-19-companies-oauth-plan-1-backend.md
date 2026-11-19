# Вход от имени компании через Taler ID — план 1: бэкенд, веб-согласие, документация, e2e

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Taler ID отдаёт сайтам (первый — trientes.org) по scope `companies` выбранные человеком компании, прошедшие KYB, и пометку, под кем он вошёл; KYB компании доходит до конца на всех окружениях.

**Architecture:** Минутный опросчик забирает из welID статус KYB компании и снимок реквизитов (`CompanyKybProfile`). Выбор «войти как» и «какие компании передать» делается на экране согласия (веб `consent.html` и мобильные ручки `/oauth/mobile/*`), проверяется на сервере и сохраняется по `grantId` (`OAuthCompanySelection`). `findAccount` провайдера по `token.grantId` достаёт выбор и отдаёт в `/oauth/me` claims `acting_as` и `companies`.

**Tech Stack:** NestJS 11, Prisma 5 (PostgreSQL), oidc-provider 9.6, Jest; статическая SPA `public/consent.html`; e2e — `taler_id_tests` (ts-node + axios).

**Спека:** `docs/superpowers/specs/2026-11-19-companies-oauth-design.md`. План 2 (мобильное приложение) — `2026-11-19-companies-oauth-plan-2-mobile.md`, делается после этого плана: ему нужны ручки из задачи 14.

---

## Карта файлов

**Создаются (бэкенд `~/taler-id`, ветка `feat/companies-oauth`):**
- `scripts/kyb-probe.ts` — разведка KYB в welID на DEV, даёт фикстуру.
- `src/kyb/__fixtures__/welid-company-applicant.json` — настоящий ответ welID по анкете компании.
- `src/kyb/welid-company.mapper.ts` (+ `.spec.ts`) — анкета welID → данные снимка.
- `src/kyb/kyb-poller.service.ts` (+ `.spec.ts`) — опрос KYB компаний.
- `src/kyb/kyb.module.ts`.
- `src/companies/companies.constants.ts` — scope, роли, срок жизни выбора.
- `src/companies/company-eligibility.ts` (+ `.spec.ts`) — какие компании подходят.
- `src/companies/company-selection.ts` (+ `.spec.ts`) — проверка и хранение выбора.
- `src/companies/company-claims.ts` (+ `.spec.ts`) — claims `acting_as` и `companies`.
- `src/companies/load-existing-grant.ts` (+ `.spec.ts`) — экран согласия при каждом входе с компаниями.
- `src/companies/company-consent.service.ts` (+ `.spec.ts`), `src/companies/companies.module.ts` — блок «компании» для обоих экранов согласия.
- `scripts/seed-companies-e2e.ts` — проверенная компания и OAuth-клиент для e2e (DEV/TEST).
- `docs/talerid-companies-oauth.md` — документация для trientes.org.
- `prisma/migrations/20261119120000_companies_oauth/migration.sql`.

**Меняются:**
- `prisma/schema.prisma` — модели `CompanyKybProfile`, `OAuthCompanySelection`, связь в `Tenant`.
- `src/kyc/kyc.service.ts` — публичный `getApplicantByExternalUserId`.
- `src/oidc/oidc-provider.factory.ts` — scope, claims, `findAccount(…, token)`, `loadExistingGrant`.
- `src/oidc/adapters/prisma-client-adapter.ts` (+ spec) — `companies` не выдаётся через DCR.
- `src/oauth-mobile/scope-descriptors.ts` (+ spec) — описание scope.
- `src/oidc/oidc-interaction.controller.ts`, `src/oidc/oidc.module.ts` — блок компаний в веб-согласии.
- `src/oauth-mobile/oauth-mobile.service.ts`, `dto/oauth-approve.dto.ts`, `oauth-mobile.module.ts` (+ spec) — блок компаний, выбор, конфиденциальные клиенты.
- `public/consent.html` — UI выбора.
- `public/oauth-guide.html` — раздел «Companies».
- `src/app.module.ts` — `KybModule`.

**e2e (`~/Downloads/taler_id_tests`):** `companies_test.ts`, `package.json` (скрипты `test:companies`, `test:companies:prod`).

---

### Task 0: Подготовка

**Files:** нет изменений.

- [ ] **Step 1: Рабочая копия**

```bash
cd ~/taler-id && git fetch -q origin
[ -d .worktrees/companies-oauth ] || git worktree add -q .worktrees/companies-oauth feat/companies-oauth
cd ~/taler-id/.worktrees/companies-oauth && git status -sb | head -1 && git log --oneline -1
[ -e node_modules ] || ln -s ../../node_modules node_modules
```
Expected: последний коммит — `docs(spec): вход от имени компании…` или новее на `feat/companies-oauth`.

- [ ] **Step 2: Базовая линия тестов**

```bash
cd ~/taler-id/.worktrees/companies-oauth && npx jest 2>&1 | grep -E "^Tests:|^Test Suites:"
```
Expected: записать числа. На 2026-11-17 падало 33 старых теста в 4 наборах (мёртвые спеки) — это база; новых падений после каждой задачи быть не должно.

---

### Task 1: Разведка KYB в welID и фикстура

Нужно узнать, где и в каком виде welID отдаёт реквизиты компании, и есть ли тестовое одобрение анкеты. Живых анкет KYB у нас нет ни одной.

**Files:**
- Create: `scripts/kyb-probe.ts`
- Create: `src/kyb/__fixtures__/welid-company-applicant.json`

> **Выполнено 2026-11-19 (исход B).** Анкета компании заводится через API, но реквизиты welID берёт только из корневого `companyInfo` в теле (`info.companyInfo` игнорирует) и отдаёт их там же; поля: `companyName, registrationNumber, country, legalAddress, postalAddress, incorporatedOn, type, email, phone, website, registrationLocation, taxId, controlScheme, beneficiaries`. Структурного адреса нет. `status/testCompleted` → 404: тестового одобрения нет, e2e — через сид (задача 15). У уровня `prj:taler/kyb-level` есть опросник `talerid-kyb-v1` — что он соберёт при живом KYB, видно только по живой анкете. Фикстура — `GET /one` анкеты `d4bc40632a73404c972c42c3c3039d95` (синтетическая компания, `review.reviewStatus = init`).

- [ ] **Step 1: Скрипт разведки**

```ts
/**
 * Разведка KYB в welID для спеки 2026-11-19-companies-oauth-design.md.
 *
 * Заводит в welID анкету компании на уровне KYB, пробует одобрить её тестовым
 * методом (как у Sumsub: status/testCompleted) и печатает ответ GET /one —
 * он становится фикстурой разбора src/kyb/__fixtures__/welid-company-applicant.json.
 *
 * Только DEV: externalUserId с префиксом kyb-probe-, к компаниям Taler ID не
 * привязан. Подпись запросов — та же, что у KYC (fr-auth.util).
 *
 * Запуск на DEV-сервере из каталога бэкенда:
 *   npx ts-node -r dotenv/config scripts/kyb-probe.ts
 */
import { frAuthHeadersOrEmpty } from '../src/kyc/fr-auth.util';
import { prefixLevel } from '../src/kyc/level-name.util';

const base = (process.env.SUMSUB_BASE_URL ?? '').replace(/\/$/, '');
const appToken = process.env.SUMSUB_APP_TOKEN ?? '';
const appSecret = process.env.SUMSUB_APP_SECRET ?? '';
const level = prefixLevel(
  process.env.SUMSUB_KYB_LEVEL_NAME || 'kyb-level',
  process.env.SUMSUB_PROJECT_ID || 'taler',
);

async function call(method: string, path: string, body?: unknown) {
  const raw = body === undefined ? '' : JSON.stringify(body);
  const res = await fetch(base + path, {
    method,
    headers: {
      ...(raw ? { 'Content-Type': 'application/json' } : {}),
      ...frAuthHeadersOrEmpty({ appToken, appSecret, method, pathWithQuery: path, body: raw }),
    },
    body: raw || undefined,
  });
  const text = await res.text();
  let data: unknown = text;
  try { data = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, data };
}

async function main() {
  if (!base.includes('test')) throw new Error(`refusing: ${base} is not a welID test instance`);
  const externalUserId = `kyb-probe-${Date.now()}`;
  console.log('== create applicant', externalUserId, level);
  const created = await call('POST', `/resources/applicants?levelName=${encodeURIComponent(level)}`, {
    externalUserId,
    type: 'company',
    info: {
      companyInfo: {
        companyName: 'ООО «Пробная Ромашка»',
        registrationNumber: '1027700132195',
        country: 'RUS',
        legalAddress: 'Москва, ул. Пробная, 1',
        incorporatedOn: '2015-03-02',
        type: 'LLC',
        taxId: '7701234567',
        website: 'https://romashka.example',
      },
    },
  });
  console.log(created.status, JSON.stringify(created.data).slice(0, 600));
  const id = (created.data as any)?.id;
  if (!id) return;

  console.log('== testCompleted GREEN');
  const approved = await call('POST', `/resources/applicants/${id}/status/testCompleted`, {
    reviewAnswer: 'GREEN',
    rejectLabels: [],
  });
  console.log(approved.status, JSON.stringify(approved.data).slice(0, 300));

  console.log('== GET /one by externalUserId');
  const one = await call('GET', `/resources/applicants/-;externalUserId=${encodeURIComponent(externalUserId)}/one`);
  console.log(one.status);
  console.log(JSON.stringify(one.data, null, 2));
}

main().catch((e) => { console.error(e); process.exit(1); });
```

- [ ] **Step 2: Запуск на DEV**

```bash
cd ~/taler-id/.worktrees/companies-oauth && git add scripts/kyb-probe.ts && git commit -qm "chore(kyb): скрипт разведки анкеты компании в welID

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>" && git push -q origin HEAD:feat/companies-oauth
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/taler-id && git fetch -q origin feat/companies-oauth && git show origin/feat/companies-oauth:scripts/kyb-probe.ts > /tmp/kyb-probe.ts && cp /tmp/kyb-probe.ts scripts/kyb-probe.ts && npx ts-node -r dotenv/config scripts/kyb-probe.ts; rm -f scripts/kyb-probe.ts"' > /tmp/kyb-probe.out 2>&1; cat /tmp/kyb-probe.out
```
(С мака до DEV TLS не проходит — ходим через бот-сервер. Скрипт копируется во временный файл и удаляется, рабочая копия DEV не меняется.)

Expected, один из исходов:
- **A.** `create` → 200/201 с `id`, `testCompleted` → 200, `GET /one` → 200 с `review.reviewResult.reviewAnswer = "GREEN"` и данными компании.
- **B.** `testCompleted` → 404/405: тестового одобрения у welID нет. Тогда для e2e используется сид-скрипт (задача 15), а одобрение настоящей анкеты проверяется руками: KYB тестовой компании в приложении Taler ID на DEV + одобрение в админке welID.
- **C.** `create` отказывает: анкету компании через API не завести. Тогда пройти KYB тестовой компании на DEV через приложение (Организации → компания → «Пройти KYB»), дождаться одобрения в админке welID и снять `GET /one` тем же `call` по `externalUserId = <tenantId>`.

Записать исход в описание коммита фикстуры.

- [ ] **Step 3: Фикстура**

Сохранить JSON из ответа `GET /one` (без изменений, только убрать персональные данные живых людей, если анкета живая) в `src/kyb/__fixtures__/welid-company-applicant.json`. Найти в нём объект с реквизитами компании и записать путь до него (ожидаемо `info.companyInfo` или `fixedInfo.companyInfo`) — он нужен в задаче 3.

- [ ] **Step 4: Commit**

```bash
git add src/kyb/__fixtures__/welid-company-applicant.json
git commit -qm "test(kyb): настоящий ответ welID по анкете компании

Исход разведки: <A|B|C — одной строкой>. Реквизиты лежат в <путь>.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Модели и миграция

**Files:**
- Modify: `prisma/schema.prisma` (модель `Tenant`, новые модели в конце файла)
- Create: `prisma/migrations/20261119120000_companies_oauth/migration.sql`

- [ ] **Step 1: Модели**

В `model Tenant` после строки `members           TenantMember[]` добавить:

```prisma
  kybProfile        CompanyKybProfile?
```

В конец `prisma/schema.prisma`:

```prisma
/// Снимок реквизитов компании из анкеты KYB в welID — на момент одобрения.
/// Отдельно от редактируемых полей Tenant: проверенное не смешивается с тем,
/// что владелец может поменять сам. Спека 2026-11-19-companies-oauth-design.md.
model CompanyKybProfile {
  id                 String    @id @default(uuid())
  tenantId           String    @unique
  tenant             Tenant    @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  applicantId        String
  legalName          String?
  registrationNumber String?
  taxId              String?
  legalForm          String?
  incorporatedOn     DateTime? @db.Date
  country            String?
  city               String?
  legalAddress       String?
  website            String?
  raw                Json
  verifiedAt         DateTime  @default(now())
  updatedAt          DateTime  @updatedAt
}

/// Выбор на экране согласия: под кем вошёл и какие компании передал.
/// Одна запись на согласие (grantId) — входы с разных устройств не путаются,
/// refresh-токен видит выбор своего входа.
model OAuthCompanySelection {
  grantId         String   @id
  userId          String
  clientId        String
  actAsTenantId   String?
  sharedTenantIds String[]
  createdAt       DateTime @default(now())

  @@index([userId, clientId, createdAt])
}
```

- [ ] **Step 2: SQL миграции без базы**

```bash
cd ~/taler-id/.worktrees/companies-oauth
git show origin/dev:prisma/schema.prisma > /tmp/schema.before.prisma
npx prisma migrate diff --from-schema-datamodel /tmp/schema.before.prisma --to-schema-datamodel prisma/schema.prisma --script > /tmp/companies.sql
cat /tmp/companies.sql
```
Expected: `CREATE TABLE "CompanyKybProfile"`, `CREATE TABLE "OAuthCompanySelection"`, уникальный индекс `tenantId`, индекс `(userId, clientId, createdAt)`, внешний ключ на `Tenant` с `ON DELETE CASCADE`. Ничего про другие таблицы.

- [ ] **Step 3: Файл миграции**

```bash
mkdir -p prisma/migrations/20261119120000_companies_oauth
{ cat <<'EOF'
-- Вход от имени компании и передача проверенных компаний через OAuth.
-- Спека: docs/superpowers/specs/2026-11-19-companies-oauth-design.md
--
-- Всё аддитивно: две новые таблицы, старый код о них не знает — миграцию можно
-- накатить до рестарта нод. Внешний ключ на "Tenant" встаёт в очередь за живыми
-- записями в эту таблицу; короткий lock_timeout — чтобы не подвесить прод.
-- Упала по таймауту — откатится весь файл, перед повтором:
--   npx prisma migrate resolve --rolled-back 20261119120000_companies_oauth
SET LOCAL lock_timeout = '5s';

EOF
cat /tmp/companies.sql; } > prisma/migrations/20261119120000_companies_oauth/migration.sql
npx prisma generate >/dev/null && npx tsc --noEmit -p tsconfig.build.json && echo ok
```
Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add prisma/schema.prisma prisma/migrations/20261119120000_companies_oauth
git commit -qm "feat(companies): модели снимка KYB компании и выбора на согласии

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Разбор анкеты welID

> **Выполнено (c526b75, 6e46aa0, 1b1b011).** Итоговый код строже, чем ниже: `raw` — только 12 известных реквизитов (белый список), даты не из календаря / до 1800 / в будущем → `null`, сайт — только разбираемый `http(s)`-URL, параметр `unknown`, не-объект → `{}`. Сигнатура `mapWelidCompany(applicant): CompanyKybData` та же.

**Files:**
- Create: `src/kyb/welid-company.mapper.ts`
- Test: `src/kyb/welid-company.mapper.spec.ts`

- [ ] **Step 1: Failing test**

```ts
import { mapWelidCompany } from './welid-company.mapper';
import fixture from './__fixtures__/welid-company-applicant.json';

// Формат welID (разведка на DEV 2026-11-19): реквизиты в корневом
// companyInfo, а не в Sumsub-овском info.companyInfo; структурного адреса нет,
// место регистрации — registrationLocation.
const welidShaped = {
  id: 'app-1',
  externalUserId: 'tenant-1',
  type: 'company',
  companyInfo: {
    companyName: '  ООО «Ромашка» ',
    registrationNumber: '1027700132195',
    country: 'RUS',
    legalAddress: 'Москва, ул. Пробная, 1',
    incorporatedOn: '2015-03-02',
    type: 'LLC',
    taxId: '7701234567',
    website: 'https://romashka.example',
    registrationLocation: 'Москва',
  },
  review: { reviewStatus: 'completed', reviewResult: { reviewAnswer: 'GREEN' } },
};

describe('mapWelidCompany', () => {
  it('takes company details from companyInfo', () => {
    const d = mapWelidCompany(welidShaped);
    expect(d).toMatchObject({
      applicantId: 'app-1',
      legalName: 'ООО «Ромашка»',
      registrationNumber: '1027700132195',
      taxId: '7701234567',
      legalForm: 'LLC',
      country: 'RUS',
      city: 'Москва',
      legalAddress: 'Москва, ул. Пробная, 1',
      website: 'https://romashka.example',
    });
    expect(d.incorporatedOn?.toISOString()).toBe('2015-03-02T00:00:00.000Z');
    // Храним только реквизиты компании, не анкету целиком (риск-метки, скоринг,
    // бенефициары и прочее бессрочно держать незачем).
    expect(d.raw).toBe(welidShaped.companyInfo);
  });

  it('keeps missing or blank fields as null instead of guessing', () => {
    const d = mapWelidCompany({ id: 'app-3', companyInfo: { companyName: ' ', incorporatedOn: 'вчера' } });
    expect(d).toMatchObject({ legalName: null, incorporatedOn: null, city: null, country: null });
  });

  it('a GREEN applicant without company details still maps (all nulls, empty raw)', () => {
    const d = mapWelidCompany({ id: 'app-4' });
    expect(d.applicantId).toBe('app-4');
    expect(d.legalName).toBeNull();
    expect(d.raw).toEqual({});
  });

  it('reads the real welID answer captured on DEV', () => {
    const d = mapWelidCompany(fixture);
    expect(d.applicantId).toBe('d4bc40632a73404c972c42c3c3039d95');
    expect(d).toMatchObject({
      legalName: 'ООО «Пробная Ромашка»',
      registrationNumber: '1027700132195',
      country: 'RUS',
      taxId: '7701234567',
      legalForm: 'LLC',
    });
    expect(d.city).toBeNull(); // registrationLocation в фикстуре пустое
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/kyb/welid-company.mapper.spec.ts`
Expected: FAIL — `Cannot find module './welid-company.mapper'`.

- [ ] **Step 3: Implementation**

```ts
/**
 * Анкета компании из welID → снимок реквизитов для CompanyKybProfile.
 * Спека 2026-11-19-companies-oauth-design.md.
 *
 * У welID реквизиты в корневом companyInfo (не в info.companyInfo, как у
 * Sumsub) — проверено на DEV 2026-11-19, фикстура рядом. Ничего не угадываем:
 * нет поля или оно пустое — null. Город — поле места регистрации
 * (registrationLocation), строку адреса не разбираем.
 */
export interface CompanyKybData {
  applicantId: string;
  legalName: string | null;
  registrationNumber: string | null;
  taxId: string | null;
  legalForm: string | null;
  incorporatedOn: Date | null;
  country: string | null;
  city: string | null;
  legalAddress: string | null;
  website: string | null;
  /** Сырой companyInfo из welID — только реквизиты, не анкета целиком. */
  raw: Record<string, unknown>;
}

function text(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return s ? s : null;
}

function day(v: unknown): Date | null {
  const s = text(v);
  if (!s || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const d = new Date(`${s}T00:00:00.000Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function mapWelidCompany(applicant: any): CompanyKybData {
  const ci = applicant?.companyInfo ?? {};
  return {
    applicantId: String(applicant?.id ?? ''),
    legalName: text(ci.companyName),
    registrationNumber: text(ci.registrationNumber),
    taxId: text(ci.taxId),
    legalForm: text(ci.type),
    incorporatedOn: day(ci.incorporatedOn),
    country: text(ci.country),
    city: text(ci.registrationLocation),
    legalAddress: text(ci.legalAddress),
    website: text(ci.website),
    raw: ci,
  };
}
```

`resolveJsonModule` должен быть включён в `tsconfig.json` (проверить: `grep resolveJsonModule tsconfig.json`). Если нет — в тесте заменить импорт на `const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, '__fixtures__/welid-company-applicant.json'), 'utf8'));`.

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/kyb/welid-company.mapper.spec.ts`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/kyb/welid-company.mapper.ts src/kyb/welid-company.mapper.spec.ts
git commit -qm "feat(kyb): разбор анкеты компании из welID

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Анкета из welID по externalUserId

**Files:**
- Modify: `src/kyc/kyc.service.ts` (`apiGet`, новый публичный метод рядом с `getApplicantByExternalId`)
- Test: `src/kyc/kyc.service.spec.ts` (новый `describe` в конце)

- [ ] **Step 1: Failing test**

В конец `src/kyc/kyc.service.spec.ts`:

```ts
describe('KycService.getApplicantByExternalUserId', () => {
  const makeService = () =>
    new KycService(
      {} as any,
      { get: () => '' } as any,
      {} as any,
      {} as any,
    );

  afterEach(() => jest.restoreAllMocks());

  it('returns the whole applicant', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ id: 'app-1', type: 'company' }), { status: 200 }),
    );
    const a = await makeService().getApplicantByExternalUserId('tenant-1');
    expect(a).toEqual({ id: 'app-1', type: 'company' });
    expect((global.fetch as jest.Mock).mock.calls[0][0]).toContain(
      '/resources/applicants/-;externalUserId=tenant-1/one',
    );
  });

  it('returns null while the applicant does not exist yet (404)', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ description: 'not found' }), { status: 404 }),
    );
    await expect(makeService().getApplicantByExternalUserId('tenant-1')).resolves.toBeNull();
  });

  it('other errors still throw', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ description: 'boom' }), { status: 500 }),
    );
    await expect(makeService().getApplicantByExternalUserId('tenant-1')).rejects.toThrow('boom');
  });
});
```
Если конструктор `KycService` в спеке собирается через `Test.createTestingModule` — оставить как выше: зависимости этим методам не нужны.

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/kyc/kyc.service.spec.ts -t getApplicantByExternalUserId`
Expected: FAIL — `getApplicantByExternalUserId is not a function`.

- [ ] **Step 3: Implementation**

В `apiGet` добавить опцию и ранний выход перед `response.json()`:

```ts
  private async apiGet(
    urlPath: string,
    opts: { allowNotFound?: boolean } = {},
  ): Promise<any> {
    // ⚠️ Подписывается РОВНО тот путь, что уходит в сеть: welID берёт сырой
    // raw_path и не декодирует проценты. urlPath уже собран с
    // encodeURIComponent — декодировать перед подписью нельзя, подпись не
    // сойдётся.
    const response = await fetch(this.baseUrl + urlPath, {
      method: 'GET',
      headers: {
        ...frAuthHeadersOrEmpty({
          appToken: this.appToken,
          appSecret: this.appSecret,
          method: 'GET',
          pathWithQuery: urlPath,
        }),
      },
      signal: AbortSignal.timeout(8000),
    });
    if (response.status === 404 && opts.allowNotFound) return null;
    const data = await response.json();
```
(остальное тело `apiGet` без изменений).

Рядом с `getApplicantByExternalId` добавить:

```ts
  /**
   * Вся анкета по externalUserId (для KYB компании это tenantId).
   * null — анкеты ещё нет: человек открыл KYB, но ничего не отправил.
   */
  async getApplicantByExternalUserId(externalUserId: string): Promise<any | null> {
    return this.apiGet(
      `/resources/applicants/-;externalUserId=${encodeURIComponent(externalUserId)}/one`,
      { allowNotFound: true },
    );
  }
```

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/kyc`
Expected: новые 3 проходят, остальные наборы `src/kyc` — как в базе.

- [ ] **Step 5: Commit**

```bash
git add src/kyc/kyc.service.ts src/kyc/kyc.service.spec.ts
git commit -qm "feat(kyc): анкета welID по externalUserId, 404 — не ошибка

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Опросчик KYB компаний

> **Выполнено (a2fc72c, 4ee7ebd).** Итог строже текста ниже: решения только при `reviewStatus = completed`; RED `RETRY` оставляет PENDING; GREEN — интерактивной транзакцией с условием `kybStatus in (PENDING, VERIFIED)`; `orderBy updatedAt desc`, окно 30 дней на обе ветки; `verifiedAt` из `review.reviewDate`; id анкеты — нормализованный из маппера. Хелпер тестов кладёт реквизиты в корневой `companyInfo`.

**Files:**
- Create: `src/kyb/kyb-poller.service.ts`, `src/kyb/kyb.module.ts`
- Test: `src/kyb/kyb-poller.service.spec.ts`
- Modify: `src/app.module.ts` (импорт и `KybModule` в `imports` рядом с `TenantModule`)

- [ ] **Step 1: Failing test**

```ts
import { KybPollerService } from './kyb-poller.service';

const applicant = (answer?: 'GREEN' | 'RED', companyInfo: object = { companyName: 'ООО «Ромашка»' }) => ({
  id: 'app-1',
  info: { companyInfo },
  ...(answer ? { review: { reviewResult: { reviewAnswer: answer } } } : {}),
});

describe('KybPollerService', () => {
  let prisma: any;
  let kyc: any;
  let svc: KybPollerService;

  beforeEach(() => {
    prisma = {
      tenant: {
        findMany: jest.fn().mockResolvedValue([]),
        update: jest.fn().mockReturnValue('tenant-update'),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      companyKybProfile: { upsert: jest.fn().mockReturnValue('profile-upsert') },
      $transaction: jest.fn().mockResolvedValue([]),
    };
    kyc = { getApplicantByExternalUserId: jest.fn() };
    svc = new KybPollerService(prisma, kyc);
  });

  it('polls pending companies and verified ones still missing a snapshot', async () => {
    await svc.pollCompanies();
    const where = prisma.tenant.findMany.mock.calls[0][0].where;
    expect(where.OR).toEqual([
      { kybStatus: 'PENDING', updatedAt: { gte: expect.any(Date) } },
      { kybStatus: 'VERIFIED', kybProfile: { is: null } },
    ]);
  });

  it('GREEN → VERIFIED and the snapshot in one transaction', async () => {
    kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('GREEN'));
    await svc.syncTenant('t-1', 'PENDING');
    expect(prisma.tenant.update).toHaveBeenCalledWith({
      where: { id: 't-1' },
      data: { kybStatus: 'VERIFIED', sumsubApplicantId: 'app-1' },
    });
    const upsert = prisma.companyKybProfile.upsert.mock.calls[0][0];
    expect(upsert.where).toEqual({ tenantId: 't-1' });
    expect(upsert.create).toMatchObject({ tenantId: 't-1', applicantId: 'app-1', legalName: 'ООО «Ромашка»' });
    expect(prisma.$transaction).toHaveBeenCalledWith(['tenant-update', 'profile-upsert']);
  });

  it('RED → REJECTED only from PENDING', async () => {
    kyc.getApplicantByExternalUserId.mockResolvedValue(applicant('RED'));
    await svc.syncTenant('t-1', 'PENDING');
    expect(prisma.tenant.updateMany).toHaveBeenCalledWith({
      where: { id: 't-1', kybStatus: 'PENDING' },
      data: { kybStatus: 'REJECTED', sumsubApplicantId: 'app-1' },
    });
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('an applicant without id is skipped — no snapshot keyed by an empty id', async () => {
    kyc.getApplicantByExternalUserId.mockResolvedValue({ ...applicant('GREEN'), id: undefined });
    await svc.syncTenant('t-1', 'PENDING');
    expect(prisma.$transaction).not.toHaveBeenCalled();
  });

  it('no applicant yet or no decision yet → nothing changes', async () => {
    kyc.getApplicantByExternalUserId.mockResolvedValueOnce(null).mockResolvedValueOnce(applicant());
    await svc.syncTenant('t-1', 'PENDING');
    await svc.syncTenant('t-1', 'PENDING');
    expect(prisma.tenant.update).not.toHaveBeenCalled();
    expect(prisma.tenant.updateMany).not.toHaveBeenCalled();
  });

  it('a round still running → the next tick is skipped (rounds never overlap)', async () => {
    let release!: () => void;
    prisma.tenant.findMany.mockReturnValueOnce(new Promise((r) => { release = () => r([]); }));
    const first = svc.pollCompanies();
    await svc.pollCompanies(); // второй тик, пока первый ждёт
    expect(prisma.tenant.findMany).toHaveBeenCalledTimes(1);
    release();
    await first;
    await svc.pollCompanies();
    expect(prisma.tenant.findMany).toHaveBeenCalledTimes(2);
  });

  it('one failing company does not stop the round', async () => {
    prisma.tenant.findMany.mockResolvedValue([
      { id: 't-1', kybStatus: 'PENDING' },
      { id: 't-2', kybStatus: 'PENDING' },
    ]);
    kyc.getApplicantByExternalUserId
      .mockRejectedValueOnce(new Error('welID down'))
      .mockResolvedValueOnce(applicant('GREEN'));
    await svc.pollCompanies();
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/kyb/kyb-poller.service.spec.ts`
Expected: FAIL — модуль не найден.

- [ ] **Step 3: Implementation**

`src/kyb/kyb-poller.service.ts`:

```ts
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import type { KycStatus } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { KycService } from '../kyc/kyc.service';
import { mapWelidCompany } from './welid-company.mapper';

/** Ручная проверка компании в welID может идти днями. */
const PENDING_WINDOW_DAYS = 30;

/**
 * Статус KYB компании и снимок её реквизитов — опросом welID.
 *
 * Вебхука KYB нет ни на одном окружении: TenantService.handleKybWebhook ни к
 * чему не подключён, а вебхук welID на TEST приходит в обработчик KYC людей.
 * Поэтому компания не становилась проверенной нигде. Спека
 * 2026-11-19-companies-oauth-design.md, часть 1.
 */
@Injectable()
export class KybPollerService {
  private readonly logger = new Logger(KybPollerService.name);
  /** До 50 запросов по 8 с — круг может пережить минуту; не накладываем. */
  private running = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly kyc: KycService,
  ) {}

  @Cron(CronExpression.EVERY_MINUTE)
  async pollCompanies() {
    if (this.running) return;
    this.running = true;
    try {
      await this.pollRound();
    } finally {
      this.running = false;
    }
  }

  private async pollRound() {
    const since = new Date(Date.now() - PENDING_WINDOW_DAYS * 24 * 60 * 60 * 1000);
    const tenants = await this.prisma.tenant.findMany({
      where: {
        OR: [
          { kybStatus: 'PENDING', updatedAt: { gte: since } },
          // одобренные вручную (админка) или до появления снимков
          { kybStatus: 'VERIFIED', kybProfile: { is: null } },
        ],
      },
      select: { id: true, kybStatus: true },
      take: 50,
    });
    for (const t of tenants) {
      try {
        await this.syncTenant(t.id, t.kybStatus);
      } catch (e) {
        this.logger.warn(`KYB poll failed for tenant ${t.id}: ${e}`);
      }
    }
  }

  async syncTenant(tenantId: string, status: KycStatus) {
    const applicant = await this.kyc.getApplicantByExternalUserId(tenantId);
    const answer = applicant?.review?.reviewResult?.reviewAnswer;
    if (!applicant?.id || !answer) return;

    if (answer === 'RED') {
      if (status !== 'PENDING') return;
      await this.prisma.tenant.updateMany({
        where: { id: tenantId, kybStatus: 'PENDING' },
        data: { kybStatus: 'REJECTED', sumsubApplicantId: applicant.id },
      });
      this.logger.log(`KYB poll: tenant=${tenantId} → REJECTED`);
      return;
    }
    if (answer !== 'GREEN') return;

    // Без данных компании снимок всё равно пишем (пустые поля + сырой ответ):
    // иначе VERIFIED без снимка опрашивался бы по кругу.
    const { raw, ...fields } = mapWelidCompany(applicant);
    const data = { ...fields, raw: raw as object, verifiedAt: new Date() };
    await this.prisma.$transaction([
      this.prisma.tenant.update({
        where: { id: tenantId },
        data: { kybStatus: 'VERIFIED', sumsubApplicantId: applicant.id },
      }),
      this.prisma.companyKybProfile.upsert({
        where: { tenantId },
        create: { tenantId, ...data },
        update: data,
      }),
    ]);
    this.logger.log(`KYB poll: tenant=${tenantId} → VERIFIED (snapshot saved)`);
  }
}
```

`src/kyb/kyb.module.ts`:

```ts
import { Module } from '@nestjs/common';
import { KycModule } from '../kyc/kyc.module';
import { KybPollerService } from './kyb-poller.service';

@Module({
  imports: [KycModule],
  providers: [KybPollerService],
})
export class KybModule {}
```

`src/app.module.ts`: `import { KybModule } from './kyb/kyb.module';` рядом с `TenantModule`, и `KybModule,` в `imports` сразу после `TenantModule,`. `ScheduleModule.forRoot()` там уже есть — второй раз не добавлять (иначе cron пойдёт дважды, см. память про двойную регистрацию).

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/kyb && npx tsc --noEmit -p tsconfig.build.json && echo ok`
Expected: все тесты `src/kyb` проходят (19 разбора + 6 опросчика), `ok`.

- [ ] **Step 5: Commit**

```bash
git add src/kyb src/app.module.ts
git commit -qm "feat(kyb): опрос KYB компаний и снимок реквизитов при одобрении

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Какие компании подходят

**Files:**
- Create: `src/companies/companies.constants.ts`, `src/companies/company-eligibility.ts`
- Test: `src/companies/company-eligibility.spec.ts`

- [ ] **Step 1: Constants**

```ts
import { TenantRole } from '@prisma/client';

/**
 * Вход от имени компании и передача проверенных компаний сайтам.
 * Спека: docs/superpowers/specs/2026-11-19-companies-oauth-design.md
 */

/** Scope, под которым сайт получает `acting_as` и `companies` в /oauth/me. */
export const COMPANIES_SCOPE = 'companies';

/** Кто может войти от имени компании и передать её данные. */
export const COMPANY_ACTOR_ROLES: readonly TenantRole[] = [TenantRole.OWNER, TenantRole.ADMIN];

/** Столько живёт согласие (ttl.Grant провайдера); выбор старше не нужен. */
export const SELECTION_TTL_DAYS = 30;
```

- [ ] **Step 2: Failing test**

```ts
import { classifyCompanies } from './company-eligibility';

const profile = { legalName: 'ООО «Ромашка»', verifiedAt: new Date('2026-11-20T10:00:00Z') } as any;
const row = (role: string, kybStatus: string, kybProfile: any = profile, id = 't-1') => ({
  role,
  tenant: { id, name: `Компания ${id}`, logoUrl: null, kybStatus, kybProfile },
});

describe('classifyCompanies', () => {
  it('OWNER and ADMIN of a verified company with a snapshot are eligible', () => {
    const { eligible } = classifyCompanies([row('OWNER', 'VERIFIED', profile, 'a'), row('ADMIN', 'VERIFIED', profile, 'b')] as any);
    expect(eligible.map((c) => [c.tenantId, c.role])).toEqual([['a', 'OWNER'], ['b', 'ADMIN']]);
    expect(eligible[0].profile).toBe(profile);
  });

  it('OPERATOR and VIEWER never act for the company and get no hint either', () => {
    const r = classifyCompanies([row('OPERATOR', 'VERIFIED'), row('VIEWER', 'PENDING', null, 't-2')] as any);
    expect(r).toEqual({ eligible: [], unverified: [] });
  });

  it('an OWNER whose company has not passed KYB gets a hint, not an option', () => {
    const r = classifyCompanies([row('OWNER', 'PENDING', null), row('ADMIN', 'REJECTED', null, 't-2')] as any);
    expect(r.eligible).toEqual([]);
    expect(r.unverified).toEqual([{ tenantId: 't-1', name: 'Компания t-1' }, { tenantId: 't-2', name: 'Компания t-2' }]);
  });

  it('VERIFIED without a snapshot is not eligible yet', () => {
    const r = classifyCompanies([row('OWNER', 'VERIFIED', null)] as any);
    expect(r.eligible).toEqual([]);
    expect(r.unverified).toEqual([{ tenantId: 't-1', name: 'Компания t-1' }]);
  });
});
```

- [ ] **Step 3: Run, expect FAIL**

Run: `npx jest src/companies/company-eligibility.spec.ts`
Expected: FAIL — модуль не найден.

- [ ] **Step 4: Implementation**

```ts
import type { CompanyKybProfile, KycStatus, TenantRole } from '@prisma/client';
import { COMPANY_ACTOR_ROLES } from './companies.constants';

export interface EligibleCompany {
  tenantId: string;
  name: string;
  logoUrl: string | null;
  role: TenantRole;
  profile: CompanyKybProfile;
}

export interface UnverifiedCompany {
  tenantId: string;
  name: string;
}

export interface MembershipRow {
  role: TenantRole;
  tenant: {
    id: string;
    name: string;
    logoUrl: string | null;
    kybStatus: KycStatus;
    kybProfile: CompanyKybProfile | null;
  };
}

/**
 * Одно правило на всё: и экран согласия, и выдача claims.
 * Подходит — человек OWNER/ADMIN, KYB пройден и есть снимок реквизитов.
 * OWNER/ADMIN без KYB — подсказка «пройдите проверку», а не вариант выбора.
 */
export function classifyCompanies(rows: MembershipRow[]): {
  eligible: EligibleCompany[];
  unverified: UnverifiedCompany[];
} {
  const eligible: EligibleCompany[] = [];
  const unverified: UnverifiedCompany[] = [];
  for (const { role, tenant } of rows) {
    if (!COMPANY_ACTOR_ROLES.includes(role)) continue;
    if (tenant.kybStatus === 'VERIFIED' && tenant.kybProfile) {
      eligible.push({
        tenantId: tenant.id,
        name: tenant.name,
        logoUrl: tenant.logoUrl,
        role,
        profile: tenant.kybProfile,
      });
    } else {
      unverified.push({ tenantId: tenant.id, name: tenant.name });
    }
  }
  return { eligible, unverified };
}

type Db = { tenantMember: { findMany: (args: any) => Promise<any[]> } };

/** Все компании человека, разложенные по правилу выше. */
export async function loadCompanies(db: Db, userId: string) {
  const rows = await db.tenantMember.findMany({
    where: { userId },
    include: { tenant: { include: { kybProfile: true } } },
    orderBy: { invitedAt: 'asc' },
  });
  return classifyCompanies(rows as MembershipRow[]);
}
```

- [ ] **Step 5: Run, expect PASS**

Run: `npx jest src/companies/company-eligibility.spec.ts`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add src/companies/companies.constants.ts src/companies/company-eligibility.ts src/companies/company-eligibility.spec.ts
git commit -qm "feat(companies): правило «компания подходит для входа от её имени»

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Выбор на согласии — проверка и хранение

**Files:**
- Create: `src/companies/company-selection.ts`
- Test: `src/companies/company-selection.spec.ts`

- [ ] **Step 1: Failing test**

```ts
import {
  CompanySelectionError,
  findLastSelection,
  resolveSelection,
  saveSelection,
} from './company-selection';

const eligible = new Set(['a', 'b']);

describe('resolveSelection', () => {
  it('nothing chosen → signed in as a person, nothing shared', () => {
    expect(resolveSelection({}, eligible)).toEqual({ actAsTenantId: null, sharedTenantIds: [] });
  });

  it('the company you sign in as is always shared, first', () => {
    expect(resolveSelection({ actAs: 'b', companyIds: ['a'] }, eligible)).toEqual({
      actAsTenantId: 'b',
      sharedTenantIds: ['b', 'a'],
    });
  });

  it('duplicates collapse', () => {
    expect(resolveSelection({ actAs: 'person', companyIds: ['a', 'a'] }, eligible).sharedTenantIds).toEqual(['a']);
  });

  it('a company that is not eligible is refused, whether act-as or shared', () => {
    expect(() => resolveSelection({ actAs: 'zzz' }, eligible)).toThrow(CompanySelectionError);
    expect(() => resolveSelection({ companyIds: ['a', 'zzz'] }, eligible)).toThrow(CompanySelectionError);
  });

  it('malformed input is refused', () => {
    expect(() => resolveSelection({ actAs: 42 as any }, eligible)).toThrow(CompanySelectionError);
    expect(() => resolveSelection({ companyIds: 'a' as any }, eligible)).toThrow(CompanySelectionError);
  });
});

describe('saveSelection / findLastSelection', () => {
  it('stores one row per grant and drops this pair’s rows older than a grant lives', async () => {
    const db: any = {
      oAuthCompanySelection: {
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
        create: jest.fn().mockResolvedValue({}),
      },
    };
    await saveSelection(db, {
      grantId: 'g-1', userId: 'u', clientId: 'c',
      selection: { actAsTenantId: 'a', sharedTenantIds: ['a'] },
    });
    const cutoff = db.oAuthCompanySelection.deleteMany.mock.calls[0][0].where.createdAt.lt as Date;
    expect(Date.now() - cutoff.getTime()).toBeGreaterThanOrEqual(30 * 864e5 - 1000);
    expect(db.oAuthCompanySelection.create).toHaveBeenCalledWith({
      data: { grantId: 'g-1', userId: 'u', clientId: 'c', actAsTenantId: 'a', sharedTenantIds: ['a'] },
    });
  });

  it('the last selection for this site is the newest row', async () => {
    const db: any = { oAuthCompanySelection: { findFirst: jest.fn().mockResolvedValue(null) } };
    await findLastSelection(db, 'u', 'c');
    expect(db.oAuthCompanySelection.findFirst).toHaveBeenCalledWith({
      where: { userId: 'u', clientId: 'c' },
      orderBy: { createdAt: 'desc' },
    });
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/companies/company-selection.spec.ts`
Expected: FAIL — модуль не найден.

- [ ] **Step 3: Implementation**

```ts
import { SELECTION_TTL_DAYS } from './companies.constants';

/** Как выбор приходит со страницы согласия или из приложения. */
export interface CompanySelectionInput {
  /** 'person' или id компании; не пришло — физлицо. */
  actAs?: unknown;
  companyIds?: unknown;
}

export interface ResolvedSelection {
  actAsTenantId: string | null;
  sharedTenantIds: string[];
}

export class CompanySelectionError extends Error {}

/**
 * Проверка выбора против подходящих компаний — странице не верим.
 * Компания, от имени которой входят, передаётся всегда и идёт первой.
 */
export function resolveSelection(
  input: CompanySelectionInput,
  eligibleIds: ReadonlySet<string>,
): ResolvedSelection {
  const actAs = input.actAs ?? 'person';
  if (typeof actAs !== 'string') throw new CompanySelectionError('act_as must be a string');
  const ids = input.companyIds ?? [];
  if (!Array.isArray(ids) || ids.some((x) => typeof x !== 'string')) {
    throw new CompanySelectionError('company_ids must be an array of strings');
  }
  const actAsTenantId = actAs === 'person' ? null : actAs;
  const shared = [...new Set([...(actAsTenantId ? [actAsTenantId] : []), ...(ids as string[])])];
  for (const id of shared) {
    if (!eligibleIds.has(id)) throw new CompanySelectionError(`company ${id} is not available`);
  }
  return { actAsTenantId, sharedTenantIds: shared };
}

type Db = {
  oAuthCompanySelection: {
    deleteMany: (args: any) => Promise<unknown>;
    create: (args: any) => Promise<unknown>;
    findFirst: (args: any) => Promise<any>;
    findUnique: (args: any) => Promise<any>;
  };
};

/**
 * Новая запись на каждое согласие. Экрана отзыва доступа нет, поэтому заодно
 * убираем записи этой пары человек–сайт старше срока жизни согласия.
 */
export async function saveSelection(
  db: Pick<Db, 'oAuthCompanySelection'> | any,
  args: { grantId: string; userId: string; clientId: string; selection: ResolvedSelection },
) {
  const cutoff = new Date(Date.now() - SELECTION_TTL_DAYS * 24 * 60 * 60 * 1000);
  await db.oAuthCompanySelection.deleteMany({
    where: { userId: args.userId, clientId: args.clientId, createdAt: { lt: cutoff } },
  });
  await db.oAuthCompanySelection.create({
    data: {
      grantId: args.grantId,
      userId: args.userId,
      clientId: args.clientId,
      actAsTenantId: args.selection.actAsTenantId,
      sharedTenantIds: args.selection.sharedTenantIds,
    },
  });
}

export function findSelection(db: any, grantId: string) {
  return db.oAuthCompanySelection.findUnique({ where: { grantId } });
}

/** Отметки по умолчанию для следующего входа на тот же сайт. */
export function findLastSelection(db: any, userId: string, clientId: string) {
  return db.oAuthCompanySelection.findFirst({
    where: { userId, clientId },
    orderBy: { createdAt: 'desc' },
  });
}
```

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/companies/company-selection.spec.ts`
Expected: 7 passed.

- [ ] **Step 5: Удаление аккаунта убирает выбор**

Внешнего ключа на `User` у `OAuthCompanySelection` нет (намеренно), а `ProfileService.deleteAccount` чистит связанные таблицы вручную — иначе записи «какие компании человек передал какому сайту» пережили бы аккаунт.

Тест — в `src/profile/profile.service.delete-account.spec.ts`: в `mockPrisma` добавить `oAuthCompanySelection: { deleteMany: jest.fn() },` и в `describe('ProfileService.deleteAccount')`:

```ts
  it('drops the person’s company choices on OAuth sites', async () => {
    mockPrisma.profile.findUnique.mockResolvedValue(null);
    await service.deleteAccount('user-1');
    expect(mockPrisma.oAuthCompanySelection.deleteMany).toHaveBeenCalledWith({
      where: { userId: 'user-1' },
    });
  });
```
Run: `npx jest src/profile/profile.service.delete-account.spec.ts` → новый тест FAIL.

В `src/profile/profile.service.ts`, `deletionStatements`, после `db.totpSecret.deleteMany(...)`:

```ts
      // Выбор компаний на согласии OAuth (OAuthCompanySelection) — без внешнего
      // ключа на User, поэтому только здесь.
      db.oAuthCompanySelection.deleteMany({ where: { userId } }),
```
и в комментарии над методом «Same six statements» → «Same seven statements».

Run: `npx jest src/profile/profile.service.delete-account.spec.ts` → PASS.

- [ ] **Step 6: Commit**

```bash
git add src/companies/company-selection.ts src/companies/company-selection.spec.ts src/profile/profile.service.ts src/profile/profile.service.delete-account.spec.ts
git commit -qm "feat(companies): проверка и хранение выбора «войти как» и «что передать»

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Claims `acting_as` и `companies`

**Files:**
- Create: `src/companies/company-claims.ts`
- Test: `src/companies/company-claims.spec.ts`

- [ ] **Step 1: Failing test**

```ts
import { buildCompanyClaims, companyClaimsFor } from './company-claims';
import type { EligibleCompany } from './company-eligibility';

const romashka: EligibleCompany = {
  tenantId: 'a',
  name: 'Ромашка',
  logoUrl: 'https://cdn/a.png',
  role: 'OWNER',
  profile: {
    legalName: 'ООО «Ромашка»', registrationNumber: '1027700132195', taxId: '7701234567',
    legalForm: 'LLC', incorporatedOn: new Date('2015-03-02T00:00:00Z'), country: 'RUS',
    city: 'Москва', legalAddress: 'Москва, ул. Пробная, 1', website: 'https://romashka.example',
    verifiedAt: new Date('2026-11-20T10:00:00Z'),
  } as any,
};

describe('buildCompanyClaims', () => {
  it('no selection (old app, no companies) → person, nothing shared', () => {
    expect(buildCompanyClaims(null, [romashka], new Map())).toEqual({
      acting_as: { type: 'person' }, companies: [],
    });
  });

  it('signed in as a company: acting_as and its full card', () => {
    const c = buildCompanyClaims({ actAsTenantId: 'a', sharedTenantIds: ['a'] }, [romashka], new Map());
    expect(c.acting_as).toEqual({ type: 'company', company_id: 'a', name: 'Ромашка' });
    expect(c.companies).toEqual([{
      company_id: 'a', name: 'Ромашка', legal_name: 'ООО «Ромашка»',
      registration_number: '1027700132195', tax_id: '7701234567', legal_form: 'LLC',
      incorporated_on: '2015-03-02', country: 'RUS', city: 'Москва',
      legal_address: 'Москва, ул. Пробная, 1', website: 'https://romashka.example',
      logo_url: 'https://cdn/a.png', logo_verified: false,
      kyb_status: 'verified', kyb_verified_at: '2026-11-20T10:00:00.000Z', role: 'OWNER',
    }]);
  });

  it('a company that lost eligibility since sign-in: acting_as revoked, card gone', () => {
    const c = buildCompanyClaims(
      { actAsTenantId: 'a', sharedTenantIds: ['a', 'b'] }, [], new Map([['a', 'Ромашка']]),
    );
    expect(c.acting_as).toEqual({ type: 'company', company_id: 'a', name: 'Ромашка', revoked: true });
    expect(c.companies).toEqual([]);
  });

  it('a deleted company: revoked with name null', () => {
    const c = buildCompanyClaims({ actAsTenantId: 'a', sharedTenantIds: ['a'] }, [], new Map());
    expect(c.acting_as).toEqual({ type: 'company', company_id: 'a', name: null, revoked: true });
  });
});

describe('companyClaimsFor', () => {
  it('reads the selection of this grant and the current eligibility', async () => {
    const db: any = {
      oAuthCompanySelection: { findUnique: jest.fn().mockResolvedValue({ actAsTenantId: null, sharedTenantIds: ['a'] }) },
      tenantMember: { findMany: jest.fn().mockResolvedValue([{
        role: 'OWNER',
        tenant: { id: 'a', name: 'Ромашка', logoUrl: null, kybStatus: 'VERIFIED', kybProfile: romashka.profile },
      }]) },
      tenant: { findMany: jest.fn().mockResolvedValue([]) },
    };
    const c = await companyClaimsFor(db, 'u', 'g-1');
    expect(db.oAuthCompanySelection.findUnique).toHaveBeenCalledWith({ where: { grantId: 'g-1' } });
    expect(c.acting_as).toEqual({ type: 'person' });
    expect(c.companies.map((x) => x.company_id)).toEqual(['a']);
  });

  it('no grant id on the token → person, nothing shared', async () => {
    const db: any = { oAuthCompanySelection: { findUnique: jest.fn() }, tenantMember: { findMany: jest.fn().mockResolvedValue([]) }, tenant: { findMany: jest.fn().mockResolvedValue([]) } };
    expect(await companyClaimsFor(db, 'u', undefined)).toEqual({ acting_as: { type: 'person' }, companies: [] });
    expect(db.oAuthCompanySelection.findUnique).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/companies/company-claims.spec.ts`
Expected: FAIL — модуль не найден.

- [ ] **Step 3: Implementation**

```ts
import { EligibleCompany, loadCompanies } from './company-eligibility';
import { findSelection } from './company-selection';

export type ActingAsClaim =
  | { type: 'person' }
  | { type: 'company'; company_id: string; name: string | null; revoked?: true };

export interface CompanyClaim {
  company_id: string;
  /** Название в Taler ID — владелец может менять, не проверено. */
  name: string;
  legal_name: string | null;
  registration_number: string | null;
  tax_id: string | null;
  legal_form: string | null;
  incorporated_on: string | null;
  country: string | null;
  city: string | null;
  legal_address: string | null;
  website: string | null;
  logo_url: string | null;
  logo_verified: false;
  kyb_status: 'verified';
  kyb_verified_at: string;
  role: string;
}

interface SelectionLike {
  actAsTenantId: string | null;
  sharedTenantIds: string[];
}

function toClaim(c: EligibleCompany): CompanyClaim {
  const p = c.profile;
  return {
    company_id: c.tenantId,
    name: c.name,
    legal_name: p.legalName,
    registration_number: p.registrationNumber,
    tax_id: p.taxId,
    legal_form: p.legalForm,
    incorporated_on: p.incorporatedOn ? p.incorporatedOn.toISOString().slice(0, 10) : null,
    country: p.country,
    city: p.city,
    legal_address: p.legalAddress,
    website: p.website,
    logo_url: c.logoUrl,
    logo_verified: false,
    kyb_status: 'verified',
    kyb_verified_at: p.verifiedAt.toISOString(),
    role: c.role,
  };
}

/**
 * Что сайт видит в /oauth/me по scope `companies`. Подходящие компании
 * проверяются на каждый запрос: снятая роль или отозванный KYB убирают компанию
 * сразу, а `acting_as` получает `revoked: true`.
 */
export function buildCompanyClaims(
  selection: SelectionLike | null,
  eligible: EligibleCompany[],
  knownNames: ReadonlyMap<string, string>,
): { acting_as: ActingAsClaim; companies: CompanyClaim[] } {
  if (!selection) return { acting_as: { type: 'person' }, companies: [] };
  const byId = new Map(eligible.map((c) => [c.tenantId, c]));

  let acting_as: ActingAsClaim = { type: 'person' };
  if (selection.actAsTenantId) {
    const id = selection.actAsTenantId;
    const company = byId.get(id);
    acting_as = company
      ? { type: 'company', company_id: id, name: company.name }
      : { type: 'company', company_id: id, name: knownNames.get(id) ?? null, revoked: true };
  }

  const companies = selection.sharedTenantIds
    .map((id) => byId.get(id))
    .filter((c): c is EligibleCompany => !!c)
    .map(toClaim);
  return { acting_as, companies };
}

/** Для findAccount провайдера: выбор этого согласия + текущая проверка. */
export async function companyClaimsFor(db: any, userId: string, grantId: string | undefined) {
  if (!grantId) return buildCompanyClaims(null, [], new Map());
  const [selection, { eligible }] = await Promise.all([
    findSelection(db, grantId),
    loadCompanies(db, userId),
  ]);
  const knownNames = new Map<string, string>();
  const actAs = selection?.actAsTenantId;
  if (actAs && !eligible.some((c) => c.tenantId === actAs)) {
    const rows = await db.tenant.findMany({ where: { id: actAs }, select: { id: true, name: true } });
    for (const r of rows) knownNames.set(r.id, r.name);
  }
  return buildCompanyClaims(selection ?? null, eligible, knownNames);
}
```

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/companies/company-claims.spec.ts`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/companies/company-claims.ts src/companies/company-claims.spec.ts
git commit -qm "feat(companies): claims acting_as и companies для /oauth/me

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Блок «компании» для экранов согласия

**Files:**
- Create: `src/companies/company-consent.service.ts`, `src/companies/companies.module.ts`
- Test: `src/companies/company-consent.service.spec.ts`

- [ ] **Step 1: Failing test**

```ts
import { BadRequestException } from '@nestjs/common';
import { CompanyConsentService } from './company-consent.service';

const verifiedRow = {
  role: 'OWNER',
  tenant: { id: 'a', name: 'Ромашка', logoUrl: null, kybStatus: 'VERIFIED',
    kybProfile: { legalName: 'ООО «Ромашка»', verifiedAt: new Date() } },
};
const pendingRow = { role: 'ADMIN', tenant: { id: 'b', name: 'Лютик', logoUrl: null, kybStatus: 'PENDING', kybProfile: null } };

describe('CompanyConsentService', () => {
  let prisma: any;
  let svc: CompanyConsentService;

  beforeEach(() => {
    prisma = {
      tenantMember: { findMany: jest.fn().mockResolvedValue([verifiedRow, pendingRow]) },
      profile: { findUnique: jest.fn().mockResolvedValue({ firstName: 'Иван', lastName: 'Петров' }) },
      oAuthCompanySelection: {
        findFirst: jest.fn().mockResolvedValue({ actAsTenantId: 'a', sharedTenantIds: ['a'] }),
        deleteMany: jest.fn().mockResolvedValue({}),
        create: jest.fn().mockResolvedValue({}),
      },
      auditLog: { create: jest.fn().mockResolvedValue({}) },
    };
    svc = new CompanyConsentService(prisma);
  });

  it('describes the choice for the consent screen', async () => {
    expect(await svc.consentBlock('u', 'trientes')).toEqual({
      person: { name: 'Иван Петров' },
      eligible: [{ id: 'a', name: 'Ромашка', legal_name: 'ООО «Ромашка»', logo_url: null, role: 'OWNER' }],
      unverified: [{ id: 'b', name: 'Лютик' }],
      last_selection: { act_as: 'a', company_ids: ['a'] },
    });
  });

  it('a stale last choice keeps only companies still eligible', async () => {
    prisma.oAuthCompanySelection.findFirst.mockResolvedValue({ actAsTenantId: 'gone', sharedTenantIds: ['gone', 'a'] });
    const b = await svc.consentBlock('u', 'trientes');
    expect(b.last_selection).toEqual({ act_as: 'person', company_ids: ['a'] });
  });

  it('validate refuses a company that is not eligible with 400', async () => {
    await expect(svc.validate('u', { actAs: 'b' })).rejects.toBeInstanceOf(BadRequestException);
  });

  it('save stores the selection and audits only when a company is shared', async () => {
    await svc.save({ grantId: 'g', userId: 'u', clientId: 'trientes', selection: { actAsTenantId: null, sharedTenantIds: [] } });
    expect(prisma.auditLog.create).not.toHaveBeenCalled();
    await svc.save({ grantId: 'g2', userId: 'u', clientId: 'trientes', selection: { actAsTenantId: 'a', sharedTenantIds: ['a'] } });
    expect(prisma.auditLog.create).toHaveBeenCalledWith({
      data: { userId: 'u', action: 'OAUTH_COMPANIES_SHARED', meta: { clientId: 'trientes', actAs: 'a', companyIds: ['a'] } },
    });
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/companies/company-consent.service.spec.ts`
Expected: FAIL — модуль не найден.

- [ ] **Step 3: Implementation**

`src/companies/company-consent.service.ts`:

```ts
import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { loadCompanies } from './company-eligibility';
import {
  CompanySelectionError,
  CompanySelectionInput,
  ResolvedSelection,
  findLastSelection,
  resolveSelection,
  saveSelection,
} from './company-selection';

/** Что экраны согласия (веб и приложение) показывают в блоке «компании». */
export interface CompanyConsentBlock {
  person: { name: string };
  eligible: { id: string; name: string; legal_name: string | null; logo_url: string | null; role: string }[];
  unverified: { id: string; name: string }[];
  last_selection: { act_as: string; company_ids: string[] } | null;
}

@Injectable()
export class CompanyConsentService {
  constructor(private readonly prisma: PrismaService) {}

  async consentBlock(userId: string, clientId: string): Promise<CompanyConsentBlock> {
    const [{ eligible, unverified }, profile, last] = await Promise.all([
      loadCompanies(this.prisma, userId),
      this.prisma.profile.findUnique({ where: { userId }, select: { firstName: true, lastName: true } }),
      findLastSelection(this.prisma, userId, clientId),
    ]);
    const ids = new Set(eligible.map((c) => c.tenantId));
    return {
      person: { name: [profile?.firstName, profile?.lastName].filter(Boolean).join(' ') },
      eligible: eligible.map((c) => ({
        id: c.tenantId,
        name: c.name,
        legal_name: c.profile.legalName,
        logo_url: c.logoUrl,
        role: c.role,
      })),
      unverified: unverified.map((c) => ({ id: c.tenantId, name: c.name })),
      last_selection: last
        ? {
            act_as: last.actAsTenantId && ids.has(last.actAsTenantId) ? last.actAsTenantId : 'person',
            company_ids: (last.sharedTenantIds as string[]).filter((id) => ids.has(id)),
          }
        : null,
    };
  }

  /** До создания согласия: неподходящая компания — 400, согласия нет. */
  async validate(userId: string, input: CompanySelectionInput): Promise<ResolvedSelection> {
    const { eligible } = await loadCompanies(this.prisma, userId);
    try {
      return resolveSelection(input, new Set(eligible.map((c) => c.tenantId)));
    } catch (e) {
      if (e instanceof CompanySelectionError) throw new BadRequestException(e.message);
      throw e;
    }
  }

  async save(args: { grantId: string; userId: string; clientId: string; selection: ResolvedSelection }) {
    await saveSelection(this.prisma, args);
    const { actAsTenantId, sharedTenantIds } = args.selection;
    if (!actAsTenantId && sharedTenantIds.length === 0) return;
    await this.prisma.auditLog.create({
      data: {
        userId: args.userId,
        action: 'OAUTH_COMPANIES_SHARED',
        meta: { clientId: args.clientId, actAs: actAsTenantId ?? 'person', companyIds: sharedTenantIds },
      },
    });
  }
}
```

`src/companies/companies.module.ts`:

```ts
import { Module } from '@nestjs/common';
import { CompanyConsentService } from './company-consent.service';

@Module({
  providers: [CompanyConsentService],
  exports: [CompanyConsentService],
})
export class CompaniesModule {}
```

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/companies`
Expected: все наборы `src/companies` проходят.

- [ ] **Step 5: Commit**

```bash
git add src/companies/company-consent.service.ts src/companies/company-consent.service.spec.ts src/companies/companies.module.ts
git commit -qm "feat(companies): блок выбора компаний для экранов согласия

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Провайдер OIDC — scope, claims, экран при каждом входе

**Files:**
- Create: `src/companies/load-existing-grant.ts`
- Test: `src/companies/load-existing-grant.spec.ts`
- Modify: `src/oidc/oidc-provider.factory.ts`

- [ ] **Step 1: Failing test**

```ts
import { createLoadExistingGrant } from './load-existing-grant';

const ctx = (opts: { scope: string; fresh?: string; remembered?: string; accountId?: string }) => ({
  oidc: {
    params: { scope: opts.scope },
    result: opts.fresh ? { consent: { grantId: opts.fresh } } : undefined,
    session: { accountId: opts.accountId ?? 'u', grantIdFor: () => opts.remembered },
    client: { clientId: 'trientes' },
    provider: { Grant: { find: jest.fn(async (id: string) => ({ id })) } },
  },
});

const verified = [{ role: 'OWNER', tenant: { id: 'a', name: 'A', logoUrl: null, kybStatus: 'VERIFIED', kybProfile: {} } }];

describe('loadExistingGrant', () => {
  it('a remembered grant is reused when companies are not requested', async () => {
    const db: any = { tenantMember: { findMany: jest.fn() } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid profile', remembered: 'g-old' }))).toEqual({ id: 'g-old' });
    expect(db.tenantMember.findMany).not.toHaveBeenCalled();
  });

  it('companies requested and an eligible company exists → no grant, consent screen shows', async () => {
    const db: any = { tenantMember: { findMany: jest.fn().mockResolvedValue(verified) } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid companies', remembered: 'g-old' }))).toBeUndefined();
  });

  it('companies requested but nothing eligible → remembered grant as usual', async () => {
    const db: any = { tenantMember: { findMany: jest.fn().mockResolvedValue([]) } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid companies', remembered: 'g-old' }))).toEqual({ id: 'g-old' });
  });

  it('the consent just given in this interaction is always used — no consent loop', async () => {
    const db: any = { tenantMember: { findMany: jest.fn().mockResolvedValue(verified) } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid companies', fresh: 'g-new', remembered: 'g-old' }))).toEqual({ id: 'g-new' });
  });

  it('nothing remembered → undefined', async () => {
    const db: any = { tenantMember: { findMany: jest.fn() } };
    expect(await createLoadExistingGrant(db)(ctx({ scope: 'openid' }))).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/companies/load-existing-grant.spec.ts`
Expected: FAIL — модуль не найден.

- [ ] **Step 3: Implementation**

`src/companies/load-existing-grant.ts`:

```ts
import { COMPANIES_SCOPE } from './companies.constants';
import { loadCompanies } from './company-eligibility';

/**
 * loadExistingGrant для oidc-provider: выбор «войти как» — на каждом входе.
 *
 * Запомненное согласие не подставляем, если сайт просит `companies`, а у
 * человека есть подходящая компания, — тогда провайдер покажет экран
 * согласия. Согласие, данное в этом же взаимодействии (result.consent),
 * подставляем всегда, иначе экран показывался бы по кругу. В остальном —
 * поведение oidc-provider по умолчанию.
 */
export function createLoadExistingGrant(db: any) {
  return async (ctx: any) => {
    const oidc = ctx.oidc;
    const fresh = oidc.result?.consent?.grantId;
    if (fresh) return oidc.provider.Grant.find(fresh);

    const accountId = oidc.session?.accountId;
    const scopes = String(oidc.params?.scope ?? '').split(' ');
    if (accountId && scopes.includes(COMPANIES_SCOPE)) {
      const { eligible } = await loadCompanies(db, accountId);
      if (eligible.length > 0) return undefined;
    }

    const remembered = oidc.session?.grantIdFor(oidc.client.clientId);
    return remembered ? oidc.provider.Grant.find(remembered) : undefined;
  };
}
```

`src/oidc/oidc-provider.factory.ts`:
1. Импорты:
```ts
import { COMPANIES_SCOPE } from '../companies/companies.constants';
import { companyClaimsFor } from '../companies/company-claims';
import { createLoadExistingGrant } from '../companies/load-existing-grant';
```
2. В `claims` после `wallet: ['wallet_address'],`:
```ts
      [COMPANIES_SCOPE]: ['acting_as', 'companies'],
```
3. В `scopes` после `'wallet',`:
```ts
      // Только клиентам, которым выдан вручную; через DCR не получить
      // (prisma-client-adapter). Спека 2026-11-19-companies-oauth-design.md.
      COMPANIES_SCOPE,
```
4. После блока `interactions: { … },`:
```ts
    loadExistingGrant: createLoadExistingGrant(config.prisma),
```
5. Сигнатура и claims в `findAccount`:
```ts
    findAccount: async (_ctx: any, sub: string, token?: any) => {
```
и в `claims(_use, scope)` переименовать `_use` в `use`, перед `return result;`:
```ts
          // Только в /oauth/me: в ID-токен claims из scope при входе с кодом не
          // идут (conformIdTokenClaims). Выбор берём по согласию этого входа.
          if (scopes.includes(COMPANIES_SCOPE) && use === 'userinfo') {
            Object.assign(result, await companyClaimsFor(config.prisma, sub, token?.grantId));
          }
```

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/companies src/oidc && npx tsc --noEmit -p tsconfig.build.json && echo ok`
Expected: `src/companies` проходит; `src/oidc` — как в базе; `ok`.

- [ ] **Step 5: Commit**

```bash
git add src/companies/load-existing-grant.ts src/companies/load-existing-grant.spec.ts src/oidc/oidc-provider.factory.ts
git commit -qm "feat(oidc): scope companies — acting_as и companies в /oauth/me, выбор на каждом входе

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: `companies` не через DCR; описание scope

**Files:**
- Modify: `src/oidc/adapters/prisma-client-adapter.ts:90-94`, `src/oauth-mobile/scope-descriptors.ts`
- Test: `src/oidc/adapters/prisma-client-adapter.spec.ts`, `src/oauth-mobile/scope-descriptors.spec.ts`

- [ ] **Step 1: Failing tests**

В `prisma-client-adapter.spec.ts` после теста про `messenger`:

```ts
  it('upsert strips companies: company data only for clients granted it by hand', async () => {
    prisma.oAuthClient.findUnique.mockResolvedValue(null);
    await adapter.upsert('dyn-client-3', {
      client_name: 'Someone',
      redirect_uris: ['https://example.com/cb'],
      token_endpoint_auth_method: 'none',
      scope: 'openid companies profile',
    }, 0);
    const createCall = prisma.oAuthClient.create.mock.calls[0][0];
    expect(createCall.data.dcrMetadata.scope).toBe('openid profile');
    expect(createCall.data.allowedScopes).toEqual(['openid', 'profile']);
  });
```

В `scope-descriptors.spec.ts`:

```ts
  it('describes companies', () => {
    expect(describeScopes(['companies'])[0]).toEqual({
      key: 'companies',
      label: 'Компании',
      description: 'Вход от имени компании и данные выбранных компаний, прошедших KYB',
    });
  });
```

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/oidc/adapters/prisma-client-adapter.spec.ts src/oauth-mobile/scope-descriptors.spec.ts`
Expected: 2 FAIL.

- [ ] **Step 3: Implementation**

`prisma-client-adapter.ts`: импорт `import { COMPANIES_SCOPE } from '../../companies/companies.constants';` и фильтр:

```ts
      // offline_access — только для проверенных партнёров, messenger — только
      // для партнёрского API, companies — только выданным вручную: через
      // открытую регистрацию их не получить.
      .filter(
        (s) => s && s !== 'offline_access' && s !== MESSENGER_SCOPE && s !== COMPANIES_SCOPE,
      )
```

`scope-descriptors.ts`, в `KNOWN_SCOPES` после `email`:

```ts
  companies: {
    label: 'Компании',
    description: 'Вход от имени компании и данные выбранных компаний, прошедших KYB',
  },
```

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/oidc/adapters/prisma-client-adapter.spec.ts src/oauth-mobile/scope-descriptors.spec.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/oidc/adapters/prisma-client-adapter.ts src/oidc/adapters/prisma-client-adapter.spec.ts src/oauth-mobile/scope-descriptors.ts src/oauth-mobile/scope-descriptors.spec.ts
git commit -qm "feat(oidc): scope companies не выдаётся через DCR, описание для согласия

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Веб-согласие — данные и приём выбора

**Files:**
- Modify: `src/oidc/oidc-interaction.controller.ts`, `src/oidc/oidc.module.ts`
- Test: `src/oidc/oidc-interaction.companies.spec.ts`

- [ ] **Step 1: Failing test**

```ts
import { BadRequestException } from '@nestjs/common';
import { OidcInteractionController } from './oidc-interaction.controller';

describe('OidcInteractionController — companies', () => {
  let oidc: any;
  let companies: any;
  let prisma: any;
  let ctrl: OidcInteractionController;
  const res = () => ({ json: jest.fn((x) => x), setHeader: jest.fn(), send: jest.fn() });
  const req = (accept = 'application/json') => ({ headers: { accept }, ip: '1.1.1.1' });
  const grantSave = jest.fn().mockResolvedValue('g-1');

  beforeEach(() => {
    oidc = {
      getInteractionDetails: jest.fn().mockResolvedValue({
        prompt: { name: 'consent' },
        params: { client_id: 'trientes', scope: 'openid profile companies' },
        session: { accountId: 'u' },
      }),
      findClient: jest.fn().mockResolvedValue({ name: 'Trientes', logoUri: null }),
      getProvider: () => ({
        Grant: jest.fn().mockImplementation(() => ({ addOIDCScope: jest.fn(), save: grantSave })),
      }),
      resolveInteractionRedirect: jest.fn().mockResolvedValue('https://trientes.org/cb?code=x'),
    };
    companies = {
      consentBlock: jest.fn().mockResolvedValue({ person: { name: 'Иван' }, eligible: [], unverified: [], last_selection: null }),
      validate: jest.fn().mockResolvedValue({ actAsTenantId: 'a', sharedTenantIds: ['a'] }),
      save: jest.fn().mockResolvedValue(undefined),
    };
    prisma = { auditLog: { create: jest.fn() } };
    ctrl = new OidcInteractionController(oidc, prisma, {} as any, companies);
    grantSave.mockClear();
  });

  it('consent details carry the companies block when companies is requested', async () => {
    const out: any = await ctrl.interaction('uid', req(), res());
    expect(companies.consentBlock).toHaveBeenCalledWith('u', 'trientes');
    expect(out.companies).toEqual({ person: { name: 'Иван' }, eligible: [], unverified: [], last_selection: null });
  });

  it('no companies block when companies is not requested', async () => {
    oidc.getInteractionDetails.mockResolvedValue({
      prompt: { name: 'consent' }, params: { client_id: 'x', scope: 'openid' }, session: { accountId: 'u' },
    });
    const out: any = await ctrl.interaction('uid', req(), res());
    expect(out.companies).toBeUndefined();
  });

  it('consent validates the choice before the grant and stores it under the grant id', async () => {
    await ctrl.consent('uid', { act_as: 'a', company_ids: ['a'] }, req(), res());
    expect(companies.validate).toHaveBeenCalledWith('u', { actAs: 'a', companyIds: ['a'] });
    expect(companies.save).toHaveBeenCalledWith({
      grantId: 'g-1', userId: 'u', clientId: 'trientes', selection: { actAsTenantId: 'a', sharedTenantIds: ['a'] },
    });
    expect(companies.validate.mock.invocationCallOrder[0]).toBeLessThan(grantSave.mock.invocationCallOrder[0]);
  });

  it('a forged company: 400 and no grant', async () => {
    companies.validate.mockRejectedValue(new BadRequestException('company zzz is not available'));
    await expect(ctrl.consent('uid', { act_as: 'zzz' }, req(), res())).rejects.toBeInstanceOf(BadRequestException);
    expect(grantSave).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/oidc/oidc-interaction.companies.spec.ts`
Expected: FAIL (конструктор без 4-го аргумента, нет `companies` в ответе).

- [ ] **Step 3: Implementation**

`oidc-interaction.controller.ts`:
- импорты: `import { COMPANIES_SCOPE } from '../companies/companies.constants';` и `import { CompanyConsentService } from '../companies/company-consent.service';`
- конструктор: `private readonly companies: CompanyConsentService,` после `redis`.
- в ветке `if (prompt.name === 'consent')` перед `return res.json({`:

```ts
      const accountId = details.session?.accountId as string | undefined;
      const companies =
        accountId && consentScopes.includes(COMPANIES_SCOPE)
          ? await this.companies.consentBlock(accountId, params.client_id as string)
          : undefined;
```
и в объект ответа после `scopeDescriptions: …,` добавить `companies,`.

- в `consent(...)`, сразу после проверки `if (!session?.accountId)`:

```ts
    const requestedScopes = (params.scope as string).split(' ');
    const approvedScopes: string[] = body.approved_scopes || requestedScopes;
    // Выбор компаний проверяем до создания согласия: неподходящая — 400.
    const selection = approvedScopes.includes(COMPANIES_SCOPE)
      ? await this.companies.validate(session.accountId, {
          actAs: body.act_as,
          companyIds: body.company_ids,
        })
      : null;
```
удалить старые две строки `const requestedScopes …` / `const approvedScopes …` ниже, а после `const grantId = await grant.save();`:

```ts
    if (selection) {
      await this.companies.save({
        grantId,
        userId: session.accountId,
        clientId: params.client_id,
        selection,
      });
    }
```
- в `@ApiBody` консента добавить свойства `act_as` (`'person'` или id компании) и `company_ids` (массив id).

`oidc.module.ts`: `imports: [CompaniesModule],` (импорт `import { CompaniesModule } from '../companies/companies.module';`).

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/oidc && npx tsc --noEmit -p tsconfig.build.json && echo ok`
Expected: новый набор 4 passed; остальные `src/oidc` — как в базе (спеки, где контроллер создаётся `new OidcInteractionController(a, b, c)`, получат `undefined` четвёртым аргументом — для не-companies путей это безопасно; если какой-то набор собирает контроллер через `Test.createTestingModule`, добавить в providers `{ provide: CompanyConsentService, useValue: {} }`).

- [ ] **Step 5: Commit**

```bash
git add src/oidc/oidc-interaction.controller.ts src/oidc/oidc.module.ts src/oidc/oidc-interaction.companies.spec.ts
git commit -qm "feat(oidc): веб-согласие отдаёт блок компаний и принимает выбор

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: Страница согласия — выбор «войти как» и «что передать»

**Files:**
- Modify: `public/consent.html` (CSS, разметка `#view-consent`, словари `T`, `ICONS`, `SCOPES`, `renderConsent`, `doConsent`)

Автотестов у страницы нет; проверка — в браузере (Step 6).

- [ ] **Step 1: Разметка** — в `#view-consent` после `<div class="scopes" id="scope-list"></div>`:

```html
      <div id="companies" hidden>
        <p class="eyebrow" data-i18n="actAsLabel"></p>
        <div class="choices" id="act-as-list" role="radiogroup"></div>
        <p class="eyebrow" data-i18n="shareLabel"></p>
        <div class="choices" id="share-list"></div>
        <p class="hint" id="unverified-hint" hidden></p>
      </div>
```

- [ ] **Step 2: Стили** — в конец `<style>`:

```css
.choices { display: grid; gap: 8px; margin: 8px 0 16px; }
.choice { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border: 1px solid var(--hair); border-radius: 12px; background: var(--inset); cursor: pointer; }
.choice input { accent-color: currentColor; }
.choice .choice-name { font-size: 14px; }
.choice .choice-meta { font-size: 12px; color: var(--muted); }
.choice[aria-disabled='true'] { opacity: .7; cursor: default; }
.hint { font-size: 12px; line-height: 1.45; color: var(--muted); margin-bottom: 12px; }
```

- [ ] **Step 3: Тексты и значок** — в `T.ru` / `T.en` добавить:

```js
      actAsLabel: 'Войти как',
      shareLabel: 'Передать данные компаний',
      kybPassed: 'KYB пройден',
      you: 'вы',
      unverifiedHint: 'Не прошли KYB: {names}. Пройдите проверку компании в приложении Taler ID — тогда её можно будет выбрать.',
```
```js
      actAsLabel: 'Sign in as',
      shareLabel: 'Share company details',
      kybPassed: 'KYB verified',
      you: 'you',
      unverifiedHint: 'Not KYB-verified: {names}. Verify the company in the Taler ID app to be able to choose it.',
```
в `ICONS`: `building: svg('<path d="M4 20.5V5.5A1.5 1.5 0 0 1 5.5 4h7A1.5 1.5 0 0 1 14 5.5v15M14 9.5h4.5A1.5 1.5 0 0 1 20 11v9.5M2.5 20.5h19M7.5 8h3M7.5 12h3M7.5 16h3"/>'),`
в `SCOPES`: `companies: { icon: 'building', ru: ['Компании', 'Вход от имени компании и данные выбранных компаний, прошедших KYB'], en: ['Companies', 'Sign in as a company and share chosen KYB-verified companies'] },`

- [ ] **Step 4: Логика** — в `state` добавить `selection: null`; в конец `renderConsent(data)` — `renderCompanies(data.companies);`; рядом с `renderConsent` новые функции:

```js
  // Выбор «войти как» и «что передать» (спека 2026-11-19-companies-oauth).
  // Блок виден, только если сайт просит companies и есть подходящая компания.
  function renderCompanies(block) {
    var box = $('companies');
    var eligible = (block && block.eligible) || [];
    box.hidden = eligible.length === 0;
    var hint = $('unverified-hint');
    var unverified = (block && block.unverified) || [];
    hint.hidden = unverified.length === 0;
    hint.textContent = unverified.length
      ? t('unverifiedHint').replace('{names}', unverified.map(function (c) { return c.name; }).join(', '))
      : '';
    if (!eligible.length) { state.selection = null; return; }

    if (!state.selection) {
      var last = block.last_selection || { act_as: 'person', company_ids: [] };
      state.selection = { actAs: last.act_as, companyIds: last.company_ids.slice() };
    }
    var sel = state.selection;

    var actList = $('act-as-list');
    actList.textContent = '';
    var options = [{ id: 'person', name: block.person.name || t('you'), meta: t('you') }]
      .concat(eligible.map(function (c) { return { id: c.id, name: c.legal_name || c.name, meta: t('kybPassed') }; }));
    options.forEach(function (o) {
      actList.appendChild(choice('radio', 'act-as', o, sel.actAs === o.id, false, function () {
        sel.actAs = o.id;
        if (o.id !== 'person' && sel.companyIds.indexOf(o.id) === -1) sel.companyIds.push(o.id);
        renderCompanies(block);
      }));
    });

    var shareList = $('share-list');
    shareList.textContent = '';
    eligible.forEach(function (c) {
      var locked = sel.actAs === c.id;
      var checked = locked || sel.companyIds.indexOf(c.id) !== -1;
      shareList.appendChild(choice('checkbox', 'share', { id: c.id, name: c.legal_name || c.name, meta: t('kybPassed') }, checked, locked, function (on) {
        sel.companyIds = sel.companyIds.filter(function (x) { return x !== c.id; });
        if (on) sel.companyIds.push(c.id);
      }));
    });
  }

  function choice(type, name, o, checked, locked, onChange) {
    var label = document.createElement('label');
    label.className = 'choice';
    if (locked) label.setAttribute('aria-disabled', 'true');
    var input = document.createElement('input');
    input.type = type;
    input.name = name;
    input.checked = checked;
    input.disabled = locked;
    input.addEventListener('change', function () { onChange(input.checked); });
    var text = document.createElement('div');
    var n = document.createElement('div');
    n.className = 'choice-name';
    n.textContent = o.name;
    var m = document.createElement('div');
    m.className = 'choice-meta';
    m.textContent = o.meta;
    text.appendChild(n);
    text.appendChild(m);
    label.appendChild(input);
    label.appendChild(text);
    return label;
  }
```
и в `doConsent()` заменить `body: JSON.stringify({}),` на:

```js
        body: JSON.stringify(state.selection
          ? { act_as: state.selection.actAs, company_ids: state.selection.companyIds }
          : {}),
```

- [ ] **Step 5: Commit**

```bash
git add public/consent.html
git commit -qm "feat(consent): выбор «войти как» и «передать данные компаний» на странице согласия

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Проверка в браузере** — после задач 15 и 18 (нужны проверенная компания и клиент на DEV/TEST). Playwright: открыть `https://<хост>/oauth/auth?client_id=companies-e2e&redirect_uri=http://localhost:19999/cb&response_type=code&scope=openid%20profile%20companies&code_challenge=<S256>&code_challenge_method=S256&state=x`, войти `integration_test@taler-test.com`, убедиться: два блока, «вы» и «E2E Verified Co», отметка компании из «войти как» заблокирована; «Разрешить» уводит на `http://localhost:19999/cb?code=…`. Повторный вход — экран снова показывается, отметки как в прошлый раз.

---

### Task 14: Мобильные ручки — блок компаний, выбор, конфиденциальные клиенты

**Files:**
- Modify: `src/oauth-mobile/oauth-mobile.service.ts`, `src/oauth-mobile/dto/oauth-approve.dto.ts`, `src/oauth-mobile/oauth-mobile.module.ts`
- Test: `src/oauth-mobile/oauth-mobile.service.spec.ts`

- [ ] **Step 1: Failing tests**

В `src/oauth-mobile/oauth-mobile.service.spec.ts`:

1. Импорт `import { CompanyConsentService } from '../companies/company-consent.service';`.
2. В обоих `describe` (`getGrantInfo` и `approve`) — `let companies: any;`, в `beforeEach` до `Test.createTestingModule`:
```ts
    companies = {
      consentBlock: jest.fn(),
      validate: jest.fn().mockResolvedValue({ actAsTenantId: null, sharedTenantIds: [] }),
      save: jest.fn().mockResolvedValue(undefined),
    };
```
и в `providers`: `{ provide: CompanyConsentService, useValue: companies },`.
3. Тест `getGrantInfo` «throws BadRequestException with error=confidential_client_not_supported_via_mobile for confidential client» заменить на:
```ts
  it('serves a confidential client (a site with a secret) — PKCE binds the code', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
    prisma.oAuthGrant.findFirst.mockResolvedValue(null);
    await expect(svc.getGrantInfo('user-1', baseParams)).resolves.toMatchObject({ client_name: 'MyBook' });
  });
```
4. Такой же тест в `describe('OAuthMobileService.approve')` заменить на:
```ts
  it('approves for a confidential client too', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'client_secret_basic',
    });
    const out = await svc.approve('user-1', baseParams);
    expect(out.redirect_uri).toContain('code=code-value-XYZ');
  });
```
5. Новые тесты в `describe('OAuthMobileService.getGrantInfo')`:
```ts
  const companiesClient = {
    clientId: 'mybook',
    clientName: 'MyBook',
    redirectUris: ['https://example.com/cb'],
    scope: 'openid profile companies',
    tokenEndpointAuthMethod: 'client_secret_basic',
  };

  it('carries the companies block and is never "remembered" when a company can be chosen', async () => {
    providerMock.Client.find.mockResolvedValue(companiesClient);
    prisma.oAuthGrant.findFirst.mockResolvedValue({ scope: 'openid profile companies' });
    companies.consentBlock.mockResolvedValue({
      person: { name: 'Иван' }, eligible: [{ id: 'a' }], unverified: [], last_selection: null,
    });
    const info = await svc.getGrantInfo('user-1', { ...baseParams, scope: 'openid profile companies' });
    expect(companies.consentBlock).toHaveBeenCalledWith('user-1', 'mybook');
    expect(info.companies?.eligible).toEqual([{ id: 'a' }]);
    expect(info.remembered).toBe(false);
  });

  it('no companies scope → no block', async () => {
    providerMock.Client.find.mockResolvedValue({
      clientId: 'mybook',
      clientName: 'MyBook',
      redirectUris: ['https://example.com/cb'],
      scope: 'profile email',
      tokenEndpointAuthMethod: 'none',
    });
    prisma.oAuthGrant.findFirst.mockResolvedValue(null);
    const info = await svc.getGrantInfo('user-1', baseParams);
    expect(info.companies).toBeUndefined();
    expect(companies.consentBlock).not.toHaveBeenCalled();
  });
```
6. Новые тесты в `describe('OAuthMobileService.approve')`:
```ts
  const companiesClient = {
    clientId: 'mybook',
    clientName: 'MyBook',
    redirectUris: ['https://example.com/cb'],
    scope: 'openid companies',
    tokenEndpointAuthMethod: 'client_secret_basic',
  };

  it('validates the company choice before the grant and stores it under the grant', async () => {
    providerMock.Client.find.mockResolvedValue(companiesClient);
    companies.validate.mockResolvedValue({ actAsTenantId: 'a', sharedTenantIds: ['a'] });
    await svc.approve('user-1', { ...baseParams, scope: 'openid companies', act_as: 'a', company_ids: ['a'] });
    expect(companies.validate).toHaveBeenCalledWith('user-1', { actAs: 'a', companyIds: ['a'] });
    expect(companies.save).toHaveBeenCalledWith({
      grantId: 'grant-jti-789', userId: 'user-1', clientId: 'mybook',
      selection: { actAsTenantId: 'a', sharedTenantIds: ['a'] },
    });
    expect(companies.validate.mock.invocationCallOrder[0])
      .toBeLessThan(providerMock._grantSpy.mock.invocationCallOrder[0]);
  });

  it('a forged company: 400 and no grant', async () => {
    providerMock.Client.find.mockResolvedValue(companiesClient);
    companies.validate.mockRejectedValue(new BadRequestException('company zzz is not available'));
    await expect(
      svc.approve('user-1', { ...baseParams, scope: 'openid companies', act_as: 'zzz' }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(providerMock._grantSpy).not.toHaveBeenCalled();
  });
```

- [ ] **Step 2: Run, expect FAIL**

Run: `npx jest src/oauth-mobile`
Expected: новые тесты FAIL.

- [ ] **Step 3: Implementation**

`dto/oauth-approve.dto.ts`: импорт `IsArray` и поля в конец класса:

```ts
  /** 'person' или id компании (scope companies). */
  @IsOptional()
  @IsString()
  act_as?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  company_ids?: string[];
```

`oauth-mobile.service.ts`:
- импорты: `import { COMPANIES_SCOPE } from '../companies/companies.constants';`, `import { CompanyConsentBlock, CompanyConsentService } from '../companies/company-consent.service';`
- в `GrantInfo` поле `companies?: CompanyConsentBlock;`
- конструктор: `private readonly companies: CompanyConsentService,`
- в `getGrantInfo` после вычисления `remembered`:

```ts
    // С компаниями выбор «войти как» — на каждом входе: «запомнено» тогда нет.
    const companies = requestedScopes.includes(COMPANIES_SCOPE)
      ? await this.companies.consentBlock(userId, params.client_id)
      : undefined;
    if (companies && companies.eligible.length > 0) remembered = false;
```
и `companies,` в возвращаемый объект.
- в `approve` перед `const provider = this.oidc.getProvider();`:

```ts
    const selection = requestedScope.split(' ').includes(COMPANIES_SCOPE)
      ? await this.companies.validate(userId, { actAs: params.act_as, companyIds: params.company_ids })
      : null;
```
после `await grant.save();`:

```ts
    if (selection) {
      await this.companies.save({ grantId: grant.jti, userId, clientId: params.client_id, selection });
    }
```
- в `findAndValidateClient` удалить блок `if (client.tokenEndpointAuthMethod !== 'none') { … }` целиком и поставить на его место комментарий:

```ts
    // Конфиденциальные клиенты (сайты с сервером и секретом) тоже проходят:
    // PKCE обязателен всем, а код на токены обменивает только сервер сайта со
    // своим секретом. Раньше такой вход на телефоне с Taler ID кончался
    // ошибкой — App Links перехватывают /oauth/auth независимо от типа клиента.
```

`oauth-mobile.module.ts`: `imports: [OidcModule, CompaniesModule],`.

- [ ] **Step 4: Run, expect PASS**

Run: `npx jest src/oauth-mobile && npx tsc --noEmit -p tsconfig.build.json && echo ok`
Expected: PASS, `ok`.

- [ ] **Step 5: Commit**

```bash
git add src/oauth-mobile
git commit -qm "feat(oauth-mobile): выбор компаний в мобильном согласии, сайты с секретом тоже

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 15: Сид для e2e — проверенная компания и OAuth-клиент

**Files:**
- Create: `scripts/seed-companies-e2e.ts`

- [ ] **Step 1: Скрипт**

```ts
/**
 * DEV/TEST: проверенная компания и OAuth-клиент для e2e-набора test:companies.
 * Спека: docs/superpowers/specs/2026-11-19-companies-oauth-design.md
 *
 * Компания «E2E Verified Co» принадлежит --owner (OWNER), KYB — VERIFIED,
 * снимок реквизитов — из фикстуры welID. Клиент companies-e2e —
 * конфиденциальный, redirect http://localhost:19999/cb, scopes
 * openid profile companies. Секрет — только в файл --out (права 600), строкой
 * COMPANIES_E2E_CLIENT_SECRET=…; без --rotate существующий не меняется.
 *
 * На PROD не запускается.
 *
 *   npx ts-node -r dotenv/config scripts/seed-companies-e2e.ts \
 *     --owner integration_test@taler-test.com --out ~/partner-keys/companies-e2e.env [--rotate]
 */
import { PrismaClient } from '@prisma/client';
import { randomBytes } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { mapWelidCompany } from '../src/kyb/welid-company.mapper';

const COMPANY = 'E2E Verified Co';
const CLIENT_ID = 'companies-e2e';
const prisma = new PrismaClient();

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  const base = process.env.BASE_URL ?? process.env.OIDC_ISSUER ?? '';
  if (/talerid\.io/.test(base)) throw new Error(`refusing on PROD (${base})`);
  const ownerEmail = arg('owner');
  const out = arg('out');
  if (!ownerEmail || !out) throw new Error('usage: --owner <email> --out <file> [--rotate]');

  const owner = await prisma.user.findFirstOrThrow({ where: { email: ownerEmail } });
  let membership = await prisma.tenantMember.findFirst({
    where: { userId: owner.id, role: 'OWNER', tenant: { name: COMPANY } },
  });
  if (!membership) {
    const tenant = await prisma.tenant.create({
      data: { name: COMPANY, members: { create: { userId: owner.id, role: 'OWNER' } } },
    });
    membership = await prisma.tenantMember.findFirstOrThrow({ where: { tenantId: tenant.id, userId: owner.id } });
  }
  const tenantId = membership.tenantId;

  const fixture = JSON.parse(
    fs.readFileSync(path.join(__dirname, '../src/kyb/__fixtures__/welid-company-applicant.json'), 'utf8'),
  );
  const { raw, ...fields } = mapWelidCompany({ ...fixture, id: `e2e-${tenantId}` });
  const data = { ...fields, raw: raw as object, verifiedAt: new Date() };
  await prisma.$transaction([
    prisma.tenant.update({ where: { id: tenantId }, data: { kybStatus: 'VERIFIED' } }),
    prisma.companyKybProfile.upsert({ where: { tenantId }, create: { tenantId, ...data }, update: data }),
  ]);

  const existing = await prisma.oAuthClient.findUnique({ where: { clientId: CLIENT_ID } });
  if (!existing || process.argv.includes('--rotate')) {
    const secret = randomBytes(32).toString('hex');
    await prisma.oAuthClient.upsert({
      where: { clientId: CLIENT_ID },
      create: {
        clientId: CLIENT_ID,
        clientSecret: secret,
        name: 'Companies e2e',
        redirectUris: ['http://localhost:19999/cb'],
        allowedScopes: ['openid', 'profile', 'companies'],
      },
      update: { clientSecret: secret },
    });
    fs.appendFileSync(out, `COMPANIES_E2E_CLIENT_SECRET=${secret}\n`, { mode: 0o600 });
    fs.chmodSync(out, 0o600);
    console.log(`client ${CLIENT_ID}: secret written to ${out}`);
  } else {
    console.log(`client ${CLIENT_ID}: exists, secret unchanged (use --rotate)`);
  }
  console.log(`company ${COMPANY}: ${tenantId} VERIFIED, owner ${ownerEmail}`);
}

main().catch((e) => { console.error(e.message); process.exit(1); }).finally(() => prisma.$disconnect());
```

Проверить по `prisma-client-adapter.find`, что клиент с секретом и `redirectUris` получит `token_endpoint_auth_method: 'client_secret_basic'` и `grant_types: ['authorization_code', 'refresh_token']` — так и должно быть (не в `PUBLIC_CLIENTS`, redirect есть).

- [ ] **Step 2: Typecheck и commit**

```bash
npx tsc --noEmit -p tsconfig.json 2>&1 | grep seed-companies-e2e || echo ok
git add scripts/seed-companies-e2e.ts
git commit -qm "chore(companies): сид проверенной компании и OAuth-клиента для e2e

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: e2e-набор `test:companies`

**Files (репозиторий `~/Downloads/taler_id_tests`):**
- Create: `companies_test.ts`
- Modify: `package.json`, `.env.dev`, `.env.prod` (ключ `COMPANIES_E2E_CLIENT_SECRET` — **не коммитить**, файлы в `.gitignore`)

- [ ] **Step 1: Набор**

```ts
/**
 * Вход от имени компании через Taler ID (scope companies) — e2e.
 * Спека taler-id: docs/superpowers/specs/2026-11-19-companies-oauth-design.md
 *
 * Предусловие (сид на сервере окружения, один раз):
 *   npx ts-node -r dotenv/config scripts/seed-companies-e2e.ts \
 *     --owner integration_test@taler-test.com --out ~/partner-keys/companies-e2e.env
 * и COMPANIES_E2E_CLIENT_SECRET из этого файла — в .env.dev / .env.prod набора.
 *
 *   npm run test:companies        (DEV)
 *   npm run test:companies:prod   (TEST)
 */
import * as crypto from 'crypto';
import axios from 'axios';

const BASE_URL = process.env.BASE_URL ?? 'https://staging.id.taler.tirol';
const SECRET = process.env.COMPANIES_E2E_CLIENT_SECRET ?? '';
const CLIENT_ID = 'companies-e2e';
const REDIRECT_URI = 'http://localhost:19999/cb';
const SCOPE = 'openid profile companies';
const COMPANY = 'E2E Verified Co';
const USER1 = { email: 'integration_test@taler-test.com', password: 'IntegrationTest123!' };
const USER2 = { email: 'integration_test_2@taler-test.com', password: 'IntegrationTest123!' };

const http = axios.create({ baseURL: BASE_URL, validateStatus: () => true });
let passed = 0;
let failed = 0;
function check(name: string, cond: boolean, info?: unknown) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; } else { console.log(`  ✗ ${name}`, info ?? ''); failed++; }
}
const auth = (t: string) => ({ headers: { Authorization: `Bearer ${t}` } });

async function login(c: { email: string; password: string }) {
  const r = await http.post('/auth/login', c);
  if (r.status !== 200) throw new Error(`login ${c.email} ${r.status}`);
  return r.data.accessToken as string;
}

function pkce() {
  const verifier = crypto.randomBytes(40).toString('base64url');
  return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
}

function query(p: { challenge: string }) {
  return {
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: SCOPE, response_type: 'code',
    code_challenge: p.challenge, code_challenge_method: 'S256', state: 's',
  };
}

/** grant-info → approve (с выбором) → обмен кода → /oauth/me. */
async function signIn(jwt: string, selection: { act_as?: string; company_ids?: string[] }) {
  const p = pkce();
  const info = await http.get('/oauth/mobile/grant-info', { params: query(p), ...auth(jwt) });
  const approve = await http.post('/oauth/mobile/approve', { ...query(p), ...selection }, auth(jwt));
  if (approve.status !== 200 && approve.status !== 201) return { info, approve };
  const code = new URL(approve.data.redirect_uri).searchParams.get('code')!;
  const token = await http.post('/oauth/token',
    new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: p.verifier }).toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${SECRET}`).toString('base64')}` } });
  const accessToken = token.data?.access_token as string;
  const me = await http.get('/oauth/me', auth(accessToken));
  return { info, approve, token, accessToken, me };
}

async function main() {
  console.log(`\nCompanies e2e → ${BASE_URL}\n`);
  if (!SECRET) throw new Error('COMPANIES_E2E_CLIENT_SECRET is not set — see the header of this file');

  const jwt1 = await login(USER1);
  const tenants = await http.get('/tenant', auth(jwt1));
  const company = (tenants.data as any[]).find((t) => t.name === COMPANY);
  if (!company) throw new Error(`no "${COMPANY}" for ${USER1.email} — run scripts/seed-companies-e2e.ts on the server`);
  check('1. seeded company is KYB-verified', company.kybStatus === 'VERIFIED', company.kybStatus);

  // 2–4. Вход от имени компании
  const asCompany = await signIn(jwt1, { act_as: company.id, company_ids: [company.id] });
  const block = asCompany.info.data?.companies;
  check('2. grant-info offers the company', block?.eligible?.some((c: any) => c.id === company.id), block);
  check('2b. grant-info is never "remembered" with a company to choose', asCompany.info.data?.remembered === false);
  check('3. token exchange with the client secret → 200', asCompany.token?.status === 200, asCompany.token?.data);
  const me = asCompany.me?.data ?? {};
  check('4. /oauth/me acting_as is the company', me.acting_as?.type === 'company' && me.acting_as?.company_id === company.id, me.acting_as);
  const card = (me.companies ?? [])[0] ?? {};
  check('4b. its card is verified and filled from KYB', card.kyb_status === 'verified' && !!card.legal_name && card.role === 'OWNER', card);
  check('4c. logo is marked as not verified', card.logo_verified === false);

  // 5. Последний выбор — отметки по умолчанию
  const again = await http.get('/oauth/mobile/grant-info', { params: query(pkce()), ...auth(jwt1) });
  check('5. last selection remembered as defaults', again.data?.companies?.last_selection?.act_as === company.id, again.data?.companies?.last_selection);

  // 6. Вход физлицом без компаний
  const asPerson = await signIn(jwt1, { act_as: 'person', company_ids: [] });
  check('6. person sign-in: acting_as person, no companies',
    asPerson.me?.data?.acting_as?.type === 'person' && (asPerson.me?.data?.companies ?? []).length === 0, asPerson.me?.data);

  // 7. Подмена
  const forged = await signIn(jwt1, { act_as: crypto.randomUUID() });
  check('7. a company that is not yours → 400', forged.approve.status === 400, forged.approve.status);

  // 8–10. ADMIN может, VIEWER — нет; снятая роль видна сразу
  const jwt2 = await login(USER2);
  const me2 = await http.get('/profile', auth(jwt2));
  const user2Id = me2.data.id as string;
  await http.delete(`/tenant/${company.id}/members/${user2Id}`, auth(jwt1));
  const add = await http.post(`/tenant/${company.id}/members/invite`, { email: USER2.email, role: 'ADMIN' }, auth(jwt1));
  check('8. user2 added as ADMIN', add.status === 200 || add.status === 201, add.data);
  const asAdmin = await signIn(jwt2, { act_as: company.id, company_ids: [company.id] });
  check('8b. ADMIN signs in as the company', asAdmin.me?.data?.acting_as?.company_id === company.id && asAdmin.me?.data?.companies?.[0]?.role === 'ADMIN', asAdmin.me?.data);

  const demote = await http.put(`/tenant/${company.id}/members/${user2Id}/role`, { role: 'VIEWER' }, auth(jwt1));
  check('9. user2 demoted to VIEWER', demote.status === 200, demote.data);
  const after = await http.get('/oauth/me', auth(asAdmin.accessToken!));
  check('10. same token: acting_as revoked, card gone',
    after.data?.acting_as?.revoked === true && (after.data?.companies ?? []).length === 0, after.data);

  await http.delete(`/tenant/${company.id}/members/${user2Id}`, auth(jwt1));

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error('FATAL', e.message); process.exit(1); });
```

- [ ] **Step 2: Скрипты** — в `package.json` рядом с `test:mcp`:

```json
    "test:companies": "dotenv -e .env.dev -- npx ts-node companies_test.ts",
    "test:companies:prod": "dotenv -e .env.prod -- npx ts-node companies_test.ts",
```
(`BASE_URL` в `.env.dev` / `.env.prod` уже задан для партнёрского набора — проверить.)

- [ ] **Step 3: Commit** (только `companies_test.ts` и `package.json`, без `.env*`)

```bash
cd ~/Downloads/taler_id_tests && git add companies_test.ts package.json
git commit -qm "test: test:companies — вход от имени компании через Taler ID

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 17: Документация для trientes.org

**Files:**
- Create: `docs/talerid-companies-oauth.md`
- Modify: `public/oauth-guide.html` (новый `<h2 id="companies">` перед `<h2 id="errors">`, ссылка в оглавлении)

- [ ] **Step 1: `docs/talerid-companies-oauth.md`**

````markdown
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

Запрос: `scope=openid profile companies`, PKCE (S256) обязателен.

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
    "logo_url": "https://…",
    "logo_verified": false,
    "kyb_status": "verified",
    "kyb_verified_at": "2026-11-20T10:00:00Z",
    "role": "OWNER"
  }]
}
```

- `sub` — всегда человек. Компания — не отдельная учётная запись.
- `acting_as.type`: `person` — вошёл физлицом; `company` — от имени компании `company_id`.
- `acting_as.revoked: true` — с момента входа компания перестала быть доступной (сняли роль, отозвали KYB, удалили). Считайте, что человек больше не представляет компанию.
- `companies` — переданные компании; компания из `acting_as` есть в списке всегда.
- Проверены KYB: `legal_name`, `registration_number`, `tax_id`, `legal_form`, `incorporated_on`, `country`, `city`, `legal_address`, `website`. **Не проверены:** `name` (название в Taler ID, его меняет владелец) и `logo_url`.
- Поле, которого не было в анкете KYB, — `null`.
- `country` — как отдаёт welID (ISO 3166-1 alpha-3, например `RUS`).
- `company_id` постоянен — по нему связывайте карточку на сайте.

## Перепроверка

С `offline_access` (по согласованию) refresh-токен позволяет позже вызвать `/oauth/me` и увидеть `revoked` или исчезнувшую компанию без нового входа.

## Пример (Node.js, openid-client)

```ts
import { Issuer, generators } from 'openid-client';

const issuer = await Issuer.discover('https://api.talerid.io/oauth');
const client = new issuer.Client({
  client_id: process.env.TALERID_CLIENT_ID!,
  client_secret: process.env.TALERID_CLIENT_SECRET!,
  redirect_uris: ['https://trientes.org/auth/talerid/callback'],
  response_types: ['code'],
});

// /auth/talerid
const verifier = generators.codeVerifier();
const url = client.authorizationUrl({
  scope: 'openid profile companies',
  code_challenge: generators.codeChallenge(verifier),
  code_challenge_method: 'S256',
  state: generators.state(),
});

// /auth/talerid/callback
const tokens = await client.callback('https://trientes.org/auth/talerid/callback', client.callbackParams(req), { code_verifier: verifier, state });
const me = await client.userinfo(tokens.access_token!);
if (me.acting_as?.type === 'company' && !me.acting_as.revoked) {
  const card = me.companies.find((c: any) => c.company_id === me.acting_as.company_id);
  // предзаполнить карточку компании из card
}
```
````

- [ ] **Step 2: Раздел в `public/oauth-guide.html`** — перед `<h2 id="errors">`:

```html
    <h2 id="companies">Companies (sign in as a company)</h2>
    <p>Request the <code>companies</code> scope (granted to a client on request, not via dynamic registration). On every sign-in the user chooses whether to sign in as themselves or as one of their KYB-verified companies (where they are OWNER or ADMIN), and which companies to share.</p>
    <p><code>/oauth/me</code> then returns <code>acting_as</code> — <code>{"type":"person"}</code> or <code>{"type":"company","company_id":"…","name":"…"}</code>, with <code>"revoked": true</code> once the company is no longer available — and <code>companies</code>: the shared companies with KYB-verified details (<code>legal_name</code>, <code>registration_number</code>, <code>tax_id</code>, <code>country</code>, <code>city</code>, <code>legal_address</code>, …). <code>name</code> and <code>logo_url</code> are not verified. These claims are in the UserInfo response only, not in the ID token.</p>
    <pre><code class="lang-json">{
  "sub": "8d3c…",
  "acting_as": { "type": "company", "company_id": "6f1c…", "name": "Romashka" },
  "companies": [{ "company_id": "6f1c…", "legal_name": "Romashka LLC", "registration_number": "1027700132195", "country": "RUS", "kyb_status": "verified", "role": "OWNER" }]
}</code></pre>
```
и пункт оглавления рядом с остальными (`<a href="#companies">Companies</a>`) — по образцу соседних ссылок навигации.

- [ ] **Step 3: Commit**

```bash
cd ~/taler-id/.worktrees/companies-oauth
git add docs/talerid-companies-oauth.md public/oauth-guide.html
git commit -qm "docs: вход через Taler ID от имени компании — для интеграторов

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 18: Полный прогон и выкатка на DEV

**Files:** нет изменений.

- [ ] **Step 1: Полный прогон**

```bash
cd ~/taler-id/.worktrees/companies-oauth && npx jest 2>&1 | grep -E "^Tests:|^Test Suites:"; npx tsc --noEmit -p tsconfig.build.json && echo tsc-ok
```
Expected: падений не больше, чем в базе задачи 0; все новые наборы зелёные; `tsc-ok`.

- [ ] **Step 2: В `dev` и на DEV**

```bash
git fetch -q origin && git rebase -q origin/dev && git push -q origin HEAD:dev
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/taler-id && git pull -q && npx prisma migrate deploy && npx prisma generate >/dev/null && npm run build >/tmp/companies-build.log 2>&1 && pm2 restart taler-id-dev >/dev/null && sleep 8 && curl -s -o /dev/null -w health:%{http_code} http://localhost:\$(grep -E ^PORT= .env | cut -d= -f2 || echo 3000)/health"'
```
Expected: `health:200`, миграция `20261119120000_companies_oauth` применена.

- [ ] **Step 3: Сид и e2e на DEV**

```bash
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/taler-id && mkdir -p ~/partner-keys && npx ts-node -r dotenv/config scripts/seed-companies-e2e.ts --owner integration_test@taler-test.com --out ~/partner-keys/companies-e2e.env"'
```
Секрет из `~/partner-keys/companies-e2e.env` на DEV — в `.env.dev` набора (на маке: `ssh … 'cat …' >> ~/Downloads/taler_id_tests/.env.dev`). Затем:

```bash
cd ~/Downloads/taler_id_tests && npm run test:companies
```
Expected: `N passed, 0 failed`. С мака TLS до DEV может не проходить — тогда гонять с бот-сервера из временного клона, как партнёрский набор (CLAUDE.md, набор 20).

- [ ] **Step 4: Опросчик KYB вживую** — заодно проверить, что у одобренной анкеты welID `review.reviewStatus` равен именно `completed` (иначе опросчик молча ничего не делает; править `kyb-poller.service.ts`). — на DEV завести компанию в приложении, пройти KYB, одобрить в админке welID; в течение минуты: `pm2 logs taler-id-dev | grep "KYB poll"` → `→ VERIFIED (snapshot saved)`, у компании появился `CompanyKybProfile`.

- [ ] **Step 5: Веб-согласие в браузере** — задача 13, шаг 6.

- [ ] **Step 6: Регрессия входа** — `npm run test:mcp` и `npm run test:device-approval` на DEV (OAuth и вход не сломаны).

TEST и PROD — отдельными командами по указанию пользователя: тот же порядок (`migrate deploy` → build → restart), на PROD — rolling по нодам; сид на PROD не запускается, клиент Trientes заводится отдельно с redirect URI сайта.
