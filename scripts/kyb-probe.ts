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
