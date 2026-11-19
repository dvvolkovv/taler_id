/**
 * DEV/TEST: проверенная компания и OAuth-клиент для e2e-набора test:companies.
 * Спека: docs/superpowers/specs/2026-11-19-companies-oauth-design.md
 *
 * Компания «E2E Verified Co» принадлежит --owner (OWNER), KYB — VERIFIED,
 * снимок реквизитов — из фикстуры welID: пройти KYB в welID по требованию
 * нельзя, поэтому статус и снимок пишутся напрямую. Номер заявки —
 * e2e-<tenantId>, чтобы засеянную компанию было видно сразу и не путали с
 * настоящей заявкой welID. Опросчик KYB её не трогает: он смотрит только
 * PENDING и VERIFIED без снимка.
 *
 * Клиент companies-e2e — конфиденциальный (client_secret_basic), redirect
 * http://localhost:19999/cb, scopes openid profile companies. Секрет — только
 * в файл --out (права 600), строкой COMPANIES_E2E_CLIENT_SECRET=…; на экран
 * не печатается. Без --rotate существующий секрет не меняется, но redirect и
 * scopes приводятся к нужным — повторный запуск чинит разъехавшуюся запись.
 *
 * На PROD не запускается. Белый список, а не чёрный: издатель (OIDC_ISSUER,
 * иначе BASE_URL + /oauth — как в src/config/configuration.ts) обязан быть на
 * staging.id.taler.tirol (DEV), id.taler.tirol (TEST) или localhost. Не задан
 * ни один — тоже отказ: молчаливого значения по умолчанию здесь нет.
 *
 *   npx ts-node -r dotenv/config scripts/seed-companies-e2e.ts \
 *     --owner integration_test@taler-test.com --out ~/partner-keys/companies-e2e.env [--rotate]
 */
import { Prisma, PrismaClient } from '@prisma/client';
import { randomBytes } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { mapWelidCompany } from '../src/kyb/welid-company.mapper';

const COMPANY = 'E2E Verified Co';
const CLIENT_ID = 'companies-e2e';
const REDIRECT_URIS = ['http://localhost:19999/cb'];
const SCOPES = ['openid', 'profile', 'companies'];
const SECRET_VAR = 'COMPANIES_E2E_CLIENT_SECRET';
const ALLOWED_HOSTS = new Set([
  'staging.id.taler.tirol',
  'id.taler.tirol',
  'localhost',
  '127.0.0.1',
]);

const USAGE =
  'usage: npx ts-node -r dotenv/config scripts/seed-companies-e2e.ts --owner <email> --out <file> [--rotate]';

const prisma = new PrismaClient();

/**
 * До любого обращения к базе. Проверяется издатель, как его считает бэкенд,
 * и BASE_URL, если задан: разъехавшаяся пара (издатель DEV, адрес PROD) —
 * тоже отказ.
 */
function assertDevOrTest(): void {
  const issuer =
    process.env.OIDC_ISSUER || `${process.env.BASE_URL || ''}/oauth`;
  const candidates = [issuer];
  if (process.env.BASE_URL) candidates.push(process.env.BASE_URL);
  for (const value of candidates) {
    let host: string;
    try {
      host = new URL(value).hostname;
    } catch {
      host = '';
    }
    if (!ALLOWED_HOSTS.has(host)) {
      throw new Error(`refusing: not DEV/TEST (${value})`);
    }
  }
}

/** Незнакомый флаг — ошибка: опечатка `--rotat` не должна молча пройти. */
function parseFlags(argv: string[]): { owner: string; out: string; rotate: boolean } {
  const values: { owner?: string; out?: string } = {};
  let rotate = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--rotate') {
      rotate = true;
    } else if (a === '--owner' || a === '--out') {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`${a} без значения\n${USAGE}`);
      }
      values[a === '--owner' ? 'owner' : 'out'] = value;
      i++;
    } else {
      throw new Error(`непонятный аргумент: ${a}\n${USAGE}`);
    }
  }
  if (!values.owner || !values.out) throw new Error(USAGE);
  return { owner: values.owner, out: values.out, rotate };
}

async function main(): Promise<void> {
  assertDevOrTest();
  const { owner: ownerEmail, out, rotate } = parseFlags(process.argv.slice(2));

  const owner = await prisma.user.findFirst({ where: { email: ownerEmail } });
  if (!owner) throw new Error(`пользователя ${ownerEmail} нет`);

  const existing = await prisma.oAuthClient.findUnique({
    where: { clientId: CLIENT_ID },
  });
  // Динамический клиент адаптер отдаёт из dcrMetadata, наши поля он бы
  // проигнорировал — и isDynamic этот скрипт не меняет никогда.
  if (existing?.isDynamic) {
    throw new Error(`клиент ${CLIENT_ID} — динамический (DCR), не трогаю`);
  }
  const needSecret = !existing || rotate;

  // Приёмник секрета — ДО изменений в базе: битый путь у --out не должен
  // всплыть уже после того, как секрет в базе сменился и потерян.
  let fd: number | undefined;
  if (needSecret) {
    fd = fs.openSync(out, 'a', 0o600);
    fs.fchmodSync(fd, 0o600);
  }

  try {
    // Компания: ищем среди тех, где --owner — OWNER; нет — заводим новую.
    const membership = await prisma.tenantMember.findFirst({
      where: { userId: owner.id, role: 'OWNER', tenant: { name: COMPANY } },
    });
    const tenantId =
      membership?.tenantId ??
      (
        await prisma.tenant.create({
          data: {
            name: COMPANY,
            members: { create: { userId: owner.id, role: 'OWNER' } },
          },
        })
      ).id;

    const fixture: unknown = JSON.parse(
      fs.readFileSync(
        path.join(__dirname, '../src/kyb/__fixtures__/welid-company-applicant.json'),
        'utf8',
      ),
    );
    const applicantId = `e2e-${tenantId}`;
    const { raw, ...fields } = mapWelidCompany({
      ...(fixture as Record<string, unknown>),
      id: applicantId,
    });
    const data = {
      ...fields,
      raw: raw as Prisma.InputJsonObject,
      verifiedAt: new Date(),
    };
    await prisma.$transaction([
      prisma.tenant.update({
        where: { id: tenantId },
        data: { kybStatus: 'VERIFIED', sumsubApplicantId: applicantId },
      }),
      prisma.companyKybProfile.upsert({
        where: { tenantId },
        create: { tenantId, ...data },
        update: data,
      }),
    ]);

    // Клиент: redirect и scopes — всегда, секрет — только новому или с --rotate.
    if (needSecret && fd !== undefined) {
      const secret = randomBytes(32).toString('hex');
      await prisma.oAuthClient.upsert({
        where: { clientId: CLIENT_ID },
        create: {
          clientId: CLIENT_ID,
          clientSecret: secret,
          name: 'Companies e2e',
          redirectUris: REDIRECT_URIS,
          allowedScopes: SCOPES,
          isDynamic: false,
        },
        update: {
          clientSecret: secret,
          redirectUris: REDIRECT_URIS,
          allowedScopes: SCOPES,
        },
      });
      fs.writeSync(fd, `${SECRET_VAR}=${secret}\n`);
      console.log(`client ${CLIENT_ID}: secret written to ${out} as ${SECRET_VAR}`);
    } else {
      await prisma.oAuthClient.update({
        where: { clientId: CLIENT_ID },
        data: { redirectUris: REDIRECT_URIS, allowedScopes: SCOPES },
      });
      console.log(
        `client ${CLIENT_ID}: exists, redirect/scopes ensured, secret unchanged (use --rotate)`,
      );
    }
    console.log(`company ${COMPANY}: ${tenantId} VERIFIED, owner ${ownerEmail}`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

main()
  .catch((e) => {
    console.error(`Ошибка: ${(e as Error).message}`);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
