/**
 * Партнёры партнёрского API мессенджера (первый — nadi): выпуск, ключи, вебхук.
 * Спека: docs/superpowers/specs/2026-09-30-partner-messenger-api-design.md
 *
 * Запуск на сервере окружения из каталога бэкенда:
 *   npx ts-node -r dotenv/config scripts/partner-admin.ts <команда> [флаги]
 *
 * Ключ и секрет вебхука показываются один раз. С --out <файл> [--var ИМЯ] они
 * не печатаются, а дописываются в файл строкой ИМЯ=значение с правами 600 —
 * так секрет не оседает в истории терминала и в логах сессий.
 * Бэкенд кэширует партнёров 30 секунд — изменения доходят за это время.
 */
import { PrismaClient } from '@prisma/client';
import { randomBytes } from 'crypto';
import * as fs from 'fs';
import { isIP } from 'net';
import { generatePartnerKey, hashPartnerKey, isValidPartnerSlug } from '../src/partner-core/partner-key.util';
import { encryptWebhookSecret, generateWebhookSecret } from '../src/partner-core/partner-secrets.util';
import { MESSENGER_SCOPE } from '../src/partner-core/partner.constants';

const prisma = new PrismaClient();

type Flags = Record<string, string>;

const USAGE = `Использование: npx ts-node -r dotenv/config scripts/partner-admin.ts <команда> [флаги]
  create        --slug <slug> --name <имя> [--ips a,b] [--out файл [--var ИМЯ]]
  rotate-key    --slug <slug> [--out файл [--var ИМЯ]]
  set-webhook   --slug <slug> --url https://… [--out файл [--var ИМЯ]]
  clear-webhook --slug <slug>
  set-ips       --slug <slug> --ips a,b | --clear   (точные адреса, без CIDR; --clear — без ограничения)
  enable | disable --slug <slug>
  show          --slug <slug>`;

/**
 * Флаги команды. Незнакомый флаг — ошибка: опечатка `--ip` вместо `--ips`
 * иначе молча сняла бы белый список партнёра на PROD.
 */
function parseFlags(argv: string[], allowed: readonly string[]): Flags {
  const flags: Flags = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) throw new Error(`непонятный аргумент: ${arg}`);
    const name = arg.slice(2);
    if (!allowed.includes(name)) throw new Error(`флаг --${name} этой команде неизвестен`);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags[name] = next;
      i++;
    } else {
      flags[name] = '';
    }
  }
  return flags;
}

function slugOf(flags: Flags): string {
  const slug = flags.slug ?? '';
  if (!isValidPartnerSlug(slug)) throw new Error('--slug обязателен: a-z, 0-9 и дефис, 2–32 символа');
  return slug;
}

/**
 * Белый список — только точные адреса, как их видит бэкенд (IPv4 без ::ffff:).
 * Маски guard не понимает: запись с CIDR никогда бы не совпала.
 */
function ipsOf(value: string): string[] {
  const ips = value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (ips.length === 0) throw new Error('--ips без адресов; снять ограничение — set-ips --clear');
  for (const ip of ips) {
    if (isIP(ip) === 0 || /^::ffff:/i.test(ip)) {
      throw new Error(`не IP-адрес: ${ip} (нужен точный IPv4 или IPv6, без маски и без ::ffff:)`);
    }
  }
  return ips;
}

/** Секрет — в файл с правами 600, либо на экран, если файл не указан. */
function reveal(flags: Flags, defaultVar: string, value: string, what: string): void {
  if (flags.out) {
    const name = flags.var || defaultVar;
    fs.appendFileSync(flags.out, `${name}=${value}\n`, { mode: 0o600 });
    fs.chmodSync(flags.out, 0o600);
    console.log(`${what} записан в ${flags.out} как ${name}`);
  } else {
    console.log(`${what} (показывается один раз, передавать вне чатов):\n${value}`);
  }
}

async function partnerOrFail(slug: string) {
  const partner = await prisma.partner.findUnique({ where: { slug } });
  if (!partner) throw new Error(`партнёра ${slug} нет — сначала create`);
  return partner;
}

async function create(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  const name = flags.name;
  if (!name) throw new Error('--name обязателен: так партнёр называется в письмах людям');
  const ips = flags.ips === undefined ? [] : ipsOf(flags.ips);
  if (await prisma.partner.findUnique({ where: { slug } })) {
    throw new Error(`партнёр ${slug} уже есть — для нового ключа rotate-key`);
  }
  const clientId = `${slug}-partner`;
  const clientName = `${name} (partner messenger)`;
  // Чужой клиент не трогаем: `--slug linkeon` иначе переписал бы живой клиент
  // linkeon-partner и сломал бы Linkeon на PROD.
  if (await prisma.oAuthClient.findUnique({ where: { clientId } })) {
    throw new Error(`OAuth-клиент ${clientId} уже существует — это не наш клиент, выберите другой slug`);
  }
  const key = generatePartnerKey(slug);
  // Токены выпускает сам бэкенд; в /oauth/token с этим клиентом никто не ходит,
  // поэтому секрет клиента случайный и нигде, кроме БД, не нужен. Клиент и
  // партнёр — одной транзакцией: сбой не оставит клиента без партнёра.
  await prisma.$transaction([
    prisma.oAuthClient.create({
      data: {
        clientId,
        clientSecret: randomBytes(32).toString('hex'),
        name: clientName,
        redirectUris: [],
        allowedScopes: [MESSENGER_SCOPE],
        verifiedPartner: true,
        isDynamic: false,
      },
    }),
    prisma.partner.create({
      data: { slug, name, keyHash: hashPartnerKey(key), ipAllowlist: ips, oauthClientId: clientId },
    }),
  ]);
  console.log(`Партнёр ${slug} создан (OAuth-клиент ${clientId}).`);
  reveal(flags, 'TALERID_PARTNER_KEY', key, 'Ключ партнёра');
}

async function rotateKey(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  await partnerOrFail(slug);
  const key = generatePartnerKey(slug);
  await prisma.partner.update({ where: { slug }, data: { keyHash: hashPartnerKey(key) } });
  reveal(flags, 'TALERID_PARTNER_KEY', key, 'Новый ключ партнёра');
}

async function setWebhook(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  await partnerOrFail(slug);
  let url: URL;
  try {
    url = new URL(flags.url ?? '');
  } catch {
    throw new Error('--url должен быть полным адресом https://…');
  }
  if (url.protocol !== 'https:') throw new Error('вебхук только по https');
  const secret = generateWebhookSecret();
  await prisma.partner.update({
    where: { slug },
    data: { webhookUrl: url.toString(), webhookSecretEnc: encryptWebhookSecret(secret) },
  });
  console.log(`Вебхук ${slug} → ${url.toString()}`);
  reveal(flags, 'TALERID_WEBHOOK_SECRET', secret, 'Секрет вебхука');
}

async function clearWebhook(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  await partnerOrFail(slug);
  await prisma.partner.update({ where: { slug }, data: { webhookUrl: null, webhookSecretEnc: null } });
  console.log(`Вебхук ${slug} снят.`);
}

async function setIps(flags: Flags): Promise<void> {
  const slug = slugOf(flags);
  // Снять ограничение — только явно: пустой список пускает партнёра с любого адреса.
  if ((flags.ips === undefined) === (flags.clear === undefined)) {
    throw new Error('нужен ровно один из флагов: --ips a,b или --clear');
  }
  if (flags.clear) throw new Error('--clear пишется без значения');
  const ips = flags.clear !== undefined ? [] : ipsOf(flags.ips);
  await partnerOrFail(slug);
  await prisma.partner.update({ where: { slug }, data: { ipAllowlist: ips } });
  console.log(`IP ${slug}: ${ips.length ? ips.join(', ') : 'без ограничения'}`);
}

async function setEnabled(flags: Flags, enabled: boolean): Promise<void> {
  const slug = slugOf(flags);
  await partnerOrFail(slug);
  await prisma.partner.update({ where: { slug }, data: { enabled } });
  console.log(`Партнёр ${slug} ${enabled ? 'включён' : 'выключен'} (бэкенд увидит за 30 с).`);
}

async function show(flags: Flags): Promise<void> {
  const partner = await partnerOrFail(slugOf(flags));
  const links = await prisma.partnerLink.groupBy({
    by: ['status'],
    where: { partnerId: partner.id },
    _count: { _all: true },
  });
  console.log({
    slug: partner.slug,
    name: partner.name,
    enabled: partner.enabled,
    oauthClientId: partner.oauthClientId,
    ipAllowlist: partner.ipAllowlist,
    webhookUrl: partner.webhookUrl,
    webhookSecret: partner.webhookSecretEnc ? 'задан' : 'нет',
    links: Object.fromEntries(links.map((l) => [l.status, l._count._all])),
  });
}

const OUT = ['out', 'var'];
const COMMANDS: Record<string, { flags: readonly string[]; run: (flags: Flags) => Promise<void> }> = {
  create: { flags: ['slug', 'name', 'ips', ...OUT], run: create },
  'rotate-key': { flags: ['slug', ...OUT], run: rotateKey },
  'set-webhook': { flags: ['slug', 'url', ...OUT], run: setWebhook },
  'clear-webhook': { flags: ['slug'], run: clearWebhook },
  'set-ips': { flags: ['slug', 'ips', 'clear'], run: setIps },
  enable: { flags: ['slug'], run: (flags) => setEnabled(flags, true) },
  disable: { flags: ['slug'], run: (flags) => setEnabled(flags, false) },
  show: { flags: ['slug'], run: show },
};

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const entry =
    command && Object.prototype.hasOwnProperty.call(COMMANDS, command) ? COMMANDS[command] : undefined;
  if (!entry) {
    console.log(USAGE);
    process.exitCode = command && command !== 'help' ? 1 : 0;
    return;
  }
  await entry.run(parseFlags(rest, entry.flags));
}

main()
  .catch((e) => {
    console.error(`Ошибка: ${(e as Error).message}`);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
