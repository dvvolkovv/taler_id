#!/usr/bin/env node
'use strict';
/**
 * Проверка отзыва партнёрской связки на НАСТОЯЩЕМ oidc-provider.
 *
 * Спека обещает: отзыв связки гасит все её токены и сокеты сразу. Юнит-тесты
 * этого не доказывают — они подменяют провайдер, а дыры жили именно на стыке
 * oidc-provider, RedisOidcAdapter и гонок между выпуском токена и отзывом
 * (ревью 2026-09-30, C1). Здесь настоящие PartnerTokensService,
 * PartnerLinkRevokerService, PartnerRealtimeService и PartnerRegistryService
 * работают против настоящего oidc-provider и настоящего RedisOidcAdapter.
 * Подменены только Redis (словарь в памяти, умеет «падать») и Prisma (таблицы
 * связок и партнёров в памяти; каждый вызов атомарен, как UPDATE в Postgres).
 *
 * Сценарии:
 *   0. основа: токен выпускается и принимается; чужой gty и JWT приложения
 *      TalerID не принимаются.
 *   1. два параллельных выпуска для связки без гранта: раньше создавали два
 *      гранта, связка запоминала последний, токен проигравшего переживал отзыв.
 *   2. грант пропал (30 дней в Redis) и пересоздан, пока старые токены живы:
 *      раньше отзывался только новый грант. Заодно — токен не переживает свой
 *      грант и при настоящем истечении по часам.
 *   3. выпуск прочитал ACTIVE-связку, отзыв успел завершиться, выпуск идёт
 *      дальше: раньше писал новый грант в REVOKED-строку, и токен был жив.
 *      Плюс отзыв, попавший между чтением гранта и записью токена.
 *   4. Redis падает внутри отзыва: раньше строка уже была REVOKED с
 *      grantId = null, токен жил, а повтор ничего не делал.
 *   5. грант, которому осталось меньше минуты, заменяется новым, пока токен
 *      старого ещё жив: не уничтожь выпуск старый грант — связка на это время
 *      держала бы два живых гранта, и отзыв гасил бы только новый.
 *   6. /token старого человека прочитал связку, тот удалил аккаунт, а ту же
 *      externalId привязали к новому аккаунту (строка та же, grantId обнулён):
 *      без сверки пользователя в обмене грант удалённого повис бы на строке
 *      нового, и токен удалённого аккаунта принимался бы.
 *
 * Запуск из корня репозитория (нужен только node_modules, ни базы, ни Redis):
 *   node scripts/verify-partner-tokens.cjs [--verbose]
 * --verbose показывает логи Nest. Код выхода 1 — какое-то утверждение не выполнилось.
 */
const path = require('path');
const crypto = require('crypto');
const assert = require('assert/strict');

const ROOT = path.resolve(__dirname, '..');

require('ts-node').register({
  transpileOnly: true,
  project: path.join(ROOT, 'tsconfig.json'),
  // tsconfig рассчитан на сборку nest (nodenext), здесь исходники грузятся через require
  compilerOptions: { module: 'commonjs', moduleResolution: 'node', resolvePackageJsonExports: false },
});
require('reflect-metadata');

const { Logger, NotFoundException, ServiceUnavailableException } = require('@nestjs/common');
const src = (rel) => require(path.join(ROOT, 'src', rel));
const { RedisOidcAdapter } = src('oidc/adapters/redis-adapter.ts');
const { PartnerTokensService } = src('partner-core/partner-tokens.service.ts');
const { PartnerLinkRevokerService } = src('partner-core/partner-link-revoker.service.ts');
const { PartnerRealtimeService } = src('partner-core/partner-realtime.service.ts');
const { PartnerRegistryService } = src('partner-core/partner-registry.service.ts');
const { MESSENGER_SCOPE, PARTNER_TOKEN_GTY } = src('partner-core/partner.constants.ts');

if (!process.argv.includes('--verbose')) Logger.overrideLogger(false);

// Часы, которые можно перевести вперёд: по ним живут и oidc-provider, и FakeRedis.
const realNow = Date.now;
let skewMs = 0;
Date.now = () => realNow() + skewMs;
const epoch = () => Math.floor(Date.now() / 1000);

/** Подмножество ioredis, которым пользуется RedisOidcAdapter. down = true — Redis лежит. */
class FakeRedis {
  constructor() {
    this.kv = new Map();
    this.exp = new Map();
    this.down = false;
    this.writes = [];
  }
  _check() {
    if (this.down) throw new Error('redis down');
  }
  _alive(k) {
    const e = this.exp.get(k);
    if (e !== undefined && e <= Date.now()) {
      this.kv.delete(k);
      this.exp.delete(k);
    }
    return this.kv.has(k);
  }
  _set(k, v, ex, sec) {
    this.kv.set(k, v);
    if (ex === 'EX') this.exp.set(k, Date.now() + sec * 1000);
    else this.exp.delete(k);
    this.writes.push(k);
  }
  _del(k) {
    this.kv.delete(k);
    this.exp.delete(k);
  }
  async get(k) {
    this._check();
    return this._alive(k) ? this.kv.get(k) : null;
  }
  async set(k, v, ex, sec) {
    this._check();
    this._set(k, v, ex, sec);
    return 'OK';
  }
  async del(k) {
    this._check();
    this._del(k);
    return 1;
  }
  async lrange(k) {
    this._check();
    return this._alive(k) ? [...this.kv.get(k)] : [];
  }
  async ttl(k) {
    this._check();
    if (!this._alive(k)) return -2;
    const e = this.exp.get(k);
    return e === undefined ? -1 : Math.ceil((e - Date.now()) / 1000);
  }
  multi() {
    const ops = [];
    const m = {
      set: (...a) => (ops.push(() => this._set(...a)), m),
      del: (k) => (ops.push(() => this._del(k)), m),
      rpush: (k, v) => (
        ops.push(() => {
          if (!this._alive(k)) this.kv.set(k, []);
          this.kv.get(k).push(v);
        }),
        m
      ),
      expire: (k, s) => (ops.push(() => this._alive(k) && this.exp.set(k, Date.now() + s * 1000)), m),
      exec: async () => {
        this._check();
        for (const op of ops) op();
        return [];
      },
    };
    return m;
  }
  /** Для проверок: жив ли ключ (без учёта down). */
  has(k) {
    return this._alive(k);
  }
}

/** Таблицы PartnerLink и Partner в памяти: ровно то, что трогают сервисы. */
function makePrisma(partners) {
  const links = new Map();
  const pick = (row, select) =>
    select ? Object.fromEntries(Object.keys(select).filter((k) => select[k]).map((k) => [k, row[k]])) : { ...row };
  const matches = (row, where) =>
    Object.entries(where).every(([key, cond]) => {
      if (key === 'OR') return cond.some((w) => matches(row, w));
      if (cond !== null && typeof cond === 'object' && 'not' in cond) return row[key] !== cond.not;
      return row[key] === cond;
    });
  const prisma = {
    links,
    partner: {
      findMany: async () => partners.map((p) => ({ ...p })),
      // по любому уникальному ключу: id, slug или oauthClientId
      findUnique: async ({ where }) => {
        const p = partners.find((x) => Object.entries(where).every(([k, v]) => x[k] === v));
        return p ? { ...p } : null;
      },
    },
    partnerLink: {
      async update({ where, data, select }) {
        const row = links.get(where.id);
        if (!row) throw new Error(`partnerLink ${where.id} not found`);
        Object.assign(row, data);
        return pick(row, select);
      },
      async updateMany({ where, data }) {
        let count = 0;
        for (const row of links.values()) {
          if (matches(row, where)) {
            Object.assign(row, data);
            count++;
          }
        }
        return { count };
      },
      async findUnique({ where, select }) {
        const row = links.get(where.id);
        return row ? pick(row, select) : null;
      },
      async findMany({ where, select }) {
        return [...links.values()].filter((row) => matches(row, where)).map((row) => pick(row, select));
      },
    },
    // Таблица в памяти без настоящих транзакций: каждый вызов уже атомарен (как
    // UPDATE в Postgres — см. шапку файла), поэтому колбэку достаточно того же клиента.
    async $transaction(fn) {
      return fn(prisma);
    },
  };
  return prisma;
}

async function main() {
  const { default: Provider } = await import('oidc-provider');

  const redis = new FakeRedis();
  // Так PrismaClientAdapter описывает сервер-серверный клиент партнёра (без redirect_uris).
  const clientMeta = {
    client_id: 'nadi-partner',
    client_secret: 'x'.repeat(40),
    redirect_uris: [],
    response_types: [],
    grant_types: ['refresh_token'],
    scope: MESSENGER_SCOPE,
    token_endpoint_auth_method: 'client_secret_basic',
  };
  const signingKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  const provider = new Provider('http://localhost/oauth', {
    adapter: (model) =>
      model === 'Client'
        ? { find: async (id) => (id === clientMeta.client_id ? clientMeta : undefined) }
        : new RedisOidcAdapter(model, redis),
    jwks: { keys: [{ ...signingKey.export({ format: 'jwk' }), use: 'sig', alg: 'RS256', kid: 'verify' }] },
    scopes: ['openid', 'offline_access', MESSENGER_SCOPE],
    // как в oidc-provider.factory.ts
    ttl: { AccessToken: 900, Grant: 30 * 24 * 3600 },
    features: { devInteractions: { enabled: false } },
  });

  process.env.PARTNER_API_ENABLED = 'true';
  const partner = {
    id: 'p1',
    slug: 'nadi',
    name: 'Nadi',
    keyHash: 'h',
    ipAllowlist: [],
    webhookUrl: null,
    webhookSecretEnc: null,
    oauthClientId: 'nadi-partner',
    enabled: true,
  };
  const prisma = makePrisma([partner]);
  const registry = new PartnerRegistryService(prisma);
  const tokens = new PartnerTokensService(provider, prisma, registry);
  const realtime = new PartnerRealtimeService();
  const disconnects = [];
  realtime.registerDisconnector((partnerId, userId) => {
    disconnects.push(`${partnerId}:${userId}`);
  });
  const revoker = new PartnerLinkRevokerService(prisma, tokens, realtime);

  // ---- помощники ----
  const newLink = (id, userId) => {
    const row = { id, partnerId: partner.id, userId, status: 'ACTIVE', grantId: null, revokedAt: null };
    prisma.links.set(id, row);
    return row;
  };
  const row = (id) => prisma.links.get(id);
  const snapshot = (id) => ({ ...row(id) });
  const issue = (link) => tokens.issueAccessToken(link, partner);
  const accepted = async (value) => (await tokens.verify(value)) !== null;
  const grantKey = (grantId) => `oidc:Grant:${grantId}`;
  const grantsWrittenSince = (mark) =>
    [...new Set(redis.writes.slice(mark).filter((k) => k.startsWith('oidc:Grant:')))];

  async function assertAllRejected(values) {
    for (const [i, value] of values.entries()) {
      assert.equal(await accepted(value), false, `token #${i + 1} is still accepted after revocation`);
    }
  }
  function assertRevokedClean(linkId, mark) {
    assert.equal(row(linkId).status, 'REVOKED', 'link is not REVOKED');
    assert.equal(row(linkId).grantId, null, 'REVOKED link still holds a grant');
    const alive = grantsWrittenSince(mark).filter((k) => redis.has(k));
    assert.deepEqual(alive, [], 'grants created by this scenario are still alive');
    assert.ok(disconnects.includes(`${partner.id}:${row(linkId).userId}`), 'link sockets were not disconnected');
  }

  const scenarios = [
    [
      '0. основа: токен принимается, чужой gty и JWT приложения — нет',
      async () => {
        const mark = redis.writes.length;
        newLink('l0', 'u0');
        const t = await issue(snapshot('l0'));
        assert.match(t.accessToken, /^[A-Za-z0-9_-]{43}$/, 'token is not 43 chars of base64url');
        assert.equal(t.expiresIn, 900);
        assert.equal(row('l0').grantId, t.grantId, 'link does not hold the grant of its token');
        const principal = await tokens.verify(t.accessToken);
        assert.deepEqual(
          { ...principal, expiresAt: undefined },
          { userId: 'u0', partnerId: 'p1', partnerSlug: 'nadi', grantId: t.grantId, expiresAt: undefined },
        );
        assert.ok(Math.abs(principal.expiresAt - (epoch() + 900)) <= 2, 'expiresAt is not now + 900');

        // Токен с тем же грантом и scope, но выпущенный не партнёрским API
        const foreign = new provider.AccessToken({
          accountId: 'u0',
          client: await provider.Client.find('nadi-partner'),
          grantId: t.grantId,
          scope: MESSENGER_SCOPE,
          gty: 'authorization_code',
        });
        assert.equal(await accepted(await foreign.save()), false, 'token with a foreign gty is accepted');
        assert.equal(await tokens.verify('eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MCJ9.c2ln'), null);

        await revoker.revokeLink({ id: 'l0' });
        await assertAllRejected([t.accessToken]);
        assertRevokedClean('l0', mark);
      },
    ],
    [
      '1. два параллельных выпуска по связке без гранта — один грант на двоих, отзыв гасит оба',
      async () => {
        const mark = redis.writes.length;
        newLink('l1', 'u1');
        // Оба выпуска доходят до сравнения с обменом, прежде чем любой из них его сделает.
        // Не дождались второго за 2 с — отпускаем как есть, и проверка ниже скажет, что гонки не было.
        const realUpdateMany = prisma.partnerLink.updateMany;
        const held = [];
        const release = () => {
          clearTimeout(timer);
          prisma.partnerLink.updateMany = realUpdateMany;
          held.splice(0).forEach((run) => run());
        };
        const timer = setTimeout(release, 2000);
        prisma.partnerLink.updateMany = (args) =>
          new Promise((resolve, reject) => {
            held.push(() => realUpdateMany(args).then(resolve, reject));
            if (held.length === 2) release();
          });
        let a;
        let b;
        try {
          [a, b] = await Promise.all([issue(snapshot('l1')), issue(snapshot('l1'))]);
        } finally {
          prisma.partnerLink.updateMany = realUpdateMany;
        }
        assert.equal(grantsWrittenSince(mark).length, 2, 'the race did not happen: expected two grants created');
        assert.equal(a.grantId, b.grantId, 'the two tokens sit on different grants');
        assert.equal(row('l1').grantId, a.grantId, 'link does not hold the grant of its tokens');
        assert.equal(grantsWrittenSince(mark).filter((k) => redis.has(k)).length, 1, 'the losing grant is left alive');
        assert.ok((await accepted(a.accessToken)) && (await accepted(b.accessToken)), 'tokens are not accepted');

        await revoker.revokeLink({ id: 'l1' });
        await assertAllRejected([a.accessToken, b.accessToken]);
        assertRevokedClean('l1', mark);
      },
    ],
    [
      '2. грант пропал и пересоздан при живых токенах — старые токены мертвы, отзыв гасит все',
      async () => {
        const mark = redis.writes.length;
        newLink('l2', 'u2');
        const t1 = await issue(snapshot('l2'));
        // Грант исчез из Redis (30 дней истекли, вытеснение) — запись токена ещё на месте
        await redis.del(grantKey(t1.grantId));
        assert.ok(redis.has(`oidc:AccessToken:${t1.accessToken}`), 'token record should outlive the grant here');
        assert.equal(await accepted(t1.accessToken), false, 'token of a vanished grant is accepted');

        const t2 = await issue(snapshot('l2'));
        assert.notEqual(t2.grantId, t1.grantId, 'vanished grant was not replaced');
        assert.equal(row('l2').grantId, t2.grantId);
        assert.ok(await accepted(t2.accessToken));

        // Настоящее истечение по часам: грант доживает последние 5 минут
        const g2 = await provider.Grant.find(t2.grantId);
        skewMs += (g2.exp - epoch() - 300) * 1000;
        const t3 = await issue(snapshot('l2'));
        assert.equal(t3.grantId, t2.grantId, 'a grant with 5 minutes left should be reused');
        assert.ok(t3.expiresIn <= 300 && t3.expiresIn >= 298, `token outlives its grant: expiresIn=${t3.expiresIn}`);
        const at3 = await provider.AccessToken.find(t3.accessToken);
        // +1: срок считается от «сейчас» чуть раньше, чем провайдер ставит exp, и между ними может смениться секунда
        assert.ok(at3.exp <= g2.exp + 1, `stored token expires after its grant: ${at3.exp} > ${g2.exp}`);
        assert.ok(await accepted(t3.accessToken));
        skewMs += 301 * 1000;
        assert.equal(await accepted(t3.accessToken), false, 'token is accepted after its grant expired');
        const t4 = await issue(snapshot('l2'));
        assert.notEqual(t4.grantId, t2.grantId, 'expired grant was not replaced');
        assert.ok(await accepted(t4.accessToken));

        await revoker.revokeLink({ id: 'l2' });
        await assertAllRejected([t1.accessToken, t2.accessToken, t3.accessToken, t4.accessToken]);
        assertRevokedClean('l2', mark);
      },
    ],
    [
      '3. отзыв посреди выпуска — REVOKED-связка не получает грант, токен не принимается',
      async () => {
        // а) выпуск прочитал связку до отзыва, а грант меняет уже после него
        const mark = redis.writes.length;
        newLink('l3', 'u3');
        const t = await issue(snapshot('l3'));
        const stale = snapshot('l3');
        await revoker.revokeLink({ id: 'l3' });
        const err = await issue(stale).then(
          () => null,
          (e) => e,
        );
        assert.ok(err instanceof NotFoundException, `expected NotFoundException, got ${err}`);
        assert.equal(err.message, 'not_linked');
        await assertAllRejected([t.accessToken]);
        assertRevokedClean('l3', mark);

        // б) отзыв целиком уместился между чтением гранта и записью токена
        const mark2 = redis.writes.length;
        newLink('l3b', 'u3b');
        await issue(snapshot('l3b'));
        const Grant = provider.Grant;
        Grant.find = async function (...args) {
          delete Grant.find;
          const found = await Grant.find(...args);
          await revoker.revokeLink({ id: 'l3b' });
          return found;
        };
        let late;
        try {
          late = await issue(snapshot('l3b'));
        } finally {
          delete Grant.find;
        }
        await assertAllRejected([late.accessToken]);
        assertRevokedClean('l3b', mark2);
      },
    ],
    [
      '4. Redis падает внутри отзыва — связка ждёт повтора с грантом, повтор гасит токен',
      async () => {
        const mark = redis.writes.length;
        newLink('l4', 'u4');
        const t = await issue(snapshot('l4'));
        assert.ok(await accepted(t.accessToken));
        const disconnectsBefore = disconnects.length;

        redis.down = true;
        let firstRevokedAt;
        try {
          await assert.rejects(revoker.revokeLink({ id: 'l4' }), /redis down/);
          assert.equal(row('l4').status, 'REVOKED');
          assert.equal(row('l4').grantId, t.grantId, 'grant was dropped from the link before it was revoked');
          assert.equal(disconnects.length, disconnectsBefore, 'sockets disconnected before tokens were revoked');
          // Статус и revokedAt — одной транзакцией ДО Redis: переживают отказ Redis рядом.
          firstRevokedAt = row('l4').revokedAt;
          assert.ok(firstRevokedAt, 'revokedAt was not set on the first, Redis-interrupted revocation');
          // пока Redis лежит: партнёрский токен — 503, а не «неверный токен»…
          await assert.rejects(tokens.verify(t.accessToken), ServiceUnavailableException);
          // …а чужой токен в Redis не ходит и получает честный 401
          assert.equal(await tokens.verify('eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1NCJ9.c2ln'), null);
        } finally {
          redis.down = false;
        }

        // Повтор — тем путём, что и удаление аккаунта: недоотозванная связка находится
        assert.equal(await revoker.revokeAllForUser('u4'), 1, 'unfinished link was not picked up by the retry');
        await assertAllRejected([t.accessToken]);
        assertRevokedClean('l4', mark);
        // Доделка не переписывает время первого отзыва своим, более поздним.
        assert.equal(row('l4').revokedAt, firstRevokedAt, 'revokedAt was rewritten by the retry that finished the revocation');
        assert.equal(await revoker.revokeAllForUser('u4'), 0, 'finished link is picked up again');
      },
    ],
    [
      '5. грант с остатком меньше минуты заменён при живом токене — старый уничтожен сразу, отзыв гасит все',
      async () => {
        const mark = redis.writes.length;
        newLink('l5', 'u5');
        const first = await issue(snapshot('l5'));
        const g1 = await provider.Grant.find(first.grantId);
        // Гранту осталось 100 с: он ещё годится, токен по нему урезается до его остатка
        skewMs += (g1.exp - epoch() - 100) * 1000;
        const old = await issue(snapshot('l5'));
        assert.equal(old.grantId, first.grantId, 'a grant with 100 s left should be reused');
        // Прошло 50 с: гранту меньше минуты, а токен по нему ещё жив
        skewMs += 50 * 1000;
        assert.ok(await accepted(old.accessToken), 'the old token should still be alive here');

        const fresh = await issue(snapshot('l5'));
        assert.notEqual(fresh.grantId, first.grantId, 'a grant with less than a minute left was not replaced');
        assert.equal(row('l5').grantId, fresh.grantId, 'link does not hold the new grant');
        assert.deepEqual(
          grantsWrittenSince(mark).filter((k) => redis.has(k)),
          [grantKey(fresh.grantId)],
          'the link holds two live grants after the replacement',
        );
        // Цена: токен старого гранта гаснет раньше своего срока — клиент на 401 просит новый
        assert.equal(await accepted(old.accessToken), false, 'token of the replaced grant is still accepted');
        assert.ok(await accepted(fresh.accessToken), 'the new token is not accepted');

        await revoker.revokeLink({ id: 'l5' });
        await assertAllRejected([old.accessToken, fresh.accessToken]);
        assertRevokedClean('l5', mark);
      },
    ],
    [
      '6. аккаунт удалён и перепривязан, пока шёл /token старого — грант удалённого не попадает на строку нового',
      async () => {
        const mark = redis.writes.length;
        newLink('l6', 'u6'); // токенов по связке ещё не выпускали — гранта нет
        const inFlight = snapshot('l6'); // /token старого человека прочитал связку…
        // …тут человек удалил аккаунт (его связки отозваны), а партнёр привязал ту же
        // externalId заново: новый аккаунт, строка переиспользована, grantId обнулён
        assert.equal(await revoker.revokeAllForUser('u6'), 1);
        Object.assign(row('l6'), { userId: 'u6-new', status: 'ACTIVE', revokedAt: null, grantId: null });

        const err = await issue(inFlight).then(
          () => null,
          (e) => e,
        );
        assert.ok(err instanceof NotFoundException, `expected NotFoundException, got ${err}`);
        assert.equal(err.message, 'not_linked');
        assert.equal(row('l6').grantId, null, "the deleted account's grant landed on the new account's link");
        assert.deepEqual(
          grantsWrittenSince(mark).filter((k) => redis.has(k)),
          [],
          'the grant of the failed in-flight issue is left alive',
        );

        // Новый человек получает токен как обычно — на свой грант
        const t = await issue(snapshot('l6'));
        assert.equal((await tokens.verify(t.accessToken))?.userId, 'u6-new', 'token is not for the new account');
        assert.equal((await provider.Grant.find(t.grantId)).accountId, 'u6-new', 'grant is not for the new account');

        await revoker.revokeLink({ id: 'l6' });
        await assertAllRejected([t.accessToken]);
        assertRevokedClean('l6', mark);
      },
    ],
  ];

  let failed = 0;
  for (const [name, run] of scenarios) {
    try {
      await run();
      console.log(`OK   ${name}`);
    } catch (e) {
      failed++;
      console.log(`FAIL ${name}\n     ${e && e.stack ? e.stack.split('\n').slice(0, 4).join('\n     ') : e}`);
    }
  }
  if (failed > 0) {
    console.log(`${failed} of ${scenarios.length} scenarios failed`);
    return 1;
  }
  console.log(`all ${scenarios.length} scenarios passed`);
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error('verify-partner-tokens crashed:', e);
    process.exit(1);
  },
);
