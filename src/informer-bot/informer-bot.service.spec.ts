import BigNumber from 'bignumber.js';
import { InformerBotService } from './informer-bot.service';

// In-memory Redis stub — only the methods the service actually calls
// (get/setEx/del) are surfaced. Each test gets its own instance so state
// doesn't leak across cases.
function makeRedisStub() {
  const store = new Map<string, string>();
  return {
    store,
    get: jest.fn(async (k: string) => store.get(k) ?? null),
    set: jest.fn(async (k: string, v: string) => {
      store.set(k, v);
    }),
    setEx: jest.fn(async (k: string, _ttl: number, v: string) => {
      store.set(k, v);
    }),
    del: jest.fn(async (k: string) => {
      store.delete(k);
    }),
  };
}

// We exercise the helper via a tiny subclass that exposes it.
class TestableService extends InformerBotService {
  constructor() {
    super(
      null as any,
      null as any,
      null as any,
      null as any,
      null as any,
      makeRedisStub() as any,
    );
  }
  public _nextMorningInBerlin(now?: Date): Date {
    return (this as any).nextMorningInBerlin(now);
  }
}

describe('InformerBotService.nextMorningInBerlin', () => {
  const svc = new TestableService();

  function berlinHourOf(d: Date): number {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: 'Europe/Berlin',
      hour: 'numeric',
      hour12: false,
    }).formatToParts(d);
    return parseInt(parts.find((p) => p.type === 'hour')!.value, 10);
  }

  it('result is exactly 09:00 Berlin time', () => {
    const out = svc._nextMorningInBerlin(new Date('2026-06-19T06:00:00Z'));
    expect(berlinHourOf(out)).toBe(9);
  });

  it('when called before 9 AM Berlin, returns today 09:00 Berlin', () => {
    // 2026-06-19 06:00 UTC = 08:00 CEST (summer +2). Berlin 08:00 < 09:00 → today.
    const out = svc._nextMorningInBerlin(new Date('2026-06-19T06:00:00Z'));
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Europe/Berlin',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).formatToParts(out);
    const get = (t: string) => parts.find((p) => p.type === t)!.value;
    expect(`${get('year')}-${get('month')}-${get('day')}`).toBe('2026-06-19');
  });

  it('when called after 9 AM Berlin, returns tomorrow 09:00 Berlin', () => {
    // 2026-06-19 12:00 UTC = 14:00 CEST → after 09:00 → tomorrow.
    const out = svc._nextMorningInBerlin(new Date('2026-06-19T12:00:00Z'));
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Europe/Berlin',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).formatToParts(out);
    const get = (t: string) => parts.find((p) => p.type === t)!.value;
    expect(`${get('year')}-${get('month')}-${get('day')}`).toBe('2026-06-20');
  });

  it('handles DST: winter morning resolves to 09:00 CET (UTC+1)', () => {
    // 2026-01-15 06:00 UTC = 07:00 CET → before 09:00 → today.
    const out = svc._nextMorningInBerlin(new Date('2026-01-15T06:00:00Z'));
    expect(berlinHourOf(out)).toBe(9);
    expect(out.toISOString()).toBe('2026-01-15T08:00:00.000Z'); // 09:00 CET = 08:00 UTC
  });

  it('handles DST: summer morning resolves to 09:00 CEST (UTC+2)', () => {
    const out = svc._nextMorningInBerlin(new Date('2026-07-15T05:00:00Z'));
    expect(berlinHourOf(out)).toBe(9);
    expect(out.toISOString()).toBe('2026-07-15T07:00:00.000Z'); // 09:00 CEST = 07:00 UTC
  });
});

describe('InformerBotService.parseAction (refill codes)', () => {
  const svc = new TestableService();

  const cases: [string, string][] = [
    ['REFILL_ACK', '✅ Понял, работаю'],
    ['REFILL_SNOOZE_1H', '🔕 Заглушить 1 час'],
    ['REFILL_SNOOZE_MORNING', '🔕 До утра 9:00'],
    ['REFILL_DISABLE', '🔇 Совсем отключить'],
    ['REFILL_ENABLE', '🔔 Включить обратно'],
    ['REFILL_SETTINGS', '⚙️ Настройки алёртов'],
  ];

  for (const [code, label] of cases) {
    it(`recognises human label "${label}" → ${code}`, () => {
      expect(svc.parseAction(label)?.code).toBe(code);
    });
    it(`recognises raw code "${code}"`, () => {
      expect(svc.parseAction(code)?.code).toBe(code);
    });
  }
});

describe('InformerBotService.parseAction (Sub-2c codes)', () => {
  const svc = new TestableService();

  const cases: [string, string][] = [
    ['FIAT_BALANCES', '💶 Балансы в евро'],
    ['FIAT_BALANCES_REFRESH', '🔄 Обновить курсы'],
  ];
  for (const [code, label] of cases) {
    it(`recognises human label "${label}" → ${code}`, () => {
      expect(svc.parseAction(label)?.code).toBe(code);
    });
    it(`recognises raw code "${code}"`, () => {
      expect(svc.parseAction(code)?.code).toBe(code);
    });
  }
});

describe('InformerBotService.parseAction (retry wallet)', () => {
  const svc = new TestableService();

  it('recognises human label "🔁 Повторить #613"', () => {
    const out = svc.parseAction('🔁 Повторить #613');
    expect(out?.code).toBe('RETRY_OPERATOR_WALLET');
    expect(out?.walletId).toBe(613);
  });

  it('recognises legacy code form RETRY_OPERATOR_WALLET:42', () => {
    const out = svc.parseAction('RETRY_OPERATOR_WALLET:42');
    expect(out?.code).toBe('RETRY_OPERATOR_WALLET');
    expect(out?.walletId).toBe(42);
  });

  it('returns null without an id', () => {
    expect(svc.parseAction('🔁 Повторить')).toBeNull();
  });
});

describe('InformerBotService.handleUserMessage (refill actions)', () => {
  function makeMocks() {
    const calls: any = { upsert: [], publishContent: [], findUnique: 0 };
    const prisma = {
      profile: {
        findUnique: jest.fn(async () => ({ informerAccess: true })),
      },
      informerAlertConfig: {
        upsert: jest.fn(async ({ where, update, create }: any) => {
          calls.upsert.push({ where, update, create });
          return { ...create, ...update };
        }),
        findUnique: jest.fn(async () => {
          calls.findUnique++;
          return null;
        }),
      },
    };
    const messenger = {
      createMessage: jest.fn(
        async (_convId: string, _userId: string, content: string) => ({
          id: 'm1',
          content,
          senderId: 'bot',
          conversationId: 'c1',
        }),
      ),
    };
    const gateway = { server: { to: () => ({ emit: jest.fn() }) } };
    return { prisma, messenger, gateway, calls };
  }

  function makeService(m: ReturnType<typeof makeMocks>) {
    const svc = new InformerBotService(
      m.prisma as any,
      null as any,
      m.messenger as any,
      m.gateway as any,
      null as any,
      makeRedisStub() as any,
    );
    // capture published content for assertions
    (svc as any).publishBotMessage = jest.fn(
      async (_uid: string, _cid: string, content: string) => {
        m.calls.publishContent.push(content);
      },
    );
    return svc;
  }

  it('REFILL_ACK upserts snoozedUntil ≈ now+30min and publishes "Принято"', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    const before = Date.now();
    await svc.handleUserMessage('u1', 'c1', '✅ Понял, работаю');
    const after = Date.now();
    expect(m.calls.upsert).toHaveLength(1);
    const u = m.calls.upsert[0].update.snoozedUntil as Date;
    const delta = u.getTime() - before;
    expect(delta).toBeGreaterThanOrEqual(30 * 60 * 1000 - 1000);
    expect(delta).toBeLessThanOrEqual(after - before + 30 * 60 * 1000);
    expect(m.calls.publishContent.join('\n')).toContain('Принято');
  });

  it('REFILL_SNOOZE_1H upserts ≈ now+1h', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    const before = Date.now();
    await svc.handleUserMessage('u1', 'c1', '🔕 Заглушить 1 час');
    const u = m.calls.upsert[0].update.snoozedUntil as Date;
    expect(u.getTime() - before).toBeGreaterThanOrEqual(60 * 60 * 1000 - 1000);
    expect(u.getTime() - before).toBeLessThanOrEqual(60 * 60 * 1000 + 1000);
    expect(m.calls.publishContent.join('\n')).toContain('1 час');
  });

  it('REFILL_SNOOZE_MORNING upserts next 9 AM Berlin', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔕 До утра 9:00');
    const u = m.calls.upsert[0].update.snoozedUntil as Date;
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: 'Europe/Berlin',
      hour: 'numeric',
      hour12: false,
    }).formatToParts(u);
    expect(parseInt(parts.find((p) => p.type === 'hour')!.value, 10)).toBe(9);
  });

  it('REFILL_DISABLE upserts enabled=false, snoozedUntil=null', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔇 Совсем отключить');
    expect(m.calls.upsert[0].update.enabled).toBe(false);
    expect(m.calls.upsert[0].update.snoozedUntil).toBeNull();
    expect(m.calls.publishContent.join('\n')).toContain('🔇 Отключено');
  });

  it('REFILL_ENABLE upserts enabled=true, snoozedUntil=null', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔔 Включить обратно');
    expect(m.calls.upsert[0].update.enabled).toBe(true);
    expect(m.calls.upsert[0].update.snoozedUntil).toBeNull();
    expect(m.calls.publishContent.join('\n')).toContain('🔔 Включено');
  });

  it('REFILL_SETTINGS reads config and publishes; no upsert', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '⚙️ Настройки алёртов');
    expect(m.calls.upsert).toHaveLength(0);
    expect(m.calls.findUnique).toBe(1);
    expect(m.calls.publishContent.join('\n')).toContain('Настройки алёртов');
  });
});

describe('InformerBotService.handleUserMessage (fiat actions)', () => {
  function makeMocks() {
    const calls: any = {
      ratesAssets: null as string[] | null,
      ratesInvalidated: false,
      published: [] as string[],
    };
    const prisma = {
      profile: {
        findUnique: jest.fn(async () => ({ informerAccess: true })),
      },
      informerAlertConfig: {
        findUnique: jest.fn(async () => null),
        upsert: jest.fn(async () => {}),
      },
    };
    const client = {
      getMiniAcquiringBalances: jest.fn(async () => ({
        chains: [
          {
            chain: 'tron',
            base_asset: 'usdt',
            supported: true,
            roles: [
              {
                role: 'hot_wallet',
                address: 'TX',
                balances: [
                  { asset: 'usdt', kind: 'native', balance: '12450' },
                ],
              },
            ],
          },
        ],
      })),
      getGatewaySystemWalletBalances: jest.fn(async () => ({
        items: [
          {
            blockchain: 'tron',
            asset_symbol: 'USDT',
            wallet_type: 'deposit',
            balance: '8350',
            address: 'TX2',
            updated_at: 1718900000,
          },
        ],
      })),
    };
    const rates = {
      getEurRates: jest.fn(async (assets: string[]) => {
        calls.ratesAssets = assets;
        const out: Record<string, BigNumber> = {};
        for (const a of assets) out[a.toLowerCase()] = new BigNumber('1');
        return out;
      }),
      invalidateCache: jest.fn(() => {
        calls.ratesInvalidated = true;
      }),
      getCacheAgeMs: jest.fn(() => 120000),
      getCoingeckoStatus: jest.fn(() => 'ok' as const),
    };
    const messenger = {
      createMessage: jest.fn(async () => ({
        id: 'm1',
        content: '',
        senderId: 'bot',
        conversationId: 'c1',
      })),
    };
    const gateway = { server: { to: () => ({ emit: jest.fn() }) } };
    return { prisma, client, rates, messenger, gateway, calls };
  }

  function makeService(m: ReturnType<typeof makeMocks>) {
    const svc = new InformerBotService(
      m.prisma as any,
      m.client as any,
      m.messenger as any,
      m.gateway as any,
      m.rates as any,
      makeRedisStub() as any,
    );
    (svc as any).publishBotMessage = jest.fn(
      async (_uid: string, _cid: string, content: string) => {
        m.calls.published.push(content);
      },
    );
    return svc;
  }

  it('FIAT_BALANCES fetches admin-API + asks rates, publishes digest', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '💶 Балансы в евро');
    expect(m.client.getMiniAcquiringBalances).toHaveBeenCalledTimes(1);
    expect(m.client.getGatewaySystemWalletBalances).toHaveBeenCalledTimes(1);
    expect(m.rates.getEurRates).toHaveBeenCalledTimes(1);
    expect(m.rates.invalidateCache).not.toHaveBeenCalled();
    const assets = (m.rates.getEurRates.mock.calls[0][0] as string[]).map((s) =>
      s.toLowerCase(),
    );
    expect(assets).toContain('usdt');
    expect(m.calls.published[0]).toContain('Балансы в евро');
  });

  it('FIAT_BALANCES_REFRESH invalidates cache before fetch', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔄 Обновить курсы');
    expect(m.rates.invalidateCache).toHaveBeenCalledTimes(1);
    expect(m.rates.getEurRates).toHaveBeenCalledTimes(1);
    expect(m.calls.published[0]).toContain('Балансы в евро');
  });
});

describe('InformerBotService.handleUserMessage (retry wallet, flow B)', () => {
  function makeMocks() {
    const published: string[] = [];
    const prisma = {
      profile: {
        findUnique: jest.fn(async () => ({ informerAccess: true })),
      },
    };
    const client = {
      retryOperatorWallet: jest.fn(async (id: number, _code: string) => ({
        wallet_id: id,
        status: 'ok',
      })),
    };
    const messenger = {
      createMessage: jest.fn(async () => ({
        id: 'm1',
        content: '',
        senderId: 'bot',
        conversationId: 'c1',
      })),
    };
    const gateway = { server: { to: () => ({ emit: jest.fn() }) } };
    const redis = makeRedisStub();
    return { prisma, client, messenger, gateway, redis, published };
  }

  function makeService(m: ReturnType<typeof makeMocks>) {
    const svc = new InformerBotService(
      m.prisma as any,
      m.client as any,
      m.messenger as any,
      m.gateway as any,
      null as any,
      m.redis as any,
    );
    (svc as any).publishBotMessage = jest.fn(
      async (_u: string, _c: string, content: string) => {
        m.published.push(content);
      },
    );
    return svc;
  }

  it('stage 1: retry button stores pending state and prompts for code', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #613');

    // Client NOT called yet — stage 1 just sets up the prompt.
    expect(m.client.retryOperatorWallet).not.toHaveBeenCalled();

    // Pending state stored with TTL.
    expect(m.redis.setEx).toHaveBeenCalledTimes(1);
    const [key, ttl, value] = m.redis.setEx.mock.calls[0];
    expect(key).toBe('informer:pending_totp:u1');
    expect(ttl).toBe(60);
    expect(JSON.parse(value)).toMatchObject({ walletId: 613 });

    expect(m.published[0]).toContain('#613');
    expect(m.published[0]).toContain('Google Authenticator');
    expect(m.published[0]).toContain('❌ Отмена ретрая');
  });

  it('stage 2: 6-digit message with pending state fires retry and clears state', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #613');
    m.published.length = 0; // reset for clarity

    await svc.handleUserMessage('u1', 'c1', '123456');

    expect(m.client.retryOperatorWallet).toHaveBeenCalledTimes(1);
    const [walletId, totpCode] = m.client.retryOperatorWallet.mock.calls[0];
    expect(walletId).toBe(613);
    expect(totpCode).toBe('123456');

    // State cleared so the same code can't be replayed.
    expect(m.redis.del).toHaveBeenCalledWith('informer:pending_totp:u1');
    expect(m.redis.store.has('informer:pending_totp:u1')).toBe(false);

    expect(m.published[0]).toContain('Повтор запущен');
    expect(m.published[0]).toContain('#613');
  });

  it('bare 6-digit message WITHOUT pending state is not interpreted as TOTP', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect(m.client.retryOperatorWallet).not.toHaveBeenCalled();
    // Falls through to the buttons-only hint.
    expect(m.published[0]).toMatch(/нажми|кнопк/i);
  });

  it('cancel button clears pending state and acknowledges', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #613');
    m.published.length = 0;

    await svc.handleUserMessage('u1', 'c1', '❌ Отмена ретрая');

    expect(m.client.retryOperatorWallet).not.toHaveBeenCalled();
    expect(m.redis.del).toHaveBeenCalledWith('informer:pending_totp:u1');
    expect(m.redis.store.has('informer:pending_totp:u1')).toBe(false);
    expect(m.published[0]).toContain('отменён');
  });

  it('non-digit message after retry button leaves pending state intact', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #613');

    // Operator pastes something else — should not fire retry, should not
    // clear the pending state (let TTL expire naturally).
    await svc.handleUserMessage('u1', 'c1', '📋 Кошельки оператора');

    expect(m.client.retryOperatorWallet).not.toHaveBeenCalled();
    expect(m.redis.store.has('informer:pending_totp:u1')).toBe(true);
  });
});
