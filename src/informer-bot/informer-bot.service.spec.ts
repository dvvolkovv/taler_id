import BigNumber from 'bignumber.js';
import { InformerBotService } from './informer-bot.service';
import {
  InformerTotpError,
  InformerTimeoutError,
  InformerUnavailableError,
} from './informer.types';
import { PendingStateStore } from './informer.pending-state';
import { InformerRefundService } from './informer.refund.service';

// In-memory Redis stub — only the methods the service actually calls
// (get/setEx/setNxEx/del) are surfaced. Each test gets its own instance so
// state doesn't leak across cases.
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
    setNxEx: jest.fn(async (k: string, _ttl: number, v: string) => {
      if (store.has(k)) return false;
      store.set(k, v);
      return true;
    }),
    del: jest.fn(async (k: string) => {
      store.delete(k);
    }),
  };
}

// We exercise the helper via a tiny subclass that exposes it.
class TestableService extends InformerBotService {
  constructor() {
    const redis = makeRedisStub();
    super(
      null as any,
      null as any,
      null as any,
      null as any,
      null as any,
      new PendingStateStore(redis as any),
      null as any,
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
    const redis = makeRedisStub();
    const svc = new InformerBotService(
      m.prisma as any,
      null as any,
      m.messenger as any,
      m.gateway as any,
      null as any,
      new PendingStateStore(redis as any),
      null as any,
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
    const redis = makeRedisStub();
    const svc = new InformerBotService(
      m.prisma as any,
      m.client as any,
      m.messenger as any,
      m.gateway as any,
      m.rates as any,
      new PendingStateStore(redis as any),
      null as any,
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

// Shared factory for handleUserMessage-level tests that need the full
// client/redis/pending/refund stack — the retry dispatch below and the
// refund wizard tests further down both build on it. Each describe block
// is free to override `client`/`rates` on top of what this returns.
function makeMocks() {
  const published: string[] = [];
  const prisma = {
    profile: {
      findUnique: jest.fn(async () => ({ informerAccess: true })),
    },
  };
  const client: {
    retryOperatorWallet: jest.Mock;
    getOperatorRequiredList: jest.Mock;
    refundOperatorWallet?: jest.Mock;
  } = {
    retryOperatorWallet: jest.fn(async (id: number, _code: string) => ({
      wallet_id: id,
      status: 'ok',
    })),
    getOperatorRequiredList: jest.fn(async () => ({
      items: [],
      total: 0,
      page: 1,
      per_page: 50,
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
  const pending = new PendingStateStore(redis as any);
  return { prisma, client, messenger, gateway, redis, pending, published };
}

function makeService(m: ReturnType<typeof makeMocks>) {
  const refund = new InformerRefundService(
    m.client as any,
    m.pending,
    m.redis as any,
  );
  const svc = new InformerBotService(
    m.prisma as any,
    m.client as any,
    m.messenger as any,
    m.gateway as any,
    null as any,
    m.pending,
    refund,
  );
  (svc as any).publishBotMessage = jest.fn(
    async (_u: string, _c: string, content: string) => {
      m.published.push(content);
    },
  );
  return svc;
}

describe('InformerBotService.handleUserMessage (retry wallet, flow B)', () => {
  it('stage 1: retry button stores pending state and prompts for code', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #613');

    // Client NOT called yet — stage 1 just sets up the prompt.
    expect(m.client.retryOperatorWallet).not.toHaveBeenCalled();

    // Pending state stored with TTL.
    expect(m.redis.setEx).toHaveBeenCalledTimes(1);
    const [key, ttl, value] = m.redis.setEx.mock.calls[0];
    expect(key).toBe('informer:pending_op:u1');
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
    expect(m.redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
    expect(m.redis.store.has('informer:pending_op:u1')).toBe(false);

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
    expect(m.redis.del).toHaveBeenCalledWith('informer:pending_op:u1');
    expect(m.redis.store.has('informer:pending_op:u1')).toBe(false);
    expect(m.published[0]).toContain('отменён');
  });

  it('non-digit message after retry button leaves pending state intact', async () => {
    const m = makeMocks();
    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #613');

    // Operator pastes something else — should not fire retry, should not
    // clear the pending state (let TTL expire naturally). Note: tapping
    // "📋 Кошельки оператора" WOULD fire the OPERATOR_WALLETS action and
    // also leave pending alone; here we use a non-matching string for
    // clarity.
    await svc.handleUserMessage('u1', 'c1', 'случайный текст');

    expect(m.client.retryOperatorWallet).not.toHaveBeenCalled();
    expect(m.redis.store.has('informer:pending_op:u1')).toBe(true);
  });

  it('OPERATOR_WALLETS publishes one message per wallet (plus header/trailer) so each retry button sits under its wallet', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList = jest.fn(async () => ({
      items: [
        {
          wallet_id: 857,
          created_at: '2026-06-24T17:06:47Z',
          withdraw_address: '0xb45CfA4ADdd2d93e38413AD55F704Ea643eD7144',
          withdraw_network: 'bsc',
          withdraw_token: 'usdc',
          withdraw_amount: '258.7',
        },
        {
          wallet_id: 855,
          created_at: '2026-06-24T14:38:46Z',
          withdraw_address: '0x538c6ED66155dAAB441C008EbF9798cfd9fd330C',
          withdraw_network: 'bsc',
          withdraw_token: 'usdc',
          withdraw_amount: '452.7',
        },
      ],
      total: 2,
      page: 1,
      per_page: 50,
    }));

    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '📋 Кошельки оператора');

    // header + 2 cards + trailer = 4 messages
    expect(m.published).toHaveLength(4);
    expect(m.published[1]).toContain('#857');
    expect(m.published[1]).toContain('[ACTION:🔁 Повторить #857]');
    expect(m.published[1]).not.toContain('#855');
    expect(m.published[2]).toContain('#855');
    expect(m.published[2]).toContain('[ACTION:🔁 Повторить #855]');
    expect(m.published[2]).not.toContain('#857');
  });

  it('TOTP rejected by admin-API re-arms pending for the same wallet (no nav back)', async () => {
    const m = makeMocks();
    // Make admin-API simulate a TOTP rejection on the first call only.
    m.client.retryOperatorWallet.mockImplementationOnce(async () => {
      throw new InformerTotpError('invalid 2fa code');
    });

    const svc = makeService(m);
    await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #613');
    m.published.length = 0;
    m.redis.setEx.mockClear();

    await svc.handleUserMessage('u1', 'c1', '000000');

    expect(m.client.retryOperatorWallet).toHaveBeenCalledTimes(1);
    // Pending re-armed for the SAME walletId so operator can retype without
    // navigating back to the list.
    expect(m.redis.setEx).toHaveBeenCalledTimes(1);
    const [key, _ttl, value] = m.redis.setEx.mock.calls[0];
    expect(key).toBe('informer:pending_op:u1');
    expect(JSON.parse(value)).toMatchObject({ walletId: 613 });
    expect(m.redis.store.has('informer:pending_op:u1')).toBe(true);
    // User-facing message points at the same wallet and asks for a fresh
    // code. It MUST NOT include the legacy bogus retry button.
    expect(m.published[0]).toContain('#613');
    expect(m.published[0]).toContain('Код не принят');
    expect(m.published[0]).not.toContain('🔄 Повторить SUBMIT_TOTP');
  });

  describe('retry на едином pending-состоянии', () => {
    it('кладёт состояние с kind=retry', async () => {
      const m = makeMocks();
      const svc = makeService(m);

      await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #1611');

      const raw = m.redis.store.get('informer:pending_op:u1');
      expect(JSON.parse(raw!)).toEqual({
        kind: 'retry',
        step: 'totp',
        walletId: 1611,
      });
    });

    it('кнопка возврата перетирает pending от retry — последняя кнопка выигрывает', async () => {
      const m = makeMocks();
      m.client.getOperatorRequiredList = jest.fn(async () => ({
        items: [
          {
            wallet_id: 1620,
            created_at: '2026-08-24T17:02:11Z',
            withdraw_address: '0xcust',
            withdraw_network: 'TRON',
            withdraw_token: 'usdt',
            withdraw_amount: '50',
          },
        ],
        total: 1,
        page: 1,
        per_page: 50,
      }));
      const svc = makeService(m);

      await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #1611');
      await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1620');

      const state = JSON.parse(m.redis.store.get('informer:pending_op:u1')!);
      expect(state.kind).toBe('refund');
      expect(state.walletId).toBe(1620);
    });

    it('6 цифр при retry-состоянии зовут retry, а не возврат', async () => {
      const m = makeMocks();
      const svc = makeService(m);

      await svc.handleUserMessage('u1', 'c1', '🔁 Повторить #1611');
      await svc.handleUserMessage('u1', 'c1', '123456');

      expect(m.client.retryOperatorWallet).toHaveBeenCalledWith(1611, '123456');
    });
  });
});

describe('мастер возврата в сервисе', () => {
  const ITEM = {
    wallet_id: 1611,
    created_at: '2026-08-24T17:02:11Z',
    withdraw_address: '0xcust',
    withdraw_network: 'TRON',
    withdraw_token: 'usdt',
    withdraw_amount: '50',
  };

  function mocksWithWallet() {
    const m = makeMocks();
    m.client.getOperatorRequiredList = jest.fn(async () => ({
      items: [ITEM],
      total: 1,
      page: 1,
      per_page: 50,
    }));
    (m.client as any).refundOperatorWallet = jest.fn(async () => ({
      wallet_id: 1611,
      status: 'ok',
    }));
    (m.redis as any).setNxEx = jest.fn(async (k: string) => {
      if (m.redis.store.has(k)) return false;
      m.redis.store.set(k, '1');
      return true;
    });
    return m;
  }

  async function walkToTotp(svc: any, m: any) {
    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');
    await svc.handleUserMessage('u1', 'c1', '👤 Вернуть плательщику #1611');
    await svc.handleUserMessage('u1', 'c1', '✅ Подтвердить возврат #1611');
  }

  it('проходит мастер целиком и зовёт API', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect((m.client as any).refundOperatorWallet).toHaveBeenCalledWith(
      1611,
      { refundToPayer: true },
      '123456',
      false,
    );
    expect(m.published.join('')).toContain('Возврат выполнен');
  });

  it('ветка с адресом отправляет refundAddress', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');
    await svc.handleUserMessage('u1', 'c1', '📮 Указать адрес #1611');
    await svc.handleUserMessage('u1', 'c1', '0xB1c4Ae4F0f8f');
    await svc.handleUserMessage('u1', 'c1', '✅ Подтвердить возврат #1611');
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect((m.client as any).refundOperatorWallet).toHaveBeenCalledWith(
      1611,
      { refundAddress: '0xB1c4Ae4F0f8f' },
      '123456',
      false,
    );
  });

  it('502 second payout переводит в gate и НЕ повторяет сам', async () => {
    const m = mocksWithWallet();
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      throw new InformerUnavailableError(
        502,
        JSON.stringify({ message: 'refund would be a second payout' }),
      );
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect((m.client as any).refundOperatorWallet).toHaveBeenCalledTimes(1);
    const state = JSON.parse(m.redis.store.get('informer:pending_op:u1')!);
    expect(state.step).toBe('gate');
    expect(m.published.join('')).toContain('Сверил, выплаты не было');
  });

  it('снятие гейта отправляет withdrawal_verified_absent=true', async () => {
    const m = mocksWithWallet();
    let call = 0;
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      if (++call === 1) {
        throw new InformerUnavailableError(
          502,
          JSON.stringify({ message: 'refund would be a second payout' }),
        );
      }
      return { wallet_id: 1611, status: 'ok' };
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');
    await svc.handleUserMessage('u1', 'c1', '✅ Сверил, выплаты не было #1611');
    await svc.handleUserMessage('u1', 'c1', '654321');

    expect((m.client as any).refundOperatorWallet).toHaveBeenLastCalledWith(
      1611,
      { refundToPayer: true },
      '654321',
      true,
    );
  });

  it('403 пересоздаёт totp-шаг возврата, а не сбрасывает мастер', async () => {
    const m = mocksWithWallet();
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      throw new InformerTotpError('bad code');
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    const state = JSON.parse(m.redis.store.get('informer:pending_op:u1')!);
    expect(state).toMatchObject({ step: 'totp', verifiedAbsent: false });
    expect(m.published.join('')).toContain('Код не принят');
  });

  it('таймаут не предлагает повтор', async () => {
    const m = mocksWithWallet();
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      throw new InformerTimeoutError();
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    const out = m.published.join('');
    expect(out).toContain('могла');
    expect(out).not.toContain('[ACTION:💸 Вернуть #1611]');
  });

  it('блокировка по кошельку отклоняет параллельный возврат', async () => {
    const m = mocksWithWallet();
    m.redis.store.set('informer:refund_inflight:1611', '1');
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect((m.client as any).refundOperatorWallet).not.toHaveBeenCalled();
    expect(m.published.join('')).toContain('уже идёт возврат');
  });

  it('блокировка снимается после успеха', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect(m.redis.store.has('informer:refund_inflight:1611')).toBe(false);
  });

  it('блокировка снимается после ошибки', async () => {
    const m = mocksWithWallet();
    (m.client as any).refundOperatorWallet = jest.fn(async () => {
      throw new InformerTimeoutError();
    });
    const svc = makeService(m);

    await walkToTotp(svc, m);
    await svc.handleUserMessage('u1', 'c1', '123456');

    expect(m.redis.store.has('informer:refund_inflight:1611')).toBe(false);
  });

  it('отмена очищает состояние без вызова API', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');
    await svc.handleUserMessage('u1', 'c1', '❌ Отмена возврата');

    expect(m.redis.store.has('informer:pending_op:u1')).toBe(false);
    expect((m.client as any).refundOperatorWallet).not.toHaveBeenCalled();
  });

  it('метка навигационной кнопки на шаге адреса не становится адресом', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');
    await svc.handleUserMessage('u1', 'c1', '📮 Указать адрес #1611');
    // Оператор по инерции жмёт навигацию из более раннего сообщения.
    await svc.handleUserMessage('u1', 'c1', '📋 Кошельки оператора');

    // Мастер сброшен, «адрес» не принят, показан список кошельков.
    expect(m.redis.store.has('informer:pending_op:u1')).toBe(false);
    expect((m.client as any).refundOperatorWallet).not.toHaveBeenCalled();
    expect(m.published.join('')).toContain('Кошельки, требующие оператора');
  });

  it('двойное нажатие кнопки возврата не дёргает список дважды', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');
    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #1611');

    expect(m.client.getOperatorRequiredList).toHaveBeenCalledTimes(1);
  });

  it('кнопка возврата по неизвестному кошельку объясняет, а не падает', async () => {
    const m = mocksWithWallet();
    const svc = makeService(m);

    await svc.handleUserMessage('u1', 'c1', '💸 Вернуть #9999');

    expect(m.published.join('')).toContain('9999');
    expect(m.redis.store.has('informer:pending_op:u1')).toBe(false);
  });
});
