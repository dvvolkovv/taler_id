import { InformerWatcher } from './informer.watcher';
import {
  InformerAuthError,
  InformerUnavailableError,
  MiniAcquiringBalances,
  OperatorRequiredList,
} from './informer.types';

function makeItem(addr: string) {
  return {
    created_at: '2026-06-02T12:49:51Z',
    withdraw_address: addr,
    withdraw_network: 'tron',
    withdraw_token: 'usdt',
    withdraw_amount: '1.0',
  };
}

function makeMocks() {
  const seenWallets: any[] = [];
  const publishes: { userId: string; content: string }[] = [];
  const bootstrappedFlag = { v: null as null | string };

  const prisma = {
    informerSeenWallet: {
      findUnique: jest.fn(async ({ where }: any) => {
        const k = where.address_network_token;
        return (
          seenWallets.find(
            (w) =>
              w.address === k.address &&
              w.network === k.network &&
              w.token === k.token,
          ) ?? null
        );
      }),
      create: jest.fn(async ({ data }: any) => {
        seenWallets.push(data);
        return data;
      }),
      deleteMany: jest.fn(async () => ({ count: 0 })),
    },
  };

  const client = {
    getOperatorRequiredList: jest.fn<Promise<OperatorRequiredList>, any[]>(),
  };

  const service = {
    listWhitelistedUserIds: jest.fn(async () => ['u1', 'u2']),
    getOrCreateChat: jest.fn(async (uid: string) => `conv-${uid}`),
    publishBotMessage: jest.fn(
      async (userId: string, _convId: string, content: string) => {
        publishes.push({ userId, content });
      },
    ),
  };

  const redis = {
    get: jest.fn(async (k: string) =>
      k === 'informer:bootstrapped' ? bootstrappedFlag.v : null,
    ),
    setEx: jest.fn(async (k: string, _ttl: number, v: string) => {
      if (k === 'informer:bootstrapped') bootstrappedFlag.v = v;
    }),
  };

  return { prisma, client, service, redis, seenWallets, publishes };
}

describe('InformerWatcher.tickForTest', () => {
  it('cold-start: first tick records items without alerts', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList.mockResolvedValueOnce({
      items: [makeItem('A'), makeItem('B'), makeItem('C')],
      total: 3,
      page: 1,
      per_page: 500,
    });
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    const result = await w.tickForTest();
    expect(result.bootstrapped).toBe(true);
    expect(m.seenWallets).toHaveLength(3);
    expect(m.publishes).toHaveLength(0);
  });

  it('subsequent tick with same items: no alerts', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList
      .mockResolvedValueOnce({
        items: [makeItem('A')],
        total: 1,
        page: 1,
        per_page: 500,
      })
      .mockResolvedValueOnce({
        items: [makeItem('A')],
        total: 1,
        page: 1,
        per_page: 500,
      });
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickForTest(); // bootstrap
    await w.tickForTest();
    expect(m.publishes).toHaveLength(0);
  });

  it('new address after bootstrap: alerts every whitelisted user', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList
      .mockResolvedValueOnce({
        items: [makeItem('A')],
        total: 1,
        page: 1,
        per_page: 500,
      })
      .mockResolvedValueOnce({
        items: [makeItem('A'), makeItem('B')],
        total: 2,
        page: 1,
        per_page: 500,
      });
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickForTest(); // bootstrap
    await w.tickForTest();
    expect(m.publishes).toHaveLength(2);
    expect(m.publishes.every((p) => p.content.includes('Новый кошелёк'))).toBe(
      true,
    );
  });

  it('auth error: no alert, no further calls, fatal mode engages', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList.mockRejectedValueOnce(
      new InformerAuthError(),
    );
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickForTest();
    expect(m.publishes).toHaveLength(0);
    expect(m.seenWallets).toHaveLength(0);
  });

  it('3 consecutive 5xx after bootstrap → downtime alert to all users', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList
      .mockResolvedValueOnce({ items: [], total: 0, page: 1, per_page: 500 })
      .mockRejectedValueOnce(new InformerUnavailableError(502, 'x'))
      .mockRejectedValueOnce(new InformerUnavailableError(502, 'x'))
      .mockRejectedValueOnce(new InformerUnavailableError(502, 'x'));
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickForTest(); // bootstrap (empty)
    await w.tickForTest();
    await w.tickForTest();
    await w.tickForTest();
    expect(m.publishes).toHaveLength(2);
    expect(m.publishes[0].content).toContain('Informer API недоступен');
  });
});

function mockMiniBalances(
  hot: { network: string; token: string; balance: string; address?: string }[],
): MiniAcquiringBalances {
  const byChain = new Map<string, typeof hot>();
  for (const h of hot) {
    const arr = byChain.get(h.network) ?? [];
    arr.push(h);
    byChain.set(h.network, arr);
  }
  return {
    chains: [...byChain.entries()].map(([chain, items]) => ({
      chain,
      base_asset: items[0].token,
      supported: true,
      roles: [
        {
          role: 'hot_wallet',
          address: items[0].address ?? `addr-${chain}`,
          balances: items.map((it) => ({
            asset: it.token,
            kind: 'native',
            balance: it.balance,
          })),
        },
      ],
    })),
  };
}

describe('InformerWatcher.computeRefillDeficits', () => {
  function makeWatcher(m: ReturnType<typeof makeMocks>) {
    return new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
  }

  it('no deficit when hot×0.9 >= pending', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList.mockResolvedValue({
      items: [
        { ...makeItem('A'), withdraw_amount: '450' },
        { ...makeItem('B'), withdraw_amount: '450' }, // total 900
      ],
      total: 2,
      page: 1,
      per_page: 500,
    });
    (m.client as any).getMiniAcquiringBalances = jest.fn(async () =>
      mockMiniBalances([{ network: 'tron', token: 'usdt', balance: '1000' }]),
    );

    const w = makeWatcher(m);
    const out = await w.computeRefillDeficits();
    expect(out).toHaveLength(0);
  });

  it('detects deficit when pending exceeds 90% of hot', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList.mockResolvedValue({
      items: [
        { ...makeItem('A'), withdraw_amount: '500' },
        { ...makeItem('B'), withdraw_amount: '450' }, // total 950
      ],
      total: 2,
      page: 1,
      per_page: 500,
    });
    (m.client as any).getMiniAcquiringBalances = jest.fn(async () =>
      mockMiniBalances([{ network: 'tron', token: 'usdt', balance: '1000' }]),
    );

    const w = makeWatcher(m);
    const out = await w.computeRefillDeficits();
    expect(out).toHaveLength(1);
    expect(out[0].chain).toBe('tron');
    expect(out[0].token).toBe('usdt');
    expect(out[0].hotBalance).toBe('1000');
    expect(out[0].pendingTotal).toBe('950');
    expect(out[0].availableForWithdrawal).toBe('900');
    expect(out[0].deficit).toBe('50');
  });

  it('skips chain/token pairs missing from mini-acquiring', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList.mockResolvedValue({
      items: [
        {
          ...makeItem('A'),
          withdraw_network: 'unknown-chain',
          withdraw_amount: '100',
        },
      ],
      total: 1,
      page: 1,
      per_page: 500,
    });
    (m.client as any).getMiniAcquiringBalances = jest.fn(async () =>
      mockMiniBalances([{ network: 'tron', token: 'usdt', balance: '1000' }]),
    );

    const w = makeWatcher(m);
    const out = await w.computeRefillDeficits();
    expect(out).toHaveLength(0);
  });

  // Anchor for adding next describe-block right after computeRefillDeficits.

  it('handles 3-network mixed case: deficit only where applicable', async () => {
    const m = makeMocks();
    m.client.getOperatorRequiredList.mockResolvedValue({
      items: [
        {
          ...makeItem('A'),
          withdraw_network: 'tron',
          withdraw_token: 'usdt',
          withdraw_amount: '500',
        },
        {
          ...makeItem('B'),
          withdraw_network: 'tron',
          withdraw_token: 'usdt',
          withdraw_amount: '450',
        }, // 950 on tron → deficit
        {
          ...makeItem('C'),
          withdraw_network: 'bitcoin',
          withdraw_token: 'btc',
          withdraw_amount: '0.1',
        }, // ok: 0.1 < 10 × 0.9
        {
          ...makeItem('D'),
          withdraw_network: 'ethereum',
          withdraw_token: 'usdc',
          withdraw_amount: '100',
        }, // no mini-acquiring entry → skip
      ],
      total: 4,
      page: 1,
      per_page: 500,
    });
    (m.client as any).getMiniAcquiringBalances = jest.fn(async () =>
      mockMiniBalances([
        { network: 'tron', token: 'usdt', balance: '1000' },
        { network: 'bitcoin', token: 'btc', balance: '10' },
      ]),
    );

    const w = makeWatcher(m);
    const out = await w.computeRefillDeficits();
    expect(out).toHaveLength(1);
    expect(out[0].chain).toBe('tron');
  });
});

function makeRefillMocks(opts: { configs?: Record<string, any> } = {}) {
  const m = makeMocks();
  const configStore: Record<string, any> = opts.configs ?? {};
  (m.prisma as any).informerAlertConfig = {
    findUnique: jest.fn(
      async ({ where }: any) => configStore[where.userId] ?? null,
    ),
    upsert: jest.fn(async ({ where, update, create }: any) => {
      configStore[where.userId] = {
        ...configStore[where.userId],
        ...create,
        ...update,
      };
      return configStore[where.userId];
    }),
  };
  return { ...m, configStore };
}

function withDeficit(
  m: ReturnType<typeof makeRefillMocks>,
  hot: string,
  pending: string,
) {
  m.client.getOperatorRequiredList.mockResolvedValue({
    items: [
      {
        created_at: '2026-06-02T12:49:51Z',
        withdraw_address: 'X',
        withdraw_network: 'tron',
        withdraw_token: 'usdt',
        withdraw_amount: pending,
      },
    ],
    total: 1,
    page: 1,
    per_page: 500,
  });
  (m.client as any).getMiniAcquiringBalances = jest.fn(async () =>
    mockMiniBalances([{ network: 'tron', token: 'usdt', balance: hot }]),
  );
}

describe('InformerWatcher.tickRefillForTest', () => {
  it('first tick with deficit → STAGE 1, publishes, sets state', async () => {
    const m = makeRefillMocks();
    withDeficit(m, '1000', '950');
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickRefillForTest();
    expect(m.publishes).toHaveLength(2);
    expect(m.publishes[0].content).toContain('STAGE 1');
    expect(m.configStore['u1'].lastDigestStage).toBe(1);
    expect(m.configStore['u1'].lastDigestAt).toBeInstanceOf(Date);
  });

  it('second tick before 30 min cooldown → no publish', async () => {
    const recent = new Date(Date.now() - 5 * 60 * 1000);
    const m = makeRefillMocks({
      configs: {
        u1: {
          userId: 'u1',
          enabled: true,
          snoozedUntil: null,
          lastDigestStage: 1,
          lastDigestAt: recent,
        },
        u2: {
          userId: 'u2',
          enabled: true,
          snoozedUntil: null,
          lastDigestStage: 1,
          lastDigestAt: recent,
        },
      },
    });
    withDeficit(m, '1000', '950');
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickRefillForTest();
    expect(m.publishes).toHaveLength(0);
  });

  it('tick after 30 min → STAGE 2 publish, state updated', async () => {
    const past = new Date(Date.now() - 31 * 60 * 1000);
    const m = makeRefillMocks({
      configs: {
        u1: {
          userId: 'u1',
          enabled: true,
          snoozedUntil: null,
          lastDigestStage: 1,
          lastDigestAt: past,
        },
        u2: {
          userId: 'u2',
          enabled: true,
          snoozedUntil: null,
          lastDigestStage: 1,
          lastDigestAt: past,
        },
      },
    });
    withDeficit(m, '1000', '950');
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickRefillForTest();
    expect(m.publishes).toHaveLength(2);
    expect(m.publishes[0].content).toContain('STAGE 2');
    expect(m.configStore['u1'].lastDigestStage).toBe(2);
  });

  it('tick after 60 min from STAGE 2 → STAGE 3', async () => {
    const past = new Date(Date.now() - 61 * 60 * 1000);
    const m = makeRefillMocks({
      configs: {
        u1: {
          userId: 'u1',
          enabled: true,
          snoozedUntil: null,
          lastDigestStage: 2,
          lastDigestAt: past,
        },
      },
    });
    m.service.listWhitelistedUserIds = jest.fn(async () => ['u1']);
    withDeficit(m, '1000', '950');
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickRefillForTest();
    expect(m.publishes).toHaveLength(1);
    expect(m.publishes[0].content).toContain('STAGE 3');
    expect(m.configStore['u1'].lastDigestStage).toBe(3);
  });

  it('STAGE 3 is silent on subsequent ticks', async () => {
    const past = new Date(Date.now() - 90 * 60 * 1000);
    const m = makeRefillMocks({
      configs: {
        u1: {
          userId: 'u1',
          enabled: true,
          snoozedUntil: null,
          lastDigestStage: 3,
          lastDigestAt: past,
        },
      },
    });
    m.service.listWhitelistedUserIds = jest.fn(async () => ['u1']);
    withDeficit(m, '1000', '950');
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickRefillForTest();
    expect(m.publishes).toHaveLength(0);
  });

  it('recovery (deficit gone) silently resets state', async () => {
    const m = makeRefillMocks({
      configs: {
        u1: {
          userId: 'u1',
          enabled: true,
          snoozedUntil: null,
          lastDigestStage: 2,
          lastDigestAt: new Date(),
        },
      },
    });
    m.service.listWhitelistedUserIds = jest.fn(async () => ['u1']);
    // pending=400, hot=1000 → available=900, deficit=−500 → no deficits
    withDeficit(m, '1000', '400');
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickRefillForTest();
    expect(m.publishes).toHaveLength(0);
    expect(m.configStore['u1'].lastDigestStage).toBe(0);
    expect(m.configStore['u1'].lastDigestAt).toBeNull();
  });

  it('snoozed user gets no publish', async () => {
    const m = makeRefillMocks({
      configs: {
        u1: {
          userId: 'u1',
          enabled: true,
          snoozedUntil: new Date(Date.now() + 3600 * 1000),
          lastDigestStage: 0,
          lastDigestAt: null,
        },
      },
    });
    m.service.listWhitelistedUserIds = jest.fn(async () => ['u1']);
    withDeficit(m, '1000', '950');
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickRefillForTest();
    expect(m.publishes).toHaveLength(0);
  });

  it('disabled user gets no publish', async () => {
    const m = makeRefillMocks({
      configs: {
        u1: {
          userId: 'u1',
          enabled: false,
          snoozedUntil: null,
          lastDigestStage: 0,
          lastDigestAt: null,
        },
      },
    });
    m.service.listWhitelistedUserIds = jest.fn(async () => ['u1']);
    withDeficit(m, '1000', '950');
    const w = new InformerWatcher(
      m.prisma as any,
      m.client as any,
      m.service as any,
      m.redis as any,
    );
    await w.tickRefillForTest();
    expect(m.publishes).toHaveLength(0);
  });
});
