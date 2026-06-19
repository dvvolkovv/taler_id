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
