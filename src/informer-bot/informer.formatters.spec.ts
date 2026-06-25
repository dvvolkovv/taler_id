import {
  formatOperatorWalletsList,
  formatMiniAcquiringBalances,
  formatGatewayWallets,
  formatNewOperatorWalletAlert,
  OPERATOR_BUTTONS,
} from './informer.formatters';

describe('formatOperatorWalletsList', () => {
  it('renders empty state as a single message with total 0', () => {
    const messages = formatOperatorWalletsList({
      items: [],
      total: 0,
      page: 1,
      per_page: 50,
    });
    expect(messages).toHaveLength(1);
    const joined = messages.join('\n');
    expect(joined).toContain('Кошельки, требующие оператора');
    expect(joined).toContain('0');
    expect(joined).toContain(OPERATOR_BUTTONS);
  });

  it('emits header + one card per wallet + nav trailer; retry button is co-located with its wallet', () => {
    const messages = formatOperatorWalletsList({
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
      total: 13,
      page: 1,
      per_page: 20,
    });
    expect(messages).toHaveLength(4); // header + 2 cards + trailer
    expect(messages[0]).toContain('Кошельки, требующие оператора');
    expect(messages[0]).toContain('13');
    // First card pairs row #857 with the #857 retry button — and ONLY that
    // button (so mobile renders one button immediately under one wallet).
    expect(messages[1]).toContain('#857');
    expect(messages[1]).toContain('0xb45CfA4ADdd2d93e38413AD55F704Ea643eD7144');
    expect(messages[1]).toContain('[ACTION:🔁 Повторить #857]');
    expect(messages[1]).not.toContain('#855');
    // Second card pairs row #855 with its own button.
    expect(messages[2]).toContain('#855');
    expect(messages[2]).toContain('0x538c6ED66155dAAB441C008EbF9798cfd9fd330C');
    expect(messages[2]).toContain('[ACTION:🔁 Повторить #855]');
    expect(messages[2]).not.toContain('#857');
    // Trailer = nav buttons, separate from wallet cards.
    expect(messages[3]).toBe(OPERATOR_BUTTONS);
  });

  it('omits retry button on items missing wallet_id (tolerant for older admin-API)', () => {
    const messages = formatOperatorWalletsList({
      items: [
        {
          // no wallet_id — admin-API stand without the field
          created_at: '2026-06-02T12:49:51Z',
          withdraw_address: 'TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG',
          withdraw_network: 'tron',
          withdraw_token: 'usdt',
          withdraw_amount: '1.0',
        },
      ],
      total: 1,
      page: 1,
      per_page: 20,
    });
    expect(messages).toHaveLength(3); // header + 1 card + trailer
    expect(messages[1]).toContain('TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG');
    expect(messages[1]).not.toContain('[ACTION:🔁');
  });
});

describe('formatMiniAcquiringBalances', () => {
  it('renders chain, role balances, and per-role error', () => {
    const md = formatMiniAcquiringBalances({
      chains: [
        {
          chain: 'Ethereum',
          base_asset: 'eth',
          supported: true,
          roles: [
            {
              role: 'cold_wallet',
              address: '0xc45c14106e7e76ab1be2ee292f7323e897658644',
              balances: [
                { asset: 'eth', kind: 'base', balance: '0.001997436761294' },
                { asset: 'usdt', kind: 'erc20', balance: '0' },
              ],
            },
            { role: 'hot_wallet', address: '', error: 'no seed configured' },
          ],
        },
      ],
    });
    expect(md).toContain('Ethereum');
    expect(md).toContain('cold_wallet');
    expect(md).toContain('hot_wallet');
    expect(md).toContain('no seed configured');
    expect(md).toContain('0.001997436761294');
  });
});

describe('formatGatewayWallets', () => {
  it('groups by blockchain + asset', () => {
    const md = formatGatewayWallets({
      items: [
        {
          blockchain: 'Binance smart chain',
          asset_symbol: 'USDT',
          wallet_type: 'cold',
          balance: '4.9030003',
          address: '0x646A64D6B30A361539a02a672Ba7090124ad8796',
          updated_at: 1781538033,
        },
      ],
    });
    expect(md).toContain('Binance smart chain');
    expect(md).toContain('USDT');
    expect(md).toContain('cold');
    expect(md).toContain('0x646A64D6B30A361539a02a672Ba7090124ad8796');
  });

  it('renders empty state', () => {
    const md = formatGatewayWallets({ items: [] });
    expect(md).toContain('Системные кошельки gateway');
    expect(md).toContain(OPERATOR_BUTTONS);
  });
});

describe('formatNewOperatorWalletAlert', () => {
  it('renders a single new-wallet alert with retry buttons', () => {
    const md = formatNewOperatorWalletAlert({
      created_at: '2026-06-02T12:49:51Z',
      withdraw_address: 'TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG',
      withdraw_network: 'tron',
      withdraw_token: 'usdt',
      withdraw_amount: '1.258494593554098000',
    });
    expect(md).toContain('Новый кошелёк ждёт оператора');
    expect(md).toContain('TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG');
    expect(md).toContain('tron');
    expect(md).toContain('usdt');
    expect(md).toContain('[ACTION:📋 Все ожидающие]');
    expect(md).toContain('[ACTION:🏦 Балансы gateway]');
  });
});

import { formatRefillDigest } from './informer.formatters';
import { RefillDeficit } from './informer.types';

const sampleDeficit = (overrides: Partial<RefillDeficit> = {}): RefillDeficit => ({
  chain: 'tron',
  token: 'usdt',
  hotAddress: 'TXxxxYYY',
  hotBalance: '800.50',
  pendingTotal: '1200.00',
  availableForWithdrawal: '720.45',
  deficit: '479.55',
  ...overrides,
});

describe('formatRefillDigest', () => {
  it('stage 1: yellow badge, all deficits rendered with colour tags', () => {
    const md = formatRefillDigest([sampleDeficit()], 1);
    expect(md).toContain('STAGE 1');
    expect(md).toContain('[B:yellow]');
    expect(md).toContain('[HOT_BADGE]HOT[/HOT_BADGE]');
    expect(md).toContain('[HOT]800.50[/HOT]');
    expect(md).toContain('[C:red]−479.55[/C]');
    expect(md).toContain('`TXxxxYYY`');
  });

  it('stage 2: red unresolved badge', () => {
    const md = formatRefillDigest([sampleDeficit()], 2);
    expect(md).toContain('STAGE 2 — UNRESOLVED');
    expect(md).toContain('[B:red]');
  });

  it('stage 3: red escalated badge', () => {
    const md = formatRefillDigest([sampleDeficit()], 3);
    expect(md).toContain('STAGE 3 — ESCALATED');
  });

  it('contains all four ack buttons', () => {
    const md = formatRefillDigest([sampleDeficit()], 1);
    expect(md).toContain('[ACTION:✅ Понял, работаю]');
    expect(md).toContain('[ACTION:🔕 Заглушить 1 час]');
    expect(md).toContain('[ACTION:🔕 До утра 9:00]');
    expect(md).toContain('[ACTION:🔇 Совсем отключить]');
  });

  it('renders multiple deficits as a list', () => {
    const md = formatRefillDigest(
      [
        sampleDeficit(),
        sampleDeficit({
          chain: 'bitcoin',
          token: 'btc',
          hotAddress: 'bc1qZZ',
          hotBalance: '0.5',
          deficit: '0.1',
        }),
      ],
      1,
    );
    expect(md).toContain('tron-usdt');
    expect(md).toContain('bitcoin-btc');
    expect(md).toContain('`bc1qZZ`');
  });

  it('does not nest colour tags inside other colour tags', () => {
    const md = formatRefillDigest([sampleDeficit()], 1);
    // No same-family tag opener can appear before a non-bracket char inside a wrapping tag.
    expect(md).not.toMatch(/\[HOT\][^[]*\[HOT_BADGE\]/);
    expect(md).not.toMatch(/\[C:[a-z]+\][^[]*\[C:[a-z]+\]/);
    expect(md).not.toMatch(/\[B:[a-z]+\][^[]*\[B:[a-z]+\]/);
  });
});

import {
  formatRefillSnoozed,
  formatRefillDisabled,
  formatRefillEnabled,
  formatRefillSettings,
} from './informer.formatters';

describe('formatRefillSnoozed', () => {
  it('contains the duration argument and re-enable button', () => {
    const md = formatRefillSnoozed('1 час');
    expect(md).toContain('1 час');
    expect(md).toContain('[ACTION:🔔 Включить обратно]');
    expect(md).toContain('[ACTION:⚙️ Настройки алёртов]');
  });

  it('accepts custom prefix', () => {
    const md = formatRefillSnoozed('30 минут', '[B:green]✅ Принято[/B]');
    expect(md).toContain('✅ Принято');
    expect(md).toContain('[B:green]');
    expect(md).toContain('30 минут');
  });
});

describe('formatRefillDisabled', () => {
  it('shows red status and only the enable button', () => {
    const md = formatRefillDisabled();
    expect(md).toContain('[B:red]');
    expect(md).toContain('🔇 Отключено');
    expect(md).toContain('[ACTION:🔔 Включить обратно]');
  });
});

describe('formatRefillEnabled', () => {
  it('shows green status and settings button', () => {
    const md = formatRefillEnabled();
    expect(md).toContain('[B:green]');
    expect(md).toContain('🔔 Включено');
    expect(md).toContain('[ACTION:⚙️ Настройки алёртов]');
  });
});

describe('formatRefillSettings', () => {
  it('enabled, not snoozed: shows Активно + disable button', () => {
    const md = formatRefillSettings({
      userId: 'u1',
      enabled: true,
      snoozedUntil: null,
      lastDigestStage: 0,
      lastDigestAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as any);
    expect(md).toContain('🔔 Активно');
    expect(md).toContain('[B:green]');
    expect(md).toContain('[ACTION:🔇 Совсем отключить]');
  });

  it('enabled, snoozed: shows snoozed status and enable button', () => {
    const future = new Date(Date.now() + 3600_000);
    const md = formatRefillSettings({
      userId: 'u1',
      enabled: true,
      snoozedUntil: future,
      lastDigestStage: 0,
      lastDigestAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as any);
    expect(md).toContain('🔕 Заглушено');
    expect(md).toContain('[B:blue]');
    expect(md).toContain('[ACTION:🔔 Включить обратно]');
  });

  it('disabled: shows Отключено + enable button', () => {
    const md = formatRefillSettings({
      userId: 'u1',
      enabled: false,
      snoozedUntil: null,
      lastDigestStage: 0,
      lastDigestAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as any);
    expect(md).toContain('🔇 Отключено');
    expect(md).toContain('[B:red]');
    expect(md).toContain('[ACTION:🔔 Включить обратно]');
  });

  it('null cfg: defaults to Активно', () => {
    const md = formatRefillSettings(null);
    expect(md).toContain('🔔 Активно');
  });
});

import { formatWelcome } from './informer.formatters';

describe('formatWelcome (extended)', () => {
  it('now includes the alert settings button', () => {
    const md = formatWelcome();
    expect(md).toContain('[ACTION:⚙️ Настройки алёртов]');
  });
});

describe('formatWelcome (Sub-2c update)', () => {
  it('now includes the fiat balances button', () => {
    const md = formatWelcome();
    expect(md).toContain('[ACTION:💶 Балансы в евро]');
  });
});

import { formatFiatBalances } from './informer.formatters';
import { FiatBalancesResult } from './informer.types';

const sampleFiat = (
  overrides: Partial<FiatBalancesResult> = {},
): FiatBalancesResult => ({
  pools: [
    {
      poolName: 'mini-acquiring',
      eurTotal: '52400',
      chains: [
        {
          chain: 'tron',
          eurTotal: '30200',
          roles: [
            {
              role: 'hot_wallet',
              eurTotal: '18500',
              tokens: [{ asset: 'usdt', native: '12450', eur: '18500' }],
            },
            {
              role: 'cold_wallet',
              eurTotal: '11700',
              tokens: [{ asset: 'usdt', native: '7850', eur: '11700' }],
            },
          ],
        },
      ],
      unpricedAssets: [],
    },
    {
      poolName: 'gateway',
      eurTotal: '18100',
      chains: [
        {
          chain: 'tron',
          eurTotal: '12400',
          flatTokens: [
            {
              asset: 'usdt',
              walletType: 'deposit',
              native: '8350',
              eur: '12400',
            },
          ],
        },
      ],
      unpricedAssets: [],
    },
  ],
  ratesCacheAgeMin: 2,
  coingeckoStatus: 'ok',
  ...overrides,
});

describe('formatFiatBalances', () => {
  it('renders both pool blocks with totals + colour badges', () => {
    const md = formatFiatBalances(sampleFiat());
    expect(md).toContain('💰 Mini-acquiring');
    expect(md).toContain('🏦 Gateway');
    expect(md).toContain('[B:green]');
    expect(md).toContain('€52 400');
    expect(md).toContain('€18 100');
  });

  it('renders mini-acquiring rows with HOT_BADGE/COLD_BADGE + tinted text', () => {
    const md = formatFiatBalances(sampleFiat());
    expect(md).toContain('[HOT_BADGE]HOT[/HOT_BADGE]');
    expect(md).toContain('[COLD_BADGE]COLD[/COLD_BADGE]');
    expect(md).toContain('[HOT]€18 500[/HOT]');
    expect(md).toContain('[COLD]€11 700[/COLD]');
    expect(md).toContain('(12 450 USDT)');
  });

  it('renders cache age header when ratesCacheAgeMin > 0', () => {
    const md = formatFiatBalances(sampleFiat({ ratesCacheAgeMin: 5 }));
    expect(md).toContain('обновлены 5 мин назад');
  });

  it('renders "впервые получены" when ratesCacheAgeMin is null', () => {
    const md = formatFiatBalances(sampleFiat({ ratesCacheAgeMin: null }));
    expect(md).toContain('впервые получены сейчас');
  });

  it('renders "только что обновлены" when ratesCacheAgeMin === 0', () => {
    const md = formatFiatBalances(sampleFiat({ ratesCacheAgeMin: 0 }));
    expect(md).toContain('только что обновлены');
  });

  it('low-pool total uses [B:yellow] when total ≤ €10 000', () => {
    const r = sampleFiat();
    r.pools[0].eurTotal = '8000';
    r.pools[0].chains[0].eurTotal = '8000';
    const md = formatFiatBalances(r);
    expect(md).toContain('[B:yellow]');
  });

  it('renders unpriced footer when present, omits otherwise', () => {
    const withUnpriced = sampleFiat();
    withUnpriced.pools[0].unpricedAssets.push({
      asset: 'sometoken',
      chain: 'ethereum',
      native: '42',
    });
    const md = formatFiatBalances(withUnpriced);
    expect(md).toContain('[C:yellow]42 SOMETOKEN на ethereum[/C]');

    const noUnpriced = sampleFiat();
    expect(formatFiatBalances(noUnpriced)).not.toContain(
      "Asset'ы не пересчитанные",
    );
  });

  it('coingeckoStatus=stale → yellow warning banner', () => {
    const md = formatFiatBalances(sampleFiat({ coingeckoStatus: 'stale' }));
    expect(md).toContain('[C:yellow]⚠️ Курсы из старого кэша');
  });

  it('coingeckoStatus=failed → red banner, no [HOT]/[COLD] EUR tags', () => {
    const md = formatFiatBalances(sampleFiat({ coingeckoStatus: 'failed' }));
    expect(md).toContain('[C:red]⚠️ Курсы недоступны');
    expect(md).not.toContain('[HOT]€');
    expect(md).not.toContain('[COLD]€');
  });

  it('does not nest colour tags inside other colour tags', () => {
    const md = formatFiatBalances(sampleFiat());
    expect(md).not.toMatch(/\[HOT\][^[]*\[HOT_BADGE\]/);
    expect(md).not.toMatch(/\[C:[a-z]+\][^[]*\[C:[a-z]+\]/);
    expect(md).not.toMatch(/\[B:[a-z]+\][^[]*\[B:[a-z]+\]/);
  });

  it('contains refresh + cross-link buttons', () => {
    const md = formatFiatBalances(sampleFiat());
    expect(md).toContain('[ACTION:🔄 Обновить курсы]');
    expect(md).toContain('[ACTION:📋 Кошельки оператора]');
    expect(md).toContain('[ACTION:💰 Балансы mini-acquiring]');
    expect(md).toContain('[ACTION:🏦 Системные кошельки gateway]');
  });
});

describe('OPERATOR_BUTTONS main menu (5 actions)', () => {
  it('contains all five main-menu buttons (regression after Sub-2c)', () => {
    expect(OPERATOR_BUTTONS).toContain('[ACTION:📋 Кошельки оператора]');
    expect(OPERATOR_BUTTONS).toContain('[ACTION:💰 Балансы mini-acquiring]');
    expect(OPERATOR_BUTTONS).toContain('[ACTION:🏦 Системные кошельки gateway]');
    expect(OPERATOR_BUTTONS).toContain('[ACTION:💶 Балансы в евро]');
    expect(OPERATOR_BUTTONS).toContain('[ACTION:⚙️ Настройки алёртов]');
  });

  it('every primary list formatter ends with the full main menu', () => {
    // formatOperatorWalletsList now emits a string[] — the menu lives in
    // the last message (trailer in non-empty case, or the only message in
    // empty case).
    expect(
      formatOperatorWalletsList({
        items: [],
        total: 0,
        page: 1,
        per_page: 50,
      }).join('\n'),
    ).toContain('[ACTION:💶 Балансы в евро]');
    expect(formatMiniAcquiringBalances({ chains: [] })).toContain(
      '[ACTION:⚙️ Настройки алёртов]',
    );
    expect(formatGatewayWallets({ items: [] })).toContain(
      '[ACTION:💶 Балансы в евро]',
    );
  });

  it('welcome includes all five buttons through OPERATOR_BUTTONS', () => {
    const md = formatWelcome();
    expect(md).toContain('[ACTION:📋 Кошельки оператора]');
    expect(md).toContain('[ACTION:💰 Балансы mini-acquiring]');
    expect(md).toContain('[ACTION:🏦 Системные кошельки gateway]');
    expect(md).toContain('[ACTION:💶 Балансы в евро]');
    expect(md).toContain('[ACTION:⚙️ Настройки алёртов]');
  });
});
