import {
  formatOperatorWalletsList,
  formatMiniAcquiringBalances,
  formatGatewayWallets,
  formatNewOperatorWalletAlert,
  OPERATOR_BUTTONS,
} from './informer.formatters';

describe('formatOperatorWalletsList', () => {
  it('renders empty state with total 0', () => {
    const md = formatOperatorWalletsList({
      items: [],
      total: 0,
      page: 1,
      per_page: 50,
    });
    expect(md).toContain('Кошельки, требующие оператора');
    expect(md).toContain('0');
    expect(md).toContain(OPERATOR_BUTTONS);
  });

  it('renders 2 items with addresses and amounts', () => {
    const md = formatOperatorWalletsList({
      items: [
        {
          created_at: '2026-06-02T12:49:51Z',
          withdraw_address: 'TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG',
          withdraw_network: 'tron',
          withdraw_token: 'usdt',
          withdraw_amount: '1.258494593554098000',
        },
        {
          created_at: '2026-05-29T15:17:25Z',
          withdraw_address: '0x89Ffc69aA86bA8b1592AbEF189B6ec5d7E33301a',
          withdraw_network: 'ethereum',
          withdraw_token: 'eth',
          withdraw_amount: '0.006338050505100000',
        },
      ],
      total: 13,
      page: 1,
      per_page: 20,
    });
    expect(md).toContain('13');
    expect(md).toContain('TGkEaodwbZWd8Sg7wGoRQU5tHYwhTWM9ZG');
    expect(md).toContain('0x89Ffc69aA86bA8b1592AbEF189B6ec5d7E33301a');
    expect(md).toContain('tron');
    expect(md).toContain('ethereum');
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
