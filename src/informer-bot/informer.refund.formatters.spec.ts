import {
  formatRefundMethodChoice,
  formatRefundAddressPrompt,
  formatRefundAddressEmpty,
  formatRefundConfirm,
  formatRefundAwaitingTotp,
  formatRefundTotpRejected,
  formatRefundCancelled,
  formatRefundResult,
  formatRefundGate,
  formatRefundFailure,
  formatRefundTimeout,
  formatRefundInFlight,
  supportsPayerDetection,
} from './informer.refund.formatters';
import { classifyRefundFailure } from './informer.refund-errors';
import { WalletCtx } from './informer.types';

/** Any `[ACTION:...]` label — used to assert a card is never a dead end. */
const HAS_ACTION_BUTTON = /\[ACTION:[^\]]+\]/;

describe('supportsPayerDetection — гейт на сети пополнения', () => {
  it('taler → true', () => {
    expect(supportsPayerDetection('taler')).toBe(true);
    expect(supportsPayerDetection('TALER')).toBe(true);
    expect(supportsPayerDetection('  taler  ')).toBe(true);
  });

  it('bsc → false', () => {
    expect(supportsPayerDetection('bsc')).toBe(false);
  });

  it('пустая строка → false (fail-closed)', () => {
    expect(supportsPayerDetection('')).toBe(false);
  });

  it('незнакомая сеть → false (fail-closed)', () => {
    expect(supportsPayerDetection('some-new-chain')).toBe(false);
  });
});

describe('мастер возврата — карточки', () => {
  const CTX: WalletCtx = {
    deposit: {
      network: 'bsc',
      token: 'usdc',
      amount: '123.45',
      address: '0xdep',
    },
    withdraw: {
      network: 'BSC',
      token: 'usdt',
      amount: '50',
      address: '0xcust',
    },
  };
  const TALER_CTX: WalletCtx = {
    ...CTX,
    deposit: { ...CTX.deposit, network: 'taler' },
  };

  // Gated on deposit.network, matching supportsPayerDetection: only a
  // Taler deposit gets the payer button. See informer.refund-flow.spec.ts
  // for the flow-level insurance test against gating on withdraw.network
  // instead.
  it('кнопка «вернуть плательщику» есть только когда deposit.network=taler', () => {
    expect(formatRefundMethodChoice(1611, CTX)).not.toContain(
      '[ACTION:👤 Вернуть плательщику #1611]',
    );
    expect(formatRefundMethodChoice(1611, TALER_CTX)).toContain(
      '[ACTION:👤 Вернуть плательщику #1611]',
    );
  });

  it('кнопка «указать адрес» всегда доступна, независимо от сети пополнения', () => {
    expect(formatRefundMethodChoice(1611, CTX)).toContain(
      '[ACTION:📮 Указать адрес #1611]',
    );
    expect(formatRefundMethodChoice(1611, TALER_CTX)).toContain(
      '[ACTION:📮 Указать адрес #1611]',
    );
  });

  it('карточка выбора способа не выдаёт ожидаемую сумму пополнения за факт и показывает обе стороны для кошелька #1646', () => {
    const md = formatRefundMethodChoice(1646, {
      deposit: {
        network: 'taler',
        token: 'tal',
        amount: '0.004760555556000000',
        address: 'tALNFJxXR5ZBVgrkPpiNX3KAHJSg1wHkYmMipx45fZJgmpC22',
      },
      withdraw: {
        network: 'bsc',
        token: 'usdc',
        amount: '59.700000005589338905',
        address: '0x75c77b569461C6065A0dec22D9fD23FaF3295157',
      },
    });
    // The withdraw figures must read as a failed withdrawal, not as a
    // preview of the refund — old rendering was the bare
    // `#1646 · 59.7 usdc · bsc` that reads as "this will be sent".
    expect(md).toContain('не прошёл вывод 59.700000005589338905 usdc в bsc');
    expect(md).not.toContain('#1646** · 59.7 usdc · bsc');
    // Deposit amount is worded as an expectation, never as a fact.
    expect(md).toContain('Ожидавшаяся сумма');
    expect(md).toContain('не факт');
    expect(md).toContain('0.004760555556000000');
    expect(md).toContain('taler');
    // deposit/withdraw mismatch is a normal swap, not an error.
    expect(md).not.toMatch(/несовпаден|ошибк/i);
  });

  it('в каждой карточке мастера есть отмена', () => {
    expect(formatRefundMethodChoice(1611, CTX)).toContain(
      '[ACTION:❌ Отмена возврата]',
    );
    expect(formatRefundAddressPrompt(1611, CTX)).toContain(
      '[ACTION:❌ Отмена возврата]',
    );
    expect(formatRefundAwaitingTotp(1611, 60)).toContain(
      '[ACTION:❌ Отмена возврата]',
    );
  });

  it('адрес запрашивается для сети пополнения, а не для сети вывода из карточки', () => {
    const md = formatRefundAddressPrompt(1646, {
      deposit: {
        network: 'taler',
        token: 'tal',
        amount: '0.0047',
        address: 'tALNcust',
      },
      withdraw: {
        network: 'bsc',
        token: 'usdc',
        amount: '59.7',
        address: '0x75c77b569461C6065A0dec22D9fD23FaF3295157',
      },
    });
    // Now that we know the deposit network, the caveat states it instead
    // of pleading ignorance.
    expect(md).not.toContain('нам неизвестно');
    expect(md).toContain('сети пополнения');
    expect(md).toContain('`taler`');
    expect(md).toContain('а НЕ в сети вывода');
    expect(md).toContain('`bsc`');
  });

  it('подтверждение адреса показывает ожидавшуюся сумму пополнения с пометкой «не факт» и параметры несостоявшегося вывода', () => {
    const md = formatRefundConfirm(1611, CTX, { refundAddress: '0xB1c4' });
    expect(md).toContain('123.45'); // ожидавшаяся сумма пополнения
    expect(md).toContain('bsc'); // сеть пополнения (CTX.deposit.network)
    expect(md).toContain('50'); // сумма несостоявшегося вывода
    expect(md).toContain('BSC'); // сеть несостоявшегося вывода
    expect(md).toContain('0xB1c4');
    expect(md).toContain('необратим');
    expect(md).toContain('[ACTION:✅ Подтвердить возврат #1611]');
    expect(md).toContain('Ожидавшаяся сумма');
    expect(md).toContain('не факт');
  });

  it('подтверждение возврата плательщику упоминает Taler, не Tron/биржи, и сохраняет предупреждения о необратимости', () => {
    const md = formatRefundConfirm(1611, TALER_CTX, { refundToPayer: true });
    expect(md).not.toContain('биржи');
    expect(md).not.toContain('Tron');
    expect(md).toContain('показать');
    expect(md).toContain('необратим');
    // Предупреждения, которые остаются независимо от гейта.
    expect(md).toContain('не сообщит, куда ушли деньги');
    expect(md).toContain('Taler');
  });

  it('успешный возврат плательщику честно говорит, что адрес неизвестен', () => {
    const md = formatRefundResult(
      { wallet_id: 1611, status: 'ok' },
      {
        refundToPayer: true,
      },
    );
    expect(md).toContain('#1611');
    expect(md).toContain('адрес получателя платформа не сообщает');
  });

  it('успешный возврат на адрес показывает адрес', () => {
    const md = formatRefundResult(
      { wallet_id: 1611, status: 'ok' },
      {
        refundAddress: '0xB1c4',
      },
    );
    expect(md).toContain('0xB1c4');
  });

  it('карточка гейта перечисляет проверки и не содержит слова «повторить»', () => {
    const md = formatRefundGate(1611, CTX, 'refund would be a second payout');
    expect(md).toContain('[ACTION:✅ Сверил, выплаты не было #1611]');
    expect(md.toLowerCase()).not.toContain('повторить');
    expect(md).toContain('0xcust');
    expect(md).toContain('BSC');
    expect(md).toContain('логируется');
  });

  it('нехватка средств на hot даёт кнопку повтора и ведёт к балансам', () => {
    const f = classifyRefundFailure(
      'hot wallet holds 3 but the refund needs 50',
    );
    const md = formatRefundFailure(1611, f);
    expect(md).toContain('[ACTION:💸 Вернуть #1611]');
    expect(md).toContain('[ACTION:💰 Балансы mini-acquiring]');
  });

  it('«уже существует» не даёт кнопки повтора и объясняет, что первая попытка прошла', () => {
    const f = classifyRefundFailure(
      'refund operation already exists for this wallet',
    );
    const md = formatRefundFailure(1611, f);
    expect(md).not.toContain('[ACTION:💸 Вернуть');
    expect(md).toContain('первая попытка');
  });

  it('отсутствие hot-wallet пути — тупик без повтора', () => {
    const f = classifyRefundFailure(
      'has no hot wallet payout path; refund manually',
    );
    const md = formatRefundFailure(1611, f);
    expect(md).not.toContain('[ACTION:💸 Вернуть');
  });

  it('недоступный узел даёт повтор', () => {
    const f = classifyRefundFailure(
      'refusing to send blind; retry once the node responds',
    );
    const md = formatRefundFailure(1611, f);
    expect(md).toContain('[ACTION:💸 Вернуть #1611]');
  });

  it('незнакомый текст помечается транспортом, но печатается целиком', () => {
    const f = classifyRefundFailure('<html>502 Bad Gateway</html>');
    const md = formatRefundFailure(1611, f);
    expect(md).toContain('502 Bad Gateway');
    expect(md).toContain('транспорт');
    expect(md).not.toContain('[ACTION:💸 Вернуть');
  });

  it('таймаут прямо говорит, что деньги могли уйти, и не даёт повтора', () => {
    const md = formatRefundTimeout(1611);
    expect(md).toContain('могла');
    expect(md).not.toContain('[ACTION:💸 Вернуть');
  });

  it('параллельный возврат по тому же кошельку отклоняется', () => {
    expect(formatRefundInFlight(1611)).toContain('#1611');
  });

  it('платформа отказала без деталей (generic_business) — тоже без кнопки повтора', () => {
    const f = classifyRefundFailure('refund failed');
    const md = formatRefundFailure(1611, f);
    expect(md).not.toContain('[ACTION:💸 Вернуть');
  });

  describe('карточки без отдельного теста на кнопку — не тупики', () => {
    it('AddressEmpty содержит хотя бы одну кнопку', () => {
      expect(formatRefundAddressEmpty(1611)).toMatch(HAS_ACTION_BUTTON);
    });

    it('TotpRejected содержит хотя бы одну кнопку', () => {
      expect(formatRefundTotpRejected(1611, 60)).toMatch(HAS_ACTION_BUTTON);
    });

    it('Cancelled содержит хотя бы одну кнопку', () => {
      expect(formatRefundCancelled()).toMatch(HAS_ACTION_BUTTON);
    });

    it('Result содержит хотя бы одну кнопку', () => {
      expect(
        formatRefundResult(
          { wallet_id: 1611, status: 'ok' },
          { refundAddress: '0xB1c4' },
        ),
      ).toMatch(HAS_ACTION_BUTTON);
    });

    it('InFlight содержит хотя бы одну кнопку', () => {
      expect(formatRefundInFlight(1611)).toMatch(HAS_ACTION_BUTTON);
    });
  });
});
