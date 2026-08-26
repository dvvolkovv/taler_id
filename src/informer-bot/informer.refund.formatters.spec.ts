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
} from './informer.refund.formatters';
import { classifyRefundFailure } from './informer.refund-errors';

/** Any `[ACTION:...]` label — used to assert a card is never a dead end. */
const HAS_ACTION_BUTTON = /\[ACTION:[^\]]+\]/;

describe('мастер возврата — карточки', () => {
  const CTX = {
    network: 'BSC',
    token: 'usdt',
    amount: '50',
    address: '0xcust',
  };
  const TALER_CTX = { ...CTX, network: 'TALER' };

  // withdraw_network says nothing about the deposit network — the API has
  // no field for it at all — so the wizard cannot gate the payer button
  // locally. Both buttons must render regardless of what withdraw_network
  // says; only the platform can accept or reject "refund to payer" (see
  // the confirm-card test below for the Taler caveat that carries that).
  it.each([['BSC', CTX], ['TALER', TALER_CTX]] as const)(
    'предлагает обе кнопки способа возврата независимо от сети (%s)',
    (_label, ctx) => {
      const md = formatRefundMethodChoice(1611, ctx);
      expect(md).toContain('[ACTION:📮 Указать адрес #1611]');
      expect(md).toContain('[ACTION:👤 Вернуть плательщику #1611]');
    },
  );

  it('карточка выбора способа не выдаёт цель вывода за сумму возврата', () => {
    const md = formatRefundMethodChoice(1646, {
      network: 'bsc',
      token: 'usdc',
      amount: '59.7',
      address: '0x75c77b569461C6065A0dec22D9fD23FaF3295157',
    });
    // The withdraw figures are present but must read as a failed
    // withdrawal, not as a preview of the refund — old rendering was the
    // bare `#1646 · 59.7 usdc · bsc` that reads as "this will be sent".
    expect(md).toContain('не прошёл вывод 59.7 usdc в bsc');
    expect(md).not.toContain('#1646** · 59.7 usdc · bsc');
    expect(md).toContain(
      'Сумма и сеть возврата определяются пополнением кошелька',
    );
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
      network: 'bsc',
      token: 'usdc',
      amount: '59.7',
      address: '0x75c77b569461C6065A0dec22D9fD23FaF3295157',
    });
    expect(md).toContain('сетью пополняли');
    expect(md).toContain('а НЕ в сети вывода');
    expect(md).toContain('`bsc`');
  });

  it('подтверждение адреса показывает целевые параметры вывода и явно предупреждает, что это не сумма возврата', () => {
    const md = formatRefundConfirm(1611, CTX, { refundAddress: '0xB1c4' });
    expect(md).toContain('50');
    expect(md).toContain('BSC');
    expect(md).toContain('0xB1c4');
    expect(md).toContain('необратим');
    expect(md).toContain('[ACTION:✅ Подтвердить возврат #1611]');
    expect(md).toContain(
      'Сумма и сеть возврата определяются пополнением кошелька',
    );
  });

  it('подтверждение возврата плательщику предупреждает про Taler-only и что платформа ничего не отправит при другом пополнении, без Tron', () => {
    const md = formatRefundConfirm(1611, TALER_CTX, { refundToPayer: true });
    expect(md).not.toContain('биржи');
    expect(md).not.toContain('Tron');
    expect(md).toContain('показать');
    expect(md).toContain('необратим');
    // Третье последствие: после успеха платформа не сообщает адрес.
    expect(md).toContain('не сообщит, куда ушли деньги');
    // Оговорка про решение платформы: Taler-only + отказ без отправки.
    expect(md).toContain('Taler');
    expect(md).toContain('отклонит запрос и **ничего не отправит**');
  });

  it('оговорка про Taler и отказ платформы появляется независимо от withdraw_network карточки', () => {
    // withdraw_network не говорит ничего о сети пополнения, так что
    // оговорка не должна зависеть от него — она про решение платформы.
    const md = formatRefundConfirm(1611, CTX, { refundToPayer: true });
    expect(md).toContain('Taler');
    expect(md).toContain('отклонит запрос и **ничего не отправит**');
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
