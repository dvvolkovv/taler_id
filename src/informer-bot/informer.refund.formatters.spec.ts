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

/** Any `[ACTION:...]` label — used to assert a card is never a dead end. */
const HAS_ACTION_BUTTON = /\[ACTION:[^\]]+\]/;

describe('мастер возврата — карточки', () => {
  const CTX = {
    network: 'BSC',
    token: 'usdt',
    amount: '50',
    address: '0xcust',
  };
  const TRON_CTX = { ...CTX, network: 'TRON' };

  it('на BSC предлагает только адрес и объясняет почему', () => {
    const md = formatRefundMethodChoice(1611, CTX);
    expect(md).toContain('[ACTION:📮 Указать адрес #1611]');
    expect(md).not.toContain('плательщику #1611]');
    expect(md).toContain('плательщик не определяется');
  });

  it('на TRON предлагает оба способа', () => {
    const md = formatRefundMethodChoice(1611, TRON_CTX);
    expect(md).toContain('[ACTION:📮 Указать адрес #1611]');
    expect(md).toContain('[ACTION:👤 Вернуть плательщику #1611]');
  });

  it('на незнакомой сети предлагает оба — fail-open', () => {
    const md = formatRefundMethodChoice(1611, { ...CTX, network: 'SOLANA' });
    expect(md).toContain('[ACTION:👤 Вернуть плательщику #1611]');
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

  it('подтверждение адреса показывает сумму, сеть и адрес назначения', () => {
    const md = formatRefundConfirm(1611, CTX, { refundAddress: '0xB1c4' });
    expect(md).toContain('50');
    expect(md).toContain('BSC');
    expect(md).toContain('0xB1c4');
    expect(md).toContain('необратим');
    expect(md).toContain('[ACTION:✅ Подтвердить возврат #1611]');
  });

  it('подтверждение возврата плательщику предупреждает про биржу и невидимый адрес', () => {
    const md = formatRefundConfirm(1611, TRON_CTX, { refundToPayer: true });
    expect(md).toContain('биржи');
    expect(md).toContain('показать');
    expect(md).toContain('необратим');
    // Четвёртое последствие: после успеха платформа не сообщает адрес.
    expect(md).toContain('не сообщит, куда ушли деньги');
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

  describe('supportsPayerDetection — регистр не влияет на результат', () => {
    it.each([
      ['tron', true],
      ['Tron', true],
      ['TRON', true],
      ['bsc', false],
      ['Bsc', false],
      ['BSC', false],
    ])('%s → %s', (network, expected) => {
      expect(supportsPayerDetection(network)).toBe(expected);
    });
  });

  describe('supportsPayerDetection — алиасы одной и той же сети совпадают', () => {
    it('eth и ethereum оба не поддерживают определение плательщика', () => {
      expect(supportsPayerDetection('eth')).toBe(false);
      expect(supportsPayerDetection('ethereum')).toBe(false);
    });

    it('btc и bitcoin оба не поддерживают определение плательщика', () => {
      expect(supportsPayerDetection('btc')).toBe(false);
      expect(supportsPayerDetection('bitcoin')).toBe(false);
    });
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
