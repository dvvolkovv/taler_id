import { advanceRefundFlow, parseRefundEntry } from './informer.refund-flow';
import { PendingOp } from './informer.pending-state';
import { refundLabels } from './informer.refund.formatters';

const CTX = {
  deposit: {
    network: 'bsc',
    token: 'usdc',
    amount: '123.45',
    address: '0xdep',
  },
  withdraw: { network: 'BSC', token: 'usdt', amount: '50', address: '0xcust' },
};
const TALER_CTX = {
  ...CTX,
  deposit: { ...CTX.deposit, network: 'taler' },
};

describe('parseRefundEntry — вход в мастер', () => {
  it('распознаёт кнопку возврата с id', () => {
    expect(parseRefundEntry('💸 Вернуть #1611')).toBe(1611);
  });

  it('распознаёт без эмодзи и решётки', () => {
    expect(parseRefundEntry('вернуть 1611')).toBe(1611);
  });

  it('не путает с кнопкой повтора', () => {
    expect(parseRefundEntry('🔁 Повторить #1611')).toBeNull();
  });

  it('не срабатывает на отмене возврата', () => {
    expect(parseRefundEntry('❌ Отмена возврата')).toBeNull();
  });

  it('не срабатывает без числа', () => {
    expect(parseRefundEntry('вернуть')).toBeNull();
  });

  it('не перезапускает мастер с шага «вернуть плательщику»', () => {
    // Иначе нажатие внутри мастера сбросило бы его в начало и потеряло
    // накопленное состояние.
    expect(parseRefundEntry('👤 Вернуть плательщику #1611')).toBeNull();
  });

  it('не путает #161 и #1611 — номер не берётся вхождением подстроки', () => {
    expect(parseRefundEntry('💸 Вернуть #1611')).not.toBe(161);
    expect(parseRefundEntry('💸 Вернуть #161')).toBe(161);
  });
});

describe('advanceRefundFlow — переходы', () => {
  const method: PendingOp = {
    kind: 'refund',
    step: 'method',
    walletId: 1611,
    ctx: CTX,
  };

  it('method + «указать адрес» → address', () => {
    const r = advanceRefundFlow(method, refundLabels.chooseAddress(1611));
    expect(r.next).toMatchObject({ step: 'address', walletId: 1611 });
    expect(r.call).toBeUndefined();
  });

  // The gate lives on ctx.deposit.network — the network that funded the
  // wallet — never on ctx.withdraw.network. `method.ctx` here has
  // deposit.network='bsc' (unsupported) while TALER_CTX has
  // deposit.network='taler' (supported); withdraw.network is 'BSC' in
  // both, on purpose, to prove the gate isn't reading that field.
  it('method + «плательщику», deposit.network=taler → confirm с toPayer', () => {
    const r = advanceRefundFlow(
      { ...method, ctx: TALER_CTX },
      refundLabels.toPayer(1611),
    );
    expect(r.next).toMatchObject({
      step: 'confirm',
      target: { refundToPayer: true },
    });
  });

  it('method + «плательщику», deposit.network=bsc → остаётся на method, без API-вызова', () => {
    const r = advanceRefundFlow(method, refundLabels.toPayer(1611));
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'method' });
    expect(r.messages.join('')).toContain('плательщик не определяется');
  });

  it('method + «плательщику», deposit.network пустой → остаётся на method (fail-closed)', () => {
    const emptyDepositNetwork = {
      ...method,
      ctx: { ...CTX, deposit: { ...CTX.deposit, network: '' } },
    };
    const r = advanceRefundFlow(
      emptyDepositNetwork,
      refundLabels.toPayer(1611),
    );
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'method' });
  });

  // Insurance test: catches a regression back to gating on withdraw_network.
  // Production wallet #1646 is exactly this shape — withdraw_network=bsc
  // masking a Taler deposit — but the failure mode we must never repeat is
  // the inverse: a withdraw.network that HAPPENS to read 'taler' must not
  // wrongly unlock the payer button for a wallet whose real deposit was on
  // another network.
  it('гейт-страховка: withdraw.network=taler, deposit.network=bsc → плательщику недоступно', () => {
    const mismatched = {
      ...method,
      ctx: {
        deposit: {
          network: 'bsc',
          token: 'usdc',
          amount: '59.7',
          address: '0xdep',
        },
        withdraw: {
          network: 'taler',
          token: 'tal',
          amount: '0.0047',
          address: 'tALNcust',
        },
      },
    };
    const r = advanceRefundFlow(mismatched, refundLabels.toPayer(1611));
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'method' });
  });

  it('method + обычная речь со словом «плательщик» НЕ выбирает получателя', () => {
    // Регрессия: "плательщик уже писал в поддержку" содержит слово
    // "плательщик", но это не нажатие кнопки — includes() ловил бы это как
    // выбор получателя и перескакивал сознательный выбор способа возврата.
    const r = advanceRefundFlow(method, 'плательщик уже писал в поддержку');
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'method' });
  });

  it('method + обычная речь со словами «указать адрес» НЕ продвигает без точного совпадения', () => {
    const r = advanceRefundFlow(method, 'надо будет указать адрес получше');
    expect(r.next).toMatchObject({ step: 'method' });
  });

  it('address + непустой текст → confirm с адресом', () => {
    const r = advanceRefundFlow(
      { ...method, step: 'address' },
      '  0xB1c4Ae4F0f8f  ',
    );
    expect(r.next).toMatchObject({
      step: 'confirm',
      target: { refundAddress: '0xB1c4Ae4F0f8f' },
    });
  });

  it('address + пробелы → остаётся на address', () => {
    const r = advanceRefundFlow({ ...method, step: 'address' }, '     ');
    expect(r.next).toMatchObject({ step: 'address' });
    expect(r.messages.join('')).toContain('Пустой адрес');
  });

  it('address + текст, совпадающий с меткой чужой кнопки → принимается как адрес (текущее поведение)', () => {
    // Зафиксировано намеренно: чистый автомат мастера возврата знает только
    // свою собственную вокабуляр (кнопки этого мастера), не полный набор
    // кнопок бота. Перехват "это же метка навигационной кнопки, а не
    // адрес" — ответственность сервиса-диспетчера (задача 9), см.
    // докстринг ветки 'address' в informer.refund-flow.ts.
    const r = advanceRefundFlow(
      { ...method, step: 'address' },
      '📋 Кошельки оператора',
    );
    expect(r.next).toMatchObject({
      step: 'confirm',
      target: { refundAddress: '📋 Кошельки оператора' },
    });
  });

  it('confirm + подтверждение → totp с verifiedAbsent=false', () => {
    const confirm: PendingOp = {
      kind: 'refund',
      step: 'confirm',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
    };
    const r = advanceRefundFlow(confirm, refundLabels.confirm(1611));
    expect(r.next).toMatchObject({ step: 'totp', verifiedAbsent: false });
  });

  it('confirm + обычная речь со словами «подтвердить возврат» НЕ продвигает', () => {
    // Регрессия: "надо будет подтвердить возврат до конца смены" —
    // обычная реплика оператора, а не нажатие кнопки. includes() пропускал
    // бы сознательный барьер перед необратимой операцией.
    const confirm: PendingOp = {
      kind: 'refund',
      step: 'confirm',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
    };
    const r = advanceRefundFlow(
      confirm,
      'надо будет подтвердить возврат до конца смены',
    );
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'confirm' });
  });

  it('totp + 6 цифр → сигнал звать API, состояние очищается', () => {
    const totp: PendingOp = {
      kind: 'refund',
      step: 'totp',
      walletId: 1611,
      ctx: CTX,
      target: { refundToPayer: true },
      verifiedAbsent: false,
    };
    const r = advanceRefundFlow(totp, '123456');
    expect(r.call).toEqual({
      walletId: 1611,
      target: { refundToPayer: true },
      totpCode: '123456',
      verifiedAbsent: false,
      ctx: CTX,
    });
    expect(r.next).toBeNull();
  });

  it('totp + не 6 цифр → остаётся, просит код', () => {
    const totp: PendingOp = {
      kind: 'refund',
      step: 'totp',
      walletId: 1611,
      ctx: CTX,
      target: { refundToPayer: true },
      verifiedAbsent: false,
    };
    const r = advanceRefundFlow(totp, 'ага сейчас');
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'totp' });
  });

  it('gate + «сверил» → totp с verifiedAbsent=true', () => {
    const gate: PendingOp = {
      kind: 'refund',
      step: 'gate',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
      upstreamMessage: 'refund would be a second payout',
    };
    const r = advanceRefundFlow(gate, refundLabels.gateCleared(1611));
    expect(r.next).toMatchObject({ step: 'totp', verifiedAbsent: true });
  });

  it('gate + 6 цифр НЕ запускает возврат в обход подтверждения', () => {
    const gate: PendingOp = {
      kind: 'refund',
      step: 'gate',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
      upstreamMessage: 'refund would be a second payout',
    };
    const r = advanceRefundFlow(gate, '123456');
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'gate' });
  });

  it('gate + «ещё не сверил, подожди» НЕ снимает гейт', () => {
    // Самый опасный кейс: отрицание содержит подстроку "сверил". includes()
    // записал бы verifiedAbsent: true из фразы, буквально означающей
    // "проверка НЕ сделана" — на шаге, единственная цель которого не
    // заплатить клиенту дважды.
    const gate: PendingOp = {
      kind: 'refund',
      step: 'gate',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
      upstreamMessage: 'refund would be a second payout',
    };
    const r = advanceRefundFlow(gate, 'ещё не сверил, подожди');
    expect(r.call).toBeUndefined();
    // Staying on 'gate' means the same object shape is returned — the
    // gate variant of PendingOp structurally has no `verifiedAbsent`
    // field at all, so there is nothing for a false assertion to leak
    // into. Progressing to 'totp' is the only path that could set it.
    expect(r.next).toEqual(gate);
  });

  it('gate + «сверил не всё» тоже НЕ снимает гейт', () => {
    const gate: PendingOp = {
      kind: 'refund',
      step: 'gate',
      walletId: 1611,
      ctx: CTX,
      target: { refundAddress: '0xB1c4' },
      upstreamMessage: 'refund would be a second payout',
    };
    const r = advanceRefundFlow(gate, 'сверил не всё');
    expect(r.call).toBeUndefined();
    expect(r.next).toMatchObject({ step: 'gate' });
  });

  it('отмена из любого состояния очищает', () => {
    for (const step of [
      'method',
      'address',
      'confirm',
      'totp',
      'gate',
    ] as const) {
      const state = {
        kind: 'refund',
        step,
        walletId: 1611,
        ctx: CTX,
        target: { refundAddress: '0xB1c4' },
        verifiedAbsent: false,
        upstreamMessage: 'x',
      } as PendingOp & { kind: 'refund' };
      const r = advanceRefundFlow(state, refundLabels.cancel);
      expect(r.next).toBeNull();
      expect(r.call).toBeUndefined();
      expect(r.messages.join('')).toContain('отменён');
    }
  });

  it('«отмена ретрая» больше не отменяет возврат — фраза принадлежит другому автомату', () => {
    // Раньше isCancel ловил и 'отмена ретрая', хотя эта ветка не вызывается
    // для retry-состояний вообще. Риск был односторонний: "отмена ретрая по
    // другому кошельку, тут не трогай" отменяла бы текущий возврат.
    const state: PendingOp & { kind: 'refund' } = {
      kind: 'refund',
      step: 'method',
      walletId: 1611,
      ctx: CTX,
    };
    const r = advanceRefundFlow(state, 'отмена ретрая по другому кошельку');
    expect(r.next).toMatchObject({ step: 'method' });
  });
});
