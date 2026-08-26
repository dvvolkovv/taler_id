import { classifyRefundFailure } from './informer.refund-errors';

describe('classifyRefundFailure', () => {
  it('распознаёт гейт двойной выплаты', () => {
    const r = classifyRefundFailure(
      'refund would be a second payout for wallet 1611',
    );
    expect(r.kind).toBe('second_payout');
    expect(r.retryable).toBe(false);
  });

  it('распознаёт нехватку средств на hot-кошельке', () => {
    const r = classifyRefundFailure(
      'hot wallet holds 3 USDT but the refund needs 50 USDT',
    );
    expect(r.kind).toBe('insufficient_hot');
    // Ничего не отправлено — повтор безопасен после пополнения.
    expect(r.retryable).toBe(true);
  });

  it('распознаёт отсутствие исходящего hot-wallet пути', () => {
    const r = classifyRefundFailure(
      'network dash has no hot wallet payout path; refund manually',
    );
    expect(r.kind).toBe('no_payout_path');
    expect(r.retryable).toBe(false);
  });

  it('распознаёт недоступный узел', () => {
    const r = classifyRefundFailure(
      'refusing to send blind; retry once the node responds',
    );
    expect(r.kind).toBe('node_unavailable');
    expect(r.retryable).toBe(true);
  });

  it('распознаёт уже отправленный возврат и запрещает повтор', () => {
    const r = classifyRefundFailure(
      'refund operation already exists for this wallet',
    );
    expect(r.kind).toBe('already_exists');
    expect(r.retryable).toBe(false);
  });

  it('трактует ровно "refund failed" как отказ без деталей', () => {
    const r = classifyRefundFailure('refund failed');
    expect(r.kind).toBe('generic_business');
    expect(r.retryable).toBe(false);
  });

  it('незнакомый текст считает транспортным сбоем, но текст сохраняет', () => {
    const r = classifyRefundFailure('<html>502 Bad Gateway</html>');
    expect(r.kind).toBe('transport');
    expect(r.message).toBe('<html>502 Bad Gateway</html>');
    expect(r.retryable).toBe(false);
  });

  it('обрезанное длинное тело тоже транспортный сбой', () => {
    const r = classifyRefundFailure('upstream connect error or disconnect/re');
    expect(r.kind).toBe('transport');
  });

  it('пустое сообщение — транспортный сбой', () => {
    expect(classifyRefundFailure('').kind).toBe('transport');
  });

  it('матчит без учёта регистра', () => {
    expect(
      classifyRefundFailure('Refund Operation Already Exists For This Wallet')
        .kind,
    ).toBe('already_exists');
  });
});
