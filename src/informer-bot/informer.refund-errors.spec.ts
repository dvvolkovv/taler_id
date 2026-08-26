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

  it('одной иглы недостаточно для insufficient_hot — нужны обе', () => {
    // Защита от подмены .every на .some: по отдельности эти фразы
    // ничего не значат, а между ними в реальном сообщении стоят суммы.
    expect(classifyRefundFailure('hot wallet holds 3 USDT').kind).toBe(
      'transport',
    );
    expect(classifyRefundFailure('the refund needs 50 USDT').kind).toBe(
      'transport',
    );
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

  it('терпит пробелы по краям у "refund failed" — это всё ещё обёртка платформы', () => {
    // Единственное правило с точным сравнением, а не подстроковым.
    // Пробелы по краям приходят от платформы, а не от прокси, поэтому
    // уводить такое сообщение в transport было бы враньём оператору:
    // платформа ответила по делу, просто без деталей.
    const r = classifyRefundFailure('  refund failed  ');
    expect(r.kind).toBe('generic_business');
    // Текст сохраняется дословно, включая пробелы.
    expect(r.message).toBe('  refund failed  ');
  });

  it('переживает undefined с нетипизированной границы', () => {
    // Типы TS тут не помогут — rawMessage приходит с HTTP-границы,
    // где реальный ответ может не совпасть с объявленным типом.
    expect(classifyRefundFailure(undefined as any).kind).toBe('transport');
    expect(classifyRefundFailure(undefined as any).message).toBe('');
  });
});
