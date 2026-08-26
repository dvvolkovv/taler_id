import {
  OperatorWalletRefundResult,
  RefundTarget,
  WalletCtx,
} from './informer.types';
import { RefundFailure } from './informer.refund-errors';
import { OPERATOR_BUTTONS } from './informer.formatters';

// ── Мастер возврата ──────────────────────────────────────────

/**
 * Contract for anything downstream that matches on button labels (the
 * task-7 wizard automaton in particular).
 *
 * The client strips the `[ACTION:...]` wrapper before echoing a label back
 * as a plain text message — by the time our code sees the operator's tap,
 * the brackets are already gone. So `"#1611".includes("#161")` is true:
 * wallet ids have no terminator after them, and substring matching alone
 * cannot tell `#161` from `#1611`. Callers must anchor on a full-string
 * match, a trailing regex capture (`/#(\d+)$/`), or a word boundary — never
 * plain `includes('#' + id)`.
 *
 * Also: `💸 Вернуть #N` (start the wizard from the wallet list) and
 * `👤 Вернуть плательщику #N` (pick the payer as the refund target, a step
 * inside the wizard) are two different commands that both contain the word
 * "Вернуть". Match on the full label text, never on that shared keyword.
 *
 * None of this bites the code in *this* file — every card here either
 * hands the id straight through as a template value or carries it in
 * pending state — but nothing enforces the contract for future callers,
 * hence the note.
 */

/**
 * Single source of truth for wizard button labels: the same builder draws
 * the `[ACTION:...]` button text AND is what `informer.refund-flow.ts`
 * compares the echoed message against. Matching by `includes('keyword')`
 * instead — as an earlier version of the automaton did — catches plain
 * chat prose that happens to share the word: "ещё не сверил" contains
 * "сверил", and on the double-payout gate step that inverts the operator's
 * actual statement into `verifiedAbsent: true`. Building both sides from
 * one constant makes that drift impossible by construction rather than a
 * matter of remembering to keep two strings in sync.
 */
export const refundLabels = {
  chooseAddress: (walletId: number) => `📮 Указать адрес #${walletId}`,
  toPayer: (walletId: number) => `👤 Вернуть плательщику #${walletId}`,
  confirm: (walletId: number) => `✅ Подтвердить возврат #${walletId}`,
  gateCleared: (walletId: number) => `✅ Сверил, выплаты не было #${walletId}`,
  cancel: '❌ Отмена возврата',
} as const;

export const REFUND_CANCEL_BUTTON = `[ACTION:${refundLabels.cancel}]`;

export const BACK_TO_WALLETS_BUTTON = '[ACTION:📋 Кошельки оператора]';

/**
 * Payer detection reads the transaction history, which the platform keeps
 * only for Tron and Taler. On the other six an empty refund_address is a
 * guaranteed 400.
 *
 * Networks are matched fail-open: an unrecognised network gets the payer
 * button, so a network the platform adds later works without a release on
 * our side. The cost of being wrong is one 400 with a readable message.
 */
const NETWORKS_WITHOUT_PAYER_DETECTION = new Set([
  'ethereum',
  'eth',
  'bsc',
  'binance-smart-chain',
  'bitcoin',
  'btc',
  'litecoin',
  'ltc',
  'dash',
  'polkadot',
  'dot',
]);

export function supportsPayerDetection(network: string): boolean {
  return !NETWORKS_WITHOUT_PAYER_DETECTION.has(
    (network ?? '').trim().toLowerCase(),
  );
}

function walletLine(walletId: number, ctx: WalletCtx): string {
  return `**#${walletId}** · ${ctx.amount} ${ctx.token} · ${ctx.network}`;
}

export function formatRefundMethodChoice(
  walletId: number,
  ctx: WalletCtx,
): string {
  const lines = [
    `💸 **Возврат средств** ${walletLine(walletId, ctx)}`,
    '',
    `Адрес вывода: \`${ctx.address}\``,
    '',
    'Куда вернуть?',
    '',
    `[ACTION:${refundLabels.chooseAddress(walletId)}]`,
  ];
  if (supportsPayerDetection(ctx.network)) {
    lines.push(`[ACTION:${refundLabels.toPayer(walletId)}]`);
  } else {
    lines.push(
      '',
      `_В сети ${ctx.network} плательщик не определяется — нужен явный адрес._`,
    );
  }
  lines.push(REFUND_CANCEL_BUTTON);
  return lines.join('\n');
}

export function formatRefundAddressPrompt(
  walletId: number,
  ctx: WalletCtx,
): string {
  return [
    `📮 **Адрес возврата для ${walletLine(walletId, ctx)}**`,
    '',
    'Пришли адрес одним сообщением. Проверю только то, что он непустой — ' +
      'формат сверит платформа.',
    '',
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundAddressEmpty(walletId: number): string {
  return [
    `⚠️ Пустой адрес не подойдёт для кошелька **#${walletId}**.`,
    '',
    'Строка из одних пробелов на стороне платформы считается пустой, ' +
      'а пустой адрес без явного флага — это отказ, а не отправка ' +
      'плательщику. Пришли адрес ещё раз.',
    '',
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundConfirm(
  walletId: number,
  ctx: WalletCtx,
  target: RefundTarget,
): string {
  const head = [`⚠️ **Подтверди возврат** ${walletLine(walletId, ctx)}`, ''];
  const body =
    'refundAddress' in target
      ? [`Получатель: \`${target.refundAddress}\``, '']
      : [
          'Получатель: **адрес плательщика, который выберет платформа**.',
          '',
          'Что это значит:',
          '• показать адрес заранее невозможно — preview у платформы нет;',
          `• на Tron определяется подписант транзакции, а не отправитель токенов — ` +
            'им может оказаться кошелёк биржи, который клиенту не принадлежит;',
          '• после успеха платформа не сообщит, куда ушли деньги.',
          '',
        ];
  return [
    ...head,
    ...body,
    'Перевод **необратим**.',
    '',
    `[ACTION:${refundLabels.confirm(walletId)}]`,
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundAwaitingTotp(
  walletId: number,
  ttlSeconds: number,
): string {
  return [
    `🔐 **Подтверди возврат кошелька #${walletId}**`,
    '',
    `Введи 6-значный код из аутентификатора в течение ${ttlSeconds} секунд.`,
    '',
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundTotpRejected(
  walletId: number,
  ttlSeconds: number,
): string {
  return [
    `⚠️ **Код не принят** для возврата кошелька **#${walletId}**.`,
    '',
    'Часы расходятся или код истёк. Возьми свежий код и пришли в течение ' +
      `${ttlSeconds} секунд.`,
    '',
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

export function formatRefundCancelled(): string {
  return [
    '[B:blue]❌ Возврат отменён.[/B]',
    'Ничего не отправлено. Начни заново кнопкой «💸 Вернуть» в списке кошельков.',
    '',
    OPERATOR_BUTTONS,
  ].join('\n');
}

export function formatRefundResult(
  result: OperatorWalletRefundResult,
  target: RefundTarget,
): string {
  const where =
    'refundAddress' in target
      ? `Получатель: \`${target.refundAddress}\``
      : 'Возврат ушёл плательщику, но **адрес получателя платформа не сообщает** — ' +
        'ни адреса, ни хэша транзакции в ответе нет. Если он нужен в вашей ' +
        'записи, восстанавливать придётся вручную по цепочке.';
  return [
    `[B:green]✅ Возврат выполнен[/B] для кошелька **#${result.wallet_id}**`,
    '',
    `Статус: \`${result.status}\``,
    where,
    '',
    OPERATOR_BUTTONS,
  ].join('\n');
}

/**
 * The double-payout gate. The wallet has a withdrawal record carrying a tx
 * hash or order id, meaning the client was already paid. Clearing the gate
 * is a deliberate, logged assertion by a human — the button is worded as a
 * claim, never as "retry", and the flag is never set automatically.
 */
export function formatRefundGate(
  walletId: number,
  ctx: WalletCtx,
  upstreamMessage: string,
): string {
  return [
    `⛔ **Возврат #${walletId} заблокирован**`,
    '',
    `\`${upstreamMessage}\``,
    '',
    'У кошелька есть запись о выплате клиенту с идентификатором. ' +
      'Возврат сейчас заплатит ему **дважды**.',
    '',
    'Прежде чем снимать гейт, проверь:',
    `• в обозревателе ${ctx.network} нет исходящей транзакции на \`${ctx.address}\` ` +
      `на ${ctx.amount} ${ctx.token};`,
    '• в бэкофисе нет успешного order id по этой выплате.',
    '',
    'Нажимая кнопку, ты утверждаешь, что сверил цепочку и выплаты не было. ' +
      'Попытка снять гейт **логируется** платформой отдельным событием ещё ' +
      'до обращения к бэкенду — она останется в журнале, даже если возврат ' +
      'затем упадёт.',
    '',
    `[ACTION:${refundLabels.gateCleared(walletId)}]`,
    REFUND_CANCEL_BUTTON,
  ].join('\n');
}

const FAILURE_HEADLINE: Record<RefundFailure['kind'], string> = {
  second_payout: '⛔ Возврат заблокирован гейтом двойной выплаты',
  insufficient_hot: '⚠️ На hot-кошельке не хватает средств',
  no_payout_path: '⛔ В этой сети нет исходящего hot-wallet',
  node_unavailable: '⚠️ Узел сети не отвечает',
  already_exists: '⛔ Возврат по этому кошельку уже существует',
  generic_business: '⚠️ Платформа отказала без деталей',
  transport: '⚠️ Похоже на транспортный сбой, а не на отказ платформы',
};

const FAILURE_ADVICE: Record<RefundFailure['kind'], string> = {
  second_payout: 'Сверь цепочку и сними гейт осознанно.',
  insufficient_hot:
    'Ничего не отправлено. Пополни hot-кошелёк этой сети и повтори.',
  no_payout_path: 'Обрабатывать вне сервиса — вручную.',
  node_unavailable:
    'Ничего не отправлено. Повтор допустим, когда узел ответит.',
  already_exists:
    'Читай это как «первая попытка прошла», а не как новую ошибку. ' +
    'Сверь вручную, повторять не надо.',
  generic_business: 'Причина не указана. Повторять вслепую не стоит.',
  transport:
    'Так выглядят ответы промежуточного прокси и обрезанные тела. ' +
    'Отправлено или нет — неизвестно, поэтому повтора не предлагаю.',
};

export function formatRefundFailure(
  walletId: number,
  failure: RefundFailure,
): string {
  const lines = [
    `${FAILURE_HEADLINE[failure.kind]} — кошелёк **#${walletId}**`,
    '',
  ];
  if (failure.message) {
    lines.push(`\`${failure.message}\``, '');
  }
  lines.push(FAILURE_ADVICE[failure.kind], '');
  if (failure.retryable) {
    lines.push(`[ACTION:💸 Вернуть #${walletId}]`);
  }
  if (failure.kind === 'insufficient_hot') {
    lines.push('[ACTION:💰 Балансы mini-acquiring]');
  }
  lines.push(BACK_TO_WALLETS_BUTTON);
  return lines.join('\n');
}

/**
 * Timeout is never a proof that nothing was sent: refund is a synchronous
 * on-chain send and our client waits longer than the platform's own budget,
 * but a network hiccup on our side still leaves the outcome unknown.
 */
export function formatRefundTimeout(walletId: number): string {
  return [
    `⚠️ **Ответ по возврату #${walletId} не пришёл вовремя**`,
    '',
    'Это **не** значит, что ничего не отправлено — транзакция **могла** уже ' +
      'уйти в сеть.',
    '',
    'Не повторяй вслепую. Сверь цепочку; если решишь повторить вручную и ' +
      'получишь «refund operation already exists» — значит первая попытка прошла.',
    '',
    BACK_TO_WALLETS_BUTTON,
  ].join('\n');
}

export function formatRefundInFlight(walletId: number): string {
  return [
    `⚠️ По кошельку **#${walletId}** уже идёт возврат.`,
    '',
    'Параллельные возвраты по одному кошельку запрещены: защита на стороне ' +
      'платформы — проверка перед действием, а не гарантия уникальности. ' +
      'Дождись результата первой попытки.',
    '',
    BACK_TO_WALLETS_BUTTON,
  ].join('\n');
}
