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
 * Payer detection reads the transaction history, which the platform can
 * reconstruct with confidence only for Taler. That used to read "Tron and
 * Taler" and the gate was a blacklist of the other six networks matched
 * fail-open — an unrecognised network got the payer button on the theory
 * that a network the platform adds later would work without a release on
 * our side.
 *
 * Reversed 2026-08-26 at the request of Vladimir (admin-API owner):
 * "Пока давай ограничимся только Taler. Для остальных сетей пока не
 * хватает фактуры." Tron in particular never belonged on the supported
 * side — on Tron the platform's history lookup resolves the transaction's
 * *signer*, not the token sender, and the signer can be an exchange's hot
 * wallet that has nothing to do with the client we're refunding.
 *
 * So the gate is now a whitelist of one, matched fail-closed: anything
 * that isn't recognised — including a brand-new network the platform adds
 * later — does not get the payer button until we have evidence for it and
 * ship a release. For a refund that can't be undone, requiring a release
 * before trusting a new network is the right trade, even though it means
 * the button doesn't self-activate for networks the platform supports in
 * the future.
 */
const NETWORKS_WITH_PAYER_DETECTION = new Set(['taler']);

export function supportsPayerDetection(network: string): boolean {
  return NETWORKS_WITH_PAYER_DETECTION.has(
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
 * Shared body for the two "this attempt's outcome is genuinely unknown"
 * cards — timeout and an unrecognised mid-send exception. Both mean the
 * same thing (the send to the admin-API was already in flight, don't
 * retry blind) and differ only in headline and whether there's a captured
 * error detail to show.
 */
function formatRefundUncertainOutcome(
  headline: string,
  detail?: string,
): string {
  const lines = [headline, ''];
  if (detail) lines.push(`\`${detail}\``, '');
  lines.push(
    'Это **не** значит, что ничего не отправлено — транзакция **могла** уже ' +
      'уйти в сеть.',
    '',
    'Не повторяй вслепую. Сверь цепочку; если решишь повторить вручную и ' +
      'получишь «refund operation already exists» — значит первая попытка прошла.',
    '',
    BACK_TO_WALLETS_BUTTON,
  );
  return lines.join('\n');
}

/**
 * Timeout is never a proof that nothing was sent: refund is a synchronous
 * on-chain send and our client waits longer than the platform's own budget,
 * but a network hiccup on our side still leaves the outcome unknown.
 */
export function formatRefundTimeout(walletId: number): string {
  return formatRefundUncertainOutcome(
    `⚠️ **Ответ по возврату #${walletId} не пришёл вовремя**`,
  );
}

/**
 * A thrown error mid-send that isn't one of the recognised admin-API shapes
 * (TOTP reject, timeout, classified 502, or a pre-send rejection like 400/
 * 401/404/422/nonce-503) — a raw network exception, a malformed response, a
 * bug. By the time this fires the call to refundOperatorWallet was already
 * in flight, so — exactly like a timeout — the outcome is unknown. Must
 * never be rendered by the generic errorToMessage() path: that one offers a
 * retry hint, and retrying here risks paying the client twice. The raw
 * detail is shown so the operator (and pm2 logs) can see the actual cause,
 * not just "something broke".
 */
export function formatRefundUnknownError(
  walletId: number,
  detail: string,
): string {
  return formatRefundUncertainOutcome(
    `⚠️ **Связь с платформой оборвалась во время отправки возврата #${walletId}**`,
    detail,
  );
}

/**
 * The platform rejected the refund request outright, before anything was
 * sent — request validation (400), our own request signing (401), a
 * misconfigured stand or an unknown wallet (404/503), a nonce-store hiccup
 * on their side (503), or a case that needs a human before it can proceed
 * (422). Unlike a timeout or an unrecognised exception, the outcome here is
 * NOT in doubt — nothing left — so this deliberately does not reuse the
 * "могла уйти" paragraph from `formatRefundUncertainOutcome`: saying that
 * here would send the operator chasing a transaction that never existed.
 * No repeat-refund button: whatever caused the rejection needs fixing
 * first, and a one-tap retry would just reproduce it.
 */
export function formatRefundRejectedBeforeSend(
  walletId: number,
  headline: string,
  detail: string,
): string {
  const lines = [`⚠️ **${headline}** — возврат #${walletId}`, ''];
  if (detail) lines.push(`\`${detail}\``, '');
  lines.push(
    'Платформа отклонила запрос **до отправки** — ничего не ушло. ' +
      'Устрани причину, прежде чем пробовать снова.',
    '',
    BACK_TO_WALLETS_BUTTON,
  );
  return lines.join('\n');
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
