import { PendingOp, PENDING_OP_TTL_SEC } from './informer.pending-state';
import { RefundTarget, WalletCtx } from './informer.types';
import {
  formatRefundAddressEmpty,
  formatRefundAddressPrompt,
  formatRefundAwaitingTotp,
  formatRefundCancelled,
  formatRefundConfirm,
  formatRefundGate,
  formatRefundMethodChoice,
  refundLabels,
} from './informer.refund.formatters';

/** What the service should do after the transition. */
export interface RefundCall {
  walletId: number;
  ctx: WalletCtx;
  target: RefundTarget;
  totpCode: string;
  verifiedAbsent: boolean;
}

export interface FlowResult {
  /** Next pending state, or null to clear it. */
  next: PendingOp | null;
  /** Messages to publish, in order. */
  messages: string[];
  /** Present only when the terminal API call should fire now. */
  call?: RefundCall;
}

const TOTP_RE = /^\d{6}$/;

/**
 * Matches the refund entry button: "💸 Вернуть #1611" or a bare
 * "вернуть 1611". Returns null for anything else — importantly for
 * "❌ Отмена возврата", which contains "возврат" but must not re-enter the
 * wizard, and for the retry button, which shares the card.
 *
 * The wallet id is always taken with a greedy digit-capture regex
 * (`(\d+)`), never with `includes('#' + id)`: the label has no terminator
 * after the number, so "#1611".includes("#161") is true and would make
 * wallets #161 and #1611 indistinguishable — a refund routed to the wrong
 * wallet.
 */
export function parseRefundEntry(content: string): number | null {
  const lower = content.trim().toLowerCase();
  if (lower.includes('отмена')) return null;
  const m = lower.match(/верн[уи]ть\s*#?(\d+)/);
  if (!m) return null;
  // "вернуть плательщику #1611" is an in-wizard step, not an entry point.
  if (lower.includes('плательщик')) return null;
  return parseInt(m[1], 10);
}

/**
 * Normalisation applied on both sides before a label comparison: trim outer
 * whitespace, collapse internal runs of whitespace to one space, casefold.
 * Kept in one place so every comparison in this file uses the same rule.
 */
function normalizeLabel(s: string): string {
  return s.trim().replace(/\s+/g, ' ').toLowerCase();
}

/**
 * Exact comparison against a label built from `informer.refund.formatters`,
 * never a substring `includes` check. The wizard cards are read and typed
 * in an ordinary chat, so words like "сверил", "плательщик" or "возврат"
 * show up in unrelated operator prose — including negations: "ещё не
 * сверил" contains "сверил" as a substring while meaning the opposite. On
 * the double-payout gate step that would flip `verifiedAbsent` to `true`
 * from a sentence that literally says the check was NOT done. Exact match
 * fails safe: an unrecognised message just redraws the current card and
 * the operator tries again — cheap, compared to a wrong assertion on an
 * irreversible transfer.
 */
function matchesLabel(content: string, label: string): boolean {
  return normalizeLabel(content) === normalizeLabel(label);
}

function isCancel(content: string): boolean {
  return matchesLabel(content, refundLabels.cancel);
}

/** Redraws `messages` without changing `state` — the common "invalid or
 * unrecognised input, show the card again" outcome. */
function stay(state: PendingOp, ...messages: string[]): FlowResult {
  return { next: state, messages };
}

/**
 * Pure transition. Never touches Redis or the network — the service does
 * both, using `next` and `call`. Keeping it pure is what makes the whole
 * table testable without mocks.
 */
export function advanceRefundFlow(
  state: PendingOp & { kind: 'refund' },
  content: string,
): FlowResult {
  const text = content.trim();

  if (isCancel(text)) {
    return { next: null, messages: [formatRefundCancelled()] };
  }

  switch (state.step) {
    case 'method': {
      if (matchesLabel(text, refundLabels.chooseAddress(state.walletId))) {
        const next: PendingOp = { ...state, step: 'address' };
        return {
          next,
          messages: [formatRefundAddressPrompt(state.walletId, state.ctx)],
        };
      }
      if (matchesLabel(text, refundLabels.toPayer(state.walletId))) {
        // No local gate on `state.ctx.network`: that field is
        // `withdraw_network` (the failed withdrawal's target), which says
        // nothing about which network funded the wallet. Only the platform
        // knows the deposit network, so only the platform can accept or
        // reject "refund to payer" — see the Taler-only caveat rendered on
        // the confirm card in informer.refund.formatters.ts.
        const target: RefundTarget = { refundToPayer: true };
        return {
          next: { ...state, step: 'confirm', target },
          messages: [formatRefundConfirm(state.walletId, state.ctx, target)],
        };
      }
      return stay(state, formatRefundMethodChoice(state.walletId, state.ctx));
    }

    case 'address': {
      // The platform trims the address and treats an all-whitespace string
      // as empty — sending it would mean an implicit refund_to_payer, which
      // must never happen without the operator saying so.
      if (text === '') {
        return stay(state, formatRefundAddressEmpty(state.walletId));
      }
      // Deliberately NOT checked against any button label here (e.g. a
      // stray "📋 Кошельки оператора" echoed from an earlier message in the
      // same conversation): a pure step machine only knows the refund
      // wizard's own vocabulary, not the bot's full button set, so it
      // would have to either hardcode every other card's labels (coupling
      // this file to the rest of the bot) or guess. Any non-empty text is
      // taken as the address exactly as typed; recognising "this looks
      // like someone else's button, not an address" is the dispatching
      // service's job (task 9), which already knows the full action set.
      const target: RefundTarget = { refundAddress: text };
      return {
        next: { ...state, step: 'confirm', target },
        messages: [formatRefundConfirm(state.walletId, state.ctx, target)],
      };
    }

    case 'confirm': {
      if (matchesLabel(text, refundLabels.confirm(state.walletId))) {
        return {
          next: { ...state, step: 'totp', verifiedAbsent: false },
          messages: [
            formatRefundAwaitingTotp(state.walletId, PENDING_OP_TTL_SEC),
          ],
        };
      }
      return stay(
        state,
        formatRefundConfirm(state.walletId, state.ctx, state.target),
      );
    }

    case 'totp': {
      if (!TOTP_RE.test(text)) {
        return stay(
          state,
          formatRefundAwaitingTotp(state.walletId, PENDING_OP_TTL_SEC),
        );
      }
      return {
        next: null,
        messages: [],
        call: {
          walletId: state.walletId,
          ctx: state.ctx,
          target: state.target,
          totpCode: text,
          verifiedAbsent: state.verifiedAbsent,
        },
      };
    }

    case 'gate': {
      // A bare TOTP must NOT fire the refund here: clearing the double-payout
      // gate is a separate, explicit assertion by the operator, and skipping
      // it would pay the client twice.
      if (matchesLabel(text, refundLabels.gateCleared(state.walletId))) {
        return {
          next: { ...state, step: 'totp', verifiedAbsent: true },
          messages: [
            formatRefundAwaitingTotp(state.walletId, PENDING_OP_TTL_SEC),
          ],
        };
      }
      return stay(
        state,
        formatRefundGate(state.walletId, state.ctx, state.upstreamMessage),
      );
    }

    default: {
      // Exhaustiveness guard: PendingOp's `refund` variants cover exactly
      // five steps. If a sixth is ever added without a branch here, fail
      // loudly instead of silently falling through to `undefined`.
      const _exhaustive: never = state;
      throw new Error(
        `informer.refund-flow: unhandled step ${(_exhaustive as PendingOp).step}`,
      );
    }
  }
}
