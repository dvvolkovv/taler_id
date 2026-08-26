/**
 * The admin-API assigns no machine-readable error codes for refund
 * rejections — the reason arrives as prose in `message` with HTTP 502.
 * Match by substring, and always keep the original text: unmatched text is
 * still human-readable and belongs in front of the operator.
 */
export type RefundFailureKind =
  | 'second_payout'
  | 'insufficient_hot'
  | 'no_payout_path'
  | 'node_unavailable'
  | 'already_exists'
  | 'generic_business'
  | 'transport';

export interface RefundFailure {
  kind: RefundFailureKind;
  /** Original upstream text, verbatim. Never hidden from the operator. */
  message: string;
  /**
   * Whether re-sending the same refund is safe. True only where the
   * platform states nothing was sent. Never used to retry automatically —
   * it only decides whether a retry button is drawn.
   */
  retryable: boolean;
}

// Order is significant: the loop below returns the FIRST rule whose needles
// all match, so a more specific rule must sit above a more general one that
// could also match its text. Right now the five needle sets below happen not
// to overlap — that's a property of today's five known upstream messages,
// not a guarantee the code enforces. Whoever adds a sixth rule needs to
// re-check for overlap by hand, and pick where in the list it goes.
//
// This table only covers 5 of the 7 `RefundFailureKind`s. Two more live past
// the loop, with a different comparison semantics (exact match, not
// substring): `generic_business` and `transport` — see the branches after
// the loop for why they aren't just two more rows here.
const RULES: Array<{
  kind: RefundFailureKind;
  needles: string[];
  retryable: boolean;
}> = [
  {
    kind: 'second_payout',
    needles: ['refund would be a second payout'],
    retryable: false,
  },
  {
    // Two needles because the amounts sit between them in the real message:
    // "hot wallet holds 3 USDT but the refund needs 50 USDT".
    kind: 'insufficient_hot',
    needles: ['hot wallet holds', 'the refund needs'],
    retryable: true,
  },
  {
    kind: 'no_payout_path',
    needles: ['has no hot wallet payout path'],
    retryable: false,
  },
  {
    kind: 'node_unavailable',
    needles: ['refusing to send blind'],
    retryable: true,
  },
  {
    kind: 'already_exists',
    needles: ['refund operation already exists'],
    retryable: false,
  },
];

export function classifyRefundFailure(rawMessage: string): RefundFailure {
  const message = rawMessage ?? '';
  const haystack = message.toLowerCase();

  for (const rule of RULES) {
    if (rule.needles.every((n) => haystack.includes(n))) {
      return { kind: rule.kind, message, retryable: rule.retryable };
    }
  }

  // The platform's generic wrapper. Known, but carries no actionable detail.
  //
  // Exact match on purpose, not `includes`: this is the one rule in the
  // whole function that isn't a substring test. Leading/trailing whitespace
  // is tolerated via `.trim()` because it still comes from the platform's
  // own wrapper, not from an intermediate proxy — trimming it into
  // `transport` would tell the operator "looks like a transport failure"
  // when the platform in fact answered on the merits, just without detail.
  // If the platform ever starts attaching detail to this wrapper — e.g.
  // "refund failed: no such wallet" — that message will NOT match here
  // (extra text breaks the exact comparison) and will fall through to
  // `transport` instead. That's a deliberate trade-off, not an oversight:
  // widening this to `includes('refund failed')` would silently swallow
  // any future detail the platform starts sending under the same prefix.
  if (haystack.trim() === 'refund failed') {
    return { kind: 'generic_business', message, retryable: false };
  }

  // Anything else: an intermediate proxy's response or a truncated body.
  // Classified as transport, but the text still travels to the operator —
  // the guide asks for both, and hiding it would lose real information.
  return { kind: 'transport', message, retryable: false };
}
