// ── Success envelope ─────────────────────────────────────────
export interface InformerEnvelope<T> {
  resultCode: 'ERCD0000';
  data: T;
}

export function assertEnvelope<T>(raw: unknown): InformerEnvelope<T> {
  if (
    typeof raw !== 'object' ||
    raw === null ||
    (raw as any).resultCode !== 'ERCD0000' ||
    !('data' in raw)
  ) {
    throw new Error(
      `informer-envelope-mismatch: ${JSON.stringify(raw).slice(0, 200)}`,
    );
  }
  return raw as InformerEnvelope<T>;
}

// ── /operator-required-wallets/count ────────────────────────
export interface OperatorRequiredCount {
  count: number;
}

// ── /operator-required-wallets ───────────────────────────────
export interface OperatorRequiredItem {
  // Optional because the public list response per current admin-API docs does
  // not include it, but the retry endpoint requires it. Tracked in
  // gsmsoft1/exchange/admin-api: when present, the chat renders a per-item
  // retry button; when absent, the button is omitted.
  wallet_id?: number;
  created_at: string;
  withdraw_address: string;
  withdraw_network: string;
  withdraw_token: string;
  withdraw_amount: string;

  // Last recorded failure for this wallet — the one that put it in the
  // operator queue. All three are optional and disappear together in two
  // very different cases: no failure was ever recorded for this wallet, OR
  // the platform's own journal is unavailable. Never render their absence
  // as "this wallet is fine".
  last_error_event?: string;
  // Prose for most events; for gate rejections the platform sends its
  // details-payload instead, e.g. {"reason":"withdrawal_intent_exists"}.
  // Union-typed so the formatter stringifies an object instead of crashing.
  last_error?: string | Record<string, unknown>;
  last_error_at?: string;
}

// ── /operator-required-wallets/{id}/retry ────────────────────
export interface OperatorWalletRetryResult {
  wallet_id: number;
  status: string;
}

// ── /operator-required-wallets/{id}/refund ───────────────────
export interface OperatorWalletRefundResult {
  wallet_id: number;
  status: string;
}

/**
 * Exactly one of the two shapes. The admin-API answers 400 with
 * "refund_address and refund_to_payer are mutually exclusive: send exactly
 * one" when both fields arrive together, so the union is enforced at the
 * type level rather than by runtime validation.
 */
export type RefundTarget =
  | { refundAddress: string }
  | { refundToPayer: true };

/**
 * Wallet facts captured at the moment the operator taps the refund button.
 * Carried through the wizard so the confirmation card can say
 * "50 usdt · BSC → 0xB1c4…" instead of a bare "#1611". The list may change
 * during the wizard; re-fetching on every step costs more and still gives
 * no guarantee.
 */
export interface WalletCtx {
  network: string;
  token: string;
  amount: string;
  address: string;
}

export interface OperatorRequiredList {
  items: OperatorRequiredItem[];
  total: number;
  page: number;
  per_page: number;
}

// ── /mini-acquiring/balances ─────────────────────────────────
export interface MiniBalanceEntry {
  asset: string;
  kind: string;
  balance: string;
  error?: string;
}

export interface MiniRoleEntry {
  role: 'cold_wallet' | 'hot_wallet' | 'gas_funding';
  address: string;
  balances?: MiniBalanceEntry[];
  error?: string;
}

export interface MiniChainEntry {
  chain: string;
  base_asset: string;
  supported: boolean;
  roles: MiniRoleEntry[];
}

export interface MiniAcquiringBalances {
  chains: MiniChainEntry[];
}

// ── /gateway/system-wallet-balances ──────────────────────────
export interface GatewayItem {
  blockchain: string;
  asset_symbol: string;
  wallet_type: string;
  balance: string;
  address: string;
  updated_at: number;
}

export interface GatewaySystemWalletBalances {
  items: GatewayItem[];
}

// ── Refill deficit (computed locally, not from admin-API) ───
export interface RefillDeficit {
  chain: string;                  // e.g. "tron"
  token: string;                  // e.g. "usdt"
  hotAddress: string;             // mini-acquiring role address
  hotBalance: string;             // raw amount as string, e.g. "1000.00"
  pendingTotal: string;           // raw aggregated pending withdrawal amount
  availableForWithdrawal: string; // hotBalance × (1 − SAFETY_MARGIN_PCT)
  deficit: string;                // pendingTotal − availableForWithdrawal, > 0 when alertable
}

// ── Fiat balances (Sub-2c, EUR dashboard) ───────────────────
export interface FiatRoleBreakdown {
  role: 'hot_wallet' | 'cold_wallet' | 'gas_funding';
  eurTotal: string;       // BigNumber.toFixed()
  tokens: Array<{ asset: string; native: string; eur: string | null }>;
}

export interface FiatChainBreakdown {
  chain: string;
  eurTotal: string;       // BigNumber.toFixed()
  roles?: FiatRoleBreakdown[];                          // mini-acquiring only
  flatTokens?: Array<{                                  // gateway only
    asset: string;
    walletType: string;
    native: string;
    eur: string | null;
  }>;
}

export interface FiatPoolDigest {
  poolName: 'mini-acquiring' | 'gateway';
  eurTotal: string;
  chains: FiatChainBreakdown[];
  unpricedAssets: Array<{ asset: string; chain: string; native: string }>;
}

export interface FiatBalancesResult {
  pools: FiatPoolDigest[];
  ratesCacheAgeMin: number | null;  // null = no fetch yet
  coingeckoStatus: 'ok' | 'stale' | 'failed';
}

// ── Errors ───────────────────────────────────────────────────
export class InformerError extends Error {
  constructor(
    message: string,
    public readonly upstreamStatus?: number,
    public readonly upstreamBody?: string,
  ) {
    super(message);
    this.name = 'InformerError';
  }
}

export class InformerAuthError extends InformerError {
  constructor(body?: string) {
    super('informer-auth-error', 401, body);
    this.name = 'InformerAuthError';
  }
}

export class InformerNotConfiguredError extends InformerError {
  constructor(status: number, body?: string) {
    super('informer-not-configured', status, body);
    this.name = 'InformerNotConfiguredError';
  }
}

export class InformerNonceStoreError extends InformerError {
  constructor(body?: string) {
    super('informer-nonce-store-unavailable', 503, body);
    this.name = 'InformerNonceStoreError';
  }
}

export class InformerUnavailableError extends InformerError {
  constructor(status: number, body?: string) {
    super('informer-unavailable', status, body);
    this.name = 'InformerUnavailableError';
  }
}

export class InformerTimeoutError extends InformerError {
  constructor() {
    super('informer-timeout');
    this.name = 'InformerTimeoutError';
  }
}

export class InformerBadRequestError extends InformerError {
  constructor(body?: string) {
    super('informer-bad-request', 400, body);
    this.name = 'InformerBadRequestError';
  }
}

export class InformerTotpError extends InformerError {
  constructor(body?: string) {
    super('informer-totp-rejected', 403, body);
    this.name = 'InformerTotpError';
  }
}

/**
 * 422 from the admin-API: the request was understood and processed, but the
 * operation needs a human — e.g. "operator intervention required: insufficient
 * USDT balance on gas wallet". The upstream message is operator-actionable, so
 * it must reach the bot chat verbatim, not be masked as "unavailable".
 */
export class InformerOperatorInterventionError extends InformerError {
  constructor(body?: string) {
    super('informer-operator-intervention', 422, body);
    this.name = 'InformerOperatorInterventionError';
  }
}

/**
 * Extracts a human-readable message from an upstream error body. Their
 * envelope is {"code":"error","data":null,"message":"..."} — prefer the
 * message field; fall back to the raw body (trimmed) if it's not JSON.
 */
export function upstreamMessageFrom(body?: string, maxLen = 500): string {
  if (!body) return '';
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed?.message === 'string' && parsed.message.trim()) {
      return parsed.message.slice(0, maxLen);
    }
  } catch {
    // not JSON — fall through to raw
  }
  return body.slice(0, maxLen);
}
