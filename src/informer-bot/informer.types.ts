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
  created_at: string;
  withdraw_address: string;
  withdraw_network: string;
  withdraw_token: string;
  withdraw_amount: string;
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
