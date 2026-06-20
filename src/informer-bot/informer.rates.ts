import { Injectable, Logger } from '@nestjs/common';
import BigNumber from 'bignumber.js';

@Injectable()
export class InformerRatesService {
  private readonly logger = new Logger(InformerRatesService.name);

  private static readonly TTL_MS = 15 * 60 * 1000;
  private static readonly CG_BATCH_URL =
    'https://api.coingecko.com/api/v3/simple/price';
  private static readonly HTTP_TIMEOUT_MS = 5000;

  // asset symbol → CoinGecko coin_id
  private static readonly CG_MAP: Record<string, string> = {
    usdt: 'tether',
    usdc: 'usd-coin',
    btc: 'bitcoin',
    eth: 'ethereum',
    bnb: 'binancecoin',
    trx: 'tron',
  };

  // asset symbol → fixed EUR per 1 unit
  private static readonly FIXED_EUR: Record<string, BigNumber> = {
    tal: new BigNumber('10800'),
  };

  private cache = new Map<string, { eur: BigNumber; fetchedAt: Date }>();
  private lastFetchSuccessAt: Date | null = null;
  private lastFetchFailedAfterSuccess = false;

  async getEurRate(
    asset: string,
    opts?: { forceRefresh?: boolean },
  ): Promise<BigNumber | null> {
    const out = await this.getEurRates([asset], opts);
    return out[asset.toLowerCase()] ?? null;
  }

  async getEurRates(
    assets: string[],
    opts?: { forceRefresh?: boolean },
  ): Promise<Record<string, BigNumber | null>> {
    const out: Record<string, BigNumber | null> = {};
    for (const raw of assets) {
      const a = raw.toLowerCase();
      if (a in InformerRatesService.FIXED_EUR) {
        out[a] = InformerRatesService.FIXED_EUR[a];
      } else if (!(a in InformerRatesService.CG_MAP)) {
        out[a] = null;
      } else {
        // TODO Task 3: CG cache + batch fetch
        out[a] = null;
      }
    }
    void opts;
    return out;
  }

  invalidateCache(): void {
    this.cache.clear();
  }

  getCacheAgeMs(): number | null {
    return this.lastFetchSuccessAt
      ? Date.now() - this.lastFetchSuccessAt.getTime()
      : null;
  }

  getCoingeckoStatus(): 'ok' | 'stale' | 'failed' {
    if (this.lastFetchFailedAfterSuccess && this.cache.size > 0) return 'stale';
    if (this.lastFetchFailedAfterSuccess) return 'failed';
    return 'ok';
  }
}
