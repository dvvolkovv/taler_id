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
    const force = opts?.forceRefresh ?? false;
    const out: Record<string, BigNumber | null> = {};
    const cgIdsToFetch: string[] = [];
    const cgAssetByCoinId: Record<string, string> = {};

    for (const raw of assets) {
      const a = raw.toLowerCase();
      if (a in InformerRatesService.FIXED_EUR) {
        out[a] = InformerRatesService.FIXED_EUR[a];
        continue;
      }
      const coinId = InformerRatesService.CG_MAP[a];
      if (!coinId) {
        out[a] = null;
        continue;
      }
      const cached = this.cache.get(a);
      const fresh =
        cached &&
        Date.now() - cached.fetchedAt.getTime() < InformerRatesService.TTL_MS;
      if (fresh && !force) {
        out[a] = cached.eur;
        continue;
      }
      out[a] = null; // placeholder, overwritten below
      cgIdsToFetch.push(coinId);
      cgAssetByCoinId[coinId] = a;
    }

    if (cgIdsToFetch.length === 0) return out;

    const url = new URL(InformerRatesService.CG_BATCH_URL);
    url.searchParams.set('ids', cgIdsToFetch.join(','));
    url.searchParams.set('vs_currencies', 'eur');

    let body: Record<string, { eur?: number | null }> | null = null;
    let fetchOk = false;
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      InformerRatesService.HTTP_TIMEOUT_MS,
    );
    try {
      const resp = await fetch(url.toString(), { signal: controller.signal });
      if (resp.ok) {
        body = (await resp.json()) as Record<string, { eur?: number | null }>;
        fetchOk = true;
      }
    } catch (e) {
      this.logger.warn(`CoinGecko fetch failed: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }

    if (fetchOk && body) {
      this.lastFetchSuccessAt = new Date();
      this.lastFetchFailedAfterSuccess = false;
      for (const coinId of cgIdsToFetch) {
        const asset = cgAssetByCoinId[coinId];
        const eur = body[coinId]?.eur;
        if (eur != null) {
          const eurBn = new BigNumber(eur);
          this.cache.set(asset, { eur: eurBn, fetchedAt: new Date() });
          out[asset] = eurBn;
        } else {
          out[asset] = null;
        }
      }
    } else {
      this.lastFetchFailedAfterSuccess = true;
      // Fall back to stale cache where possible.
      for (const coinId of cgIdsToFetch) {
        const asset = cgAssetByCoinId[coinId];
        const cached = this.cache.get(asset);
        out[asset] = cached?.eur ?? null;
      }
    }

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
