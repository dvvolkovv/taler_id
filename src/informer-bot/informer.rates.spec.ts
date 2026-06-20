import BigNumber from 'bignumber.js';
import { InformerRatesService } from './informer.rates';

describe('InformerRatesService FIXED_EUR', () => {
  it('returns hardcoded €10800 for tal without any HTTP', async () => {
    const spy = jest
      .spyOn(globalThis, 'fetch')
      .mockRejectedValue(new Error('fetch should not be called'));
    const svc = new InformerRatesService();
    const rate = await svc.getEurRate('tal');
    expect(rate).toEqual(new BigNumber('10800'));
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('normalises asset symbol to lowercase before lookup', async () => {
    const svc = new InformerRatesService();
    const rate = await svc.getEurRate('TAL');
    expect(rate).toEqual(new BigNumber('10800'));
  });

  it('returns null for an asset that is neither in FIXED nor CG_MAP', async () => {
    const spy = jest
      .spyOn(globalThis, 'fetch')
      .mockRejectedValue(new Error('fetch should not be called'));
    const svc = new InformerRatesService();
    const rate = await svc.getEurRate('zzz-unknown');
    expect(rate).toBeNull();
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

function mockCgResponse(
  body: Record<string, { eur?: number | null }>,
  status = 200,
): jest.SpyInstance {
  return jest.spyOn(globalThis, 'fetch').mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as any);
}

describe('InformerRatesService CG cache lifecycle', () => {
  it('first call with empty cache → HTTP fired, cache populated', async () => {
    const spy = mockCgResponse({
      tether: { eur: 0.92 },
      bitcoin: { eur: 56342 },
    });
    const svc = new InformerRatesService();
    const out = await svc.getEurRates(['usdt', 'btc']);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(out['usdt']?.toString()).toBe('0.92');
    expect(out['btc']?.toString()).toBe('56342');
    expect(svc.getCoingeckoStatus()).toBe('ok');
    expect(svc.getCacheAgeMs()).not.toBeNull();
    spy.mockRestore();
  });

  it('second call within TTL → no HTTP, returns cached', async () => {
    const spy = mockCgResponse({ tether: { eur: 0.92 } });
    const svc = new InformerRatesService();
    await svc.getEurRates(['usdt']);
    spy.mockClear();
    const out = await svc.getEurRates(['usdt']);
    expect(spy).not.toHaveBeenCalled();
    expect(out['usdt']?.toString()).toBe('0.92');
    spy.mockRestore();
  });

  it('forceRefresh=true ignores cache', async () => {
    const spy = mockCgResponse({ tether: { eur: 0.92 } });
    const svc = new InformerRatesService();
    await svc.getEurRates(['usdt']);
    spy.mockClear();
    spy.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ tether: { eur: 1.0 } }),
    } as any);
    const out = await svc.getEurRates(['usdt'], { forceRefresh: true });
    expect(spy).toHaveBeenCalledTimes(1);
    expect(out['usdt']?.toString()).toBe('1');
    spy.mockRestore();
  });

  it('invalidateCache wipes; next call fires HTTP again', async () => {
    const spy = mockCgResponse({ tether: { eur: 0.92 } });
    const svc = new InformerRatesService();
    await svc.getEurRates(['usdt']);
    spy.mockClear();
    svc.invalidateCache();
    await svc.getEurRates(['usdt']);
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });

  it('batch: one HTTP for multiple CG assets, FIXED bypassed', async () => {
    const spy = mockCgResponse({
      tether: { eur: 0.92 },
      bitcoin: { eur: 56342 },
    });
    const svc = new InformerRatesService();
    const out = await svc.getEurRates(['tal', 'usdt', 'btc']);
    expect(spy).toHaveBeenCalledTimes(1);
    const url = spy.mock.calls[0][0] as string;
    expect(url).toContain('ids=');
    expect(url).toContain('tether');
    expect(url).toContain('bitcoin');
    expect(url).not.toContain('tal'); // FIXED skipped
    expect(out['tal']?.toString()).toBe('10800');
    expect(out['usdt']?.toString()).toBe('0.92');
    expect(out['btc']?.toString()).toBe('56342');
    spy.mockRestore();
  });

  it('partial response: requested coin missing in CG body → null for that asset', async () => {
    const spy = mockCgResponse({ tether: { eur: 0.92 } });
    const svc = new InformerRatesService();
    const out = await svc.getEurRates(['usdt', 'btc']);
    expect(out['usdt']?.toString()).toBe('0.92');
    expect(out['btc']).toBeNull();
    spy.mockRestore();
  });

  it('CG 5xx with no prior cache → null + status=failed', async () => {
    const spy = mockCgResponse({}, 503);
    const svc = new InformerRatesService();
    const out = await svc.getEurRates(['usdt']);
    expect(out['usdt']).toBeNull();
    expect(svc.getCoingeckoStatus()).toBe('failed');
    spy.mockRestore();
  });

  it('CG 5xx after a previous success → returns stale cache + status=stale', async () => {
    const spy = mockCgResponse({ tether: { eur: 0.92 } });
    const svc = new InformerRatesService();
    await svc.getEurRates(['usdt']);
    spy.mockResolvedValue({
      ok: false,
      status: 503,
      json: async () => ({}),
    } as any);
    const out = await svc.getEurRates(['usdt'], { forceRefresh: true });
    expect(out['usdt']?.toString()).toBe('0.92');
    expect(svc.getCoingeckoStatus()).toBe('stale');
    spy.mockRestore();
  });

  it('getCacheAgeMs returns null before any successful fetch', () => {
    const svc = new InformerRatesService();
    expect(svc.getCacheAgeMs()).toBeNull();
  });
});
