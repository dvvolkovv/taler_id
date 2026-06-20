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
