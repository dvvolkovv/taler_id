import { AppController } from './app.controller';

describe('AppController.appleAppSiteAssociation', () => {
  it('returns AASA with both bundle IDs', () => {
    const c = new AppController();
    const out = c.appleAppSiteAssociation();
    expect(out.applinks.apps).toEqual([]);
    expect(out.applinks.details).toHaveLength(2);
    expect(out.applinks.details.map((d) => d.appID).sort()).toEqual([
      'MG58MDUNZ2.tirol.taler.talerIdMobile',
      'MG58MDUNZ2.tirol.taler.talerIdMobile.dev',
    ]);
    out.applinks.details.forEach((d) => {
      expect(d.paths).toEqual(['/room/*', '/ui/invite*']);
    });
  });
});

describe('AppController.androidAssetLinks', () => {
  it('returns assetlinks JSON with prod and dev packages', () => {
    const c = new AppController();
    const out = c.androidAssetLinks();
    expect(Array.isArray(out)).toBe(true);
    expect(out).toHaveLength(2);
    const packages = out.map((e) => e.target.package_name).sort();
    expect(packages).toEqual([
      'tirol.taler.taler_id_mobile',
      'tirol.taler.taler_id_mobile.dev',
    ]);
    const prod = out.find((e) => e.target.package_name === 'tirol.taler.taler_id_mobile');
    const dev = out.find((e) => e.target.package_name === 'tirol.taler.taler_id_mobile.dev');
    expect(prod.target.sha256_cert_fingerprints).toHaveLength(1);
    expect(dev.target.sha256_cert_fingerprints).toHaveLength(2);
    expect(prod.target.namespace).toBe('android_app');
    expect(prod.relation).toEqual(['delegate_permission/common.handle_all_urls']);
  });
});
