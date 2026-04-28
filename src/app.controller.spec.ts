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
