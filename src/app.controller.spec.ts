import { AppController } from './app.controller';

// These files are what actually decides whether a link opens the app: naming a
// domain in the manifest counts for nothing unless the domain vouches for that
// exact package and signing key. Serving one fixed copy everywhere is how the
// talerid domains ended up advertising the aeza packages, so no app could claim
// api.talerid.io links at all (2026-08-03).
const req = (host: string) => ({ headers: { host } });

const AEZA_IOS = [
  'MG58MDUNZ2.tirol.taler.talerIdMobile',
  'MG58MDUNZ2.tirol.taler.talerIdMobile.dev',
];
const AEZA_ANDROID = [
  'tirol.taler.taler_id_mobile',
  'tirol.taler.taler_id_mobile.dev',
];

describe('AppController.appleAppSiteAssociation', () => {
  const c = new AppController();

  it.each(['id.taler.tirol', 'staging.id.taler.tirol'])(
    'serves the aeza bundles on %s',
    (host) => {
      const out = c.appleAppSiteAssociation(req(host));
      expect(out.applinks.apps).toEqual([]);
      expect(out.applinks.details.map((d) => d.appID).sort()).toEqual(AEZA_IOS);
    },
  );

  it.each(['api.talerid.io', 'talerid.io', 'ru.talerid.io'])(
    'serves only the public talerid bundle on %s',
    (host) => {
      const out = c.appleAppSiteAssociation(req(host));
      expect(out.applinks.details.map((d) => d.appID)).toEqual([
        'MG58MDUNZ2.io.talerid.app',
      ]);
    },
  );

  it('claims /oauth/auth exactly, never as a prefix', () => {
    // /oauth/auth/:uid is where the browser consent page continues; if the app
    // grabbed that too it would pull the user out of a flow they started in the
    // browser, which is the thing the consent fix just repaired.
    for (const host of ['id.taler.tirol', 'api.talerid.io']) {
      for (const detail of c.appleAppSiteAssociation(req(host)).applinks
        .details) {
        expect(detail.paths).toContain('/oauth/auth');
        expect(detail.paths).not.toContain('/oauth/auth/*');
        expect(detail.paths).not.toContain('/oauth/authorize');
      }
    }
  });

  it('ignores a port on the Host header', () => {
    const out = c.appleAppSiteAssociation(req('api.talerid.io:443'));
    expect(out.applinks.details.map((d) => d.appID)).toEqual([
      'MG58MDUNZ2.io.talerid.app',
    ]);
  });

  it('falls back to the aeza bundles for an unknown host', () => {
    const out = c.appleAppSiteAssociation(req('localhost'));
    expect(out.applinks.details.map((d) => d.appID).sort()).toEqual(AEZA_IOS);
  });
});

describe('AppController.androidAssetLinks', () => {
  const c = new AppController();

  it('serves both aeza packages on the aeza hosts', () => {
    const out = c.androidAssetLinks(req('id.taler.tirol'));
    expect(out.map((e) => e.target.package_name).sort()).toEqual(AEZA_ANDROID);

    const prod = out.find(
      (e) => e.target.package_name === 'tirol.taler.taler_id_mobile',
    );
    const dev = out.find(
      (e) => e.target.package_name === 'tirol.taler.taler_id_mobile.dev',
    );
    expect(prod.target.sha256_cert_fingerprints).toHaveLength(1);
    expect(dev.target.sha256_cert_fingerprints).toHaveLength(2);
    expect(prod.target.namespace).toBe('android_app');
    expect(prod.relation).toEqual(['delegate_permission/common.handle_all_urls']);
  });

  it('serves only io.talerid.app on the talerid hosts', () => {
    const out = c.androidAssetLinks(req('api.talerid.io'));
    expect(out).toHaveLength(1);
    expect(out[0].target.package_name).toBe('io.talerid.app');
  });

  it('vouches for the documented talerid upload key', () => {
    // Published APKs are verified against this same fingerprint before upload;
    // if the two ever disagree, installed apps stop accepting updates and links
    // stop opening, with no error to explain either.
    const out = c.androidAssetLinks(req('talerid.io'));
    expect(out[0].target.sha256_cert_fingerprints).toEqual([
      '12:D7:AB:50:36:59:5E:51:09:EF:43:27:73:FF:23:C6:3F:62:0D:23:4E:56:95:C6:7A:74:2F:2E:1F:4C:9B:8D',
    ]);
  });

  it('never mixes the two tracks on one host', () => {
    for (const host of ['id.taler.tirol', 'api.talerid.io']) {
      const packages = c
        .androidAssetLinks(req(host))
        .map((e) => e.target.package_name);
      const tracks = new Set(
        packages.map((p) => (p === 'io.talerid.app' ? 'talerid' : 'aeza')),
      );
      expect(tracks.size).toBe(1);
    }
  });
});
