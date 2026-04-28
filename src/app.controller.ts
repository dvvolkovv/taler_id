import { Controller, Get, Header, Redirect } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  @Redirect('/ui/index.html')
  root() {}

  @Get('health')
  health() {
    return { status: 'ok', timestamp: new Date().toISOString() };
  }

  @Get('.well-known/openid-configuration')
  @Redirect('/oauth/.well-known/openid-configuration')
  openidConfiguration() {}

  @Get('.well-known/apple-app-site-association')
  @Header('Content-Type', 'application/json')
  appleAppSiteAssociation() {
    return {
      applinks: {
        apps: [],
        details: [
          {
            appID: 'MG58MDUNZ2.tirol.taler.talerIdMobile',
            paths: ['/room/*', '/ui/invite*'],
          },
          {
            appID: 'MG58MDUNZ2.tirol.taler.talerIdMobile.dev',
            paths: ['/room/*', '/ui/invite*'],
          },
        ],
      },
    };
  }

  @Get('.well-known/assetlinks.json')
  @Header('Content-Type', 'application/json')
  androidAssetLinks() {
    return [
      {
        relation: ['delegate_permission/common.handle_all_urls'],
        target: {
          namespace: 'android_app',
          package_name: 'tirol.taler.taler_id_mobile',
          sha256_cert_fingerprints: [
            '55:08:99:75:33:25:B9:D6:1B:71:70:FD:77:0A:13:B5:82:D6:EE:41:3C:6F:25:C0:C8:D9:AF:87:9E:0C:44:99',
          ],
        },
      },
      {
        relation: ['delegate_permission/common.handle_all_urls'],
        target: {
          namespace: 'android_app',
          package_name: 'tirol.taler.taler_id_mobile.dev',
          sha256_cert_fingerprints: [
            '55:08:99:75:33:25:B9:D6:1B:71:70:FD:77:0A:13:B5:82:D6:EE:41:3C:6F:25:C0:C8:D9:AF:87:9E:0C:44:99',
            'CE:F2:7D:2C:83:A4:F7:0E:7D:6A:2F:D0:61:79:01:96:B2:72:07:78:02:41:00:BC:2A:BB:58:16:37:E1:04:51',
          ],
        },
      },
    ];
  }

  @Get('app/version')
  appVersion() {
    return {
      ios: { version: '1.0.36', build: 122, required: false },
      android: { version: '1.0.36', build: 122, required: false },
      updateUrl: {
        ios: 'https://apps.apple.com/app/taler-id/id6741208498',
        android: 'https://id.taler.tirol/download/taler-id.apk',
      },
    };
  }
}
