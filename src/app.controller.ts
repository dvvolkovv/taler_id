import { Controller, Get, Header, Param, Query, Redirect, Res } from '@nestjs/common';
import type { Response } from 'express';
import { join } from 'path';
import { APP_RELEASES } from './app-releases';

@Controller()
export class AppController {
  @Get()
  @Redirect('/ui/index.html')
  root() {}

  // Guest invite landing for a voice call room — served on /room/<code>
  // so links shared from the mobile call screen open the LiveKit web client
  // (public/room.html) for users without the app installed.
  @Get('room/:code')
  roomPage(@Param('code') _code: string, @Res() res: Response) {
    res.sendFile(join(__dirname, '..', 'public', 'room.html'));
  }

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
    const paths = ['/oauth/authorize', '/room/*', '/ui/invite*', '/invite*'];
    return {
      applinks: {
        apps: [],
        details: [
          {
            appID: 'MG58MDUNZ2.tirol.taler.talerIdMobile',
            paths,
          },
          {
            appID: 'MG58MDUNZ2.tirol.taler.talerIdMobile.dev',
            paths,
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
  appVersion(@Query('flavor') flavor?: string) {
    const isDev = flavor === 'dev';
    const env = process.env;
    // Env-overridable so the DO/talerid build advertises its own track + APK URL;
    // defaults preserve aeza (prod/dev) behaviour when these vars are unset.
    const latest = {
      version: env.APP_LATEST_VERSION || '1.1.19',
      build: parseInt(env.APP_LATEST_BUILD || '218', 10),
    };
    const androidUrl =
      env.APP_UPDATE_URL_ANDROID ||
      (isDev
        ? 'https://id.taler.tirol/download/taler-id-dev.apk'
        : 'https://id.taler.tirol/download/taler-id.apk');
    const iosUrl =
      env.APP_UPDATE_URL_IOS ||
      'https://apps.apple.com/app/taler-id/id6741208498';
    return {
      ios: { ...latest, required: false },
      android: { ...latest, required: false },
      updateUrl: { ios: iosUrl, android: androidUrl },
      releases: APP_RELEASES,
    };
  }
}

