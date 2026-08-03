import {
  Controller,
  Get,
  Header,
  Param,
  Query,
  Redirect,
  Req,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { join } from 'path';
import { APP_RELEASES } from './app-releases';

interface AndroidApp {
  packageName: string;
  fingerprints: string[];
}

/**
 * Paths the app claims from a link.
 *
 * `/oauth/auth` is matched exactly, never as a prefix: `/oauth/auth/:uid` is the
 * URL the browser consent page continues at, and letting the app intercept that
 * would yank the user out of a flow they started in the browser.
 */
const DEEP_LINK_PATHS = [
  '/oauth/auth',
  '/room/*',
  '/ui/invite*',
  '/invite*',
];

const AEZA_SIGNING_FINGERPRINT =
  '55:08:99:75:33:25:B9:D6:1B:71:70:FD:77:0A:13:B5:82:D6:EE:41:3C:6F:25:C0:C8:D9:AF:87:9E:0C:44:99';

// Upload key for the public talerid build; documented in CLAUDE.md and verified
// against every published APK with `apksigner verify --print-certs`.
const TALERID_SIGNING_FINGERPRINT =
  '12:D7:AB:50:36:59:5E:51:09:EF:43:27:73:FF:23:C6:3F:62:0D:23:4E:56:95:C6:7A:74:2F:2E:1F:4C:9B:8D';

const AEZA_APPS = {
  ios: [
    'MG58MDUNZ2.tirol.taler.talerIdMobile',
    'MG58MDUNZ2.tirol.taler.talerIdMobile.dev',
  ],
  android: [
    {
      packageName: 'tirol.taler.taler_id_mobile',
      fingerprints: [AEZA_SIGNING_FINGERPRINT],
    },
    {
      packageName: 'tirol.taler.taler_id_mobile.dev',
      fingerprints: [
        AEZA_SIGNING_FINGERPRINT,
        'CE:F2:7D:2C:83:A4:F7:0E:7D:6A:2F:D0:61:79:01:96:B2:72:07:78:02:41:00:BC:2A:BB:58:16:37:E1:04:51',
      ],
    },
  ] as AndroidApp[],
};

const TALERID_APPS = {
  ios: ['MG58MDUNZ2.io.talerid.app'],
  android: [
    {
      packageName: 'io.talerid.app',
      fingerprints: [TALERID_SIGNING_FINGERPRINT],
    },
  ] as AndroidApp[],
};

/**
 * Which app may claim links on the host being asked.
 *
 * These files are the only thing that decides it: an app can name a domain in
 * its manifest all it likes, but the OS will not hand it a link unless the
 * domain vouches for that exact package and signing key. Keeping them
 * host-specific is what stops the aeza builds and the public talerid build from
 * fighting over the same URL when both are installed — which is also why the
 * copy served here previously, listing aeza packages on the talerid domains, let
 * nothing at all open.
 */
function appsForHost(req: any) {
  const host = String(req?.headers?.host ?? '')
    .split(':')[0]
    .toLowerCase();
  return host.endsWith('talerid.io') ? TALERID_APPS : AEZA_APPS;
}

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
  appleAppSiteAssociation(@Req() req: any) {
    return {
      applinks: {
        apps: [],
        details: appsForHost(req).ios.map((appID) => ({
          appID,
          paths: DEEP_LINK_PATHS,
        })),
      },
    };
  }

  @Get('.well-known/assetlinks.json')
  @Header('Content-Type', 'application/json')
  androidAssetLinks(@Req() req: any) {
    return appsForHost(req).android.map(
      ({ packageName, fingerprints }: AndroidApp) => ({
        relation: ['delegate_permission/common.handle_all_urls'],
        target: {
          namespace: 'android_app',
          package_name: packageName,
          sha256_cert_fingerprints: fingerprints,
        },
      }),
    );
  }

  @Get('app/version')
  appVersion(@Query('flavor') flavor?: string) {
    const isDev = flavor === 'dev';
    const env = process.env;
    // Env-overridable so the DO/talerid build advertises its own track + APK URL;
    // defaults preserve aeza (prod/dev) behaviour when these vars are unset.
    const latest = {
      version: env.APP_LATEST_VERSION || '1.1.22',
      build: parseInt(env.APP_LATEST_BUILD || '223', 10),
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

