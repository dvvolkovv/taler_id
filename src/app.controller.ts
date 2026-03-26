import { Controller, Get, Redirect } from '@nestjs/common';

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
