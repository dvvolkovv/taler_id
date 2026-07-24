import { Module } from '@nestjs/common';
import { MailController } from './mail.controller';
import { MailAccountService } from './mail-account.service';
import { MailBridgeService } from './mail-bridge.service';
import { MailcowClient } from './mailcow.client';

@Module({
  controllers: [MailController],
  providers: [MailcowClient, MailAccountService, MailBridgeService],
  exports: [MailAccountService, MailBridgeService], // понадобятся assistant tools в Phase 2
})
export class MailModule {}
