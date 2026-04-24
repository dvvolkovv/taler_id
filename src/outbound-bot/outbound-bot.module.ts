import { Module, forwardRef } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { RedisModule } from '../redis/redis.module';
import { BillingModule } from '../billing/billing.module';
import { OutboundBotController } from './outbound-bot.controller';
import { OutboundBotService } from './outbound-bot.service';
import { SipService } from './sip.service';

@Module({
  // BillingModule provides GatingService/MeteringService used to gate each
  // outbound call dispatch on the campaign owner's balance. forwardRef because
  // BillingModule transitively depends on MessengerModule (for the gateway
  // token) and MessengerModule already imports OutboundBotModule — so without
  // forwardRef we'd get a DI cycle.
  imports: [ConfigModule, RedisModule, forwardRef(() => BillingModule)],
  controllers: [OutboundBotController],
  providers: [OutboundBotService, SipService],
  exports: [OutboundBotService],
})
export class OutboundBotModule {}
