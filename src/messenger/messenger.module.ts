import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MessengerController } from './messenger.controller';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';
import { FcmService } from '../common/fcm.service';
import { ApnsService } from '../common/apns.service';

@Module({
  imports: [ConfigModule],
  controllers: [MessengerController],
  providers: [MessengerService, MessengerGateway, FcmService, ApnsService],
})
export class MessengerModule {}
