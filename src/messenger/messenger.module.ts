import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MessengerController } from './messenger.controller';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';

@Module({
  imports: [ConfigModule],
  controllers: [MessengerController],
  providers: [MessengerService, MessengerGateway],
})
export class MessengerModule {}
