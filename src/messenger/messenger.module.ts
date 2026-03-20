import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MessengerController } from './messenger.controller';
import { MessengerGateway } from './messenger.gateway';
import { MessengerService } from './messenger.service';
import { FcmService } from '../common/fcm.service';
import { ApnsService } from '../common/apns.service';
import { FileStorageService } from '../common/file-storage.service';
import { ThumbnailService } from '../common/thumbnail.service';

@Module({
  imports: [ConfigModule],
  controllers: [MessengerController],
  providers: [MessengerService, MessengerGateway, FcmService, ApnsService, FileStorageService, ThumbnailService],
})
export class MessengerModule {}
