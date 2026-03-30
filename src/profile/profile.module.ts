import { Module } from '@nestjs/common';
import { ProfileController } from './profile.controller';
import { ProfileService } from './profile.service';
import { FileStorageService } from '../common/file-storage.service';
import { ThumbnailService } from '../common/thumbnail.service';

@Module({
  controllers: [ProfileController],
  providers: [ProfileService, FileStorageService, ThumbnailService],
  exports: [ProfileService],
})
export class ProfileModule {}
