import { Module } from '@nestjs/common';
import { ProfileController } from './profile.controller';
import { ProfileService } from './profile.service';
import { S3Service } from './s3.service';

@Module({
  controllers: [ProfileController],
  providers: [ProfileService, S3Service],
  exports: [ProfileService],
})
export class ProfileModule {}
