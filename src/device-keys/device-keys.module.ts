import { Module } from '@nestjs/common';
import { DeviceKeysController } from './device-keys.controller';
import { DeviceKeysService } from './device-keys.service';
import { PrismaModule } from '../prisma/prisma.module';
import { FcmService } from '../common/fcm.service';

@Module({
  imports: [PrismaModule],
  controllers: [DeviceKeysController],
  providers: [DeviceKeysService, FcmService],
  exports: [DeviceKeysService],
})
export class DeviceKeysModule {}
