import { Module } from '@nestjs/common';
import { VoiceController } from './voice.controller';
import { VoiceService } from './voice.service';
import { FileStorageService } from '../common/file-storage.service';
import { BillingModule } from '../billing/billing.module';

@Module({
  imports: [BillingModule],
  controllers: [VoiceController],
  providers: [VoiceService, FileStorageService],
})
export class VoiceModule {}
