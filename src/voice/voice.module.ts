import { Module, forwardRef } from '@nestjs/common';
import { VoiceController } from './voice.controller';
import { VoiceService } from './voice.service';
import { FileStorageService } from '../common/file-storage.service';
import { BillingModule } from '../billing/billing.module';
import { GroupCallModule } from './group-call/group-call.module';
import { RoomChatBufferService } from './room-chat-buffer.service';

@Module({
  imports: [BillingModule, forwardRef(() => GroupCallModule)],
  controllers: [VoiceController],
  providers: [VoiceService, FileStorageService, RoomChatBufferService],
  exports: [VoiceService],
})
export class VoiceModule {}
