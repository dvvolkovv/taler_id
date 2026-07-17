import { forwardRef, Module } from '@nestjs/common';
import { AssistantController } from './assistant.controller';
import { AssistantService } from './assistant.service';
import { AssistantChatService } from './assistant-chat.service';
import { AssistantChatController } from './assistant-chat.controller';
import { BillingModule } from '../billing/billing.module';
import { MessengerModule } from '../messenger/messenger.module';
import { FcmService } from '../common/fcm.service';

@Module({
  imports: [BillingModule, forwardRef(() => MessengerModule)],
  controllers: [AssistantController, AssistantChatController],
  providers: [AssistantService, AssistantChatService, FcmService],
  exports: [AssistantChatService],
})
export class AssistantModule {}
