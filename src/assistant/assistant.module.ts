import { forwardRef, Module } from '@nestjs/common';
import { AssistantController } from './assistant.controller';
import { AssistantService } from './assistant.service';
import { AssistantChatService } from './assistant-chat.service';
import { AssistantChatController } from './assistant-chat.controller';
import { AssistantInstructionsService } from './assistant-instructions.service';
import { BillingModule } from '../billing/billing.module';
import { MessengerModule } from '../messenger/messenger.module';
import { FcmService } from '../common/fcm.service';

@Module({
  // forwardRef on BillingModule too: MessengerModule now imports AssistantModule
  // (analyst→assistant mirror), so the require chain Billing→Messenger→Assistant
  // evaluates this file before BillingModule's class binding exists.
  imports: [forwardRef(() => BillingModule), forwardRef(() => MessengerModule)],
  controllers: [AssistantController, AssistantChatController],
  providers: [AssistantService, AssistantChatService, AssistantInstructionsService, FcmService],
  exports: [AssistantChatService],
})
export class AssistantModule {}
