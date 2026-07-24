import { Module, forwardRef } from '@nestjs/common';
import { MessengerModule } from '../messenger/messenger.module';
import { SystemChannelService } from './system-channel.service';

// PrismaModule is @Global() — no need to import it here.
@Module({
  imports: [forwardRef(() => MessengerModule)],
  providers: [SystemChannelService],
  exports: [SystemChannelService],
})
export class SystemChannelModule {}
