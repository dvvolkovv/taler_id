import { Module } from '@nestjs/common';
import { CalendarModule } from '../calendar/calendar.module';
import { TasksModule } from '../tasks/tasks.module';
import { NotesModule } from '../notes/notes.module';
import { MessengerModule } from '../messenger/messenger.module';
import { MailModule } from '../mail/mail.module';
import { OidcModule } from '../oidc/oidc.module';
import { McpController } from './mcp.controller';
import { McpServerFactory } from './mcp-server.factory';
import { McpAuthGuard } from './mcp-auth.guard';

@Module({
  imports: [
    CalendarModule,
    TasksModule,
    NotesModule,
    MessengerModule,
    MailModule,
    OidcModule,
  ],
  controllers: [McpController],
  providers: [McpServerFactory, McpAuthGuard],
})
export class McpModule {}
