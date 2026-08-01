import { Injectable } from '@nestjs/common';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { CalendarService } from '../calendar/calendar.service';
import { TasksService } from '../tasks/tasks.service';
import { NotesService } from '../notes/notes.service';
import { MessengerService } from '../messenger/messenger.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { MailBridgeService } from '../mail/mail-bridge.service';
import { registerCalendarTools } from './tools/calendar.tools';
import { registerTaskTools, registerScheduleTool } from './tools/task.tools';
import { registerNotesTools } from './tools/notes.tools';
import {
  registerMessengerReadTools,
  registerMessengerSendTool,
} from './tools/messenger.tools';
import { registerMailReadTools, registerMailSendTool } from './tools/mail.tools';

@Injectable()
export class McpServerFactory {
  constructor(
    private readonly calendar: CalendarService,
    private readonly tasks: TasksService,
    private readonly notes: NotesService,
    private readonly messenger: MessengerService,
    // конкретный класс (не Pick<>): mapped-type в DI-конструкторе даёт metadata
    // `Object` → Nest не резолвит зависимость (boot-crash на DEV 2026-07-24)
    private readonly gateway: MessengerGateway,
    private readonly mailBridge: MailBridgeService,
  ) {}

  buildServer(userId: string, scopes: string[]): McpServer {
    const server = new McpServer({ name: 'talerid', version: '1.0.0' });
    if (scopes.includes('mcp:calendar')) {
      registerCalendarTools(server, this.calendar, userId);
      registerTaskTools(server, this.tasks, userId);
      registerScheduleTool(server, this.calendar, this.tasks, userId);
    }
    if (scopes.includes('mcp:notes')) {
      registerNotesTools(server, this.notes, userId);
    }
    if (scopes.includes('mcp:messages.read')) {
      registerMessengerReadTools(server, this.messenger, userId);
    }
    if (scopes.includes('mcp:messages.send')) {
      registerMessengerSendTool(server, this.messenger, this.gateway, userId);
    }
    if (scopes.includes('mcp:mail.read')) {
      registerMailReadTools(server, this.mailBridge, userId);
    }
    if (scopes.includes('mcp:mail.send')) {
      registerMailSendTool(server, this.mailBridge, userId);
    }
    return server;
  }
}
