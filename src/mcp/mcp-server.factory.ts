import { Injectable } from '@nestjs/common';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { CalendarService } from '../calendar/calendar.service';
import { NotesService } from '../notes/notes.service';
import { MessengerService } from '../messenger/messenger.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { registerCalendarTools } from './tools/calendar.tools';
import { registerNotesTools } from './tools/notes.tools';
import {
  registerMessengerReadTools,
  registerMessengerSendTool,
} from './tools/messenger.tools';

@Injectable()
export class McpServerFactory {
  constructor(
    private readonly calendar: CalendarService,
    private readonly notes: NotesService,
    private readonly messenger: MessengerService,
    private readonly gateway: Pick<MessengerGateway, 'deliverNewMessage'>,
  ) {}

  buildServer(userId: string, scopes: string[]): McpServer {
    const server = new McpServer({ name: 'talerid', version: '1.0.0' });
    if (scopes.includes('mcp:calendar')) {
      registerCalendarTools(server, this.calendar, userId);
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
    return server;
  }
}
