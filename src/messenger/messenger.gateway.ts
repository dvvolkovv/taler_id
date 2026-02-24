import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { ConfigService } from '@nestjs/config';
import { MessengerService } from './messenger.service';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';

@WebSocketGateway({ namespace: '/messenger', cors: { origin: '*' } })
export class MessengerGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server;

  private publicKey: string;

  constructor(
    private readonly service: MessengerService,
    private readonly configService: ConfigService,
  ) {
    const publicKeyPath = this.configService.get<string>('jwt.publicKeyPath') ?? '';
    this.publicKey = fs.readFileSync(publicKeyPath, 'utf8');
  }

  async handleConnection(client: Socket) {
    try {
      const token = (client.handshake.auth?.token as string)?.replace('Bearer ', '');
      if (!token) throw new Error('No token');
      const payload = jwt.verify(token, this.publicKey, { algorithms: ['RS256'] }) as any;
      client.data.userId = payload.sub;
      client.join(`user:${payload.sub}`);
    } catch {
      client.disconnect();
    }
  }

  handleDisconnect(client: Socket) {}

  @SubscribeMessage('join')
  async handleJoin(client: Socket, payload: { conversationId: string }) {
    try {
      await this.service.assertParticipant(payload.conversationId, client.data.userId);
      client.join(payload.conversationId);
    } catch {
      client.emit('error', { message: 'Not a participant' });
    }
  }

  @SubscribeMessage('message')
  async handleMessage(client: Socket, payload: { conversationId: string; content: string }) {
    try {
      const msg = await this.service.createMessage(
        payload.conversationId,
        client.data.userId,
        payload.content,
      );
      this.server.to(payload.conversationId).emit('new_message', msg);
    } catch (e) {
      client.emit('error', { message: e.message });
    }
  }

  @SubscribeMessage('typing')
  handleTyping(client: Socket, payload: { conversationId: string; isTyping: boolean }) {
    client.to(payload.conversationId).emit('typing', {
      conversationId: payload.conversationId,
      userId: client.data.userId,
      isTyping: payload.isTyping,
    });
  }

  @SubscribeMessage('call_invite')
  handleCallInvite(client: Socket, payload: { conversationId: string; roomName: string }) {
    client.to(payload.conversationId).emit('call_invite', {
      fromUserId: client.data.userId,
      roomName: payload.roomName,
    });
  }
}
