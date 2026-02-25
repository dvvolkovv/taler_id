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
import { FcmService } from '../common/fcm.service';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';

@WebSocketGateway({ namespace: '/messenger', cors: { origin: '*' } })
export class MessengerGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server;

  private publicKey: string;

  constructor(
    private readonly service: MessengerService,
    private readonly configService: ConfigService,
    private readonly fcmService: FcmService,
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
      const senderName = await this.service.getUserDisplayName(client.data.userId);
      const enrichedMsg = { ...msg, senderName };
      // Emit to conversation room (for users who have the chat open)
      this.server.to(payload.conversationId).emit('new_message', enrichedMsg);
      // Also emit to personal rooms of all participants (for users on other screens)
      const participants = await this.service.getParticipants(payload.conversationId);
      for (const p of participants) {
        this.server.to(`user:${p.userId}`).emit('new_message', enrichedMsg);
      }
    } catch (e) {
      client.emit('error', { message: (e as Error).message });
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
  async handleCallInvite(
    client: Socket,
    payload: { conversationId: string; roomName: string },
  ) {
    const fromUserName = await this.service.getUserDisplayName(client.data.userId);
    const participants = await this.service.getParticipants(payload.conversationId);
    const calleeIds = participants
      .filter((p) => p.userId !== client.data.userId)
      .map((p) => p.userId);

    for (const calleeId of calleeIds) {
      this.server.to(`user:${calleeId}`).emit('call_invite', {
        fromUserId: client.data.userId,
        fromUserName,
        roomName: payload.roomName,
        conversationId: payload.conversationId,
      });
      // Send FCM push for background/killed app
      const calleeToken = await this.service.getFcmToken(calleeId);
      if (calleeToken) {
        this.fcmService.sendCallInvite(calleeToken, fromUserName, payload.roomName, payload.conversationId).catch(() => {});
      }
    }
  }

  @SubscribeMessage('call_ended')
  async handleCallEnded(client: Socket, payload: { conversationId: string; roomName: string }) {
    const participants = await this.service.getParticipants(payload.conversationId);
    const calleeIds = participants
      .filter((p) => p.userId !== client.data.userId)
      .map((p) => p.userId);
    for (const calleeId of calleeIds) {
      this.server.to(`user:${calleeId}`).emit('call_ended', {
        roomName: payload.roomName,
        fromUserId: client.data.userId,
      });
    }
  }
}
