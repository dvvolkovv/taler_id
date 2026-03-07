import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Logger } from '@nestjs/common';
import { Server, Socket } from 'socket.io';
import { ConfigService } from '@nestjs/config';
import { MessengerService } from './messenger.service';
import { FcmService } from '../common/fcm.service';
import { ApnsService } from '../common/apns.service';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { PrismaService } from '../prisma/prisma.service';

@WebSocketGateway({ namespace: '/messenger', cors: { origin: '*' } })
export class MessengerGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server;
  private readonly logger = new Logger(MessengerGateway.name);

  private publicKey: string;

  constructor(
    private readonly service: MessengerService,
    private readonly configService: ConfigService,
    private readonly fcmService: FcmService,
    private readonly apnsService: ApnsService,
    private readonly prisma: PrismaService,
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
  async handleMessage(client: Socket, payload: { conversationId: string; content: string; fileUrl?: string; fileName?: string; fileSize?: number; fileType?: string }) {
    try {
      const fileData = payload.fileUrl ? { fileUrl: payload.fileUrl, fileName: payload.fileName, fileSize: payload.fileSize, fileType: payload.fileType } : undefined;
      const msg = await this.service.createMessage(
        payload.conversationId,
        client.data.userId,
        payload.content,
        fileData,
      );
      const senderName = await this.service.getUserDisplayName(client.data.userId);
      const enrichedMsg = { ...msg, senderName };
      this.server.to(payload.conversationId).emit('new_message', enrichedMsg);
      const participants = await this.service.getParticipants(payload.conversationId);
      for (const p of participants) {
        if (p.userId === client.data.userId) continue;
        this.server.to(`user:${p.userId}`).emit('new_message', enrichedMsg);
        const socketsInConv = await this.server.in(payload.conversationId).fetchSockets();
        const recipientInConv = socketsInConv.some(s => s.data.userId === p.userId);
        const sockets = await this.server.in(`user:${p.userId}`).fetchSockets();
        const isOnline = sockets.length > 0;
        if (isOnline) {
          await this.service.markDelivered(msg.id);
          this.server.to(`user:${client.data.userId}`).emit('message_updated', { id: msg.id, isDelivered: true });
        }
        this.logger.log(`FCM: recipientId=${p.userId} online=${isOnline} inConv=${recipientInConv} → push=${!recipientInConv}`);
        if (!recipientInConv) {
          const muted = await this.service.isParticipantMuted(payload.conversationId, p.userId);
          if (muted) {
            this.logger.log(`FCM skipped for ${p.userId}: conversation muted`);
          } else {
            const fcmToken = await this.service.getFcmToken(p.userId);
            if (fcmToken) {
              this.fcmService.sendNewMessage(
                fcmToken,
                senderName,
                payload.content,
                payload.conversationId,
              ).then(() => this.logger.log(`FCM sent to ${p.userId}`))
               .catch(e => this.logger.error(`FCM failed for ${p.userId}:`, e));
            }
          }
        }
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
    payload: { conversationId: string; roomName: string; inviteeId?: string; e2eeKey?: string },
  ) {
    const fromUserName = await this.service.getUserDisplayName(client.data.userId);
    const convType = await this.service.getConversationType(payload.conversationId);
    const isGroup = convType === 'GROUP';

    let calleeIds: string[];
    if (payload.inviteeId) {
      calleeIds = [payload.inviteeId];
    } else {
      const participants = await this.service.getParticipants(payload.conversationId);
      calleeIds = participants
        .filter((p) => p.userId !== client.data.userId)
        .map((p) => p.userId);
    }

    // For group calls, emit group_call_started to all participants
    if (isGroup) {
      const participants = await this.service.getParticipants(payload.conversationId);
      for (const p of participants) {
        this.server.to(`user:${p.userId}`).emit('group_call_started', {
          conversationId: payload.conversationId,
          roomName: payload.roomName,
          initiatorName: fromUserName,
          initiatorId: client.data.userId,
        });
      }
    }

    for (const calleeId of calleeIds) {
      // Check mute before sending push (but still send socket event for banner)
      const muted = await this.service.isParticipantMuted(payload.conversationId, calleeId);

      this.server.to(`user:${calleeId}`).emit('call_invite', {
        fromUserId: client.data.userId,
        fromUserName,
        roomName: payload.roomName,
        conversationId: payload.conversationId,
        isGroupCall: isGroup,
        ...(payload.e2eeKey ? { e2eeKey: payload.e2eeKey } : {}),
      });

      if (!muted) {
        const calleeToken = await this.service.getFcmToken(calleeId);
        if (calleeToken) {
          this.fcmService.sendCallInvite(calleeToken, fromUserName, payload.roomName, payload.conversationId, payload.e2eeKey).catch(() => {});
        }
        const voipToken = await this.service.getVoipToken(calleeId);
        if (voipToken) {
          this.apnsService.sendVoIPCallInvite(voipToken, {
            nameCaller: isGroup ? `${fromUserName} (группа)` : fromUserName,
            roomName: payload.roomName,
            conversationId: payload.conversationId,
            ...(payload.e2eeKey ? { e2eeKey: payload.e2eeKey } : {}),
          }).catch(() => {});
        }
      } else {
        this.logger.log(`Call push skipped for ${calleeId}: conversation muted`);
      }
    }
  }

  @SubscribeMessage('call_ended')
  async handleCallEnded(client: Socket, payload: { conversationId: string; roomName: string }) {
    const convType = await this.service.getConversationType(payload.conversationId);
    const isGroup = convType === 'GROUP';

    const participants = await this.service.getParticipants(payload.conversationId);
    for (const p of participants) {
      this.server.to(`user:${p.userId}`).emit('call_ended', {
        roomName: payload.roomName,
        fromUserId: client.data.userId,
      });
      const token = await this.service.getFcmToken(p.userId);
      if (token) {
        this.fcmService.sendCallCancelled(token, payload.roomName).catch(() => {});
      }
    }

    // For group calls, emit group_call_ended so banner disappears
    if (isGroup) {
      for (const p of participants) {
        this.server.to(`user:${p.userId}`).emit('group_call_ended', {
          conversationId: payload.conversationId,
          roomName: payload.roomName,
        });
      }
    }

    try {
      const log = await this.prisma.callLog.findUnique({ where: { roomName: payload.roomName } });
      if (log && !log.endedAt) {
        const endedAt = new Date();
        const durationSec = Math.round((endedAt.getTime() - log.startedAt.getTime()) / 1000);
        await this.prisma.callLog.update({ where: { roomName: payload.roomName }, data: { endedAt, durationSec } });
      }
    } catch (_) {}
  }

  @SubscribeMessage('call_answered')
  async handleCallAnswered(client: Socket, payload: { conversationId: string; roomName: string }) {
    try {
      const participants = await this.service.getParticipants(payload.conversationId);
      for (const p of participants.filter((p) => p.userId !== client.data.userId)) {
        this.server.to(`user:${p.userId}`).emit('call_answered', {
          roomName: payload.roomName,
        });
      }
    } catch (e) {}
  }

  @SubscribeMessage('mark_read')
  async handleMarkRead(client: Socket, payload: { conversationId: string }) {
    try {
      const updatedIds = await this.service.markConversationRead(payload.conversationId, client.data.userId);
      if (updatedIds.length > 0) {
        const participants = await this.service.getParticipants(payload.conversationId);
        for (const p of participants) {
          if (p.userId === client.data.userId) continue;
          this.server.to(`user:${p.userId}`).emit('messages_read', {
            conversationId: payload.conversationId,
            messageIds: updatedIds,
          });
        }
      }
    } catch (e) {}
  }

  // ─── Group events broadcast ───

  /** Emit a group event to all participants' personal rooms */
  async emitToConversationParticipants(conversationId: string, event: string, data: any) {
    const participants = await this.service.getParticipants(conversationId);
    for (const p of participants) {
      this.server.to(`user:${p.userId}`).emit(event, data);
    }
  }

  /** Emit to a specific user's personal room */
  emitToUser(userId: string, event: string, data: any) {
    this.server.to(`user:${userId}`).emit(event, data);
  }
}
