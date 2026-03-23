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
  async handleMessage(client: Socket, payload: {
    conversationId: string; content: string;
    fileUrl?: string; fileName?: string; fileSize?: number; fileType?: string;
    s3Key?: string; thumbnailSmallUrl?: string; thumbnailMediumUrl?: string; thumbnailLargeUrl?: string;
  }) {
    try {
      const fileData = payload.fileUrl ? {
        fileUrl: payload.fileUrl, fileName: payload.fileName,
        fileSize: payload.fileSize, fileType: payload.fileType,
        s3Key: payload.s3Key,
        thumbnailSmallUrl: payload.thumbnailSmallUrl,
        thumbnailMediumUrl: payload.thumbnailMediumUrl,
        thumbnailLargeUrl: payload.thumbnailLargeUrl,
      } : undefined;
      const msg = await this.service.createMessage(
        payload.conversationId,
        client.data.userId,
        payload.content,
        fileData,
      );
      const senderName = await this.service.getUserDisplayName(client.data.userId);
      const enrichedMsg = { ...msg, senderName, reactions: [] };
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

  @SubscribeMessage('edit_message')
  async handleEditMessage(client: Socket, payload: { conversationId: string; messageId: string; content: string }) {
    try {
      const updated = await this.service.editMessage(payload.messageId, client.data.userId, payload.content);
      this.server.to(payload.conversationId).emit('message_updated', {
        id: updated.id, content: updated.content, isEdited: true,
      });
    } catch (e) {
      client.emit('error', { message: e.message });
    }
  }

  @SubscribeMessage('delete_message')
  async handleDeleteMessage(client: Socket, payload: { conversationId: string; messageId: string; scope: 'self' | 'all' }) {
    try {
      const result = await this.service.deleteMessage(payload.messageId, client.data.userId, payload.scope);
      if (payload.scope === 'all') {
        this.server.to(payload.conversationId).emit('message_deleted', {
          messageId: payload.messageId,
          conversationId: payload.conversationId,
          scope: 'all',
        });
      } else {
        this.server.to(`user:${client.data.userId}`).emit('message_deleted', {
          messageId: payload.messageId,
          conversationId: payload.conversationId,
          scope: 'self',
        });
      }
    } catch (e) {
      client.emit('error', { message: e.message });
    }
  }

  @SubscribeMessage('typing')
  async handleTyping(client: Socket, payload: { conversationId: string; isTyping: boolean }) {
    const userId = client.data.userId;
    let userName: string | undefined;
    try {
      const profile = await this.prisma.profile.findUnique({
        where: { userId },
        select: { firstName: true, lastName: true },
      });
      if (profile) {
        userName = [profile.firstName, profile.lastName].filter(Boolean).join(' ') || undefined;
      }
    } catch (_) {}
    client.to(payload.conversationId).emit('typing', {
      conversationId: payload.conversationId,
      userId,
      userName,
      isTyping: payload.isTyping,
    });
  }

  @SubscribeMessage('call_invite')
  async handleCallInvite(
    client: Socket,
    payload: { conversationId: string; roomName: string; inviteeId?: string; e2eeKey?: string },
  ) {
    const callerInfo = await this.service.getUserCallInfo(client.data.userId);
    const fromUserName = callerInfo.name;
    const fromUserAvatar = callerInfo.avatarUrl;
    const hasConversation = payload.conversationId && payload.conversationId.length > 0;
    const convType = hasConversation ? await this.service.getConversationType(payload.conversationId) : null;
    const isGroup = convType === 'GROUP';

    let calleeIds: string[];
    if (payload.inviteeId) {
      calleeIds = [payload.inviteeId];
    } else if (hasConversation) {
      const participants = await this.service.getParticipants(payload.conversationId);
      calleeIds = participants
        .filter((p) => p.userId !== client.data.userId)
        .map((p) => p.userId);
    } else {
      return; // No inviteeId and no conversationId — nothing to do
    }

    // Add callees to CallLog so missed calls appear in their history
    try {
      const log = await this.prisma.callLog.findUnique({ where: { roomName: payload.roomName } });
      if (log) {
        const allIds = new Set([...log.participantIds, ...calleeIds]);
        await this.prisma.callLog.update({
          where: { roomName: payload.roomName },
          data: { participantIds: [...allIds] },
        });
      }
    } catch (_) {}

    // For group calls, emit group_call_started to all participants
    if (isGroup && hasConversation) {
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
      const muted = hasConversation
        ? await this.service.isParticipantMuted(payload.conversationId, calleeId)
        : false;

      this.server.to(`user:${calleeId}`).emit('call_invite', {
        fromUserId: client.data.userId,
        fromUserName,
        fromUserAvatar,
        roomName: payload.roomName,
        conversationId: payload.conversationId || undefined,
        isGroupCall: isGroup,
        ...(payload.e2eeKey ? { e2eeKey: payload.e2eeKey } : {}),
      });

      if (!muted) {
        const calleeToken = await this.service.getFcmToken(calleeId);
        if (calleeToken) {
          this.fcmService.sendCallInvite(calleeToken, fromUserName, payload.roomName, payload.conversationId || '', payload.e2eeKey).catch(() => {});
        }
        const voipToken = await this.service.getVoipToken(calleeId);
        if (voipToken) {
          this.apnsService.sendVoIPCallInvite(voipToken, {
            nameCaller: isGroup ? `${fromUserName} (группа)` : fromUserName,
            roomName: payload.roomName,
            conversationId: payload.conversationId || '',
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
    this.logger.log(`[call_ended] from=${client.data.userId} room=${payload.roomName} conv=${payload.conversationId}`);
    const convType = await this.service.getConversationType(payload.conversationId);
    const isGroup = convType === 'GROUP';

    const participants = await this.service.getParticipants(payload.conversationId);

    // Look up CallLog to determine initiator and whether call was answered
    let callLog: any = null;
    try {
      callLog = await this.prisma.callLog.findUnique({ where: { roomName: payload.roomName } });
    } catch (_) {}
    const initiatorId = callLog?.initiatorId;
    // Call is considered answered if:
    // 1. answeredAt is set (callee sent call_answered), OR
    // 2. call_ended came from the callee (they were in the room = answered), OR
    // 3. call_ended came from someone other than the initiator (they participated)
    const senderIsCallee = initiatorId && client.data.userId !== initiatorId;
    // If callee is ending the call, also set answeredAt if not yet set (fixes race condition)
    if (senderIsCallee && callLog && !callLog.answeredAt) {
      try {
        const answeredAt = callLog.startedAt;
        const updateData: any = { answeredAt };
        // If endedAt was already set by initiator, recalculate durationSec
        if (callLog.endedAt) {
          updateData.durationSec = Math.round(
            (new Date(callLog.endedAt).getTime() - new Date(answeredAt).getTime()) / 1000,
          );
        }
        callLog = await this.prisma.callLog.update({
          where: { roomName: payload.roomName },
          data: updateData,
        });
      } catch (_) {}
    }
    // Determine wasAnswered AFTER fallback so it reflects the updated state
    const wasAnswered = !!callLog?.answeredAt || !!senderIsCallee;
    this.logger.log(`[call_ended] initiator=${initiatorId} senderIsCallee=${senderIsCallee} wasAnswered=${wasAnswered} answeredAt=${callLog?.answeredAt} endedAt=${callLog?.endedAt}`);

    const callerProfile = initiatorId
      ? await this.prisma.profile.findUnique({ where: { userId: initiatorId } })
      : null;
    const callerName = callerProfile ? `${callerProfile.firstName ?? ''} ${callerProfile.lastName ?? ''}`.trim() : 'Неизвестный';

    for (const p of participants) {
      this.server.to(`user:${p.userId}`).emit('call_ended', {
        roomName: payload.roomName,
        fromUserId: client.data.userId,
      });
      // Send missed call push ONLY when call was never answered,
      // and ONLY to non-initiators (callees who missed the call).
      // Also skip if endedAt already set (another call_ended already processed).
      if (!wasAnswered && !callLog?.endedAt && initiatorId && p.userId !== initiatorId) {
        const token = await this.service.getFcmToken(p.userId);
        if (token) {
          this.fcmService.sendCallCancelled(token, payload.roomName, callerName).catch(() => {});
        }
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
      const log = callLog ?? await this.prisma.callLog.findUnique({ where: { roomName: payload.roomName } });
      if (log && !log.endedAt) {
        const endedAt = new Date();
        // durationSec = talk time (from answeredAt), or 0 if never answered
        const durationSec = log.answeredAt
          ? Math.round((endedAt.getTime() - new Date(log.answeredAt).getTime()) / 1000)
          : 0;
        await this.prisma.callLog.update({ where: { roomName: payload.roomName }, data: { endedAt, durationSec } });
      }
    } catch (_) {}
  }

  @SubscribeMessage('call_answered')
  async handleCallAnswered(client: Socket, payload: { conversationId: string; roomName: string }) {
    this.logger.log(`[call_answered] from=${client.data.userId} room=${payload.roomName} conv=${payload.conversationId}`);
    try {
      // Mark answeredAt in CallLog (first answer wins)
      try {
        const log = await this.prisma.callLog.findUnique({ where: { roomName: payload.roomName } });
        if (log && !log.answeredAt) {
          await this.prisma.callLog.update({
            where: { roomName: payload.roomName },
            data: { answeredAt: new Date() },
          });
        }
      } catch (_) {}
      const participants = await this.service.getParticipants(payload.conversationId);
      for (const p of participants.filter((p) => p.userId !== client.data.userId)) {
        this.server.to(`user:${p.userId}`).emit('call_answered', {
          roomName: payload.roomName,
        });
      }
    } catch (e) {}
  }


  @SubscribeMessage('react_message')
  async handleReactMessage(client: Socket, payload: { conversationId: string; messageId: string; emoji: string }) {
    try {
      const reactions = await this.service.toggleReaction(payload.messageId, client.data.userId, payload.emoji);
      const participants = await this.service.getParticipants(payload.conversationId);
      for (const p of participants) {
        this.server.to(`user:${p.userId}`).emit('message_reaction_updated', {
          messageId: payload.messageId,
          conversationId: payload.conversationId,
          reactions,
        });
      }
    } catch (e) {
      client.emit('error', { message: (e as Error).message });
    }
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

  /** HTTP fallback for call_ended (used by mobile app as backup) */
  async endCallFromHttp(userId: string, conversationId: string, roomName: string) {
    await this.handleCallEnded({ data: { userId } } as any, { conversationId, roomName });
  }
}
