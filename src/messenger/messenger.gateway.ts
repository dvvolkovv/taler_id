import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  ConnectedSocket,
  MessageBody,
} from '@nestjs/websockets';
import { Logger, OnModuleInit } from '@nestjs/common';
import { Server, Socket } from 'socket.io';
import { ConfigService } from '@nestjs/config';
import { MessengerService } from './messenger.service';
import { AiTwinService } from './ai-twin.service';
import { AiAnalystService } from '../ai-analyst/ai-analyst.service';
import { OutboundBotService } from '../outbound-bot/outbound-bot.service';
import { FcmService } from '../common/fcm.service';
import { ApnsService } from '../common/apns.service';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { PHASE_LABELS, resolveToolLabel, ToolKind } from '../ai-analyst/ai-analyst-labels';

@WebSocketGateway({ namespace: '/messenger', cors: { origin: '*' } })
export class MessengerGateway
  implements OnGatewayConnection, OnGatewayDisconnect, OnModuleInit
{
  @WebSocketServer() server: Server;
  private readonly logger = new Logger(MessengerGateway.name);

  private publicKey: string;

  constructor(
    private readonly service: MessengerService,
    private readonly configService: ConfigService,
    private readonly fcmService: FcmService,
    private readonly apnsService: ApnsService,
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly aiTwin: AiTwinService,
    private readonly aiAnalyst: AiAnalystService,
    private readonly outboundBot: OutboundBotService,
  ) {
    const publicKeyPath = this.configService.get<string>('jwt.publicKeyPath') ?? '';
    this.publicKey = publicKeyPath ? fs.readFileSync(publicKeyPath, 'utf8') : '';
  }

  onModuleInit() {
    // Wire AiTwinService so it can emit Socket.io events back to the right
    // users without holding a reference to the Server object itself.
    // Wire OutboundBotService Socket.IO emitter
    this.outboundBot.registerEmitter(async (target, event, data) => {
      // target can be userId (for status events) or conversationId (for messages)
      this.server.to(target).emit(event, data);
      // Also emit to each participant's personal room for reliability
      if (event === 'new_message' && data?.conversationId) {
        try {
          const parts = await this.service.getParticipants(data.conversationId);
          for (const p of parts) {
            this.server.to(`user:${p.userId}`).emit(event, data);
          }
        } catch {}
      }
    });
    this.aiTwin.registerEmitters(
      (callerId, payload) => {
        this.server.to(`user:${callerId}`).emit('call_ai_twin_offer', payload);
      },
      (targetUserId, payload) => {
        this.server.to(`user:${targetUserId}`).emit('call_ai_twin_joined', payload);
      },
    );
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

  handleDisconnect(client: Socket) {
    if (client.data.userId) {
      this.prisma.user.update({
        where: { id: client.data.userId },
        data: { lastSeen: new Date() },
      }).catch(() => {});
    }
  }

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
    s3Key?: string; thumbnailSmallUrl?: string; thumbnailMediumUrl?: string; thumbnailLargeUrl?: string; silent?: boolean;
    topicId?: string; clientTempId?: string;
  }) {
    try {
      // Idempotency: skip duplicate messages sent during reconnects.
      // On duplicate we still MUST tell the sender we have their message —
      // otherwise the client's persistent pending queue retries forever.
      if (payload.clientTempId) {
        const dedupKey = `msg:dedup:${client.data.userId}:${payload.clientTempId}`;
        const alreadySent = await this.redis.get(dedupKey);
        if (alreadySent) {
          this.logger.log(`[handleMessage] Duplicate clientTempId=${payload.clientTempId}, ack-only`);
          client.emit('message_acked', {
            clientTempId: payload.clientTempId,
            messageId: alreadySent !== '1' ? alreadySent : undefined,
          });
          return;
        }
        // Store for 24h so reconnect storms across app restarts are caught.
        // Value will be overwritten with real messageId after insert.
        await this.redis.setEx(dedupKey, 86400, '1');
      }
      const fileData = payload.fileUrl ? {
        fileUrl: payload.fileUrl, fileName: payload.fileName,
        fileSize: payload.fileSize, fileType: payload.fileType,
        s3Key: payload.s3Key,
        thumbnailSmallUrl: payload.thumbnailSmallUrl,
        thumbnailMediumUrl: payload.thumbnailMediumUrl,
        thumbnailLargeUrl: payload.thumbnailLargeUrl,
      } : undefined;
      // For DIRECT conversations, check contact/block status BEFORE saving message
      const msgConvType = await this.service.getConversationType(payload.conversationId);
      if (msgConvType === 'DIRECT') {
        const allParticipants = await this.service.getParticipants(payload.conversationId);
        const otherParticipant = allParticipants.find(p => p.userId !== client.data.userId);
        if (otherParticipant) {
          // Check if sender is blocked by recipient
          const blocked = await this.prisma.blockedUser.findFirst({
            where: { blockerId: otherParticipant.userId, blockedId: client.data.userId },
          });
          if (blocked) {
            client.emit('error', { message: 'Вы заблокированы этим пользователем' });
            return;
          }
          // Check if still contacts
          const stillContacts = await this.service.hasContactWith(client.data.userId, otherParticipant.userId);
          if (!stillContacts) {
            client.emit('error', { message: 'Пользователь удалил вас из контактов' });
            return;
          }
        }
      }
      // Check channel permissions
      if (msgConvType === "CHANNEL") {
        await this.service.assertCanPostInChannel(payload.conversationId, client.data.userId);
      }
      const msg = await this.service.createMessage(
        payload.conversationId,
        client.data.userId,
        payload.content,
        fileData,
        payload.topicId,
      );
      const senderName = await this.service.getUserDisplayName(client.data.userId);
      const enrichedMsg = { ...msg, senderName, reactions: [] };
      // Update dedup key with real messageId so future duplicate retries can
      // receive the server-side id (useful for clients that lost the original
      // new_message broadcast).
      if (payload.clientTempId) {
        const dedupKey = `msg:dedup:${client.data.userId}:${payload.clientTempId}`;
        await this.redis.setEx(dedupKey, 86400, msg.id);
      }
      // Explicit ack to sender with mapping clientTempId → messageId so the
      // sender reliably clears its pending queue even if it misses the
      // broadcast below (e.g. socket reconnect race).
      if (payload.clientTempId) {
        client.emit('message_acked', {
          clientTempId: payload.clientTempId,
          messageId: msg.id,
        });
      }
      this.server.to(payload.conversationId).emit('new_message', enrichedMsg);

      // AI Analyst: dispatch user message to Claude Worker asynchronously.
      // The response will appear as a new system message in the same chat.
      if (msgConvType === 'AI_ANALYST') {
        // Claude Worker's multer rejects files over this size with 500.
        // Skip them silently in history; reject the current message loudly.
        const MAX_ANALYST_FILE_BYTES = 20 * 1024 * 1024;

        if (payload.fileUrl && payload.fileSize && payload.fileSize > MAX_ANALYST_FILE_BYTES) {
          const mb = (payload.fileSize / 1024 / 1024).toFixed(1);
          const errMsg = await this.service.createMessage(
            payload.conversationId,
            client.data.userId,
            `❌ Файл «${payload.fileName || 'file'}» слишком большой (${mb} МБ). Лимит для AI Аналитика — 20 МБ.`,
            undefined,
            undefined,
            true,
          );
          this.server.to(`user:${client.data.userId}`).emit('new_message', {
            ...errMsg,
            senderName: 'AI Аналитик',
            isSystem: true,
          });
          return;
        }

        // Collect files from recent user messages (current + last few) so
        // that when the user sends 2 files as separate messages then types
        // a question, Claude sees all the files, not just the last one.
        const recentFiles: { url: string; name: string }[] = [];
        try {
          const recent = await this.prisma.message.findMany({
            where: {
              conversationId: payload.conversationId,
              isSystem: false,
              fileUrl: { not: null },
              OR: [
                { fileSize: null },
                { fileSize: { lte: MAX_ANALYST_FILE_BYTES } },
              ],
            },
            orderBy: { sentAt: 'desc' },
            take: 10,
            select: { fileUrl: true, fileName: true },
          });
          for (const m of recent) {
            if (m.fileUrl) {
              recentFiles.push({ url: m.fileUrl, name: m.fileName || 'file' });
            }
          }
        } catch (_) {}
        // Also include the current message's file if any
        if (payload.fileUrl && !recentFiles.some(f => f.url === payload.fileUrl)) {
          recentFiles.unshift({ url: payload.fileUrl, name: payload.fileName || 'file' });
        }
        this._dispatchToAnalyst(
          client.data.userId,
          payload.conversationId,
          payload.content,
          recentFiles,
        );
        // No push notifications or delivery tracking for AI_ANALYST — the
        // user is the only participant. Skip the rest of the handler.
        return;
      }

      // AI Outbound Bot: dispatch user message to start a call campaign.
      this.logger.log(`[AI_OUTBOUND] msgConvType=${msgConvType} convId=${payload.conversationId} content=${(payload.content || "").slice(0,50)}`);
      if (msgConvType === 'AI_OUTBOUND') {
        const recentFiles: { url: string; name: string }[] = [];
        try {
          const recent = await this.prisma.message.findMany({
            where: { conversationId: payload.conversationId, isSystem: false, fileUrl: { not: null } },
            orderBy: { sentAt: 'desc' }, take: 10, select: { fileUrl: true, fileName: true },
          });
          for (const m of recent) { if (m.fileUrl) recentFiles.push({ url: m.fileUrl, name: m.fileName || 'file' }); }
        } catch (_) {}
        if (payload.fileUrl && !recentFiles.some(f => f.url === payload.fileUrl)) {
          recentFiles.unshift({ url: payload.fileUrl, name: payload.fileName || 'file' });
        }
        this.outboundBot.handleUserMessage({
          userId: client.data.userId,
          conversationId: payload.conversationId,
          messageText: payload.content,
          topicId: payload.topicId,
          fileUrls: recentFiles.length > 0 ? recentFiles : undefined,
        });
        return;
      }

      const participants = await this.service.getParticipants(payload.conversationId);
      for (const p of participants) {
        if (p.userId === client.data.userId) continue;
        // Skip delivery if recipient has blocked sender
        const isBlocked = await this.prisma.blockedUser.findFirst({
          where: { blockerId: p.userId, blockedId: client.data.userId },
        });
        if (isBlocked) continue;
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
        if (!recipientInConv && !payload.silent) {
          const muted = await this.service.isParticipantMuted(payload.conversationId, p.userId);
          if (muted) {
            this.logger.log(`FCM skipped for ${p.userId}: conversation muted`);
          } else {
            const fcmToken = await this.service.getFcmToken(p.userId);
            if (fcmToken) {
              const pushText = (() => {
                const c = payload.content ?? '';
                if (c.startsWith('[CONTACT]')) return '📇 Контакт';
                if (c.startsWith('[POLL]')) return '📊 Опрос';
                if (payload.fileUrl) {
                  const ft = payload.fileType ?? '';
                  if (ft === 'image') return '🖼 Фото';
                  if (ft === 'video') return '🎥 Видео';
                  if (ft === 'audio') return '🎵 Аудио';
                  return '📎 Файл';
                }
                return c;
              })();
              this.fcmService.sendNewMessage(
                fcmToken,
                senderName,
                pushText,
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
    this.logger.log(`[call_invite] caller=${client.data.userId} conv=${payload.conversationId} room=${payload.roomName} inviteeId=${payload.inviteeId}`);
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

    // CallLog will be updated per-callee after passing block/contact checks

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
      // Skip if callee has blocked the caller
      const callBlocked = await this.prisma.blockedUser.findFirst({
        where: { blockerId: calleeId, blockedId: client.data.userId },
      });
      if (callBlocked) continue;
      // For DIRECT calls, skip if not contacts
      if (!isGroup) {
        const areContacts = await this.service.hasContactWith(client.data.userId, calleeId);
        if (!areContacts) continue;
      }
      // Add callee to CallLog ONLY after passing all checks
      try {
        const log = await this.prisma.callLog.findUnique({ where: { roomName: payload.roomName } });
        if (log && !log.participantIds.includes(calleeId)) {
          await this.prisma.callLog.update({
            where: { roomName: payload.roomName },
            data: { participantIds: [...log.participantIds, calleeId] },
          });
        }
      } catch (_) {}

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

      // If the callee has AI twin enabled, schedule a fallback so that if
      // they don't answer within N seconds the caller gets offered the
      // option to leave a message with their voice twin. Only for 1:1 calls
      // — group calls don't make sense for an AI twin.
      if (!isGroup) {
        try {
          const calleeProfile = await this.prisma.profile.findUnique({
            where: { userId: calleeId },
            select: {
              aiTwinEnabled: true,
              aiTwinTimeoutSeconds: true,
              aiTwinPrompt: true,
              aiTwinVoiceId: true,
              firstName: true,
              lastName: true,
            },
          });
          if (calleeProfile?.aiTwinEnabled) {
            const calleeName = [
              calleeProfile.firstName,
              calleeProfile.lastName,
            ]
              .filter(Boolean)
              .join(' ')
              .trim();
            await this.aiTwin.schedulePending({
              roomName: payload.roomName,
              callerId: client.data.userId,
              calleeId,
              conversationId: payload.conversationId,
              prompt: (calleeProfile.aiTwinPrompt ?? '').trim(),
              voiceId:
                calleeProfile.aiTwinVoiceId ||
                process.env.DEFAULT_AI_TWIN_VOICE_ID ||
                'KHq0FLdHpP6d1h5s1sce',
              calleeName: calleeName || 'пользователь',
              callerName: fromUserName || 'звонящий',
              timeoutSeconds: calleeProfile.aiTwinTimeoutSeconds || 30,
            });
          }
        } catch (e) {
          this.logger.warn(`AI twin schedule failed: ${(e as Error).message}`);
        }
      }

      if (!muted) {
        const calleeToken = await this.service.getFcmToken(calleeId);
        this.logger.log(`[call_invite] calleeId=${calleeId} fcmToken=${calleeToken ? "YES(" + calleeToken.substring(0,20) + "...)" : "NULL"}`);
        if (calleeToken) {
          this.fcmService.sendCallInvite(calleeToken, fromUserName, payload.roomName, payload.conversationId || '', payload.e2eeKey, fromUserAvatar ?? undefined).catch(() => {});
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
    // Cancel any pending AI twin fallback — the call is over.
    this.aiTwin.cancelPending(payload.roomName).catch(() => {});
    const msgConvType = await this.service.getConversationType(payload.conversationId);
    const isGroup = msgConvType === 'GROUP';

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
        // Skip missed call notification if callee blocked the initiator or not contacts
        const calleeBlockedInitiator = await this.prisma.blockedUser.findFirst({
          where: { blockerId: p.userId, blockedId: initiatorId },
        });
        if (calleeBlockedInitiator) continue;
        if (!isGroup) {
          const areContacts = await this.service.hasContactWith(initiatorId, p.userId);
          if (!areContacts) continue;
        }
        const token = await this.service.getFcmToken(p.userId);
        if (token) {
          this.fcmService.sendCallCancelled(token, payload.roomName, callerName).catch(() => {});
        }
        // Create system message "Missed call" in the conversation
        if (payload.conversationId) {
          try {
            const missedMsg = await this.prisma.message.create({
              data: {
                conversationId: payload.conversationId,
                senderId: initiatorId,
                content: '📞 Пропущенный звонок',
                isSystem: true,
              },
            });
            // conversation lastMessage updated by message creation trigger
            // Emit to conversation so it appears in real-time
            this.server.to(payload.conversationId).emit('new_message', {
              ...missedMsg,
              sender: { id: initiatorId, username: callerName, profile: null },
            });
          } catch (e) {
            this.logger.error('Failed to create missed call message:', e);
          }
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
    // Human callee picked up — cancel any pending AI twin fallback.
    this.aiTwin.cancelPending(payload.roomName).catch(() => {});
    // If the AI twin had already taken over, kick it out so the human can
    // take the call. Runs async — takeover completes in ~100ms and the human
    // join happens in parallel via the standard LiveKit connect flow.
    this.aiTwin
      .takeoverCall(payload.roomName)
      .then(async (tookOver) => {
        if (!tookOver) return;
        this.logger.log(
          `[call_answered] AI twin removed from room=${payload.roomName} — human taking over`,
        );
        // Tell the caller's UI that the AI badge should come down. Look up
        // the initiator from CallLog — the caller isn't the socket client
        // sending call_answered (that's the callee).
        try {
          const log = await this.prisma.callLog.findUnique({
            where: { roomName: payload.roomName },
          });
          if (log?.initiatorId) {
            this.server
              .to(`user:${log.initiatorId}`)
              .emit('call_ai_twin_left', { roomName: payload.roomName });
          }
        } catch (_) {}
      })
      .catch(() => {});
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

  @SubscribeMessage('call_ai_twin_accepted')
  async handleAiTwinAccepted(
    client: Socket,
    payload: { roomName: string },
  ) {
    this.logger.log(
      `[call_ai_twin_accepted] caller=${client.data.userId} room=${payload.roomName}`,
    );
    const result = await this.aiTwin.acceptOffer(
      payload.roomName,
      client.data.userId,
    );
    if (!result.ok) {
      client.emit('error', {
        message: `AI twin offer rejected: ${result.reason}`,
      });
    }
  }

  @SubscribeMessage('call_ai_twin_declined')
  async handleAiTwinDeclined(
    client: Socket,
    payload: { roomName: string },
  ) {
    this.logger.log(
      `[call_ai_twin_declined] caller=${client.data.userId} room=${payload.roomName}`,
    );
    await this.aiTwin.declineOffer(payload.roomName);
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

  /**
   * Emit a Socket.io event to a specific user's personal room. Mirrors the
   * inline `server.to(`user:${userId}`).emit(...)` pattern used throughout
   * this gateway. Provided for cross-module use (e.g., GroupCallGateway in
   * voice/group-call routes group_call_* events through here).
   */
  emitToUser(userId: string, event: string, data: any) {
    this.server.to(`user:${userId}`).emit(event, data);
  }

  /** Get user's preferred language from their profile. Defaults to 'en'. */
  private async getUserLang(userId: string): Promise<'ru' | 'en'> {
    const profile = await this.prisma.profile.findUnique({
      where: { userId },
      select: { language: true },
    });
    const lang = profile?.language;
    return lang === 'ru' ? 'ru' : 'en';
  }

  /** HTTP fallback for call_ended (used by mobile app as backup) */
  async endCallFromHttp(userId: string, conversationId: string, roomName: string) {
    await this.handleCallEnded({ data: { userId } } as any, { conversationId, roomName });
  }

  // ── Call Hold/Resume ──────────────────────────────────────────────

  @SubscribeMessage('call_hold')
  async handleCallHold(client: any, payload: { roomName: string; conversationId?: string }) {
    const userId = client.data?.userId;
    if (!userId || !payload.roomName) return;
    this.logger.log(`[call_hold] from=${userId} room=${payload.roomName}`);

    if (payload.conversationId) {
      const participants = await this.prisma.conversationParticipant.findMany({
        where: { conversationId: payload.conversationId },
        select: { userId: true },
      });
      for (const p of participants) {
        if (p.userId === userId) continue;
        this.server.to(`user:${p.userId}`).emit('call_hold', {
          roomName: payload.roomName,
          userId,
        });
      }
    }
  }

  @SubscribeMessage('call_resume')
  async handleCallResume(client: any, payload: { roomName: string; conversationId?: string }) {
    const userId = client.data?.userId;
    if (!userId || !payload.roomName) return;
    this.logger.log(`[call_resume] from=${userId} room=${payload.roomName}`);

    if (payload.conversationId) {
      const participants = await this.prisma.conversationParticipant.findMany({
        where: { conversationId: payload.conversationId },
        select: { userId: true },
      });
      for (const p of participants) {
        if (p.userId === userId) continue;
        this.server.to(`user:${p.userId}`).emit('call_resume', {
          roomName: payload.roomName,
          userId,
        });
      }
    }
  }

  @SubscribeMessage("thread_reply")
  async handleThreadReply(
    @ConnectedSocket() client: Socket,
    @MessageBody() payload: { conversationId: string; threadParentId: string; content: string },
  ) {
    const msg = await this.service.sendThreadReply(
      payload.conversationId,
      client.data.userId,
      payload.content,
      payload.threadParentId,
    );
    const senderName = await this.service.getUserDisplayName(client.data.userId);
    const count = await this.service.getThreadCount(payload.threadParentId);
    this.server.to(payload.conversationId).emit("new_thread_reply", {
      ...msg,
      senderName,
      threadParentId: payload.threadParentId,
      threadReplyCount: count,
    });
  }

  // ─── AI Analyst dispatch ──────────────────────────────────────

  /**
   * Fire-and-forget: sends the user's message to the Claude Worker,
   * streams chunks back as `analyst_chunk` events, and creates the
   * final response as a system message in the conversation.
   */
  private async _dispatchToAnalyst(
    userId: string,
    conversationId: string,
    messageText: string,
    fileUrls: { url: string; name: string }[],
  ): Promise<void> {
    const started = Date.now();
    // Create the timeout promise synchronously (before any await) so fake timers
    // in tests can advance past it reliably.
    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('AI Analyst timeout (180 s)')), 180_000),
    );

    const lang = await this.getUserLang(userId);
    const counts: Record<ToolKind, number> = { search: 0, file: 0, cmd: 0, image: 0, other: 0 };
    let preparingEmitted = false;

    const emitTyping = (emoji: string, label: string) => {
      this.server.to(`user:${userId}`).emit('typing', {
        conversationId,
        userId: 'ai-analyst-bot',
        userName: 'AI Аналитик',
        isTyping: true,
        typingText: `${emoji} ${label}`,
      });
    };
    const clearTyping = () => {
      this.server.to(`user:${userId}`).emit('typing', {
        conversationId,
        userId: 'ai-analyst-bot',
        isTyping: false,
      });
    };

    // Phase: thinking
    emitTyping(PHASE_LABELS.thinking.emoji, PHASE_LABELS.thinking[lang]);

    try {
      const submitPromise = this.aiAnalyst.submitTask({
        userId, conversationId, messageText,
        fileUrls: fileUrls.length > 0 ? fileUrls : undefined,
        onTool: (tool, input) => {
          const lbl = resolveToolLabel(tool, input);
          counts[lbl.kind]++;
          emitTyping(lbl.emoji, lbl[lang]);
        },
        onChunk: (chunkText) => {
          if (!preparingEmitted) {
            emitTyping(PHASE_LABELS.preparing.emoji, PHASE_LABELS.preparing[lang]);
            preparingEmitted = true;
          }
          this.server.to(`user:${userId}`).emit('analyst_chunk', {
            conversationId, text: chunkText,
          });
        },
      });
      const { text, outputFiles } = await Promise.race([submitPromise, timeoutPromise]);

      // Append output files list (existing behaviour preserved)
      let content = text;
      if (outputFiles && outputFiles.length > 0) {
        const fileList = outputFiles
          .map((f: any) => `📎 [${f.name}](http://5.101.115.184:3033${f.url})`)
          .join('\n');
        content += '\n\n' + fileList;
      }

      const durationMs = Date.now() - started;
      const steps = (Object.entries(counts) as [ToolKind, number][])
        .filter(([_, v]) => v > 0)
        .map(([kind, count]) => ({ kind, count }));
      const metadata = { steps, durationMs };

      const botMsg = await this.service.createMessage(
        conversationId, userId, content, undefined, undefined,
        true, metadata,
      );

      clearTyping();
      this.server.to(`user:${userId}`).emit('new_message', {
        ...botMsg, senderName: 'AI Аналитик', isSystem: true,
      });
      this.server.to(`user:${userId}`).emit('analyst_seam', {
        conversationId, messageId: botMsg.id, steps, durationMs,
      });
    } catch (e) {
      const err = e as Error;
      this.logger.error(`[AI Analyst] dispatch failed: ${err.message}`);
      emitTyping(PHASE_LABELS.error.emoji, `${PHASE_LABELS.error[lang]}: ${err.message}`);
      try {
        const errMsg = await this.service.createMessage(
          conversationId, userId,
          `❌ ${lang === 'ru' ? 'Ошибка анализа' : 'Analysis error'}: ${err.message}`,
          undefined, undefined, true,
          { steps: [], durationMs: Date.now() - started, error: true },
        );
        clearTyping();
        this.server.to(`user:${userId}`).emit('new_message', {
          ...errMsg, senderName: 'AI Аналитик', isSystem: true,
        });
      } catch {
        clearTyping();
      }
    }
  }
}
