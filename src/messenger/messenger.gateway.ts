import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  ConnectedSocket,
  MessageBody,
} from '@nestjs/websockets';
import {
  forwardRef,
  Inject,
  Logger,
  OnModuleInit,
  Optional,
} from '@nestjs/common';
import { Server, Socket } from 'socket.io';
import { ConfigService } from '@nestjs/config';
import { MessengerService, buildForwardedFrom } from './messenger.service';
import { AiTwinService } from './ai-twin.service';
import { AiAnalystService } from '../ai-analyst/ai-analyst.service';
import { InformerBotService } from '../informer-bot/informer-bot.service';
import { AssistantChatService } from '../assistant/assistant-chat.service';
import { FcmService } from '../common/fcm.service';
import { systemMessagePushText } from './system-message-text.util';
import { ApnsService } from '../common/apns.service';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import { isApiAccessToken } from '../common/utils/access-token.util';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import {
  PHASE_LABELS,
  resolveToolLabel,
  ToolKind,
} from '../ai-analyst/ai-analyst-labels';

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
    @Inject(forwardRef(() => AssistantChatService))
    private readonly assistantChat: AssistantChatService,
    @Optional() private readonly informerBot?: InformerBotService,
  ) {
    const publicKeyPath =
      this.configService.get<string>('jwt.publicKeyPath') ?? '';
    this.publicKey = publicKeyPath
      ? fs.readFileSync(publicKeyPath, 'utf8')
      : '';
  }

  onModuleInit() {
    // Wire AiTwinService so it can emit Socket.io events back to the right
    // users without holding a reference to the Server object itself.
    this.aiTwin.registerEmitters(
      (callerId, payload) => {
        this.server.to(`user:${callerId}`).emit('call_ai_twin_offer', payload);
      },
      (targetUserId, payload) => {
        this.server
          .to(`user:${targetUserId}`)
          .emit('call_ai_twin_joined', payload);
      },
    );
  }

  async handleConnection(client: Socket) {
    try {
      const token = (client.handshake.auth?.token as string)?.replace(
        'Bearer ',
        '',
      );
      if (!token) throw new Error('No token');
      const payload = jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'],
      }) as any;
      // OIDC ID tokens are signed with the same key — reject them here too.
      if (!isApiAccessToken(payload)) throw new Error('Not an access token');
      client.data.userId = payload.sub;
      client.data.connectedAt = Date.now();
      client.join(`user:${payload.sub}`);
    } catch {
      client.disconnect();
    }
  }

  handleDisconnect(client: Socket) {
    if (client.data.userId) {
      this.prisma.user
        .update({
          where: { id: client.data.userId },
          data: { lastSeen: new Date() },
        })
        .catch(() => {});
    }
  }

  @SubscribeMessage('join')
  async handleJoin(client: Socket, payload: { conversationId: string }) {
    try {
      await this.service.assertParticipant(
        payload.conversationId,
        client.data.userId,
      );
      client.join(payload.conversationId);
    } catch {
      client.emit('error', { message: 'Not a participant' });
    }
  }

  @SubscribeMessage('message')
  async handleMessage(
    client: Socket,
    payload: {
      conversationId: string;
      content: string;
      fileUrl?: string;
      fileName?: string;
      fileSize?: number;
      fileType?: string;
      s3Key?: string;
      thumbnailSmallUrl?: string;
      thumbnailMediumUrl?: string;
      thumbnailLargeUrl?: string;
      silent?: boolean;
      topicId?: string;
      clientTempId?: string;
      origin?: string;
      replyToId?: string;
    },
  ) {
    try {
      this.logger.log(
        `[handleMessage] socket=${client.id} user=${client.data.userId} conv=${payload.conversationId} tempId=${payload.clientTempId ?? 'none'} content=${(payload.content || '').slice(0, 40)}`,
      );
      // Idempotency: skip duplicate messages sent during reconnects.
      // Atomic SETNX so two emits in the same millisecond don't both pass
      // the check-then-act gap (the old GET+SETEX pattern raced and let
      // duplicates through). On duplicate we still MUST tell the sender we
      // have their message — otherwise the client's persistent pending
      // queue retries forever.
      let dedupKey: string | null = null;
      if (payload.clientTempId) {
        dedupKey = `msg:dedup:${client.data.userId}:${payload.clientTempId}`;
        // setNxEx returns true if we acquired the slot, false if a sibling
        // already did.
        const acquired = await this.redis.setNxEx(dedupKey, 86400, '1');
        if (!acquired) {
          // Look up the real messageId stored by the winner (may still be
          // '1' if the winner is mid-flight — that's fine, sender just
          // gets ack later via broadcast).
          const stored = await this.redis.get(dedupKey);
          this.logger.log(
            `[handleMessage] Duplicate clientTempId=${payload.clientTempId} (atomic), ack-only`,
          );
          client.emit('message_acked', {
            clientTempId: payload.clientTempId,
            messageId: stored && stored !== '1' ? stored : undefined,
          });
          return;
        }
      }
      const fileData = payload.fileUrl
        ? {
            fileUrl: payload.fileUrl,
            fileName: payload.fileName,
            fileSize: payload.fileSize,
            fileType: payload.fileType,
            s3Key: payload.s3Key,
            thumbnailSmallUrl: payload.thumbnailSmallUrl,
            thumbnailMediumUrl: payload.thumbnailMediumUrl,
            thumbnailLargeUrl: payload.thumbnailLargeUrl,
          }
        : undefined;
      // For DIRECT conversations, check contact/block status BEFORE saving message
      const msgConvType = await this.service.getConversationType(
        payload.conversationId,
      );
      if (msgConvType === 'DIRECT') {
        const allParticipants = await this.service.getParticipants(
          payload.conversationId,
        );
        const otherParticipant = allParticipants.find(
          (p) => p.userId !== client.data.userId,
        );
        if (otherParticipant) {
          // Check if sender is blocked by recipient
          const blocked = await this.prisma.blockedUser.findFirst({
            where: {
              blockerId: otherParticipant.userId,
              blockedId: client.data.userId,
            },
          });
          if (blocked) {
            client.emit('error', {
              message: 'Вы заблокированы этим пользователем',
            });
            return;
          }
          // Check if still contacts
          const stillContacts = await this.service.hasContactWith(
            client.data.userId,
            otherParticipant.userId,
          );
          if (!stillContacts) {
            client.emit('error', {
              message: 'Пользователь удалил вас из контактов',
            });
            return;
          }
        }
      }
      // Check channel permissions
      if (msgConvType === 'CHANNEL') {
        await this.service.assertCanPostInChannel(
          payload.conversationId,
          client.data.userId,
        );
      }
      // Reconnect-drain window: stale client outboxes re-fire pending
      // entries immediately after the socket connects. A message arriving
      // within seconds of connect that duplicates old content is a phantom
      // resend, not a human typing (2026-07-17 ghost incident).
      const phantomSuspect =
        typeof client.data.connectedAt === 'number' &&
        Date.now() - client.data.connectedAt < 15_000;
      const msg = await this.service.createMessage(
        payload.conversationId,
        client.data.userId,
        payload.content,
        fileData,
        payload.topicId,
        undefined,
        undefined,
        payload.clientTempId,
        phantomSuspect,
        payload.replyToId ? { replyToId: payload.replyToId } : undefined,
      );
      if ((msg as any).deduped) {
        // Phantom resend of an already-stored message: ack the sender so its
        // pending queue clears, but never re-broadcast or push the old row.
        if (payload.clientTempId) {
          const dedupKey = `msg:dedup:${client.data.userId}:${payload.clientTempId}`;
          await this.redis.setEx(dedupKey, 86400, msg.id);
          client.emit('message_acked', {
            clientTempId: payload.clientTempId,
            messageId: msg.id,
          });
        }
        this.logger.warn(
          `[handleMessage] Phantom resend blocked: user=${client.data.userId} conv=${payload.conversationId} msg=${msg.id}`,
        );
        return;
      }
      const senderName = await this.service.getUserDisplayName(
        client.data.userId,
      );
      const enrichedMsg = {
        ...msg,
        senderName,
        reactions: [],
        replyTo: await this.service.loadReplyPreview((msg as any).replyToId),
        forwardedFrom: buildForwardedFrom(msg),
      };
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
      // Room broadcast is done eagerly — all sockets joined to the conversation
      // room see the message immediately, including the sender's own echo.
      // AI-веткам не нужен fan-out — они единственные участники, см. ниже.
      // Ordering invariant: broadcastNewMessage BEFORE AI early-returns so the
      // sender always sees their own message echoed; fanOutToParticipants AFTER
      // because AI_ANALYST / AI_INFORMER skip that block entirely (the user is
      // the sole participant — no blocks, markDelivered, or FCM to run).
      this.broadcastNewMessage(enrichedMsg, payload.conversationId);

      // AI Analyst: dispatch user message to Claude Worker asynchronously.
      // The response will appear as a new system message in the same chat.
      if (msgConvType === 'AI_ANALYST') {
        // Claude Worker's multer rejects files over this size with 500.
        // Skip them silently in history; reject the current message loudly.
        const MAX_ANALYST_FILE_BYTES = 20 * 1024 * 1024;

        if (
          payload.fileUrl &&
          payload.fileSize &&
          payload.fileSize > MAX_ANALYST_FILE_BYTES
        ) {
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
        if (
          payload.fileUrl &&
          !recentFiles.some((f) => f.url === payload.fileUrl)
        ) {
          recentFiles.unshift({
            url: payload.fileUrl,
            name: payload.fileName || 'file',
          });
        }
        this._dispatchToAnalyst(
          client.data.userId,
          payload.conversationId,
          payload.content,
          recentFiles,
          payload.origin === 'assistant' ? 'assistant' : undefined,
        );
        // No push notifications or delivery tracking for AI_ANALYST — the
        // user is the only participant. Skip the rest of the handler.
        return;
      }

      // AI_OUTBOUND dispatch removed in 1.1.0 — feature was sunset; any
      // legacy AI_OUTBOUND conversations fall through to the regular
      // messaging path (which is harmless since the chats are now inert).

      if (msgConvType === 'AI_INFORMER') {
        if (this.informerBot) {
          this.informerBot.handleUserMessage(
            client.data.userId,
            payload.conversationId,
            payload.content || '',
          );
        }
        return;
      }

      // Per-participant fan-out (block skip, per-user emit, markDelivered,
      // FCM push) runs only for non-AI conversations. AI_ANALYST and
      // AI_INFORMER already returned above — this is intentional: those
      // conversations have exactly one human participant so getParticipants,
      // markDelivered, and FCM are unnecessary DB/network round-trips.
      await this.fanOutToParticipants(
        enrichedMsg,
        client.data.userId,
        payload.conversationId,
        { silent: payload.silent, senderName },
      );

    } catch (e) {
      // Observability: message-send failures were silently swallowed (only emitted to
      // the client) — a stale-client / missing-column break shipped dead pushes for a
      // day before anyone noticed (incident 2026-07-10). Log server-side too.
      this.logger.error(
        `handleMessage failed (user=${client.data?.userId} conv=${payload?.conversationId}): ${(e as Error).message}`,
        (e as Error).stack,
      );
      client.emit('error', { message: (e as Error).message });
    }
  }

  /**
   * Emit `new_message` to every socket currently joined to the conversation
   * room. This is a cheap, synchronous-like fan-out that does NOT touch the
   * database (no getParticipants, no markDelivered, no FCM).
   *
   * Called eagerly in the socket `message` handler BEFORE any AI-branch
   * early-returns so the sender always sees their own message echoed in real
   * time regardless of conversation type.
   *
   * Structural guarantee: this method MUST NOT call getParticipants or
   * markDelivered — tests assert this (see deliver.spec.ts regression test).
   */
  broadcastNewMessage(enrichedMsg: any, conversationId: string): void {
    this.server.to(conversationId).emit('new_message', enrichedMsg);
  }

  /**
   * Per-participant delivery loop: skips blocked recipients, emits per-user
   * `new_message`, marks delivered when the recipient has a live socket, and
   * fires FCM push when the recipient is NOT currently viewing the conversation
   * (respecting per-participant mute + opts.silent).
   *
   * Called ONLY for non-AI conversation types (after AI_ANALYST / AI_INFORMER
   * early-returns in the socket handler). AI conversations skip this entirely
   * because the user is the sole participant — getParticipants, markDelivered,
   * and FCM are unnecessary round-trips for those paths.
   *
   * @param enrichedMsg    Persisted message row + { senderName, reactions: [] }.
   * @param senderId       Sending user id.
   * @param conversationId Target conversation id.
   * @param opts.silent    If true, skip FCM push (matches socket payload.silent).
   * @param opts.senderName Optional pre-resolved sender display name for FCM
   *                        push title; defaults to enrichedMsg.senderName.
   */
  async fanOutToParticipants(
    enrichedMsg: any,
    senderId: string,
    conversationId: string,
    opts: { silent?: boolean; senderName?: string; systemPost?: boolean } = {},
  ): Promise<void> {
    const senderName =
      opts.senderName ?? (enrichedMsg?.senderName as string | undefined) ?? '';
    const participants = await this.service.getParticipants(conversationId);
    // Один cross-node fetchSockets на весь fan-out, не per-participant:
    // на системном канале (24k участников) внутрицикловой вызов делал 24k
    // одинаковых запросов и валился по таймауту (PROD 2026-07-24).
    let socketsInConv: any[] = [];
    try {
      socketsInConv = await this.server.in(conversationId).fetchSockets();
    } catch (e) {
      this.logger.warn(
        `fanOut: conv fetchSockets failed (${(e as Error).message}) — считаем всех вне разговора`,
      );
    }
    const userIdsInConv = new Set(
      socketsInConv.map((s) => s.data?.userId).filter(Boolean),
    );
    for (const p of participants) {
      if (p.userId === senderId) continue;
      try {
      // Skip delivery if recipient has blocked sender
      const isBlocked = await this.prisma.blockedUser.findFirst({
        where: { blockerId: p.userId, blockedId: senderId },
      });
      if (isBlocked) continue;
      this.server.to(`user:${p.userId}`).emit('new_message', enrichedMsg);
      const recipientInConv = userIdsInConv.has(p.userId);
      const sockets = await this.server.in(`user:${p.userId}`).fetchSockets();
      const isOnline = sockets.length > 0;
      if (isOnline) {
        await this.service.markDelivered(enrichedMsg.id);
        this.server
          .to(`user:${senderId}`)
          .emit('message_updated', { id: enrichedMsg.id, isDelivered: true });
      }
      this.logger.log(
        `FCM: recipientId=${p.userId} online=${isOnline} inConv=${recipientInConv} → push=${!recipientInConv}`,
      );
      if (!recipientInConv && !opts.silent) {
        const isCriticalNews = opts.systemPost === true && enrichedMsg?.metadata?.newsType === 'critical';
        const muted = isCriticalNews
          ? false // critical system-channel news bypasses mute (server-controlled path only)
          : await this.service.isParticipantMuted(conversationId, p.userId);
        if (muted) {
          this.logger.log(`FCM skipped for ${p.userId}: conversation muted`);
        } else {
          const fcmTokens = await this.service.getFcmTokens(p.userId);
          if (fcmTokens.length) {
            const pushText = (() => {
              const c = (enrichedMsg?.content as string | null) ?? '';
              // У служебных сообщений в content лежит JSON, который
              // расшифровывает клиент при отрисовке ленты. В пуше
              // расшифровывать некому — без этой ветки в шторку прилетало
              // «{"action":"member_added",…}».
              if (enrichedMsg?.isSystem) return systemMessagePushText(c);
              if (c.startsWith('[CONTACT]')) return '📇 Контакт';
              if (c.startsWith('[POLL]')) return '📊 Опрос';
              if (enrichedMsg?.fileUrl) {
                const ft = (enrichedMsg?.fileType as string | null) ?? '';
                if (ft === 'image') return '🖼 Фото';
                if (ft === 'video') return '🎥 Видео';
                if (ft === 'audio') return '🎵 Аудио';
                return '📎 Файл';
              }
              return c;
            })();
            // Fan out to every logged-in device of the recipient.
            for (const fcmToken of fcmTokens) {
              this.fcmService
                .sendNewMessage(
                  fcmToken,
                  senderName,
                  pushText,
                  conversationId,
                )
                .then(() => this.logger.log(`FCM sent to ${p.userId}`))
                .catch((e) =>
                  this.logger.error(`FCM failed for ${p.userId}:`, e),
                );
            }
          }
        }
      }
      } catch (e) {
        // Один недоставленный участник не должен обрывать fan-out остальным
        // (инцидент PROD 2026-07-24: fetchSockets timeout убил рассылку 24k юзерам)
        this.logger.warn(
          `fanOut: delivery to ${p.userId} failed: ${(e as Error).message}`,
        );
      }
    }
  }

  /**
   * Post-persist delivery for a new message. Broadcasts to the conversation
   * room, then per-participant: skips blocked recipients, emits per-user
   * new_message, marks delivered when the recipient has any live socket,
   * and fires FCM push when the recipient is NOT currently viewing the
   * conversation (respecting per-participant mute + opts.silent).
   *
   * Thin composition of broadcastNewMessage + fanOutToParticipants.
   * Shared with the MCP send_message tool (see mcp/tools/messenger.tools.ts)
   * so MCP-originated messages get identical delivery semantics — before the
   * extraction, MCP-sent messages were silent for offline recipients, ignored
   * blocks, and never bumped delivered status.
   *
   * @param enrichedMsg  Persisted message row + { senderName, reactions: [] }.
   * @param senderId     Sending user id.
   * @param conversationId  Target conversation id.
   * @param opts.silent  If true, skip FCM push (matches socket payload.silent).
   * @param opts.senderName  Optional pre-resolved sender display name for FCM
   *                         push title; defaults to enrichedMsg.senderName.
   */
  async deliverNewMessage(
    enrichedMsg: any,
    senderId: string,
    conversationId: string,
    opts: { silent?: boolean; senderName?: string; systemPost?: boolean } = {},
  ): Promise<void> {
    this.broadcastNewMessage(enrichedMsg, conversationId);
    await this.fanOutToParticipants(enrichedMsg, senderId, conversationId, opts);
  }

  @SubscribeMessage('edit_message')
  async handleEditMessage(
    client: Socket,
    payload: { conversationId: string; messageId: string; content: string },
  ) {
    try {
      const updated = await this.service.editMessage(
        payload.messageId,
        client.data.userId,
        payload.content,
      );
      this.server.to(payload.conversationId).emit('message_updated', {
        id: updated.id,
        content: updated.content,
        isEdited: true,
      });
    } catch (e) {
      client.emit('error', { message: e.message });
    }
  }

  @SubscribeMessage('delete_message')
  async handleDeleteMessage(
    client: Socket,
    payload: {
      conversationId: string;
      messageId: string;
      scope: 'self' | 'all';
    },
  ) {
    try {
      const result = await this.service.deleteMessage(
        payload.messageId,
        client.data.userId,
        payload.scope,
      );
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
  async handleTyping(
    client: Socket,
    payload: { conversationId: string; isTyping: boolean },
  ) {
    const userId = client.data.userId;
    let userName: string | undefined;
    try {
      const profile = await this.prisma.profile.findUnique({
        where: { userId },
        select: { firstName: true, lastName: true },
      });
      if (profile) {
        userName =
          [profile.firstName, profile.lastName].filter(Boolean).join(' ') ||
          undefined;
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
    payload: {
      conversationId: string;
      roomName: string;
      inviteeId?: string;
      e2eeKey?: string;
    },
  ) {
    const callerInfo = await this.service.getUserCallInfo(client.data.userId);
    this.logger.log(
      `[call_invite] caller=${client.data.userId} conv=${payload.conversationId} room=${payload.roomName} inviteeId=${payload.inviteeId}`,
    );
    const fromUserName = callerInfo.name;
    const fromUserAvatar = callerInfo.avatarUrl;
    const hasConversation =
      payload.conversationId && payload.conversationId.length > 0;
    const convType = hasConversation
      ? await this.service.getConversationType(payload.conversationId)
      : null;
    const isGroup = convType === 'GROUP';

    let calleeIds: string[];
    if (payload.inviteeId) {
      calleeIds = [payload.inviteeId];
    } else if (hasConversation) {
      const participants = await this.service.getParticipants(
        payload.conversationId,
      );
      calleeIds = participants
        .filter((p) => p.userId !== client.data.userId)
        .map((p) => p.userId);
    } else {
      return; // No inviteeId and no conversationId — nothing to do
    }

    // CallLog will be updated per-callee after passing block/contact checks

    // For group calls, emit group_call_started to all participants
    if (isGroup && hasConversation) {
      const participants = await this.service.getParticipants(
        payload.conversationId,
      );
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
        const areContacts = await this.service.hasContactWith(
          client.data.userId,
          calleeId,
        );
        if (!areContacts) continue;
      }
      // Add callee to CallLog ONLY after passing all checks
      try {
        const log = await this.prisma.callLog.findUnique({
          where: { roomName: payload.roomName },
        });
        if (log && !log.participantIds.includes(calleeId)) {
          await this.prisma.callLog.update({
            where: { roomName: payload.roomName },
            data: { participantIds: [...log.participantIds, calleeId] },
          });
        }
      } catch (_) {}

      // Check mute before sending push (but still send socket event for banner)
      const muted = hasConversation
        ? await this.service.isParticipantMuted(
            payload.conversationId,
            calleeId,
          )
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
            const calleeName = [calleeProfile.firstName, calleeProfile.lastName]
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
        // Multi-device: fan the call wake-push out to EVERY logged-in device of
        // the callee (tablet + PC + phone), not just the last to register a token.
        const calleeTokens = await this.service.getFcmTokens(calleeId);
        this.logger.log(
          `[call_invite] calleeId=${calleeId} fcmTokens=${calleeTokens.length}`,
        );
        for (const calleeToken of calleeTokens) {
          this.fcmService
            .sendCallInvite(
              calleeToken,
              fromUserName,
              payload.roomName,
              payload.conversationId || '',
              payload.e2eeKey,
              fromUserAvatar ?? undefined,
            )
            .catch(() => {});
        }
        const voipTokens = await this.service.getVoipTokens(calleeId);
        for (const voipToken of voipTokens) {
          this.apnsService
            .sendVoIPCallInvite(voipToken, {
              nameCaller: isGroup ? `${fromUserName} (группа)` : fromUserName,
              roomName: payload.roomName,
              conversationId: payload.conversationId || '',
              ...(payload.e2eeKey ? { e2eeKey: payload.e2eeKey } : {}),
            })
            .catch(() => {});
        }
      } else {
        this.logger.log(
          `Call push skipped for ${calleeId}: conversation muted`,
        );
      }
    }
  }

  @SubscribeMessage('call_ended')
  async handleCallEnded(
    client: Socket,
    payload: { conversationId: string; roomName: string },
  ) {
    this.logger.log(
      `[call_ended] from=${client.data.userId} room=${payload.roomName} conv=${payload.conversationId}`,
    );

    // Atomic dedup: both initiator and callee often emit call_ended within
    // milliseconds of each other (e.g. timeout on caller side + reject on
    // callee side). Previously the check-then-act on callLog.endedAt raced
    // and BOTH handlers passed the gate, producing duplicate "Пропущенный
    // звонок" system messages and double FCM pushes. SETNX with 1-hour TTL
    // is per-room and lets only the first call_ended do the side effects.
    const dedupKey = `call:ended:${payload.roomName}`;
    const acquired = await this.redis.setNxEx(dedupKey, 3600, '1');
    if (!acquired) {
      this.logger.log(
        `[call_ended] duplicate for ${payload.roomName} — emitting socket event only, skipping side effects`,
      );
      // Still emit call_ended to whoever may need it for UI cleanup, but
      // do not create another missed-call message or push FCM again.
      const dupParticipants = await this.service.getParticipants(
        payload.conversationId,
      );
      for (const p of dupParticipants) {
        this.server.to(`user:${p.userId}`).emit('call_ended', {
          roomName: payload.roomName,
          fromUserId: client.data.userId,
        });
      }
      return;
    }

    // Cancel any pending AI twin fallback — the call is over.
    this.aiTwin.cancelPending(payload.roomName).catch(() => {});
    const msgConvType = await this.service.getConversationType(
      payload.conversationId,
    );
    const isGroup = msgConvType === 'GROUP';

    const participants = await this.service.getParticipants(
      payload.conversationId,
    );

    // Look up CallLog to determine initiator and whether call was answered
    let callLog: any = null;
    try {
      callLog = await this.prisma.callLog.findUnique({
        where: { roomName: payload.roomName },
      });
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
            (new Date(callLog.endedAt).getTime() -
              new Date(answeredAt).getTime()) /
              1000,
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
    this.logger.log(
      `[call_ended] initiator=${initiatorId} senderIsCallee=${senderIsCallee} wasAnswered=${wasAnswered} answeredAt=${callLog?.answeredAt} endedAt=${callLog?.endedAt}`,
    );

    const callerProfile = initiatorId
      ? await this.prisma.profile.findUnique({ where: { userId: initiatorId } })
      : null;
    const callerName = callerProfile
      ? `${callerProfile.firstName ?? ''} ${callerProfile.lastName ?? ''}`.trim()
      : 'Неизвестный';

    for (const p of participants) {
      this.server.to(`user:${p.userId}`).emit('call_ended', {
        roomName: payload.roomName,
        fromUserId: client.data.userId,
      });
      // Send missed call push ONLY when call was never answered,
      // and ONLY to non-initiators (callees who missed the call).
      // Also skip if endedAt already set (another call_ended already processed).
      if (
        !wasAnswered &&
        !callLog?.endedAt &&
        initiatorId &&
        p.userId !== initiatorId
      ) {
        // Skip missed call notification if callee blocked the initiator or not contacts
        const calleeBlockedInitiator = await this.prisma.blockedUser.findFirst({
          where: { blockerId: p.userId, blockedId: initiatorId },
        });
        if (calleeBlockedInitiator) continue;
        if (!isGroup) {
          const areContacts = await this.service.hasContactWith(
            initiatorId,
            p.userId,
          );
          if (!areContacts) continue;
        }
        // Cancel the ringing on every device that got the invite push.
        const tokens = await this.service.getFcmTokens(p.userId);
        for (const token of tokens) {
          this.fcmService
            .sendCallCancelled(token, payload.roomName, callerName)
            .catch(() => {});
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
      const log =
        callLog ??
        (await this.prisma.callLog.findUnique({
          where: { roomName: payload.roomName },
        }));
      if (log && !log.endedAt) {
        const endedAt = new Date();
        // durationSec = talk time (from answeredAt), or 0 if never answered
        const durationSec = log.answeredAt
          ? Math.round(
              (endedAt.getTime() - new Date(log.answeredAt).getTime()) / 1000,
            )
          : 0;
        await this.prisma.callLog.update({
          where: { roomName: payload.roomName },
          data: { endedAt, durationSec },
        });
      }
    } catch (_) {}
  }

  @SubscribeMessage('call_answered')
  async handleCallAnswered(
    client: Socket,
    payload: { conversationId: string; roomName: string },
  ) {
    this.logger.log(
      `[call_answered] from=${client.data.userId} room=${payload.roomName} conv=${payload.conversationId}`,
    );
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
        const log = await this.prisma.callLog.findUnique({
          where: { roomName: payload.roomName },
        });
        if (log && !log.answeredAt) {
          await this.prisma.callLog.update({
            where: { roomName: payload.roomName },
            data: { answeredAt: new Date() },
          });
        }
      } catch (_) {}
      const participants = await this.service.getParticipants(
        payload.conversationId,
      );
      for (const p of participants.filter(
        (p) => p.userId !== client.data.userId,
      )) {
        this.server.to(`user:${p.userId}`).emit('call_answered', {
          roomName: payload.roomName,
        });
      }
      // Multi-device: tell the answerer's OWN other devices to stop ringing.
      // `client.to(room)` broadcasts to every socket in the answerer's user room
      // EXCEPT the answering socket (so the device that picked up isn't told to
      // dismiss its own active call). The client's dashboard call_answered handler
      // already dismisses CallKit + the invite for any room it isn't currently in.
      client.to(`user:${client.data.userId}`).emit('call_answered', {
        roomName: payload.roomName,
      });
      // Sleeping devices have no live socket — their CallKit rings from the
      // VoIP/FCM push alone. Send a cancel push to every device of the
      // answerer; the client guards against ending an already-accepted call,
      // so the answering device is unaffected.
      try {
        const tokens = await this.service.getFcmTokens(client.data.userId);
        for (const token of tokens) {
          this.fcmService
            .sendCallCancelled(token, payload.roomName, 'answered_elsewhere')
            .catch(() => {});
        }
      } catch (_) {}
    } catch (e) {}
  }

  @SubscribeMessage('call_ai_twin_accepted')
  async handleAiTwinAccepted(client: Socket, payload: { roomName: string }) {
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
  async handleAiTwinDeclined(client: Socket, payload: { roomName: string }) {
    this.logger.log(
      `[call_ai_twin_declined] caller=${client.data.userId} room=${payload.roomName}`,
    );
    await this.aiTwin.declineOffer(payload.roomName);
  }

  @SubscribeMessage('react_message')
  async handleReactMessage(
    client: Socket,
    payload: { conversationId: string; messageId: string; emoji: string },
  ) {
    try {
      const reactions = await this.service.toggleReaction(
        payload.messageId,
        client.data.userId,
        payload.emoji,
      );
      const participants = await this.service.getParticipants(
        payload.conversationId,
      );
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
  async handleMarkRead(
    client: Socket,
    payload: { conversationId: string; upToSentAt?: string; upToMessageId?: string },
  ) {
    try {
      const userId = client.data.userId;
      const advanced = await this.service.advanceReadHorizon(
        payload.conversationId,
        userId,
        payload.upToSentAt ? new Date(payload.upToSentAt) : null,
        payload.upToMessageId ?? null,
      );
      if (!advanced) return; // no-op (monotonic)
      const evt = {
        conversationId: payload.conversationId,
        userId,
        lastReadAt: advanced.lastReadAt.toISOString(),
        lastReadMessageId: advanced.lastReadMessageId,
      };
      // Receipts to the other participants (senders) + this user's OTHER devices.
      const participants = await this.service.getParticipants(payload.conversationId);
      for (const p of participants) {
        this.server.to(`user:${p.userId}`).emit('conversation_read', evt);
      }
      // Legacy event kept during client transition (harmless double-signal).
      this.server.to(`user:${userId}`).emit('messages_read', {
        conversationId: payload.conversationId,
        messageIds: [],
      });
      // Clear-on-read fan-out to backgrounded devices — Task 5.
      await this.clearOnRead(userId, payload.conversationId, advanced.lastReadAt);
    } catch (e) {
      this.logger.error(`mark_read failed (conv=${payload?.conversationId}): ${(e as Error).message}`);
    }
  }

  // ─── Group events broadcast ───

  /** Emit a group event to all participants' personal rooms */
  async emitToConversationParticipants(
    conversationId: string,
    event: string,
    data: any,
  ) {
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

  /**
   * Removes every socket of `userId` from a conversation's Socket.IO room.
   *
   * Room membership is granted on `join` and used to be kept until the socket
   * disconnected, so a user removed from a group went on receiving its live
   * messages for the rest of their session. Goes through the Redis adapter, so
   * it also reaches sockets held by the other app node.
   */
  evictFromConversationRoom(userId: string, conversationId: string) {
    this.server.in(`user:${userId}`).socketsLeave(conversationId);
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
  async endCallFromHttp(
    userId: string,
    conversationId: string,
    roomName: string,
  ) {
    await this.handleCallEnded({ data: { userId } } as any, {
      conversationId,
      roomName,
    });
  }

  // ── Call Hold/Resume ──────────────────────────────────────────────

  @SubscribeMessage('call_hold')
  async handleCallHold(
    client: any,
    payload: { roomName: string; conversationId?: string },
  ) {
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
  async handleCallResume(
    client: any,
    payload: { roomName: string; conversationId?: string },
  ) {
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

  @SubscribeMessage('thread_reply')
  async handleThreadReply(
    @ConnectedSocket() client: Socket,
    @MessageBody()
    payload: {
      conversationId: string;
      threadParentId: string;
      content: string;
    },
  ) {
    const msg = await this.service.sendThreadReply(
      payload.conversationId,
      client.data.userId,
      payload.content,
      payload.threadParentId,
    );
    const senderName = await this.service.getUserDisplayName(
      client.data.userId,
    );
    const count = await this.service.getThreadCount(payload.threadParentId);
    this.server.to(payload.conversationId).emit('new_thread_reply', {
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
    origin?: 'assistant',
  ): Promise<void> {
    const started = Date.now();
    // Idle timeout resets on every chunk/tool event from the Worker. Hard cap
    // bounds total runtime so a wedged session can't hang forever. Created
    // synchronously (before any await) so fake timers in tests work reliably.
    const IDLE_TIMEOUT_MS = 180_000;
    const HARD_TIMEOUT_MS = 15 * 60 * 1000;
    let timeoutReject: (err: Error) => void = () => {};
    let idleTimer: ReturnType<typeof setTimeout> | null = null;
    let hardTimer: ReturnType<typeof setTimeout> | null = null;
    const armIdle = () => {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(
        () => timeoutReject(new Error('AI Analyst idle timeout (180 s)')),
        IDLE_TIMEOUT_MS,
      );
    };
    const clearTimers = () => {
      if (idleTimer) clearTimeout(idleTimer);
      if (hardTimer) clearTimeout(hardTimer);
      idleTimer = null;
      hardTimer = null;
    };
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutReject = reject;
      armIdle();
      hardTimer = setTimeout(
        () => reject(new Error('AI Analyst hard timeout (15 min)')),
        HARD_TIMEOUT_MS,
      );
    });

    const lang = await this.getUserLang(userId);
    const counts: Record<ToolKind, number> = {
      search: 0,
      file: 0,
      cmd: 0,
      image: 0,
      other: 0,
    };
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
        userId,
        conversationId,
        messageText,
        fileUrls: fileUrls.length > 0 ? fileUrls : undefined,
        onHeartbeat: () => armIdle(),
        onTool: (tool, input) => {
          armIdle();
          const lbl = resolveToolLabel(tool, input);
          counts[lbl.kind]++;
          emitTyping(lbl.emoji, lbl[lang]);
        },
        onChunk: (chunkText) => {
          armIdle();
          if (!preparingEmitted) {
            emitTyping(
              PHASE_LABELS.preparing.emoji,
              PHASE_LABELS.preparing[lang],
            );
            preparingEmitted = true;
          }
          this.server.to(`user:${userId}`).emit('analyst_chunk', {
            conversationId,
            text: chunkText,
          });
        },
      });
      const { text, outputFiles } = await Promise.race([
        submitPromise,
        timeoutPromise,
      ]);
      clearTimers();

      // Mirror Worker-produced files to an nginx-served path so mobile
      // clients can actually fetch them (Worker's own /files/ is locked
      // behind an iptables allowlist).
      let content = text;
      if (outputFiles && outputFiles.length > 0) {
        const mirrored = await this.aiAnalyst.mirrorOutputFiles(
          conversationId,
          outputFiles,
        );
        if (mirrored.length > 0) {
          const fileList = mirrored
            .map((f) => `📎 [${f.name}](${f.publicUrl})`)
            .join('\n');
          content += '\n\n' + fileList;
        }
      }

      const durationMs = Date.now() - started;
      const steps = (Object.entries(counts) as [ToolKind, number][])
        .filter(([_, v]) => v > 0)
        .map(([kind, count]) => ({ kind, count }));
      const metadata = { steps, durationMs };

      const botMsg = await this.service.createMessage(
        conversationId,
        userId,
        content,
        undefined,
        undefined,
        true,
        metadata,
      );

      clearTyping();
      this.server.to(`user:${userId}`).emit('new_message', {
        ...botMsg,
        senderName: 'AI Аналитик',
        isSystem: true,
      });
      this.server.to(`user:${userId}`).emit('analyst_seam', {
        conversationId,
        messageId: botMsg.id,
        steps,
        durationMs,
      });
      if (origin === 'assistant') {
        // Mirror the reply into the AI_ASSISTANT thread (spec: analyst intercept).
        this.assistantChat
          .appendAnalystReply(userId, text, conversationId)
          .catch((e) =>
            this.logger.error(
              `[AI Analyst] assistant-thread mirror failed: ${(e as Error).message}`,
            ),
          );
      }
    } catch (e) {
      clearTimers();
      const err = e as Error;
      this.logger.error(`[AI Analyst] dispatch failed: ${err.message}`);
      emitTyping(
        PHASE_LABELS.error.emoji,
        `${PHASE_LABELS.error[lang]}: ${err.message}`,
      );
      try {
        const errMsg = await this.service.createMessage(
          conversationId,
          userId,
          `❌ ${lang === 'ru' ? 'Ошибка анализа' : 'Analysis error'}: ${err.message}`,
          undefined,
          undefined,
          true,
          { steps: [], durationMs: Date.now() - started, error: true },
        );
        clearTyping();
        this.server.to(`user:${userId}`).emit('new_message', {
          ...errMsg,
          senderName: 'AI Аналитик',
          isSystem: true,
        });
      } catch {
        clearTyping();
      }
    }
  }

  private async clearOnRead(
    userId: string,
    conversationId: string,
    lastReadAt: Date,
  ): Promise<void> {
    // Online other-devices already got `conversation_read` over the socket (Task 3).
    // Push a silent read_sync so BACKGROUNDED devices cancel this chat's notifications.
    const tokens = await this.service.getFcmTokensForUser(userId);
    await Promise.all(
      tokens.map((t) =>
        this.fcmService.sendReadSync(t, conversationId, lastReadAt.toISOString()).catch((e) =>
          this.logger.error(`read_sync push failed for ${userId}: ${(e as Error).message}`),
        ),
      ),
    );
  }
}
