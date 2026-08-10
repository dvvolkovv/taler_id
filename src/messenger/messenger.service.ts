import {
  Injectable,
  ForbiddenException,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { FileStorageService } from '../common/file-storage.service';
import { resolveUserIdOrUsername } from '../common/utils/user-id.util';
import { extractMentionHandles, resolveMentions } from './mention.util';

/** Потолок на пачку пересылки; совпадает с потолком выделения в клиенте. */
const FORWARD_BATCH_LIMIT = 50;

/** Сколько символов оригинала уезжает в превью цитаты. */
const REPLY_PREVIEW_LIMIT = 200;

/** Потолок черновика; с запасом больше любого разумного сообщения. */
const DRAFT_MAX_LENGTH = 20000;

/**
 * Имя для показа: «Имя Фамилия», иначе username, иначе ничего.
 * Ровно та же лесенка, что и в остальных местах сервиса.
 */
function displayNameOf(user: any): string | null {
  if (!user) return null;
  const firstLast =
    [user.profile?.firstName, user.profile?.lastName]
      .filter(Boolean)
      .join(' ')
      .trim() || null;
  return firstLast ?? user.username ?? null;
}

/**
 * Превью цитаты для клиента.
 *
 * Мягко удалённый оригинал возвращается с `isDeleted: true` и пустым телом:
 * строка в базе осталась, но показывать её содержимое уже нельзя — клиент
 * рисует «Сообщение удалено». Полный текст не отдаём никогда, только первые
 * REPLY_PREVIEW_LIMIT символов: цитата — это подпись, а не копия.
 */
export function buildReplyPreview(replyTo: any): any | null {
  if (!replyTo) return null;
  const isDeleted = !!replyTo.deletedAt;
  return {
    id: replyTo.id,
    senderId: replyTo.senderId ?? null,
    senderName: displayNameOf(replyTo.sender),
    content: isDeleted ? '' : (replyTo.content ?? '').slice(0, REPLY_PREVIEW_LIMIT),
    fileType: isDeleted ? null : (replyTo.fileType ?? null),
    fileName: isDeleted ? null : (replyTo.fileName ?? null),
    isDeleted,
  };
}

/** Атрибуция пересылки, либо null у обычного сообщения. */
export function buildForwardedFrom(m: any): any | null {
  if (!m?.forwardedFromUserId && !m?.forwardedFromName) return null;
  return {
    userId: m.forwardedFromUserId ?? null,
    name: m.forwardedFromName ?? null,
    messageId: m.forwardedFromMessageId ?? null,
  };
}

@Injectable()
export class MessengerService {
  private readonly logger = new Logger(MessengerService.name);

  constructor(
    private prisma: PrismaService,
    private readonly fileStorage: FileStorageService,
  ) {}

  // ─── DIRECT conversations (existing) ───

  async findExistingDirectConversation(userAId: string, userBId: string) {
    return this.prisma.conversation.findFirst({
      where: {
        type: 'DIRECT',
        AND: [
          { participants: { some: { userId: userAId } } },
          { participants: { some: { userId: userBId } } },
        ],
      },
    });
  }

  async getOrCreateDirectConversation(userAId: string, userBId: string) {
    const [idA, idB] = [userAId, userBId].sort();
    return this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${idA} || '-' || ${idB}))`;
      const existing = await tx.conversation.findFirst({
        where: {
          type: 'DIRECT',
          AND: [
            { participants: { some: { userId: userAId } } },
            { participants: { some: { userId: userBId } } },
          ],
        },
        include: {
          participants: true,
          messages: { orderBy: { sentAt: 'desc' }, take: 1 },
        },
      });
      if (existing) {
        const pinnedMap = await this._loadPinnedMap([existing.id], userAId, tx);
        return this._formatConversation(
          existing,
          userAId,
          undefined,
          undefined,
          undefined,
          pinnedMap,
        );
      }
      const conv = await tx.conversation.create({
        data: {
          type: 'DIRECT',
          participants: { create: [{ userId: userAId }, { userId: userBId }] },
        },
        include: { participants: true, messages: true },
      });
      // Беседа только что создана — пинов быть не может.
      return this._formatConversation(conv, userAId);
    });
  }

  // ─── GROUP conversations (new) ───

  async createGroupConversation(
    creatorId: string,
    name: string,
    participantIds: string[],
  ) {
    if (!name || name.trim().length === 0)
      throw new BadRequestException('Group name is required');
    // Ensure creator is in participant list
    const allIds = [...new Set([creatorId, ...participantIds])];
    const conv = await this.prisma.conversation.create({
      data: {
        type: 'GROUP',
        name: name.trim(),
        createdById: creatorId,
        participants: {
          create: allIds.map((uid) => ({
            userId: uid,
            role: uid === creatorId ? 'OWNER' : 'MEMBER',
          })),
        },
      },
      include: { participants: true, messages: true },
    });
    // System message: group created
    await this._createSystemMessage(conv.id, creatorId, 'group_created');
    // Беседа только что создана — пинов быть не может.
    return this._formatConversation(conv, creatorId);
  }

  async assertGroupRole(
    conversationId: string,
    userId: string,
    roles: string[],
  ) {
    const p = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
    });
    if (!p) throw new ForbiddenException('Not a participant');
    if (!roles.includes(p.role))
      throw new ForbiddenException('Insufficient role');
    return p;
  }

  async addGroupMembers(
    conversationId: string,
    requesterId: string,
    userIds: string[],
  ) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP')
      throw new BadRequestException('Not a group conversation');
    await this.assertGroupRole(conversationId, requesterId, ['OWNER', 'ADMIN']);
    const existing = await this.prisma.conversationParticipant.findMany({
      where: { conversationId, userId: { in: userIds } },
    });
    const existingIds = new Set(existing.map((p) => p.userId));
    const newIds = userIds.filter((id) => !existingIds.has(id));
    if (newIds.length === 0) return [];
    await this.prisma.conversationParticipant.createMany({
      data: newIds.map((uid) => ({
        conversationId,
        userId: uid,
        role: 'MEMBER' as const,
      })),
    });
    // System messages for each added member
    for (const uid of newIds) {
      await this._createSystemMessage(
        conversationId,
        requesterId,
        'member_added',
        uid,
      );
    }
    return newIds;
  }

  async removeGroupMember(
    conversationId: string,
    requesterId: string,
    targetUserId: string,
  ) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP')
      throw new BadRequestException('Not a group conversation');
    const requester = await this.assertGroupRole(conversationId, requesterId, [
      'OWNER',
      'ADMIN',
    ]);
    const target = await this.prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: { conversationId, userId: targetUserId },
      },
    });
    if (!target) throw new NotFoundException('User is not a participant');
    // ADMIN cannot remove OWNER or other ADMIN
    if (
      requester.role === 'ADMIN' &&
      (target.role === 'OWNER' || target.role === 'ADMIN')
    ) {
      throw new ForbiddenException('Cannot remove OWNER or ADMIN');
    }
    await this.prisma.conversationParticipant.delete({
      where: {
        conversationId_userId: { conversationId, userId: targetUserId },
      },
    });
    await this._createSystemMessage(
      conversationId,
      requesterId,
      'member_removed',
      targetUserId,
    );
  }

  async changeGroupMemberRole(
    conversationId: string,
    requesterId: string,
    targetUserId: string,
    newRole: string,
  ) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP')
      throw new BadRequestException('Not a group conversation');
    const requester = await this.assertGroupRole(conversationId, requesterId, [
      'OWNER',
      'ADMIN',
    ]);
    if (requesterId === targetUserId)
      throw new BadRequestException('Cannot change own role');
    const target = await this.prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: { conversationId, userId: targetUserId },
      },
    });
    if (!target) throw new NotFoundException('User is not a participant');
    // Only OWNER can assign ADMIN
    if (newRole === 'ADMIN' && requester.role !== 'OWNER') {
      throw new ForbiddenException('Only OWNER can assign ADMIN');
    }
    // ADMIN cannot change OWNER's or other ADMIN's role
    if (
      requester.role === 'ADMIN' &&
      (target.role === 'OWNER' || target.role === 'ADMIN')
    ) {
      throw new ForbiddenException('Cannot change OWNER or ADMIN role');
    }
    await this.prisma.conversationParticipant.update({
      where: {
        conversationId_userId: { conversationId, userId: targetUserId },
      },
      data: { role: newRole as any },
    });
    await this._createSystemMessage(
      conversationId,
      requesterId,
      'role_changed',
      targetUserId,
      newRole,
    );
    return { userId: targetUserId, newRole };
  }

  async updateGroupInfo(
    conversationId: string,
    requesterId: string,
    data: {
      name?: string;
      avatarUrl?: string;
      description?: string;
      slowMode?: boolean;
      invitePolicy?: string;
      autoDeleteDays?: number | null;
      topicsEnabled?: boolean;
    },
  ) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP')
      throw new BadRequestException('Not a group conversation');
    await this.assertGroupRole(conversationId, requesterId, ['OWNER', 'ADMIN']);
    const update: any = {};
    if (data.name !== undefined) update.name = data.name.trim();
    if (data.avatarUrl !== undefined) update.avatarUrl = data.avatarUrl;
    if (data.description !== undefined) update.description = data.description;
    if (data.slowMode !== undefined) update.slowMode = data.slowMode;
    if (data.invitePolicy !== undefined)
      update.invitePolicy = data.invitePolicy;
    if (data.autoDeleteDays !== undefined)
      update.autoDeleteDays = data.autoDeleteDays;
    if (data.topicsEnabled !== undefined)
      update.topicsEnabled = data.topicsEnabled;
    if (Object.keys(update).length === 0) return conv;
    return this.prisma.conversation.update({
      where: { id: conversationId },
      data: update,
    });
  }

  async leaveGroup(conversationId: string, userId: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP')
      throw new BadRequestException('Not a group conversation');
    const participant = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
    });
    if (!participant) throw new ForbiddenException('Not a participant');
    // If OWNER leaves, transfer ownership
    if (participant.role === 'OWNER') {
      const nextOwner = await this.prisma.conversationParticipant.findFirst({
        where: { conversationId, userId: { not: userId } },
        orderBy: [{ role: 'asc' }, { joinedAt: 'asc' }], // ADMIN < MEMBER alphabetically, so ADMINs first
      });
      if (nextOwner) {
        await this.prisma.conversationParticipant.update({
          where: { id: nextOwner.id },
          data: { role: 'OWNER' },
        });
      }
    }
    await this.prisma.conversationParticipant.delete({
      where: { conversationId_userId: { conversationId, userId } },
    });
    await this._createSystemMessage(conversationId, userId, 'member_left');
  }

  async deleteGroup(conversationId: string, requesterId: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP')
      throw new BadRequestException('Not a group conversation');
    await this.assertGroupRole(conversationId, requesterId, ['OWNER']);
    await this.prisma.conversation.delete({ where: { id: conversationId } });
  }

  async getGroupMembers(conversationId: string, userId: string) {
    await this.assertParticipant(conversationId, userId);
    const participants = await this.prisma.conversationParticipant.findMany({
      where: { conversationId },
      orderBy: [{ role: 'asc' }, { joinedAt: 'asc' }],
    });
    const userIds = participants.map((p) => p.userId);
    const users = await this.prisma.user.findMany({
      where: { id: { in: userIds } },
      select: {
        id: true,
        username: true,
        lastSeen: true,
        profile: {
          select: {
            firstName: true,
            lastName: true,
            avatarUrl: true,
            status: true,
          },
        },
      },
    });
    const userMap = Object.fromEntries(users.map((u) => [u.id, u]));
    return participants.map((p) => {
      const u = userMap[p.userId];
      return {
        id: p.id,
        userId: p.userId,
        role: p.role,
        joinedAt: p.joinedAt,
        firstName: u?.profile?.firstName ?? null,
        lastName: u?.profile?.lastName ?? null,
        username: u?.username ?? null,
        avatarUrl: u?.profile?.avatarUrl ?? null,
      };
    });
  }

  // ─── Existing methods (updated) ───

  async getConversations(userId: string) {
    const bare = await this.prisma.conversation.findMany({
      where: {
        participants: { some: { userId } },
        NOT: { type: 'AI_ASSISTANT' },
      },
      include: {
        _count: { select: { participants: true } },
        messages: {
          where: { deletedAt: null, NOT: { hiddenFor: { some: { userId } } } },
          orderBy: { sentAt: 'desc' },
          take: 1,
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    // Каналы (в т.ч. системный «Taler ID — Новости») могут иметь десятки тысяч
    // подписчиков — грузить их всех в список бесед нельзя (24k строк на запрос,
    // а «первый чужой участник» превращался в случайное имя вроде «Smoke Test»
    // в качестве otherUserName). Для каналов берём только СВОЮ строку участника
    // (роль/мьют/lastReadAt), для остальных типов — всех, как раньше.
    const channelIds = bare.filter((c) => c.type === 'CHANNEL').map((c) => c.id);
    const dyadIds = bare.filter((c) => c.type !== 'CHANNEL').map((c) => c.id);
    const parts = await this.prisma.conversationParticipant.findMany({
      where: {
        OR: [
          ...(dyadIds.length ? [{ conversationId: { in: dyadIds } }] : []),
          ...(channelIds.length
            ? [{ conversationId: { in: channelIds }, userId }]
            : []),
        ],
      },
    });
    const partsByConv: Record<string, typeof parts> = {};
    for (const p of parts) {
      (partsByConv[p.conversationId] ??= []).push(p);
    }
    const conversations = bare.map((c) => ({
      ...c,
      participants: partsByConv[c.id] ?? [],
    }));

    const pinnedMap = await this._loadPinnedMap(
      conversations.map((c) => c.id),
      userId,
    );

    const allUserIds = [
      ...new Set([
        ...conversations.flatMap((c) => c.participants.map((p) => p.userId)),
        // Отправители последних сообщений (например, системный юзер канала —
        // он НЕ участник, но его имя нужно для превью «Taler ID: …»)
        ...conversations
          .map((c) => c.messages?.[0]?.senderId)
          .filter((id): id is string => !!id),
        // Авторы пинов — тоже не всегда участники (тот же системный юзер).
        ...Object.values(pinnedMap)
          .map((p) => p.top?.senderId)
          .filter((id): id is string => !!id),
      ]),
    ];
    const users = await this.prisma.user.findMany({
      where: { id: { in: allUserIds } },
      select: {
        id: true,
        username: true,
        profile: {
          select: { firstName: true, lastName: true, avatarUrl: true },
        },
      },
    });
    const userMap = Object.fromEntries(users.map((u) => [u.id, u]));

    const convIds = conversations.map((c) => c.id);
    // Unread is derived from the per-participant read HORIZON
    // (ConversationParticipant.lastReadAt) — the SAME source as
    // GET /messenger/read-state and unreadCountFor(). mark_read only advances
    // the horizon and no longer touches the legacy Message.isRead flag, so
    // counting isRead=false left the conversation-list badge stuck after a chat
    // was read (it flickered 0 then back). Reuse the already-loaded participants.
    const unreadMap: Record<string, number> = {};
    await Promise.all(
      conversations.map(async (conv) => {
        const mine = conv.participants.find((p) => p.userId === userId);
        unreadMap[conv.id] = await this.prisma.message.count({
          where: {
            conversationId: conv.id,
            senderId: { not: userId },
            // Horizon once a read cursor exists; else fall back to the legacy
            // isRead flag so conversations read under the old model (no cursor
            // yet) don't count their entire history as unread.
            ...(mine?.lastReadAt ? { sentAt: { gt: mine.lastReadAt } } : { isRead: false }),
          },
        });
      }),
    );

    // Непрочитанные упоминания — отдельным счётчиком: в шумной группе бейдж
    // «есть непрочитанное» ничего не значит, а «тебя позвали» значит.
    const mentionMap: Record<string, number> = {};
    await Promise.all(
      conversations.map(async (conv) => {
        const mine = conv.participants.find((p) => p.userId === userId);
        mentionMap[conv.id] = await this.prisma.message.count({
          where: {
            conversationId: conv.id,
            senderId: { not: userId },
            mentionedUserIds: { has: userId },
            deletedAt: null,
            ...(mine?.lastReadAt
              ? { sentAt: { gt: mine.lastReadAt } }
              : { isRead: false }),
          },
        });
      }),
    );

    // Fetch active calls for all conversations
    const activeCalls = await this.prisma.callLog.findMany({
      where: { conversationId: { in: convIds }, endedAt: null },
      select: { conversationId: true, roomName: true },
    });
    const activeCallMap: Record<string, string> = {};
    for (const c of activeCalls) {
      if (c.conversationId) activeCallMap[c.conversationId] = c.roomName;
    }

    // Load contact aliases for name overrides
    const aliases = await this.prisma.contactAlias.findMany({
      where: { ownerId: userId },
    });
    const aliasMap: Record<string, string> = {};
    for (const a of aliases) aliasMap[a.targetId] = a.customName;

    return conversations.map((conv) => ({
      ...this._formatConversation(
        conv,
        userId,
        userMap,
        activeCallMap,
        aliasMap,
        pinnedMap,
      ),
      unreadCount: unreadMap[conv.id] ?? 0,
      mentionCount: mentionMap[conv.id] ?? 0,
    }));
  }

  /** Пины перечисленных бесед одним запросом: {conversationId: {count, top}}.
   *  Строки идут по pinnedAt desc (id — тай-брейкер), поэтому первая
   *  встреченная для беседы и есть верхний пин. hiddenFor исключаем по той же
   *  причине, что и в listPinned: скрытый у себя пин не должен ни считаться,
   *  ни показываться в плашке. */
  private async _loadPinnedMap(
    conversationIds: string[],
    userId: string,
    client: { message: { findMany: Function } } = this.prisma as any,
  ): Promise<Record<string, { count: number; top: any }>> {
    if (conversationIds.length === 0) return {};
    const rows = await client.message.findMany({
      where: {
        conversationId: { in: conversationIds },
        pinnedAt: { not: null },
        deletedAt: null,
        NOT: { hiddenFor: { some: { userId } } },
      },
      orderBy: [{ pinnedAt: 'desc' }, { id: 'desc' }],
      select: {
        id: true,
        conversationId: true,
        content: true,
        senderId: true,
        sentAt: true,
        pinnedAt: true,
      },
    });
    const map: Record<string, { count: number; top: any }> = {};
    for (const r of rows) {
      const entry = (map[r.conversationId] ??= { count: 0, top: null });
      entry.count++;
      if (!entry.top) entry.top = r;
    }
    return map;
  }

  private _formatConversation(
    conv: any,
    currentUserId: string,
    userMap?: Record<string, any>,
    activeCallMap?: Record<string, string>,
    aliasMap?: Record<string, string>,
    pinnedMap?: Record<string, { count: number; top: any }>,
  ) {
    const myParticipant = conv.participants.find(
      (p: any) => p.userId === currentUserId,
    );
    // У каналов нет «собеседника»: первый попавшийся из тысяч подписчиков
    // давал случайное имя/аватар в списке чатов (инцидент «Smoke Test» в
    // системном канале на PROD, 2026-07-24).
    const otherParticipant =
      conv.type === 'CHANNEL'
        ? null
        : conv.participants.find((p: any) => p.userId !== currentUserId);
    const otherUser =
      otherParticipant && userMap ? userMap[otherParticipant.userId] : null;
    const otherFirstLast = otherUser
      ? [otherUser.profile?.firstName, otherUser.profile?.lastName]
          .filter(Boolean)
          .join(' ')
          .trim() || null
      : null;
    const otherUserName =
      (aliasMap && otherParticipant
        ? aliasMap[otherParticipant.userId]
        : null) ??
      otherFirstLast ??
      otherUser?.username ??
      null;
    const lastMsg = conv.messages?.[0] ?? null;

    const pin = pinnedMap?.[conv.id];
    const pinSender = pin?.top && userMap ? userMap[pin.top.senderId] : null;
    const pinSenderName = pinSender
      ? [pinSender.profile?.firstName, pinSender.profile?.lastName]
          .filter(Boolean)
          .join(' ')
          .trim() ||
        pinSender.username ||
        null
      : null;

    // Find sender name for last message (for group chats)
    let lastMessageSenderName: string | null = null;
    if (lastMsg && userMap && lastMsg.senderId !== currentUserId) {
      const senderUser = userMap[lastMsg.senderId];
      if (senderUser) {
        lastMessageSenderName =
          [senderUser.profile?.firstName, senderUser.profile?.lastName]
            .filter(Boolean)
            .join(' ')
            .trim() ||
          senderUser.username ||
          null;
      }
    }

    return {
      id: conv.id,
      type: conv.type,
      name: conv.name ?? null,
      avatarUrl: conv.avatarUrl ?? null,
      description: conv.description ?? null,
      participantCount: conv._count?.participants ?? conv.participants.length,
      myRole: myParticipant?.role ?? null,
      participantIds: conv.participants.map((p: any) => p.userId),
      lastMessageContent: lastMsg?.content ?? null,
      lastMessageAt: lastMsg?.sentAt ?? null,
      lastMessageSenderId: lastMsg?.senderId ?? null,
      lastMessageSenderName,
      lastMessageIsSystem: lastMsg?.isSystem ?? false,
      otherUserId: otherParticipant?.userId ?? null,
      otherUserName,
      otherUserAvatar: otherUser?.profile?.avatarUrl ?? null,
      otherUserStatus: otherUser?.profile?.status ?? null,
      otherUserLastSeen: otherUser?.lastSeen ?? null,
      isMuted: myParticipant?.isMuted ?? false,
      mutedUntil: myParticipant?.mutedUntil ?? null,
      activeCallRoomName: activeCallMap?.[conv.id] ?? null,
      slowMode: conv.slowMode ?? false,
      topicsEnabled: conv.topicsEnabled ?? false,
      autoDeleteDays: conv.autoDeleteDays ?? null,
      invitePolicy: conv.invitePolicy ?? 'all',
      // CHANNEL-specific metadata (undefined for non-channels so JSON omits the fields)
      subscribersCount:
        conv.type === 'CHANNEL'
          ? (conv._count?.participants ?? conv.participants.length)
          : undefined,
      isSubscribed: conv.type === 'CHANNEL' ? !!myParticipant : undefined,
      pinnedCount: pin?.count ?? 0,
      topPinned: pin?.top
        ? {
            id: pin.top.id,
            // Плашке хватает превью; системные посты бывают на несколько экранов.
            content: (pin.top.content ?? '').slice(0, 200),
            senderName: pinSenderName,
            sentAt: pin.top.sentAt,
            pinnedAt: pin.top.pinnedAt,
          }
        : null,
      pinsDismissedAt: myParticipant?.pinsDismissedAt ?? null,
      // Состояние списка чатов — персональное, поэтому берётся из своей строки
      // участия, а не из беседы.
      draft: myParticipant?.draft ?? null,
      draftAt: myParticipant?.draftAt ?? null,
      archivedAt: myParticipant?.archivedAt ?? null,
      chatPinnedAt: myParticipant?.chatPinnedAt ?? null,
      // системный канал (Taler ID — Новости): клиенты не могут отписаться
      isSystem: conv.isSystem ? true : undefined,
    };
  }

  async getMessages(
    conversationId: string,
    userId: string,
    cursor?: string,
    limit = 30,
    topicId?: string,
  ) {
    await this.assertParticipant(conversationId, userId);
    const messages = await this.prisma.message.findMany({
      where: {
        conversationId,
        ...(topicId ? { topicId } : {}),
        deletedAt: null,
        NOT: { hiddenFor: { some: { userId } } },
      },
      include: {
        sender: {
          select: {
            username: true,
            profile: { select: { firstName: true, lastName: true } },
          },
        },
        reactions: { select: { userId: true, emoji: true } },
        replyTo: {
          select: {
            id: true,
            senderId: true,
            content: true,
            fileType: true,
            fileName: true,
            deletedAt: true,
            sender: {
              select: {
                username: true,
                profile: { select: { firstName: true, lastName: true } },
              },
            },
          },
        },
      },
      orderBy: { sentAt: 'desc' },
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    const hasMore = messages.length > limit;
    const sliced = hasMore ? messages.slice(0, limit) : messages;
    const enriched = sliced.map((m: any) => {
      const senderName = displayNameOf(m.sender);
      const { sender, reactions, replyTo, ...rest } = m;
      return {
        ...rest,
        senderName,
        reactions: reactions ?? [],
        replyTo: buildReplyPreview(replyTo),
        forwardedFrom: buildForwardedFrom(m),
      };
    });
    return {
      messages: enriched,
      nextCursor: hasMore ? sliced[limit - 1].id : undefined,
    };
  }

  async sync(
    userId: string,
    cursor?: string,
    limit = 200,
  ): Promise<{
    messages: any[];
    nextCursor: string | null;
    hasMore: boolean;
  }> {
    const cap = Math.min(Math.max(limit, 1), 500);

    if (!cursor) {
      const last = await this.prisma.message.findFirst({
        where: {
          deletedAt: null,
          conversation: {
            participants: { some: { userId } },
          },
          NOT: { hiddenFor: { some: { userId } } },
        },
        orderBy: [{ sentAt: 'desc' }, { id: 'desc' }],
        select: { id: true, sentAt: true },
      });
      const nextCursor = last
        ? `${last.sentAt.toISOString()}|${last.id}`
        : `${new Date().toISOString()}|`;
      return { messages: [], nextCursor, hasMore: false };
    }

    const sepIdx = cursor.indexOf('|');
    if (sepIdx === -1) {
      throw new Error('Invalid sync cursor format');
    }
    const cursorTsStr = cursor.slice(0, sepIdx);
    const cursorTsDate = new Date(cursorTsStr);
    const cursorId = cursor.slice(sepIdx + 1);
    if (Number.isNaN(cursorTsDate.getTime())) {
      throw new Error('Invalid sync cursor timestamp');
    }
    // Re-format as a safe ISO string (no user-supplied characters in the SQL literal).
    // sentAt is stored as "timestamp without time zone"; stripping the trailing Z keeps
    // the comparison in the same naive-timestamp domain and avoids Prisma serializing
    // the Date as a timestamptz wire type which breaks the PostgreSQL row comparison.
    const safeCursorTs = cursorTsDate.toISOString().replace('Z', '');

    const rows: any[] = await this.prisma.$queryRaw`
      SELECT
        m.id,
        m."conversationId",
        m."senderId",
        m.content,
        m."sentAt",
        m."isSystem",
        m."isEdited",
        m."isDelivered",
        m."isRead",
        m."editedAt",
        m."fileUrl",
        m."fileName",
        m."fileSize",
        m."fileType",
        m."s3Key",
        m."thumbnailSmallUrl",
        m."thumbnailMediumUrl",
        m."thumbnailLargeUrl",
        m."fileRecordId",
        m."threadParentId",
        m."topicId",
        m.metadata,
        m."replyToId",
        m."forwardedFromUserId",
        m."forwardedFromName",
        m."forwardedFromMessageId",
        u.username AS "senderUsername",
        p."firstName" AS "senderFirstName",
        p."lastName" AS "senderLastName",
        COALESCE(
          (
            SELECT json_agg(json_build_object('userId', r."userId", 'emoji', r.emoji))
            FROM "MessageReaction" r WHERE r."messageId" = m.id
          ),
          '[]'::json
        ) AS reactions,
        -- Превью цитаты собирается здесь же: иначе синхронизация отдавала бы
        -- ответы без оригинала, а getMessages — с ним, и расхождение всплыло бы
        -- только на втором устройстве.
        (
          SELECT json_build_object(
            'id', rm.id,
            'senderId', rm."senderId",
            'senderFirstName', rp."firstName",
            'senderLastName', rp."lastName",
            'senderUsername', ru.username,
            'content', rm.content,
            'fileType', rm."fileType",
            'fileName', rm."fileName",
            'deletedAt', rm."deletedAt"
          )
          FROM "Message" rm
          LEFT JOIN "User" ru ON ru.id = rm."senderId"
          LEFT JOIN "Profile" rp ON rp."userId" = ru.id
          WHERE rm.id = m."replyToId"
        ) AS "replyToRaw"
      FROM "Message" m
      JOIN "ConversationParticipant" cp
        ON cp."conversationId" = m."conversationId" AND cp."userId" = ${userId}
      LEFT JOIN "User" u ON u.id = m."senderId"
      LEFT JOIN "Profile" p ON p."userId" = u.id
      WHERE m."deletedAt" IS NULL
        AND NOT EXISTS (
          SELECT 1 FROM "MessageHidden" h
          WHERE h."messageId" = m.id AND h."userId" = ${userId}
        )
        AND (m."sentAt" > ${Prisma.raw(`'${safeCursorTs}'::timestamp`)}
          OR (m."sentAt" = ${Prisma.raw(`'${safeCursorTs}'::timestamp`)} AND m.id > ${cursorId}))
      ORDER BY m."sentAt" ASC, m.id ASC
      LIMIT ${cap + 1}
    `;

    const hasMore = rows.length > cap;
    const sliced = hasMore ? rows.slice(0, cap) : rows;
    const enriched = sliced.map((r: any) => {
      const firstLast =
        [r.senderFirstName, r.senderLastName].filter(Boolean).join(' ').trim() ||
        null;
      const senderName = firstLast ?? r.senderUsername ?? null;
      const {
        senderUsername,
        senderFirstName,
        senderLastName,
        replyToRaw,
        ...rest
      } = r;
      return {
        ...rest,
        senderName,
        reactions: r.reactions ?? [],
        // json_build_object отдаёт плоскую строку — приводим к той же форме
        // вложенного sender, которую ждёт общий сборщик превью.
        replyTo: buildReplyPreview(
          replyToRaw
            ? {
                ...replyToRaw,
                sender: {
                  username: replyToRaw.senderUsername,
                  profile: {
                    firstName: replyToRaw.senderFirstName,
                    lastName: replyToRaw.senderLastName,
                  },
                },
              }
            : null,
        ),
        forwardedFrom: buildForwardedFrom(r),
      };
    });

    const last = sliced[sliced.length - 1];
    const nextCursor = last
      ? `${(last.sentAt instanceof Date ? last.sentAt : new Date(last.sentAt)).toISOString()}|${last.id}`
      : cursor;

    return { messages: enriched, nextCursor, hasMore };
  }

  async getSharedMedia(
    conversationId: string,
    userId: string,
    type?: string,
    cursor?: string,
    limit = 50,
  ) {
    await this.assertParticipant(conversationId, userId);
    const fileTypes =
      type === 'documents'
        ? ['document']
        : type === 'links'
          ? []
          : ['image', 'video'];
    const where: any = {
      conversationId,
      deletedAt: null,
      NOT: { hiddenFor: { some: { userId } } },
    };
    if (type === 'links') {
      where.content = { contains: 'http' };
      where.fileType = null;
    } else {
      where.fileType = { in: fileTypes };
    }
    const messages = await this.prisma.message.findMany({
      where,
      select: {
        id: true,
        content: true,
        sentAt: true,
        senderId: true,
        fileUrl: true,
        fileName: true,
        fileSize: true,
        fileType: true,
        thumbnailSmallUrl: true,
        thumbnailMediumUrl: true,
        thumbnailLargeUrl: true,
      },
      orderBy: { sentAt: 'desc' },
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    const hasMore = messages.length > limit;
    const sliced = hasMore ? messages.slice(0, limit) : messages;
    return {
      items: sliced,
      nextCursor: hasMore ? sliced[limit - 1].id : undefined,
    };
  }

  async createMessage(
    conversationId: string,
    senderId: string,
    content: string,
    fileData?: {
      fileUrl?: string;
      fileName?: string;
      fileSize?: number;
      fileType?: string;
      s3Key?: string;
      thumbnailSmallUrl?: string;
      thumbnailMediumUrl?: string;
      thumbnailLargeUrl?: string;
    },
    topicId?: string,
    isSystem?: boolean,
    metadata?: Record<string, any>,
    clientTempId?: string,
    phantomSuspect?: boolean,
    relations?: {
      replyToId?: string | null;
      forwardedFromUserId?: string | null;
      forwardedFromName?: string | null;
      forwardedFromMessageId?: string | null;
    },
  ) {
    // Every write path — socket, REST, MCP, informer bot, system channel —
    // funnels through here, so this is the single place that has to prove the
    // sender belongs to the conversation. Without it any authenticated user
    // could post into an arbitrary conversation by guessing its id.
    await this.assertParticipant(conversationId, senderId);

    // Ответ проверяем здесь же и по той же причине: цитата тащит за собой кусок
    // чужого сообщения, поэтому право на неё доказывается на единственном входе,
    // а не в каждом вызывающем.
    if (relations?.replyToId) {
      await this._assertReplyTarget(
        relations.replyToId,
        conversationId,
        topicId,
      );
    }

    // Упоминания разбирает сервер, а не клиент: иначе можно было бы «упомянуть»
    // постороннего и пробить ему уведомление мимо отключённых. Запрос делается
    // только если в тексте вообще есть похожее на @логин — обычная отправка
    // лишнего похода в базу не получает.
    const mentionedUserIds = isSystem
      ? []
      : await this._resolveMentions(conversationId, senderId, content);

    // Пустые поля не подмешиваем: обычная вставка должна выглядеть ровно так же,
    // как до появления ответов и пересылок.
    const relationData = {
      ...(mentionedUserIds.length ? { mentionedUserIds } : {}),
      ...(relations?.replyToId ? { replyToId: relations.replyToId } : {}),
      ...(relations?.forwardedFromUserId
        ? { forwardedFromUserId: relations.forwardedFromUserId }
        : {}),
      ...(relations?.forwardedFromName
        ? { forwardedFromName: relations.forwardedFromName }
        : {}),
      ...(relations?.forwardedFromMessageId
        ? { forwardedFromMessageId: relations.forwardedFromMessageId }
        : {}),
    };

    // Phantom-resend content dedup (incidents 2026-07-10 and 2026-07-17):
    // stale pre-1.0.98 client outboxes re-fire old messages on every socket
    // reconnect. Ancient clients send no clientTempId at all; 1.0.8x-era
    // clients attach a FRESH tempId to a resend of a message originally
    // saved without one — both bypass the (senderId, clientTempId) unique
    // index. The observed ghost was 42 days old, hence the 90-day window.
    // For tempId-carrying sends the check only applies inside the
    // reconnect-drain window (phantomSuspect: message arrived seconds after
    // socket connect — outbox drains fire immediately, humans don't), so a
    // deliberate identical repeat typed later is never swallowed.
    // Callers must NOT broadcast rows returned with `deduped: true`.
    // Пересылка дедупу не подлежит: переслать один и тот же текст второй раз —
    // осознанное действие пользователя, а не фантомный ресенд выпавшего клиента.
    if (
      !isSystem &&
      !fileData &&
      !relations?.forwardedFromMessageId &&
      content.length >= 20 &&
      (!clientTempId || phantomSuspect)
    ) {
      const dup = await this.prisma.message.findFirst({
        where: {
          conversationId,
          senderId,
          content,
          sentAt: { gte: new Date(Date.now() - 90 * 24 * 3600 * 1000) },
        },
        orderBy: { sentAt: 'desc' },
      });
      if (dup) {
        this.logger?.warn?.(
          `[createMessage] content-dedup hit: sender=${senderId} conv=${conversationId} len=${content.length} tempId=${clientTempId ?? 'none'}`,
        );
        return { ...dup, deduped: true };
      }
    }
    // Durable idempotency: the Redis dedup key lives 24h, but broken client
    // outboxes retry stuck sends for weeks. The unique index on
    // (senderId, clientTempId) makes the retry collide; return the original
    // row instead of inserting a copy.
    if (clientTempId) {
      try {
        return await this.prisma.message.create({
          data: {
            conversationId,
            senderId,
            content,
            clientTempId,
            ...fileData,
            ...(topicId ? { topicId } : {}),
            ...(isSystem ? { isSystem } : {}),
            ...(metadata ? { metadata } : {}),
            ...relationData,
          },
        });
      } catch (e: any) {
        if (e?.code === 'P2002') {
          const existing = await this.prisma.message.findFirst({
            where: { senderId, clientTempId },
          });
          if (existing) return { ...existing, deduped: true };
        }
        throw e;
      }
    }
    return this.prisma.message.create({
      data: {
        conversationId,
        senderId,
        content,
        ...fileData,
        ...(topicId ? { topicId } : {}),
        ...(isSystem ? { isSystem } : {}),
        ...(metadata ? { metadata } : {}),
        ...relationData,
      },
    });
  }

  /**
   * Кого упомянули в сообщении.
   *
   * Кандидатов ищем сразу запросом, ограниченным участниками беседы и списком
   * найденных логинов, — грузить всех участников нельзя: у системного канала их
   * двенадцать с лишним тысяч.
   */
  private async _resolveMentions(
    conversationId: string,
    senderId: string,
    content: string,
  ): Promise<string[]> {
    const handles = extractMentionHandles(content);
    if (handles.length === 0) return [];
    const rows: Array<{ userId: string; username: string | null }> =
      await this.prisma.$queryRaw`
        SELECT cp."userId" AS "userId", u.username AS username
        FROM "ConversationParticipant" cp
        JOIN "User" u ON u.id = cp."userId"
        WHERE cp."conversationId" = ${conversationId}
          AND u.username IS NOT NULL
          AND LOWER(u.username) IN (${Prisma.join(handles)})
      `;
    return resolveMentions(content, rows, senderId);
  }

  /**
   * Черновик беседы.
   *
   * Хранится на строке участия, а не на беседе: текст персональный. Пустой (и
   * состоящий из одних пробелов) текст стирает черновик — иначе «стёр всё,
   * остался пробел» оставлял бы чат с вечной пометкой «черновик».
   */
  async setDraft(conversationId: string, userId: string, text: string) {
    const trimmed = (text ?? '').trim();
    if (trimmed.length > DRAFT_MAX_LENGTH) {
      throw new BadRequestException(
        `Draft cannot exceed ${DRAFT_MAX_LENGTH} characters`,
      );
    }
    await this.assertParticipant(conversationId, userId);
    return this.prisma.conversationParticipant.update({
      where: { conversationId_userId: { conversationId, userId } },
      data: trimmed
        ? { draft: trimmed, draftAt: new Date() }
        : { draft: null, draftAt: null },
    });
  }

  /** Архив беседы — тоже персональный: у собеседника чат остаётся на месте. */
  async setArchived(conversationId: string, userId: string, archived: boolean) {
    await this.assertParticipant(conversationId, userId);
    return this.prisma.conversationParticipant.update({
      where: { conversationId_userId: { conversationId, userId } },
      data: { archivedAt: archived ? new Date() : null },
    });
  }

  /**
   * Закрепление беседы в списке чатов.
   *
   * Не путать с закреплением сообщения внутри беседы: имена похожи, сущности
   * разные. Отметка времени, а не флаг, — она же задаёт порядок закреплённых.
   */
  async setChatPinned(conversationId: string, userId: string, pinned: boolean) {
    await this.assertParticipant(conversationId, userId);
    return this.prisma.conversationParticipant.update({
      where: { conversationId_userId: { conversationId, userId } },
      data: { chatPinnedAt: pinned ? new Date() : null },
    });
  }

  /**
   * Превью цитаты для только что созданной строки: `createMessage` возвращает
   * голую запись без связей, а в `new_message` цитата должна уехать сразу —
   * иначе получатель увидит ответ без того, на что отвечают, до перезагрузки
   * истории.
   */
  async loadReplyPreview(replyToId: string | null | undefined) {
    if (!replyToId) return null;
    const original = await this.prisma.message.findUnique({
      where: { id: replyToId },
      select: {
        id: true,
        senderId: true,
        content: true,
        fileType: true,
        fileName: true,
        deletedAt: true,
        sender: {
          select: {
            username: true,
            profile: { select: { firstName: true, lastName: true } },
          },
        },
      },
    });
    return buildReplyPreview(original);
  }

  /**
   * Ответ можно поставить только на живое сообщение той же беседы и того же
   * топика. Кросс-беседный ответ — это утечка: цитата переносит фрагмент чужой
   * переписки туда, где у автора цитаты доступа нет. Кросс-топиковый —
   * рассинхрон рендера: оригинал не виден на экране, где показан ответ.
   *
   * Плохой `replyToId` — ошибка, а не молчаливое обнуление: иначе клиент считает,
   * что отправил ответ, а получатели видят обычное сообщение.
   */
  private async _assertReplyTarget(
    replyToId: string,
    conversationId: string,
    topicId?: string,
  ) {
    const original = await this.prisma.message.findUnique({
      where: { id: replyToId },
      select: {
        id: true,
        conversationId: true,
        topicId: true,
        deletedAt: true,
      },
    });
    if (!original || original.deletedAt) {
      throw new BadRequestException('Reply target not found');
    }
    if (original.conversationId !== conversationId) {
      throw new BadRequestException(
        'Reply target belongs to another conversation',
      );
    }
    if ((original.topicId ?? null) !== (topicId ?? null)) {
      throw new BadRequestException('Reply target belongs to another topic');
    }
  }

  /**
   * Пересылка.
   *
   * Тело копируется из хранимого оригинала, а не приходит от клиента: иначе
   * можно приписать произвольный текст чужому имени. По той же причине здесь
   * проверяется участие пересылающего в *исходной* беседе — без этого любой
   * аутентифицированный пользователь вытащил бы сообщение, зная только его id.
   */
  async forwardMessages(
    targetConversationId: string,
    userId: string,
    messageIds: string[],
  ) {
    if (!Array.isArray(messageIds) || messageIds.length === 0) {
      throw new BadRequestException('No messages to forward');
    }
    if (messageIds.length > FORWARD_BATCH_LIMIT) {
      throw new BadRequestException(
        `Cannot forward more than ${FORWARD_BATCH_LIMIT} messages at once`,
      );
    }
    await this.assertParticipant(targetConversationId, userId);

    const sources = await this.prisma.message.findMany({
      where: { id: { in: messageIds }, deletedAt: null },
      include: {
        sender: {
          select: {
            username: true,
            profile: { select: { firstName: true, lastName: true } },
          },
        },
      },
    });
    if (sources.length === 0) {
      throw new BadRequestException('Nothing to forward');
    }

    const sourceConvIds = [
      ...new Set(sources.map((m: any) => m.conversationId)),
    ];
    const memberships = await this.prisma.conversationParticipant.findMany({
      where: { userId, conversationId: { in: sourceConvIds } },
      select: { conversationId: true },
    });
    const allowed = new Set(
      memberships.map((m: any) => m.conversationId),
    );
    if (sourceConvIds.some((id) => !allowed.has(id))) {
      throw new ForbiddenException('Not a participant of the source conversation');
    }

    // Порядок восстанавливаем по запрошенному списку: findMany возвращает строки
    // в своём порядке, а пачка должна лечь в чат так, как её выделили.
    const byId = new Map(sources.map((m: any) => [m.id, m]));
    const created: any[] = [];
    for (const id of messageIds) {
      const src = byId.get(id);
      if (!src) continue;
      created.push(
        await this.createMessage(
          targetConversationId,
          userId,
          src.content,
          src.fileUrl
            ? {
                fileUrl: src.fileUrl,
                fileName: src.fileName ?? undefined,
                fileSize: src.fileSize ?? undefined,
                fileType: src.fileType ?? undefined,
                s3Key: src.s3Key ?? undefined,
                thumbnailSmallUrl: src.thumbnailSmallUrl ?? undefined,
                thumbnailMediumUrl: src.thumbnailMediumUrl ?? undefined,
                thumbnailLargeUrl: src.thumbnailLargeUrl ?? undefined,
              }
            : undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          // Цепочка не растёт: пересылка пересылки сохраняет исходного автора,
          // а не того, через кого сообщение прошло по дороге.
          src.forwardedFromUserId
            ? {
                forwardedFromUserId: src.forwardedFromUserId,
                forwardedFromName: src.forwardedFromName,
                forwardedFromMessageId: src.forwardedFromMessageId,
              }
            : {
                forwardedFromUserId: src.senderId,
                forwardedFromName: displayNameOf(src.sender),
                forwardedFromMessageId: src.id,
              },
        ),
      );
    }
    return created;
  }

  async assertParticipant(conversationId: string, userId: string) {
    const p = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
    });
    if (!p) throw new ForbiddenException('Not a participant');
    return p;
  }

  async searchUsers(query: string, currentUserId: string) {
    const isPhone = /^\+?[\d\s\-()+]+$/.test(query.trim());
    const users = await this.prisma.user.findMany({
      where: {
        id: { not: currentUserId },
        deletedAt: null,
        ...(isPhone
          ? { phone: query.trim() }
          : {
              OR: [
                { username: { contains: query, mode: 'insensitive' } },
                { email: { contains: query, mode: 'insensitive' } },
                {
                  profile: {
                    firstName: { contains: query, mode: 'insensitive' },
                  },
                },
                {
                  profile: {
                    lastName: { contains: query, mode: 'insensitive' },
                  },
                },
              ],
            }),
      },
      select: {
        id: true,
        username: true,
        email: true,
        profile: {
          select: { firstName: true, lastName: true, avatarUrl: true },
        },
        kycRecord: { select: { status: true } },
      },
      take: 20,
    });
    return users.map((u) => ({
      id: u.id,
      username: u.username,
      email: u.email,
      firstName: u.profile?.firstName,
      lastName: u.profile?.lastName,
      avatarUrl: u.profile?.avatarUrl,
      kycStatus: u.kycRecord?.status ?? 'UNVERIFIED',
    }));
  }

  async getParticipants(conversationId: string) {
    return this.prisma.conversationParticipant.findMany({
      where: { conversationId },
    });
  }

  async getFcmToken(userId: string): Promise<string | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { fcmToken: true },
    });
    return user?.fcmToken ?? null;
  }

  async getVoipToken(userId: string): Promise<string | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { voipToken: true },
    });
    return user?.voipToken ?? null;
  }

  /**
   * Multi-device push: all distinct FCM tokens for a user's currently-active
   * sessions (one per logged-in device), so wake-pushes reach EVERY device, not
   * just the last one to register. Falls back to the legacy single User.fcmToken
   * when no session carries a token (transition + safety if the Session.fcmToken
   * column is absent on an un-migrated environment — the try/catch makes this a
   * no-op there instead of breaking the call path).
   */
  async getFcmTokens(userId: string): Promise<string[]> {
    const tokens = new Set<string>();
    try {
      const sessions = await this.prisma.session.findMany({
        where: {
          userId,
          isRevoked: false,
          expiresAt: { gt: new Date() },
          fcmToken: { not: null },
        },
        select: { fcmToken: true },
      });
      for (const s of sessions) if (s.fcmToken) tokens.add(s.fcmToken);
    } catch {
      /* Session.fcmToken column not present (pre-migration env) — fall back */
    }
    if (tokens.size === 0) {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { fcmToken: true },
      });
      if (user?.fcmToken) tokens.add(user.fcmToken);
    }
    return [...tokens];
  }

  /** Thin wrapper over getFcmTokens for clear-on-read fan-out (Task 5). */
  async getFcmTokensForUser(userId: string): Promise<string[]> {
    return this.getFcmTokens(userId); // all logged-in devices' tokens
  }

  /** Multi-device VoIP (iOS CallKit) tokens — same semantics as getFcmTokens. */
  async getVoipTokens(userId: string): Promise<string[]> {
    const tokens = new Set<string>();
    try {
      const sessions = await this.prisma.session.findMany({
        where: {
          userId,
          isRevoked: false,
          expiresAt: { gt: new Date() },
          voipToken: { not: null },
        },
        select: { voipToken: true },
      });
      for (const s of sessions) if (s.voipToken) tokens.add(s.voipToken);
    } catch {
      /* Session.voipToken column not present (pre-migration env) — fall back */
    }
    if (tokens.size === 0) {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { voipToken: true },
      });
      if (user?.voipToken) tokens.add(user.voipToken);
    }
    return [...tokens];
  }

  async getUserDisplayName(userId: string): Promise<string> {
    const info = await this.getUserCallInfo(userId);
    return info.name;
  }

  async getUserCallInfo(
    userId: string,
  ): Promise<{ name: string; avatarUrl: string | null }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        profile: {
          select: { firstName: true, lastName: true, avatarUrl: true },
        },
      },
    });
    if (!user) return { name: 'Пользователь', avatarUrl: null };
    const fullName = [
      (user as any).profile?.firstName,
      (user as any).profile?.lastName,
    ]
      .filter(Boolean)
      .join(' ')
      .trim();
    return {
      name: fullName || (user as any).username || 'Пользователь',
      avatarUrl: (user as any).profile?.avatarUrl ?? null,
    };
  }

  async editMessage(messageId: string, senderId: string, newContent: string) {
    const msg = await this.prisma.message.findUnique({
      where: { id: messageId },
    });
    if (!msg || msg.senderId !== senderId) throw new Error('Not allowed');
    return this.prisma.message.update({
      where: { id: messageId },
      data: { content: newContent, isEdited: true, editedAt: new Date() },
    });
  }

  async deleteMessage(
    messageId: string,
    requesterId: string,
    scope: 'self' | 'all',
  ) {
    const msg = await this.prisma.message.findUnique({
      where: { id: messageId },
    });
    if (!msg) throw new Error('Message not found');
    if (scope === 'all') {
      if (msg.senderId !== requesterId)
        throw new ForbiddenException('Only sender can delete for everyone');
      await this.prisma.message.update({
        where: { id: messageId },
        data: { deletedAt: new Date() },
      });

      // Handle FileRecord refCount decrement
      if ((msg as any).fileRecordId) {
        try {
          const fileRecord = await this.prisma.fileRecord.update({
            where: { id: (msg as any).fileRecordId },
            data: { refCount: { decrement: 1 } },
          });
          if (fileRecord.refCount <= 0) {
            // Delete all associated S3 objects
            try {
              await this.fileStorage.delete(fileRecord.s3Key);
              if (fileRecord.thumbnailSmall)
                await this.fileStorage.delete(fileRecord.thumbnailSmall);
              if (fileRecord.thumbnailMedium)
                await this.fileStorage.delete(fileRecord.thumbnailMedium);
              if (fileRecord.thumbnailLarge)
                await this.fileStorage.delete(fileRecord.thumbnailLarge);
            } catch (e) {
              this.logger.error(
                'Failed to delete S3 objects for FileRecord:',
                e,
              );
            }
            await this.prisma.fileRecord.delete({
              where: { id: fileRecord.id },
            });
          }
        } catch (e) {
          this.logger.error('Failed to update FileRecord refCount:', e);
        }
      }
    } else {
      await (this.prisma as any).messageHidden.upsert({
        where: { messageId_userId: { messageId, userId: requesterId } },
        create: { messageId, userId: requesterId },
        update: {},
      });
    }
    return { messageId, conversationId: msg.conversationId, scope };
  }

  async markDelivered(messageId: string): Promise<void> {
    await this.prisma.message.update({
      where: { id: messageId },
      data: { isDelivered: true },
    });
  }

  async markConversationRead(
    conversationId: string,
    userId: string,
  ): Promise<string[]> {
    const messages = await this.prisma.message.findMany({
      where: { conversationId, isRead: false, senderId: { not: userId } },
      select: { id: true },
    });
    const ids = messages.map((m: any) => m.id);
    if (ids.length === 0) return [];
    await this.prisma.message.updateMany({
      where: { id: { in: ids } },
      data: { isRead: true, isDelivered: true },
    });
    return ids;
  }

  async advanceReadHorizon(
    conversationId: string,
    userId: string,
    upToSentAt: Date | null,
    upToMessageId: string | null,
  ): Promise<{ lastReadAt: Date; lastReadMessageId: string | null } | null> {
    // Resolve "read to latest" for old clients (no horizon in payload).
    if (!upToSentAt) {
      const latest = await this.prisma.message.findFirst({
        where: { conversationId },
        orderBy: [{ sentAt: 'desc' }, { id: 'desc' }],
        select: { id: true, sentAt: true },
      });
      if (!latest) return null;
      upToSentAt = latest.sentAt;
      upToMessageId = latest.id;
    }
    const p = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
      select: { lastReadAt: true },
    });
    // Monotonic: only advance.
    if (p?.lastReadAt && p.lastReadAt.getTime() >= upToSentAt.getTime()) return null;
    await this.prisma.conversationParticipant.update({
      where: { conversationId_userId: { conversationId, userId } },
      data: { lastReadAt: upToSentAt, lastReadMessageId: upToMessageId },
    });
    return { lastReadAt: upToSentAt, lastReadMessageId: upToMessageId };
  }

  async getReadState(conversationId: string, userId: string) {
    await this.assertParticipant(conversationId, userId);
    return this.prisma.conversationParticipant.findMany({
      where: { conversationId },
      select: { userId: true, lastReadAt: true, lastReadMessageId: true },
    });
  }

  async unreadCountFor(conversationId: string, userId: string): Promise<number> {
    const p = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
      select: { lastReadAt: true },
    });
    return this.prisma.message.count({
      where: {
        conversationId,
        senderId: { not: userId },
        // Horizon once a read cursor exists; else legacy isRead fallback
        // (matches getConversations so the list badge and read-state agree).
        ...(p?.lastReadAt ? { sentAt: { gt: p.lastReadAt } } : { isRead: false }),
      },
    });
  }

  async readStateForUser(userId: string) {
    const parts = await this.prisma.conversationParticipant.findMany({
      where: { userId },
      select: { conversationId: true, lastReadAt: true },
    });
    const out = [];
    for (const p of parts) {
      out.push({
        conversationId: p.conversationId,
        myLastReadAt: p.lastReadAt ? p.lastReadAt.toISOString() : null,
        unread: await this.unreadCountFor(p.conversationId, userId),
      });
    }
    return { conversations: out };
  }

  // ─── Helpers ───

  private async _getConversationOrThrow(conversationId: string) {
    const conv = await this.prisma.conversation.findUnique({
      where: { id: conversationId },
    });
    if (!conv) throw new NotFoundException('Conversation not found');
    return conv;
  }

  /** Кто может закреплять: в канале и группе — только OWNER/ADMIN,
   *  в остальных типах бесед (DIRECT, SAVED, AI_*) — любой участник. */
  private async _assertCanPin(
    conv: { id: string; type: string },
    userId: string,
  ) {
    const me = await this.assertParticipant(conv.id, userId);
    if (
      (conv.type === 'CHANNEL' || conv.type === 'GROUP') &&
      me.role !== 'OWNER' &&
      me.role !== 'ADMIN'
    ) {
      throw new ForbiddenException('Only admins can pin in this conversation');
    }
    return me;
  }

  private _pinnedCount(conversationId: string): Promise<number> {
    return this.prisma.message.count({
      where: { conversationId, pinnedAt: { not: null }, deletedAt: null },
    });
  }

  private async _createSystemMessage(
    conversationId: string,
    actorId: string,
    action: string,
    targetUserId?: string,
    extra?: string,
  ) {
    const actorName = await this.getUserDisplayName(actorId);
    const targetName = targetUserId
      ? await this.getUserDisplayName(targetUserId)
      : null;
    let content: string;
    switch (action) {
      case 'group_created':
        content = JSON.stringify({ action, actor: actorName });
        break;
      case 'member_added':
        content = JSON.stringify({
          action,
          actor: actorName,
          target: targetName,
        });
        break;
      case 'member_removed':
        content = JSON.stringify({
          action,
          actor: actorName,
          target: targetName,
        });
        break;
      case 'member_left':
        content = JSON.stringify({ action, actor: actorName });
        break;
      case 'role_changed':
        content = JSON.stringify({
          action,
          actor: actorName,
          target: targetName,
          role: extra,
        });
        break;
      case 'message_pinned':
        content = JSON.stringify({
          action,
          actor: actorName,
          preview: extra ?? '',
        });
        break;
      default:
        content = JSON.stringify({ action, actor: actorName });
    }
    return this.prisma.message.create({
      data: { conversationId, senderId: actorId, content, isSystem: true },
    });
  }

  async muteConversation(
    conversationId: string,
    userId: string,
    durationMinutes?: number,
  ) {
    await this.assertParticipant(conversationId, userId);
    const mutedUntil = durationMinutes
      ? new Date(Date.now() + durationMinutes * 60 * 1000)
      : null;
    await this.prisma.conversationParticipant.update({
      where: { conversationId_userId: { conversationId, userId } },
      data: { isMuted: true, mutedUntil },
    });
    return { isMuted: true, mutedUntil };
  }

  async unmuteConversation(conversationId: string, userId: string) {
    await this.assertParticipant(conversationId, userId);
    await this.prisma.conversationParticipant.update({
      where: { conversationId_userId: { conversationId, userId } },
      data: { isMuted: false, mutedUntil: null },
    });
    return { isMuted: false, mutedUntil: null };
  }

  async getActiveCallForConversation(
    conversationId: string,
  ): Promise<string | null> {
    const log = await this.prisma.callLog.findFirst({
      where: { conversationId, endedAt: null },
      select: { roomName: true },
    });
    return log?.roomName ?? null;
  }

  // ─── Saved Messages ───

  async getOrCreateSavedChat(userId: string): Promise<string> {
    const existing = await this.prisma.conversation.findFirst({
      where: { type: 'SAVED', participants: { some: { userId } } },
    });
    if (existing) return existing.id;
    const conv = await this.prisma.conversation.create({
      data: {
        type: 'SAVED',
        name: 'Избранное',
        createdById: userId,
        participants: { create: { userId, role: 'OWNER' } },
      },
    });
    return conv.id;
  }
  // ─── AI Analyst ───

  async getOrCreateAiAnalystChat(userId: string): Promise<string> {
    const existing = await this.prisma.conversation.findFirst({
      where: { type: 'AI_ANALYST', participants: { some: { userId } } },
    });
    if (existing) return existing.id;
    const conv = await this.prisma.conversation.create({
      data: {
        type: 'AI_ANALYST',
        name: 'AI Аналитик',
        createdById: userId,
        participants: { create: { userId, role: 'OWNER' } },
      },
    });
    return conv.id;
  }

  // ─── Channels ───

  async createChannel(
    creatorId: string,
    name: string,
    description?: string,
    avatarUrl?: string,
  ) {
    const conv = await this.prisma.conversation.create({
      data: {
        type: 'CHANNEL',
        name,
        description,
        avatarUrl,
        createdById: creatorId,
        participants: {
          create: { userId: creatorId, role: 'OWNER' },
        },
      },
    });
    return conv;
  }

  async subscribeToChannel(channelId: string, userId: string) {
    const conv = await this._getConversationOrThrow(channelId);
    if (conv.type !== 'CHANNEL') throw new BadRequestException('Not a channel');
    const existing = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId: channelId, userId } },
    });
    if (existing) return { ok: true, alreadySubscribed: true };
    await this.prisma.conversationParticipant.create({
      data: { conversationId: channelId, userId, role: 'SUBSCRIBER' },
    });
    return { ok: true, alreadySubscribed: false };
  }

  async unsubscribeFromChannel(channelId: string, userId: string) {
    const conv = await this._getConversationOrThrow(channelId);
    if (conv.type !== 'CHANNEL') throw new BadRequestException('Not a channel');
    if ((conv as any).isSystem) {
      throw new ForbiddenException('Нельзя отписаться от системного канала');
    }
    const existing = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId: channelId, userId } },
    });
    if (!existing) throw new BadRequestException('Not subscribed');
    if (existing.role === 'OWNER') {
      throw new BadRequestException(
        'Owner cannot unsubscribe, delete channel instead',
      );
    }
    await this.prisma.conversationParticipant.delete({
      where: { conversationId_userId: { conversationId: channelId, userId } },
    });
    return { ok: true };
  }

  async assertCanPostInChannel(conversationId: string, userId: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'CHANNEL') return; // not a channel, anyone can post
    const participant = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
    });
    if (
      !participant ||
      (participant.role !== 'OWNER' && participant.role !== 'ADMIN')
    ) {
      throw new ForbiddenException('Only admins can post in channels');
    }
  }

  async listChannels(userId: string, q?: string, limit = 20, offset = 0) {
    const take = Math.min(Math.max(limit, 1), 50);
    const where: any = { type: 'CHANNEL' };
    if (q && q.trim().length > 0) {
      where.name = { contains: q.trim(), mode: 'insensitive' };
    }
    const rows = await this.prisma.conversation.findMany({
      where,
      include: {
        participants: { select: { userId: true } },
        _count: { select: { participants: true } },
      },
      orderBy: [{ updatedAt: 'desc' }],
      take,
      skip: offset,
    });
    return rows
      .map((r) => ({
        id: r.id,
        name: r.name,
        description: r.description,
        avatarUrl: r.avatarUrl,
        subscribersCount: r._count.participants,
        isSubscribed: r.participants.some((p) => p.userId === userId),
      }))
      .sort((a, b) => b.subscribersCount - a.subscribersCount);
  }

  async getChannelDetails(channelId: string, userId: string) {
    const conv = await this.prisma.conversation.findUnique({
      where: { id: channelId },
      include: {
        participants: true,
        _count: { select: { participants: true } },
      },
    });
    if (!conv) throw new NotFoundException('Channel not found');
    if (conv.type !== 'CHANNEL') throw new BadRequestException('Not a channel');
    const me = conv.participants.find((p) => p.userId === userId);
    return {
      id: conv.id,
      name: conv.name,
      description: conv.description,
      avatarUrl: conv.avatarUrl,
      subscribersCount: conv._count.participants,
      isSubscribed: !!me,
      myRole: me ? me.role : null,
    };
  }

  async updateChannel(
    channelId: string,
    userId: string,
    patch: { name?: string; description?: string; avatarUrl?: string },
  ) {
    const conv = await this._getConversationOrThrow(channelId);
    if (conv.type !== 'CHANNEL') throw new BadRequestException('Not a channel');
    const me = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId: channelId, userId } },
    });
    if (!me || (me.role !== 'OWNER' && me.role !== 'ADMIN')) {
      throw new ForbiddenException('Only channel admins can edit');
    }
    const data: any = {};
    if (patch.name !== undefined) data.name = patch.name;
    if (patch.description !== undefined) data.description = patch.description;
    if (patch.avatarUrl !== undefined) data.avatarUrl = patch.avatarUrl;
    await this.prisma.conversation.update({ where: { id: channelId }, data });
    return this.getChannelDetails(channelId, userId);
  }

  async deleteChannel(channelId: string, userId: string) {
    const conv = await this._getConversationOrThrow(channelId);
    if (conv.type !== 'CHANNEL') throw new BadRequestException('Not a channel');
    const me = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId: channelId, userId } },
    });
    if (!me || me.role !== 'OWNER') {
      throw new ForbiddenException('Only the owner can delete the channel');
    }
    await this.prisma.conversation.delete({ where: { id: channelId } });
    return { ok: true };
  }

  async postToChannel(channelId: string, userId: string, content: string) {
    await this.assertCanPostInChannel(channelId, userId);
    if (!content || content.trim().length === 0) {
      throw new BadRequestException('Content is empty');
    }
    if (content.length > 4000) {
      throw new BadRequestException('Content exceeds 4000 characters');
    }
    const msg = await this.createMessage(channelId, userId, content);
    return { messageId: msg.id, createdAt: msg.sentAt };
  }

  async getMessageById(messageId: string) {
    return this.prisma.message.findUnique({ where: { id: messageId } });
  }

  // ─── Pinned messages ───

  /** Закрепить сообщение. opts.silent — не создавать сервисное сообщение
   *  (используется админским постом с pin: true, чтобы не слать второй push). */
  async pinMessage(
    conversationId: string,
    messageId: string,
    userId: string,
    opts: { silent?: boolean } = {},
  ) {
    const conv = await this._getConversationOrThrow(conversationId);
    await this._assertCanPin(conv, userId);

    const msg = await this.prisma.message.findUnique({
      where: { id: messageId },
    });
    if (!msg || msg.conversationId !== conversationId || msg.deletedAt) {
      throw new NotFoundException('Message not found');
    }
    if (msg.isSystem) {
      throw new BadRequestException('System messages cannot be pinned');
    }
    if (msg.pinnedAt) {
      return {
        pinnedAt: msg.pinnedAt,
        pinnedCount: await this._pinnedCount(conversationId),
        alreadyPinned: true,
        systemMessageId: null,
      };
    }

    const pinnedAt = new Date();
    const claimed = await this.prisma.message.updateMany({
      where: { id: messageId, conversationId, pinnedAt: null },
      data: { pinnedAt, pinnedById: userId },
    });
    if (claimed.count === 0) {
      // Проиграли гонку: кто-то закрепил это же сообщение в тот же момент.
      // Ведём себя как при повторном пине — второго сервисного сообщения
      // (а значит и второго пуша) быть не должно.
      const current = await this.prisma.message.findUnique({
        where: { id: messageId },
      });
      return {
        pinnedAt: current?.pinnedAt ?? null,
        pinnedCount: await this._pinnedCount(conversationId),
        alreadyPinned: true,
        systemMessageId: null,
      };
    }

    let systemMessageId: string | null = null;
    if (!opts.silent) {
      const preview = (msg.content ?? '').slice(0, 80);
      const sys = await this._createSystemMessage(
        conversationId,
        userId,
        'message_pinned',
        undefined,
        preview,
      );
      systemMessageId = sys.id;
    }

    return {
      pinnedAt,
      pinnedCount: await this._pinnedCount(conversationId),
      alreadyPinned: false,
      systemMessageId,
    };
  }

  async unpinMessage(
    conversationId: string,
    messageId: string,
    userId: string,
  ) {
    const conv = await this._getConversationOrThrow(conversationId);
    await this._assertCanPin(conv, userId);
    // pinnedAt: { not: null } — иначе updateMany засчитывает строку как
    // обновлённую и при записи null поверх null, и wasPinned всегда true даже
    // на повторном откреплении. Контроллер по этому флагу решает, слать ли
    // message_unpinned, так что без условия он рассылал бы пустые события.
    // Поймано e2e-набором на DEV; юнит-тест не ловил — там updateMany замокан.
    const result = await this.prisma.message.updateMany({
      where: { id: messageId, conversationId, pinnedAt: { not: null } },
      data: { pinnedAt: null, pinnedById: null },
    });
    return {
      pinnedCount: await this._pinnedCount(conversationId),
      wasPinned: result.count > 0,
    };
  }

  async listPinned(
    conversationId: string,
    userId: string,
    limit = 50,
    offset = 0,
  ) {
    await this.assertParticipant(conversationId, userId);
    const take = Number.isFinite(limit)
      ? Math.min(Math.max(Math.trunc(limit), 1), 100)
      : 50;
    const skip = Number.isFinite(offset) && offset > 0 ? Math.trunc(offset) : 0;
    const where = {
      conversationId,
      pinnedAt: { not: null },
      // deleteMessage не снимает pinnedAt — иначе удалённое сообщение
      // осталось бы висеть в закреплённых.
      deletedAt: null,
      // hiddenFor — «удалить у себя»; такой пин не должен ни попадать в
      // выдачу, ни считаться в total, иначе счётчик «N из M» врёт навсегда.
      NOT: { hiddenFor: { some: { userId } } },
    };
    const rows = await this.prisma.message.findMany({
      where,
      include: {
        sender: {
          select: {
            username: true,
            profile: { select: { firstName: true, lastName: true } },
          },
        },
      },
      orderBy: [{ pinnedAt: 'desc' }, { id: 'desc' }],
      take,
      skip,
    });
    const messages = rows.map((m: any) => {
      const u = m.sender;
      const firstLast = u
        ? [u.profile?.firstName, u.profile?.lastName]
            .filter(Boolean)
            .join(' ')
            .trim() || null
        : null;
      const { sender, ...rest } = m;
      return { ...rest, senderName: firstLast ?? u?.username ?? null };
    });
    const total = await this.prisma.message.count({ where });
    return { messages, total };
  }

  async unpinAll(conversationId: string, userId: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    await this._assertCanPin(conv, userId);
    const res = await this.prisma.message.updateMany({
      where: { conversationId, pinnedAt: { not: null } },
      data: { pinnedAt: null, pinnedById: null },
    });
    return { unpinned: res.count };
  }

  /** Спрятать плашку закреплённых лично для себя. Плашка вернётся,
   *  когда появится пин с pinnedAt позже этой отметки.
   *
   *  upTo — pinnedAt верхнего пина, который клиент реально видел. Без него
   *  берём максимальный pinnedAt беседы: сегодняшнее «сейчас» скрыло бы и
   *  пин, прилетевший, пока запрос шёл до сервера. Тот же приём, что в
   *  advanceReadHorizon. */
  async dismissPins(conversationId: string, userId: string, upTo?: Date) {
    await this.assertParticipant(conversationId, userId);
    const now = new Date();
    // Курсор от клиента не доверенный: битую дату игнорируем (упадёт в
    // фолбэк), будущую подрезаем до «сейчас». Иначе разъехавшиеся часы на
    // клиенте скрыли бы плашку навсегда — вместе с ещё не созданными пинами.
    let pinsDismissedAt =
      upTo && !Number.isNaN(upTo.getTime())
        ? upTo > now
          ? now
          : upTo
        : undefined;
    if (!pinsDismissedAt) {
      const newest = await this.prisma.message.aggregate({
        where: { conversationId, pinnedAt: { not: null }, deletedAt: null },
        _max: { pinnedAt: true },
      });
      pinsDismissedAt = newest._max.pinnedAt ?? now;
    }
    await this.prisma.conversationParticipant.update({
      where: { conversationId_userId: { conversationId, userId } },
      data: { pinsDismissedAt },
    });
    return { pinsDismissedAt };
  }

  // ─── Polls ───

  async createPoll(
    conversationId: string,
    senderId: string,
    question: string,
    options: string[],
    isAnonymous = false,
    isMultiple = false,
  ) {
    await this.assertParticipant(conversationId, senderId);
    if (options.length < 2 || options.length > 10)
      throw new BadRequestException('2-10 options required');

    const msg = await this.prisma.message.create({
      data: {
        conversationId,
        senderId,
        content: '[POLL]' + JSON.stringify({ question }),
        fileType: 'poll',
      },
    });

    const poll = await this.prisma.poll.create({
      data: {
        messageId: msg.id,
        question,
        isAnonymous,
        isMultiple,
        options: {
          create: options.map((text, i) => ({ text, position: i })),
        },
      },
      include: { options: { include: { votes: true } } },
    });

    return { message: msg, poll };
  }

  async votePoll(optionId: string, userId: string) {
    const option = await this.prisma.pollOption.findUnique({
      where: { id: optionId },
      include: { poll: { include: { message: { select: { conversationId: true } } } } },
    });
    if (!option) throw new NotFoundException('Option not found');
    // Voting in a poll you cannot see also outs you as a voter to that chat.
    await this.assertParticipant(option.poll.message.conversationId, userId);

    // Check if already voted on this option
    const existing = await this.prisma.pollVote.findUnique({
      where: { optionId_userId: { optionId, userId } },
    });

    if (existing) {
      // Unvote
      await this.prisma.pollVote.delete({ where: { id: existing.id } });
    } else {
      // If not multiple choice, remove previous votes on other options
      if (!option.poll.isMultiple) {
        const allOptions = await this.prisma.pollOption.findMany({
          where: { pollId: option.pollId },
        });
        await this.prisma.pollVote.deleteMany({
          where: { optionId: { in: allOptions.map((o) => o.id) }, userId },
        });
      }
      await this.prisma.pollVote.create({ data: { optionId, userId } });
    }

    return this.getPollData(option.pollId);
  }

  async getPollData(pollId: string) {
    return this.prisma.poll.findUnique({
      where: { id: pollId },
      include: {
        options: {
          include: { votes: { select: { userId: true } } },
          orderBy: { position: 'asc' },
        },
      },
    });
  }

  async getPollByMessageId(messageId: string, userId: string) {
    // Poll results carry per-option voter ids, so an unchecked read both leaks
    // the question and de-anonymises who voted for what.
    const message = await this.prisma.message.findUnique({
      where: { id: messageId },
      select: { conversationId: true },
    });
    if (!message) throw new NotFoundException('Message not found');
    await this.assertParticipant(message.conversationId, userId);

    return this.prisma.poll.findUnique({
      where: { messageId },
      include: {
        options: {
          include: { votes: { select: { userId: true } } },
          orderBy: { position: 'asc' },
        },
      },
    });
  }
  // ─── Threads ───

  async getThreadReplies(messageId: string, userId: string) {
    // Resolve the conversation from the message itself rather than trusting the
    // convId in the URL — otherwise the check is satisfied by naming a
    // conversation the caller does belong to while reading someone else's thread.
    const parent = await this.prisma.message.findUnique({
      where: { id: messageId },
      select: { conversationId: true },
    });
    if (!parent) throw new NotFoundException('Message not found');
    await this.assertParticipant(parent.conversationId, userId);

    return this.prisma.message.findMany({
      where: { threadParentId: messageId, deletedAt: null },
      orderBy: { sentAt: 'asc' },
      include: {
        sender: {
          select: {
            id: true,
            username: true,
            profile: {
              select: { firstName: true, lastName: true, avatarUrl: true },
            },
          },
        },
      },
    });
  }

  async getThreadCount(messageId: string): Promise<number> {
    return this.prisma.message.count({
      where: { threadParentId: messageId, deletedAt: null },
    });
  }

  async sendThreadReply(
    conversationId: string,
    senderId: string,
    content: string,
    threadParentId: string,
    fileData?: any,
  ) {
    // Does not go through createMessage, so it needs its own check: matching
    // the parent's conversationId only proves the thread is consistent, not
    // that the sender may write to it.
    await this.assertParticipant(conversationId, senderId);

    const parent = await this.prisma.message.findUnique({
      where: { id: threadParentId },
    });
    if (!parent) throw new NotFoundException('Parent message not found');
    if (parent.conversationId !== conversationId)
      throw new BadRequestException('Message not in this conversation');
    const msg = await this.prisma.message.create({
      data: {
        conversationId,
        senderId,
        content,
        threadParentId,
        fileUrl: fileData?.fileUrl,
        fileName: fileData?.fileName,
        fileSize: fileData?.fileSize,
        fileType: fileData?.fileType,
      },
    });
    return msg;
  }
  // ─── Topics ───

  async getTopics(conversationId: string, userId: string) {
    // Topics come back enriched with the text of each topic's latest message.
    await this.assertParticipant(conversationId, userId);

    const topics = await this.prisma.topic.findMany({
      where: { conversationId },
      orderBy: { createdAt: 'asc' },
    });
    const enriched = await Promise.all(
      topics.map(async (topic) => {
        const lastMsg = await this.prisma.message.findFirst({
          where: { topicId: topic.id, deletedAt: null },
          orderBy: { sentAt: 'desc' },
          include: {
            sender: {
              select: {
                username: true,
                profile: { select: { firstName: true, lastName: true } },
              },
            },
          },
        });
        let lastMessageContent: string | null = null;
        if (lastMsg) {
          if (lastMsg.fileType === 'image') lastMessageContent = '🖼 Фото';
          else if (lastMsg.fileType === 'video')
            lastMessageContent = '🎥 Видео';
          else if (lastMsg.fileType === 'audio')
            lastMessageContent = '🎵 Голосовое';
          else if (lastMsg.fileType === 'video_note')
            lastMessageContent = '📹 Видеосообщение';
          else lastMessageContent = lastMsg.content;
        }
        const senderProfile = (lastMsg as any)?.sender?.profile;
        const senderName = senderProfile
          ? [senderProfile.firstName, senderProfile.lastName]
              .filter(Boolean)
              .join(' ')
              .trim() || (lastMsg as any)?.sender?.username
          : ((lastMsg as any)?.sender?.username ?? null);
        return {
          ...topic,
          lastMessageContent,
          lastMessageAt: lastMsg?.sentAt ?? null,
          lastMessageSenderId: lastMsg?.senderId ?? null,
          lastMessageSenderName: senderName ?? null,
          lastMessageIsDelivered: lastMsg?.isDelivered ?? false,
          lastMessageIsRead: lastMsg?.isRead ?? false,
        };
      }),
    );
    return enriched;
  }

  async createTopic(
    conversationId: string,
    userId: string,
    title: string,
    icon?: string,
  ) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP')
      throw new BadRequestException('Topics only for groups');
    // Being a group was the only requirement here, so anyone could add topics
    // to a group they are not in. deleteTopic already goes through
    // assertGroupRole; creation was the gap.
    await this.assertParticipant(conversationId, userId);

    return this.prisma.topic.create({
      data: { conversationId, title, icon: icon || '💬', createdBy: userId },
    });
  }

  async deleteTopic(topicId: string, userId: string) {
    const topic = await this.prisma.topic.findUnique({
      where: { id: topicId },
    });
    if (!topic) throw new NotFoundException('Topic not found');
    await this.assertGroupRole(topic.conversationId, userId, [
      'OWNER',
      'ADMIN',
    ]);
    await this.prisma.topic.delete({ where: { id: topicId } });
  }
  async getConversationType(conversationId: string): Promise<string | null> {
    const conv = await this.prisma.conversation.findUnique({
      where: { id: conversationId },
      select: { type: true },
    });
    return conv?.type ?? null;
  }

  async isParticipantMuted(
    conversationId: string,
    userId: string,
  ): Promise<boolean> {
    const p = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
      select: { isMuted: true, mutedUntil: true },
    });
    if (!p || !p.isMuted) return false;
    if (p.mutedUntil && p.mutedUntil < new Date()) {
      await this.prisma.conversationParticipant.update({
        where: { conversationId_userId: { conversationId, userId } },
        data: { isMuted: false, mutedUntil: null },
      });
      return false;
    }
    return true;
  }

  // ─── Contact Requests ───

  async sendContactRequest(senderId: string, receiverId: string) {
    if (senderId === receiverId)
      throw new BadRequestException('Cannot send request to yourself');

    // Check if receiver has blocked sender
    const blocked = await this.prisma.blockedUser.findFirst({
      where: { blockerId: receiverId, blockedId: senderId },
    });
    if (blocked) throw new ForbiddenException('Не удалось отправить запрос');

    // Check if there's already an accepted contact or existing conversation
    const existing = await this.prisma.contactRequest.findUnique({
      where: { senderId_receiverId: { senderId, receiverId } },
    });
    if (existing?.status === 'ACCEPTED')
      throw new BadRequestException('Already contacts');
    if (existing?.status === 'PENDING') {
      // Check 24h cooldown for resending
      const hoursSince =
        (Date.now() - new Date(existing.updatedAt).getTime()) /
        (1000 * 60 * 60);
      if (hoursSince < 24) {
        throw new BadRequestException(
          'Повторный запрос можно отправить через ' +
            Math.ceil(24 - hoursSince) +
            ' ч.',
        );
      }
      // Allow resend — update timestamp
      const request = await this.prisma.contactRequest.update({
        where: { id: existing.id },
        data: { updatedAt: new Date() },
      });
      const sender = await this.prisma.user.findUnique({
        where: { id: senderId },
        include: {
          profile: {
            select: { firstName: true, lastName: true, avatarUrl: true },
          },
        },
      });
      const senderName =
        [sender?.profile?.firstName, sender?.profile?.lastName]
          .filter(Boolean)
          .join(' ') ||
        sender?.username ||
        '';
      return {
        ...request,
        senderName,
        senderAvatar: sender?.profile?.avatarUrl,
        senderUsername: sender?.username,
        resent: true,
      };
    }

    // Check reverse direction too
    const reverse = await this.prisma.contactRequest.findUnique({
      where: {
        senderId_receiverId: { senderId: receiverId, receiverId: senderId },
      },
    });
    if (reverse?.status === 'ACCEPTED')
      throw new BadRequestException('Already contacts');
    if (reverse?.status === 'PENDING') {
      // Auto-accept: they already want to talk to us
      return this.acceptContactRequest(reverse.id, senderId);
    }

    const request = await this.prisma.contactRequest.upsert({
      where: { senderId_receiverId: { senderId, receiverId } },
      create: { senderId, receiverId, status: 'PENDING' },
      update: { status: 'PENDING', updatedAt: new Date() },
    });

    // Get sender info for notification
    const sender = await this.prisma.user.findUnique({
      where: { id: senderId },
      include: {
        profile: {
          select: { firstName: true, lastName: true, avatarUrl: true },
        },
      },
    });
    const senderName =
      [sender?.profile?.firstName, sender?.profile?.lastName]
        .filter(Boolean)
        .join(' ') ||
      sender?.username ||
      '';

    return {
      ...request,
      senderName,
      senderAvatar: sender?.profile?.avatarUrl,
      senderUsername: sender?.username,
    };
  }

  async getContactRequests(userId: string) {
    const incoming = await this.prisma.contactRequest.findMany({
      where: { receiverId: userId, status: 'PENDING' },
      orderBy: { createdAt: 'desc' },
    });

    // Enrich with sender profiles
    const enriched = await Promise.all(
      incoming.map(async (r) => {
        const sender = await this.prisma.user.findUnique({
          where: { id: r.senderId },
          include: {
            profile: {
              select: { firstName: true, lastName: true, avatarUrl: true },
            },
          },
        });
        return {
          ...r,
          senderName:
            [sender?.profile?.firstName, sender?.profile?.lastName]
              .filter(Boolean)
              .join(' ') ||
            sender?.username ||
            '',
          senderAvatar: sender?.profile?.avatarUrl,
          senderUsername: sender?.username,
          senderEmail: sender?.email,
        };
      }),
    );
    return enriched;
  }

  async getSentContactRequests(userId: string) {
    const sent = await this.prisma.contactRequest.findMany({
      where: { senderId: userId },
      orderBy: { createdAt: 'desc' },
    });

    // Enrich with receiver profiles
    const enriched = await Promise.all(
      sent.map(async (r) => {
        const receiver = await this.prisma.user.findUnique({
          where: { id: r.receiverId },
          include: {
            profile: {
              select: { firstName: true, lastName: true, avatarUrl: true },
            },
          },
        });
        return {
          ...r,
          receiverName:
            [receiver?.profile?.firstName, receiver?.profile?.lastName]
              .filter(Boolean)
              .join(' ') ||
            receiver?.username ||
            '',
          receiverAvatar: receiver?.profile?.avatarUrl,
          receiverUsername: receiver?.username,
          receiverEmail: receiver?.email,
        };
      }),
    );
    return enriched;
  }

  async acceptContactRequest(requestId: string, userId: string) {
    const request = await this.prisma.contactRequest.findUnique({
      where: { id: requestId },
    });
    if (!request) throw new NotFoundException('Request not found');
    if (request.receiverId !== userId && request.senderId !== userId) {
      throw new ForbiddenException('Not your request');
    }
    if (request.status !== 'PENDING')
      throw new BadRequestException('Request already processed');

    await this.prisma.contactRequest.update({
      where: { id: requestId },
      data: { status: 'ACCEPTED' },
    });

    // Create direct conversation
    const conv = await this.getOrCreateDirectConversation(
      request.senderId,
      request.receiverId,
    );

    return {
      senderId: request.senderId,
      receiverId: request.receiverId,
      conversationId: conv.id,
    };
  }

  async rejectContactRequest(requestId: string, userId: string) {
    const request = await this.prisma.contactRequest.findUnique({
      where: { id: requestId },
    });
    if (!request) throw new NotFoundException('Request not found');
    if (request.receiverId !== userId)
      throw new ForbiddenException('Not your request');

    return this.prisma.contactRequest.update({
      where: { id: requestId },
      data: { status: 'REJECTED' },
    });
  }

  async hasContactWith(userA: string, userB: string): Promise<boolean> {
    const contact = await this.prisma.contactRequest.findFirst({
      where: {
        status: 'ACCEPTED',
        OR: [
          { senderId: userA, receiverId: userB },
          { senderId: userB, receiverId: userA },
        ],
      },
    });
    return !!contact;
  }

  async listContacts(userId: string) {
    const requests = await this.prisma.contactRequest.findMany({
      where: {
        status: 'ACCEPTED',
        OR: [{ senderId: userId }, { receiverId: userId }],
      },
      select: { senderId: true, receiverId: true },
    });
    const ids = requests.map((r) =>
      r.senderId === userId ? r.receiverId : r.senderId,
    );
    if (ids.length === 0) return [];
    return this.prisma.user.findMany({
      where: { id: { in: ids } },
      select: {
        id: true,
        username: true,
        profile: { select: { firstName: true, lastName: true } },
      },
    });
  }

  async getContactStatus(
    myId: string,
    targetIdOrUsername: string,
  ): Promise<{
    isContact: boolean;
    pendingRequest: 'sent' | 'received' | null;
    requestId: string | null;
    isBlocked: boolean;
    iBlockedThem: boolean;
  }> {
    // Accept either a userId (UUID) or a username — share-link deep-link
    // (https://id.taler.tirol/u/<username>) hits this endpoint with username.
    const targetId = await resolveUserIdOrUsername(this.prisma, targetIdOrUsername);
    if (!targetId) {
      return {
        isContact: false,
        pendingRequest: null,
        requestId: null,
        isBlocked: false,
        iBlockedThem: false,
      };
    }
    const [req, block, iBlock] = await Promise.all([
      this.prisma.contactRequest.findFirst({
        where: {
          OR: [
            { senderId: myId, receiverId: targetId },
            { senderId: targetId, receiverId: myId },
          ],
        },
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.blockedUser.findFirst({
        where: { blockerId: targetId, blockedId: myId },
      }),
      this.prisma.blockedUser.findFirst({
        where: { blockerId: myId, blockedId: targetId },
      }),
    ]);
    const isBlocked = !!block;
    const iBlockedThem = !!iBlock;
    if (!req)
      return {
        isContact: false,
        pendingRequest: null,
        requestId: null,
        isBlocked,
        iBlockedThem,
      };
    if (req.status === 'ACCEPTED')
      return {
        isContact: true,
        pendingRequest: null,
        requestId: null,
        isBlocked,
        iBlockedThem,
      };
    if (req.status === 'PENDING') {
      const dir: 'sent' | 'received' =
        req.senderId === myId ? 'sent' : 'received';
      return {
        isContact: false,
        pendingRequest: dir,
        requestId: req.id,
        isBlocked,
        iBlockedThem,
      };
    }
    return {
      isContact: false,
      pendingRequest: null,
      requestId: null,
      isBlocked,
      iBlockedThem,
    };
  }

  // ─── Reactions ───

  async toggleReaction(messageId: string, userId: string, emoji: string) {
    const msg = await this.prisma.message.findUnique({
      where: { id: messageId },
    });
    if (!msg) throw new Error('Message not found');
    await this.assertParticipant(msg.conversationId, userId);

    const existing = await (this.prisma as any).messageReaction.findUnique({
      where: { messageId_userId: { messageId, userId } },
    });

    if (existing && existing.emoji === emoji) {
      // Same emoji — remove reaction
      await (this.prisma as any).messageReaction.delete({
        where: { id: existing.id },
      });
    } else if (existing) {
      // Different emoji — update
      await (this.prisma as any).messageReaction.update({
        where: { id: existing.id },
        data: { emoji },
      });
    } else {
      // New reaction
      await (this.prisma as any).messageReaction.create({
        data: { messageId, userId, emoji },
      });
    }

    // Return current reactions for this message
    return this.getMessageReactions(messageId);
  }

  async getMessageReactions(messageId: string) {
    const reactions = await (this.prisma as any).messageReaction.findMany({
      where: { messageId },
      select: { userId: true, emoji: true },
    });
    return reactions;
  }

  // ─── Message search ───

  async searchMessages(query: string, userId: string) {
    if (!query || query.length < 2) return [];
    const conversations = await this.prisma.conversation.findMany({
      where: { participants: { some: { userId } } },
      select: { id: true },
    });
    const convIds = conversations.map((c) => c.id);
    const messages = await this.prisma.message.findMany({
      where: {
        conversationId: { in: convIds },
        content: { contains: query, mode: 'insensitive' },
        deletedAt: null,
      },
      orderBy: { sentAt: 'desc' },
      take: 50,
      select: {
        id: true,
        content: true,
        sentAt: true,
        conversationId: true,
        senderId: true,
      },
    });
    // Enrich with sender names and conversation info
    const userIds = [...new Set(messages.map((m) => m.senderId))];
    const users = await this.prisma.user.findMany({
      where: { id: { in: userIds } },
      select: {
        id: true,
        username: true,
        profile: { select: { firstName: true, lastName: true } },
      },
    });
    const userMap: Record<string, string> = {};
    for (const u of users) {
      userMap[u.id] =
        [u.profile?.firstName, u.profile?.lastName].filter(Boolean).join(' ') ||
        u.username ||
        '';
    }
    return messages.map((m) => ({
      ...m,
      senderName: userMap[m.senderId] || '',
    }));
  }
  // ─── Contact Aliases ───

  async getContactAliases(ownerId: string) {
    return this.prisma.contactAlias.findMany({ where: { ownerId } });
  }

  async setContactAlias(ownerId: string, targetId: string, customName: string) {
    return this.prisma.contactAlias.upsert({
      where: { ownerId_targetId: { ownerId, targetId } },
      create: { ownerId, targetId, customName },
      update: { customName },
    });
  }

  async removeContactAlias(ownerId: string, targetId: string) {
    try {
      await this.prisma.contactAlias.delete({
        where: { ownerId_targetId: { ownerId, targetId } },
      });
    } catch (_) {}
    return { ok: true };
  }

  async deleteContact(myId: string, targetId: string) {
    await this.prisma.contactRequest.deleteMany({
      where: {
        OR: [
          { senderId: myId, receiverId: targetId },
          { senderId: targetId, receiverId: myId },
        ],
      },
    });
    return { ok: true };
  }

  async blockUser(myId: string, targetId: string) {
    // Delete contact relationship first
    await this.deleteContact(myId, targetId);
    // Create block record
    try {
      await this.prisma.blockedUser.create({
        data: { blockerId: myId, blockedId: targetId },
      });
    } catch (_) {}
    return { ok: true };
  }

  async unblockUser(myId: string, targetId: string) {
    await this.prisma.blockedUser.deleteMany({
      where: { blockerId: myId, blockedId: targetId },
    });
    // Restore contact relationship so they don't need to re-add each other
    const existing = await this.prisma.contactRequest.findFirst({
      where: {
        OR: [
          { senderId: myId, receiverId: targetId },
          { senderId: targetId, receiverId: myId },
        ],
      },
    });
    if (!existing) {
      await this.prisma.contactRequest.create({
        data: { senderId: myId, receiverId: targetId, status: 'ACCEPTED' },
      });
    } else if (existing.status !== 'ACCEPTED') {
      await this.prisma.contactRequest.update({
        where: { id: existing.id },
        data: { status: 'ACCEPTED' },
      });
    }
    return { ok: true };
  }

  async isBlockedBy(myId: string, targetId: string): Promise<boolean> {
    const block = await this.prisma.blockedUser.findFirst({
      where: {
        OR: [
          { blockerId: myId, blockedId: targetId },
          { blockerId: targetId, blockedId: myId },
        ],
      },
    });
    return !!block;
  }

  /** Find a Message row by the S3 key stored in its fileUrl query parameter. */
  async findMessageByFileKey(key: string) {
    // The fileUrl looks like .../download?key=<encoded-key>
    return this.prisma.message.findFirst({
      where: {
        OR: [
          { s3Key: key },
          { fileUrl: { contains: encodeURIComponent(key) } },
        ],
      },
      select: { fileType: true },
    });
  }
}
