import { Injectable, ForbiddenException, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { FileStorageService } from '../common/file-storage.service';

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
        include: { participants: true, messages: { orderBy: { sentAt: 'desc' }, take: 1 } },
      });
      if (existing) return this._formatConversation(existing, userAId);
      const conv = await tx.conversation.create({
        data: {
          type: 'DIRECT',
          participants: { create: [{ userId: userAId }, { userId: userBId }] },
        },
        include: { participants: true, messages: true },
      });
      return this._formatConversation(conv, userAId);
    });
  }

  // ─── GROUP conversations (new) ───

  async createGroupConversation(creatorId: string, name: string, participantIds: string[]) {
    if (!name || name.trim().length === 0) throw new BadRequestException('Group name is required');
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
    return this._formatConversation(conv, creatorId);
  }

  async assertGroupRole(conversationId: string, userId: string, roles: string[]) {
    const p = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
    });
    if (!p) throw new ForbiddenException('Not a participant');
    if (!roles.includes(p.role)) throw new ForbiddenException('Insufficient role');
    return p;
  }

  async addGroupMembers(conversationId: string, requesterId: string, userIds: string[]) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP') throw new BadRequestException('Not a group conversation');
    await this.assertGroupRole(conversationId, requesterId, ['OWNER', 'ADMIN']);
    const existing = await this.prisma.conversationParticipant.findMany({
      where: { conversationId, userId: { in: userIds } },
    });
    const existingIds = new Set(existing.map((p) => p.userId));
    const newIds = userIds.filter((id) => !existingIds.has(id));
    if (newIds.length === 0) return [];
    await this.prisma.conversationParticipant.createMany({
      data: newIds.map((uid) => ({ conversationId, userId: uid, role: 'MEMBER' as const })),
    });
    // System messages for each added member
    for (const uid of newIds) {
      await this._createSystemMessage(conversationId, requesterId, 'member_added', uid);
    }
    return newIds;
  }

  async removeGroupMember(conversationId: string, requesterId: string, targetUserId: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP') throw new BadRequestException('Not a group conversation');
    const requester = await this.assertGroupRole(conversationId, requesterId, ['OWNER', 'ADMIN']);
    const target = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId: targetUserId } },
    });
    if (!target) throw new NotFoundException('User is not a participant');
    // ADMIN cannot remove OWNER or other ADMIN
    if (requester.role === 'ADMIN' && (target.role === 'OWNER' || target.role === 'ADMIN')) {
      throw new ForbiddenException('Cannot remove OWNER or ADMIN');
    }
    await this.prisma.conversationParticipant.delete({
      where: { conversationId_userId: { conversationId, userId: targetUserId } },
    });
    await this._createSystemMessage(conversationId, requesterId, 'member_removed', targetUserId);
  }

  async changeGroupMemberRole(conversationId: string, requesterId: string, targetUserId: string, newRole: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP') throw new BadRequestException('Not a group conversation');
    const requester = await this.assertGroupRole(conversationId, requesterId, ['OWNER', 'ADMIN']);
    if (requesterId === targetUserId) throw new BadRequestException('Cannot change own role');
    const target = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId: targetUserId } },
    });
    if (!target) throw new NotFoundException('User is not a participant');
    // Only OWNER can assign ADMIN
    if (newRole === 'ADMIN' && requester.role !== 'OWNER') {
      throw new ForbiddenException('Only OWNER can assign ADMIN');
    }
    // ADMIN cannot change OWNER's or other ADMIN's role
    if (requester.role === 'ADMIN' && (target.role === 'OWNER' || target.role === 'ADMIN')) {
      throw new ForbiddenException('Cannot change OWNER or ADMIN role');
    }
    await this.prisma.conversationParticipant.update({
      where: { conversationId_userId: { conversationId, userId: targetUserId } },
      data: { role: newRole as any },
    });
    await this._createSystemMessage(conversationId, requesterId, 'role_changed', targetUserId, newRole);
    return { userId: targetUserId, newRole };
  }

  async updateGroupInfo(conversationId: string, requesterId: string, data: { name?: string; avatarUrl?: string; description?: string; slowMode?: boolean; invitePolicy?: string; autoDeleteDays?: number | null; topicsEnabled?: boolean }) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP') throw new BadRequestException('Not a group conversation');
    await this.assertGroupRole(conversationId, requesterId, ['OWNER', 'ADMIN']);
    const update: any = {};
    if (data.name !== undefined) update.name = data.name.trim();
    if (data.avatarUrl !== undefined) update.avatarUrl = data.avatarUrl;
    if (data.description !== undefined) update.description = data.description;
    if (data.slowMode !== undefined) update.slowMode = data.slowMode;
    if (data.invitePolicy !== undefined) update.invitePolicy = data.invitePolicy;
    if (data.autoDeleteDays !== undefined) update.autoDeleteDays = data.autoDeleteDays;
    if (data.topicsEnabled !== undefined) update.topicsEnabled = data.topicsEnabled;
    if (Object.keys(update).length === 0) return conv;
    return this.prisma.conversation.update({
      where: { id: conversationId },
      data: update,
    });
  }

  async leaveGroup(conversationId: string, userId: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== 'GROUP') throw new BadRequestException('Not a group conversation');
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
    if (conv.type !== 'GROUP') throw new BadRequestException('Not a group conversation');
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
        profile: { select: { firstName: true, lastName: true, avatarUrl: true, status: true } },
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
    const conversations = await this.prisma.conversation.findMany({
      where: { participants: { some: { userId } } },
      include: {
        participants: true,
        messages: { where: { deletedAt: null, NOT: { hiddenFor: { some: { userId } } } }, orderBy: { sentAt: 'desc' }, take: 1 },
      },
      orderBy: { createdAt: 'desc' },
    });

    const allUserIds = [...new Set(conversations.flatMap((c) => c.participants.map((p) => p.userId)))];
    const users = await this.prisma.user.findMany({
      where: { id: { in: allUserIds } },
      select: {
        id: true,
        username: true,
        profile: { select: { firstName: true, lastName: true, avatarUrl: true } },
      },
    });
    const userMap = Object.fromEntries(users.map((u) => [u.id, u]));

    const convIds = conversations.map((c) => c.id);
    const unreadCounts = await this.prisma.message.groupBy({
      by: ['conversationId'],
      where: {
        conversationId: { in: convIds },
        senderId: { not: userId },
        isRead: false,
      },
      _count: { id: true },
    });
    const unreadMap: Record<string, number> = {};
    for (const r of unreadCounts) {
      unreadMap[r.conversationId] = r._count.id;
    }

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
    const aliases = await this.prisma.contactAlias.findMany({ where: { ownerId: userId } });
    const aliasMap: Record<string, string> = {};
    for (const a of aliases) aliasMap[a.targetId] = a.customName;

    return conversations.map((conv) => ({
      ...this._formatConversation(conv, userId, userMap, activeCallMap, aliasMap),
      unreadCount: unreadMap[conv.id] ?? 0,
    }));
  }

  private _formatConversation(conv: any, currentUserId: string, userMap?: Record<string, any>, activeCallMap?: Record<string, string>, aliasMap?: Record<string, string>) {
    const myParticipant = conv.participants.find((p: any) => p.userId === currentUserId);
    const otherParticipant = conv.participants.find((p: any) => p.userId !== currentUserId);
    const otherUser = otherParticipant && userMap ? userMap[otherParticipant.userId] : null;
    const otherFirstLast = otherUser
      ? ([otherUser.profile?.firstName, otherUser.profile?.lastName].filter(Boolean).join(' ').trim() || null)
      : null;
    const otherUserName = (aliasMap && otherParticipant ? aliasMap[otherParticipant.userId] : null) ?? otherFirstLast ?? otherUser?.username ?? null;
    const lastMsg = conv.messages?.[0] ?? null;

    // Find sender name for last message (for group chats)
    let lastMessageSenderName: string | null = null;
    if (lastMsg && userMap && lastMsg.senderId !== currentUserId) {
      const senderUser = userMap[lastMsg.senderId];
      if (senderUser) {
        lastMessageSenderName = [senderUser.profile?.firstName, senderUser.profile?.lastName]
          .filter(Boolean).join(' ').trim() || senderUser.username || null;
      }
    }

    return {
      id: conv.id,
      type: conv.type,
      name: conv.name ?? null,
      avatarUrl: conv.avatarUrl ?? null,
      description: conv.description ?? null,
      participantCount: conv.participants.length,
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
      invitePolicy: conv.invitePolicy ?? "all",
    };
  }

  async getMessages(conversationId: string, userId: string, cursor?: string, limit = 30) {
    await this.assertParticipant(conversationId, userId);
    const messages = await this.prisma.message.findMany({
      where: {
        conversationId,
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
      },
      orderBy: { sentAt: 'desc' },
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    const hasMore = messages.length > limit;
    const sliced = hasMore ? messages.slice(0, limit) : messages;
    const enriched = sliced.map((m: any) => {
      const u = m.sender;
      const firstLast = u
        ? ([u.profile?.firstName, u.profile?.lastName].filter(Boolean).join(' ').trim() || null)
        : null;
      const senderName = firstLast ?? u?.username ?? null;
      const { sender, reactions, ...rest } = m;
      return { ...rest, senderName, reactions: reactions ?? [] };
    });
    return {
      messages: enriched,
      nextCursor: hasMore ? sliced[limit - 1].id : undefined,
    };
  }

  async getSharedMedia(conversationId: string, userId: string, type?: string, cursor?: string, limit = 50) {
    await this.assertParticipant(conversationId, userId);
    const fileTypes = type === 'documents'
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
        id: true, content: true, sentAt: true, senderId: true,
        fileUrl: true, fileName: true, fileSize: true, fileType: true,
        thumbnailSmallUrl: true, thumbnailMediumUrl: true, thumbnailLargeUrl: true,
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

  async createMessage(conversationId: string, senderId: string, content: string, fileData?: {
    fileUrl?: string; fileName?: string; fileSize?: number; fileType?: string;
    s3Key?: string; thumbnailSmallUrl?: string; thumbnailMediumUrl?: string; thumbnailLargeUrl?: string;
  }, topicId?: string) {
    return this.prisma.message.create({ data: { conversationId, senderId, content, ...fileData, ...(topicId ? { topicId } : {}) } });
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
                { profile: { firstName: { contains: query, mode: 'insensitive' } } },
                { profile: { lastName: { contains: query, mode: 'insensitive' } } },
              ],
            }),
      },
      select: {
        id: true,
        username: true,
        email: true,
        profile: { select: { firstName: true, lastName: true, avatarUrl: true } },
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

  async getUserDisplayName(userId: string): Promise<string> {
    const info = await this.getUserCallInfo(userId);
    return info.name;
  }

  async getUserCallInfo(userId: string): Promise<{ name: string; avatarUrl: string | null }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { profile: { select: { firstName: true, lastName: true, avatarUrl: true } } },
    });
    if (!user) return { name: 'Пользователь', avatarUrl: null };
    const fullName = [(user as any).profile?.firstName, (user as any).profile?.lastName]
      .filter(Boolean).join(' ').trim();
    return {
      name: fullName || (user as any).username || 'Пользователь',
      avatarUrl: (user as any).profile?.avatarUrl ?? null,
    };
  }

  async editMessage(messageId: string, senderId: string, newContent: string) {
    const msg = await this.prisma.message.findUnique({ where: { id: messageId } });
    if (!msg || msg.senderId !== senderId) throw new Error('Not allowed');
    return this.prisma.message.update({
      where: { id: messageId },
      data: { content: newContent, isEdited: true, editedAt: new Date() },
    });
  }

  async deleteMessage(messageId: string, requesterId: string, scope: 'self' | 'all') {
    const msg = await this.prisma.message.findUnique({ where: { id: messageId } });
    if (!msg) throw new Error('Message not found');
    if (scope === 'all') {
      if (msg.senderId !== requesterId) throw new ForbiddenException('Only sender can delete for everyone');
      await this.prisma.message.update({ where: { id: messageId }, data: { deletedAt: new Date() } });

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
              if (fileRecord.thumbnailSmall) await this.fileStorage.delete(fileRecord.thumbnailSmall);
              if (fileRecord.thumbnailMedium) await this.fileStorage.delete(fileRecord.thumbnailMedium);
              if (fileRecord.thumbnailLarge) await this.fileStorage.delete(fileRecord.thumbnailLarge);
            } catch (e) {
              this.logger.error('Failed to delete S3 objects for FileRecord:', e);
            }
            await this.prisma.fileRecord.delete({ where: { id: fileRecord.id } });
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

  async markConversationRead(conversationId: string, userId: string): Promise<string[]> {
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

  // ─── Helpers ───

  private async _getConversationOrThrow(conversationId: string) {
    const conv = await this.prisma.conversation.findUnique({ where: { id: conversationId } });
    if (!conv) throw new NotFoundException('Conversation not found');
    return conv;
  }

  private async _createSystemMessage(
    conversationId: string,
    actorId: string,
    action: string,
    targetUserId?: string,
    extra?: string,
  ) {
    const actorName = await this.getUserDisplayName(actorId);
    const targetName = targetUserId ? await this.getUserDisplayName(targetUserId) : null;
    let content: string;
    switch (action) {
      case 'group_created':
        content = JSON.stringify({ action, actor: actorName });
        break;
      case 'member_added':
        content = JSON.stringify({ action, actor: actorName, target: targetName });
        break;
      case 'member_removed':
        content = JSON.stringify({ action, actor: actorName, target: targetName });
        break;
      case 'member_left':
        content = JSON.stringify({ action, actor: actorName });
        break;
      case 'role_changed':
        content = JSON.stringify({ action, actor: actorName, target: targetName, role: extra });
        break;
      default:
        content = JSON.stringify({ action, actor: actorName });
    }
    return this.prisma.message.create({
      data: { conversationId, senderId: actorId, content, isSystem: true },
    });
  }

  async muteConversation(conversationId: string, userId: string, durationMinutes?: number) {
    await this.assertParticipant(conversationId, userId);
    const mutedUntil = durationMinutes ? new Date(Date.now() + durationMinutes * 60 * 1000) : null;
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

  async getActiveCallForConversation(conversationId: string): Promise<string | null> {
    const log = await this.prisma.callLog.findFirst({
      where: { conversationId, endedAt: null },
      select: { roomName: true },
    });
    return log?.roomName ?? null;
  }











  // ─── Saved Messages ───

  async getOrCreateSavedChat(userId: string): Promise<string> {
    const existing = await this.prisma.conversation.findFirst({
      where: { type: "SAVED", participants: { some: { userId } } },
    });
    if (existing) return existing.id;
    const conv = await this.prisma.conversation.create({
      data: {
        type: "SAVED",
        name: "Избранное",
        createdById: userId,
        participants: { create: { userId, role: "OWNER" } },
      },
    });
    return conv.id;
  }
  // ─── Channels ───

  async createChannel(creatorId: string, name: string, description?: string, avatarUrl?: string) {
    const conv = await this.prisma.conversation.create({
      data: {
        type: "CHANNEL",
        name,
        description,
        avatarUrl,
        createdById: creatorId,
        participants: {
          create: { userId: creatorId, role: "OWNER" },
        },
      },
    });
    return conv;
  }

  async subscribeToChannel(channelId: string, userId: string) {
    const conv = await this._getConversationOrThrow(channelId);
    if (conv.type !== "CHANNEL") throw new BadRequestException("Not a channel");
    const existing = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId: channelId, userId } },
    });
    if (existing) throw new BadRequestException("Already subscribed");
    await this.prisma.conversationParticipant.create({
      data: { conversationId: channelId, userId, role: "SUBSCRIBER" },
    });
    return { ok: true };
  }

  async unsubscribeFromChannel(channelId: string, userId: string) {
    const conv = await this._getConversationOrThrow(channelId);
    if (conv.type !== "CHANNEL") throw new BadRequestException("Not a channel");
    await this.prisma.conversationParticipant.delete({
      where: { conversationId_userId: { conversationId: channelId, userId } },
    });
    return { ok: true };
  }

  async assertCanPostInChannel(conversationId: string, userId: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== "CHANNEL") return; // not a channel, anyone can post
    const participant = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
    });
    if (!participant || (participant.role !== "OWNER" && participant.role !== "ADMIN")) {
      throw new ForbiddenException("Only admins can post in channels");
    }
  }
  // ─── Polls ───

  async createPoll(conversationId: string, senderId: string, question: string, options: string[], isAnonymous = false, isMultiple = false) {
    await this.assertParticipant(conversationId, senderId);
    if (options.length < 2 || options.length > 10) throw new BadRequestException("2-10 options required");

    const msg = await this.prisma.message.create({
      data: {
        conversationId,
        senderId,
        content: "[POLL]" + JSON.stringify({ question }),
        fileType: "poll",
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
      include: { poll: true },
    });
    if (!option) throw new NotFoundException("Option not found");

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
        const allOptions = await this.prisma.pollOption.findMany({ where: { pollId: option.pollId } });
        await this.prisma.pollVote.deleteMany({
          where: { optionId: { in: allOptions.map(o => o.id) }, userId },
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
          orderBy: { position: "asc" },
        },
      },
    });
  }

  async getPollByMessageId(messageId: string) {
    return this.prisma.poll.findUnique({
      where: { messageId },
      include: {
        options: {
          include: { votes: { select: { userId: true } } },
          orderBy: { position: "asc" },
        },
      },
    });
  }
  // ─── Threads ───

  async getThreadReplies(messageId: string) {
    return this.prisma.message.findMany({
      where: { threadParentId: messageId, deletedAt: null },
      orderBy: { sentAt: "asc" },
      include: { sender: { select: { id: true, username: true, profile: { select: { firstName: true, lastName: true, avatarUrl: true } } } } },
    });
  }

  async getThreadCount(messageId: string): Promise<number> {
    return this.prisma.message.count({
      where: { threadParentId: messageId, deletedAt: null },
    });
  }

  async sendThreadReply(conversationId: string, senderId: string, content: string, threadParentId: string, fileData?: any) {
    const parent = await this.prisma.message.findUnique({ where: { id: threadParentId } });
    if (!parent) throw new NotFoundException("Parent message not found");
    if (parent.conversationId !== conversationId) throw new BadRequestException("Message not in this conversation");
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

  async getTopics(conversationId: string) {
    const topics = await this.prisma.topic.findMany({
      where: { conversationId },
      orderBy: { createdAt: "asc" },
    });
    const enriched = await Promise.all(topics.map(async (topic) => {
      const lastMsg = await this.prisma.message.findFirst({
        where: { topicId: topic.id, deletedAt: null },
        orderBy: { sentAt: "desc" },
        include: {
          sender: { select: { username: true, profile: { select: { firstName: true, lastName: true } } } },
        },
      });
      let lastMessageContent: string | null = null;
      if (lastMsg) {
        if (lastMsg.fileType === 'image') lastMessageContent = '🖼 Фото';
        else if (lastMsg.fileType === 'video') lastMessageContent = '🎥 Видео';
        else if (lastMsg.fileType === 'audio') lastMessageContent = '🎵 Голосовое';
        else if (lastMsg.fileType === 'video_note') lastMessageContent = '📹 Видеосообщение';
        else lastMessageContent = lastMsg.content;
      }
      const senderProfile = (lastMsg as any)?.sender?.profile;
      const senderName = senderProfile
        ? ([senderProfile.firstName, senderProfile.lastName].filter(Boolean).join(' ').trim() || (lastMsg as any)?.sender?.username)
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
    }));
    return enriched;
  }

  async createTopic(conversationId: string, userId: string, title: string, icon?: string) {
    const conv = await this._getConversationOrThrow(conversationId);
    if (conv.type !== "GROUP") throw new BadRequestException("Topics only for groups");
    return this.prisma.topic.create({
      data: { conversationId, title, icon: icon || "💬", createdBy: userId },
    });
  }

  async deleteTopic(topicId: string, userId: string) {
    const topic = await this.prisma.topic.findUnique({ where: { id: topicId } });
    if (!topic) throw new NotFoundException("Topic not found");
    await this.assertGroupRole(topic.conversationId, userId, ["OWNER", "ADMIN"]);
    await this.prisma.topic.delete({ where: { id: topicId } });
  }
  async getConversationType(conversationId: string): Promise<string | null> {
    const conv = await this.prisma.conversation.findUnique({
      where: { id: conversationId },
      select: { type: true },
    });
    return conv?.type ?? null;
  }

  async isParticipantMuted(conversationId: string, userId: string): Promise<boolean> {
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
    if (senderId === receiverId) throw new BadRequestException('Cannot send request to yourself');

    // Check if receiver has blocked sender
    const blocked = await this.prisma.blockedUser.findFirst({
      where: { blockerId: receiverId, blockedId: senderId },
    });
    if (blocked) throw new ForbiddenException('Не удалось отправить запрос');

    // Check if there's already an accepted contact or existing conversation
    const existing = await this.prisma.contactRequest.findUnique({
      where: { senderId_receiverId: { senderId, receiverId } },
    });
    if (existing?.status === 'ACCEPTED') throw new BadRequestException('Already contacts');
    if (existing?.status === 'PENDING') {
      // Check 24h cooldown for resending
      const hoursSince = (Date.now() - new Date(existing.updatedAt).getTime()) / (1000 * 60 * 60);
      if (hoursSince < 24) {
        throw new BadRequestException('Повторный запрос можно отправить через ' + Math.ceil(24 - hoursSince) + ' ч.');
      }
      // Allow resend — update timestamp
      const request = await this.prisma.contactRequest.update({
        where: { id: existing.id },
        data: { updatedAt: new Date() },
      });
      const sender = await this.prisma.user.findUnique({
        where: { id: senderId },
        include: { profile: { select: { firstName: true, lastName: true, avatarUrl: true } } },
      });
      const senderName = [sender?.profile?.firstName, sender?.profile?.lastName]
        .filter(Boolean).join(' ') || sender?.username || '';
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
      where: { senderId_receiverId: { senderId: receiverId, receiverId: senderId } },
    });
    if (reverse?.status === 'ACCEPTED') throw new BadRequestException('Already contacts');
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
      include: { profile: { select: { firstName: true, lastName: true, avatarUrl: true } } },
    });
    const senderName = [sender?.profile?.firstName, sender?.profile?.lastName]
      .filter(Boolean).join(' ') || sender?.username || '';

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
          include: { profile: { select: { firstName: true, lastName: true, avatarUrl: true } } },
        });
        return {
          ...r,
          senderName: [sender?.profile?.firstName, sender?.profile?.lastName]
            .filter(Boolean).join(' ') || sender?.username || '',
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
          include: { profile: { select: { firstName: true, lastName: true, avatarUrl: true } } },
        });
        return {
          ...r,
          receiverName: [receiver?.profile?.firstName, receiver?.profile?.lastName]
            .filter(Boolean).join(' ') || receiver?.username || '',
          receiverAvatar: receiver?.profile?.avatarUrl,
          receiverUsername: receiver?.username,
          receiverEmail: receiver?.email,
        };
      }),
    );
    return enriched;
  }

  async acceptContactRequest(requestId: string, userId: string) {
    const request = await this.prisma.contactRequest.findUnique({ where: { id: requestId } });
    if (!request) throw new NotFoundException('Request not found');
    if (request.receiverId !== userId && request.senderId !== userId) {
      throw new ForbiddenException('Not your request');
    }
    if (request.status !== 'PENDING') throw new BadRequestException('Request already processed');

    await this.prisma.contactRequest.update({
      where: { id: requestId },
      data: { status: 'ACCEPTED' },
    });

    // Create direct conversation
    const conv = await this.getOrCreateDirectConversation(request.senderId, request.receiverId);

    return {
      senderId: request.senderId,
      receiverId: request.receiverId,
      conversationId: conv.id,
    };
  }

  async rejectContactRequest(requestId: string, userId: string) {
    const request = await this.prisma.contactRequest.findUnique({ where: { id: requestId } });
    if (!request) throw new NotFoundException('Request not found');
    if (request.receiverId !== userId) throw new ForbiddenException('Not your request');

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

  async getContactStatus(myId: string, targetId: string): Promise<{ isContact: boolean; pendingRequest: 'sent' | 'received' | null; requestId: string | null; isBlocked: boolean; iBlockedThem: boolean }> {
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
      this.prisma.blockedUser.findFirst({ where: { blockerId: targetId, blockedId: myId } }),
      this.prisma.blockedUser.findFirst({ where: { blockerId: myId, blockedId: targetId } }),
    ]);
    const isBlocked = !!block;
    const iBlockedThem = !!iBlock;
    if (!req) return { isContact: false, pendingRequest: null, requestId: null, isBlocked, iBlockedThem };
    if (req.status === 'ACCEPTED') return { isContact: true, pendingRequest: null, requestId: null, isBlocked, iBlockedThem };
    if (req.status === 'PENDING') {
      const dir: 'sent' | 'received' = req.senderId === myId ? 'sent' : 'received';
      return { isContact: false, pendingRequest: dir, requestId: req.id, isBlocked, iBlockedThem };
    }
    return { isContact: false, pendingRequest: null, requestId: null, isBlocked, iBlockedThem };
  }

  // ─── Reactions ───

  async toggleReaction(messageId: string, userId: string, emoji: string) {
    const msg = await this.prisma.message.findUnique({ where: { id: messageId } });
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
    const convIds = conversations.map(c => c.id);
    const messages = await this.prisma.message.findMany({
      where: {
        conversationId: { in: convIds },
        content: { contains: query, mode: "insensitive" },
        deletedAt: null,
      },
      orderBy: { sentAt: "desc" },
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
    const userIds = [...new Set(messages.map(m => m.senderId))];
    const users = await this.prisma.user.findMany({
      where: { id: { in: userIds } },
      select: { id: true, username: true, profile: { select: { firstName: true, lastName: true } } },
    });
    const userMap: Record<string, string> = {};
    for (const u of users) {
      userMap[u.id] = [u.profile?.firstName, u.profile?.lastName].filter(Boolean).join(" ") || u.username || "";
    }
    return messages.map(m => ({
      ...m,
      senderName: userMap[m.senderId] || "",
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
}