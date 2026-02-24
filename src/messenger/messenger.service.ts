import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class MessengerService {
  constructor(private prisma: PrismaService) {}

  async getOrCreateDirectConversation(userAId: string, userBId: string) {
    const existing = await this.prisma.conversation.findFirst({
      where: {
        type: 'DIRECT',
        AND: [
          { participants: { some: { userId: userAId } } },
          { participants: { some: { userId: userBId } } },
        ],
      },
      include: { participants: true, messages: { orderBy: { sentAt: 'desc' }, take: 1 } },
    });
    const conv = existing ?? await this.prisma.conversation.create({
      data: {
        type: 'DIRECT',
        participants: { create: [{ userId: userAId }, { userId: userBId }] },
      },
      include: { participants: true, messages: true },
    });
    return this._formatConversation(conv, userAId);
  }

  async getConversations(userId: string) {
    const conversations = await this.prisma.conversation.findMany({
      where: { participants: { some: { userId } } },
      include: {
        participants: true,
        messages: { orderBy: { sentAt: 'desc' }, take: 1 },
      },
      orderBy: { createdAt: 'desc' },
    });

    const allUserIds = [...new Set(conversations.flatMap((c) => c.participants.map((p) => p.userId)))];
    const users = await this.prisma.user.findMany({
      where: { id: { in: allUserIds } },
      select: {
        id: true,
        username: true,
        profile: { select: { firstName: true, lastName: true } },
      },
    });
    const userMap = Object.fromEntries(users.map((u) => [u.id, u]));

    return conversations.map((conv) => this._formatConversation(conv, userId, userMap));
  }

  private _formatConversation(conv: any, currentUserId: string, userMap?: Record<string, any>) {
    const otherParticipant = conv.participants.find((p: any) => p.userId !== currentUserId);
    const otherUser = otherParticipant && userMap ? userMap[otherParticipant.userId] : null;
    const otherUserName = otherUser
      ? (otherUser.username ?? ([otherUser.profile?.firstName, otherUser.profile?.lastName].filter(Boolean).join(' ') || null))
      : null;
    const lastMsg = conv.messages?.[0] ?? null;
    return {
      id: conv.id,
      participantIds: conv.participants.map((p: any) => p.userId),
      lastMessageContent: lastMsg?.content ?? null,
      lastMessageAt: lastMsg?.sentAt ?? null,
      lastMessageSenderId: lastMsg?.senderId ?? null,
      otherUserId: otherParticipant?.userId ?? null,
      otherUserName,
    };
  }

  async getMessages(conversationId: string, userId: string, cursor?: string, limit = 30) {
    await this.assertParticipant(conversationId, userId);
    const messages = await this.prisma.message.findMany({
      where: { conversationId },
      orderBy: { sentAt: 'desc' },
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    const hasMore = messages.length > limit;
    return {
      messages: hasMore ? messages.slice(0, limit) : messages,
      nextCursor: hasMore ? messages[limit - 1].id : undefined,
    };
  }

  async createMessage(conversationId: string, senderId: string, content: string) {
    return this.prisma.message.create({ data: { conversationId, senderId, content } });
  }

  async assertParticipant(conversationId: string, userId: string) {
    const p = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
    });
    if (!p) throw new ForbiddenException('Not a participant');
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
}
