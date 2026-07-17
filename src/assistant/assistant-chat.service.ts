import { forwardRef, Inject, Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { MessengerService } from '../messenger/messenger.service';
import { FcmService } from '../common/fcm.service';

export type AssistantActionType =
  | 'message_sent'
  | 'event_created'
  | 'analyst_reply'
  | 'call_made'
  | 'contact_added'
  | 'channel_post';

export interface AssistantAction {
  type: AssistantActionType;
  entityId: string;
  conversationId?: string;
  title: string;
}

export interface AssistantEntry {
  role: 'user' | 'assistant';
  source: 'voice' | 'text';
  text: string;
  action?: AssistantAction;
}

const ANALYST_BUBBLE_MAX = 500;

@Injectable()
export class AssistantChatService {
  private readonly logger = new Logger(AssistantChatService.name);

  constructor(
    private readonly prisma: PrismaService,
    @Inject(forwardRef(() => MessengerGateway))
    private readonly gateway: MessengerGateway,
    @Inject(forwardRef(() => MessengerService))
    private readonly messengerService: MessengerService,
    private readonly fcm: FcmService,
  ) {}

  async getOrCreateThread(userId: string): Promise<string> {
    const existing = await this.prisma.conversation.findFirst({
      where: { type: 'AI_ASSISTANT', participants: { some: { userId } } },
    });
    if (existing) return existing.id;
    const conv = await this.prisma.conversation.create({
      data: {
        type: 'AI_ASSISTANT',
        name: 'AI Ассистент',
        createdById: userId,
        participants: { create: { userId, role: 'OWNER' } },
      },
    });
    this.logger.log(`Created AI_ASSISTANT conversation ${conv.id} for user ${userId}`);
    return conv.id;
  }

  /** Batch-append voice-session replicas / action bubbles. Emits new_message per row. */
  async appendEntries(userId: string, entries: AssistantEntry[]) {
    const conversationId = await this.getOrCreateThread(userId);
    const created: any[] = [];
    for (const e of entries) {
      const metadata: Record<string, any> = {
        assistantRole: e.role,
        source: e.source,
      };
      if (e.action) metadata.action = e.action;
      const msg = await this.prisma.message.create({
        data: {
          conversationId,
          senderId: userId,
          content: e.text,
          isSystem: e.role === 'assistant',
          metadata,
        },
      });
      created.push(msg);
      this.gateway.server.to(`user:${userId}`).emit('new_message', {
        ...msg,
        senderName: e.role === 'assistant' ? 'AI Ассистент' : undefined,
      });
    }
    return { conversationId, messageIds: created.map((m) => m.id) };
  }

  /** Intercepted AI-Analyst reply → truncated bubble + link + push. */
  async appendAnalystReply(
    userId: string,
    fullText: string,
    analystConversationId: string,
  ) {
    const conversationId = await this.getOrCreateThread(userId);
    const truncated =
      fullText.length > ANALYST_BUBBLE_MAX
        ? fullText.slice(0, ANALYST_BUBBLE_MAX) + '…'
        : fullText;
    const msg = await this.prisma.message.create({
      data: {
        conversationId,
        senderId: userId,
        content: truncated,
        isSystem: true,
        metadata: {
          assistantRole: 'assistant',
          source: 'text',
          action: {
            type: 'analyst_reply',
            entityId: analystConversationId,
            title: 'Ответ AI Аналитика',
          },
        },
      },
    });
    this.gateway.server.to(`user:${userId}`).emit('new_message', {
      ...msg,
      senderName: 'AI Ассистент',
    });
    try {
      const tokens = await this.messengerService.getFcmTokensForUser(userId);
      await Promise.all(
        tokens.map((t: string) =>
          this.fcm.sendNewMessage(t, 'AI Ассистент', truncated, conversationId),
        ),
      );
    } catch (e) {
      this.logger.warn(`analyst-reply push failed: ${(e as Error).message}`);
    }
    return msg;
  }

  async textTurn(userId: string, dto: any): Promise<any> {
    throw new Error('not implemented'); // Task 4
  }
}
