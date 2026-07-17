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

  private static readonly HISTORY_LIMIT = 30;

  /** One text turn. Stateless: tool round-trips echo state from the client. */
  async textTurn(
    userId: string,
    dto: {
      text?: string;
      instructions: string;
      tools: any[];
      pendingAssistantMessage?: any;
      toolResults?: { tool_call_id: string; output: string }[];
    },
  ) {
    const conversationId = await this.getOrCreateThread(userId);

    if (dto.text) {
      const userMsg = await this.prisma.message.create({
        data: {
          conversationId,
          senderId: userId,
          content: dto.text,
          isSystem: false,
          metadata: { assistantRole: 'user', source: 'text' },
        },
      });
      this.gateway.server.to(`user:${userId}`).emit('new_message', userMsg);
    }

    // Context: last N thread messages, chronological.
    const historyRows = await this.prisma.message.findMany({
      where: { conversationId, deletedAt: null },
      orderBy: { sentAt: 'desc' },
      take: AssistantChatService.HISTORY_LIMIT,
    });
    const history = historyRows
      .reverse()
      .filter((m) => (m.content ?? '').length > 0)
      .map((m) => ({
        role:
          (m.metadata as any)?.assistantRole === 'assistant' || m.isSystem
            ? ('assistant' as const)
            : ('user' as const),
        content: m.content,
      }));

    const messages: any[] = [{ role: 'system', content: dto.instructions }, ...history];
    if (dto.text) {
      // the just-persisted user message is in `history` only if findMany saw
      // it; guard against lag by ensuring the last entry is the current text
      if (messages[messages.length - 1]?.content !== dto.text) {
        messages.push({ role: 'user', content: dto.text });
      }
    }
    if (dto.pendingAssistantMessage && dto.toolResults) {
      messages.push(dto.pendingAssistantMessage);
      for (const r of dto.toolResults) {
        messages.push({ role: 'tool', tool_call_id: r.tool_call_id, content: r.output });
      }
    }

    const reply = await this.callOpenAI({
      messages,
      tools: dto.tools?.length ? dto.tools : undefined,
    });

    if (reply.tool_calls && reply.tool_calls.length > 0) {
      return {
        status: 'tool_calls' as const,
        assistantMessage: { role: 'assistant', content: reply.content ?? null, tool_calls: reply.tool_calls },
        toolCalls: reply.tool_calls,
      };
    }

    const finalText = reply.content ?? '';
    const assistantMsg = await this.prisma.message.create({
      data: {
        conversationId,
        senderId: userId,
        content: finalText,
        isSystem: true,
        metadata: { assistantRole: 'assistant', source: 'text' },
      },
    });
    this.gateway.server.to(`user:${userId}`).emit('new_message', {
      ...assistantMsg,
      senderName: 'AI Ассистент',
    });
    return { status: 'final' as const, text: finalText, messageId: assistantMsg.id };
  }

  /** Thin OpenAI chat-completions wrapper (mocked in unit tests). */
  private async callOpenAI(payload: {
    messages: any[];
    tools?: any[];
  }): Promise<{ content: string | null; tool_calls?: any[] }> {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) throw new Error('OPENAI_API_KEY not configured');
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-4o',
        messages: payload.messages,
        ...(payload.tools ? { tools: payload.tools } : {}),
      }),
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      throw new Error(`OpenAI ${res.status}: ${errText.slice(0, 300)}`);
    }
    const data = await res.json();
    const msg = data.choices?.[0]?.message ?? {};
    return { content: msg.content ?? null, tool_calls: msg.tool_calls };
  }
}
