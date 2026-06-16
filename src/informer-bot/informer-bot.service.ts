import { Inject, Injectable, Logger, forwardRef } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { MessengerService } from '../messenger/messenger.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { InformerClient } from './informer.client';
import {
  formatOperatorWalletsList,
  formatMiniAcquiringBalances,
  formatGatewayWallets,
  formatWelcome,
  formatButtonsOnlyHint,
  formatClientError,
} from './informer.formatters';
import {
  InformerAuthError,
  InformerNotConfiguredError,
  InformerNonceStoreError,
  InformerUnavailableError,
  InformerTimeoutError,
} from './informer.types';

const ANTI_FLOOD_MS = 3000;

const ACTION_CODES = [
  'OPERATOR_WALLETS',
  'MINI_ACQUIRING',
  'GATEWAY_WALLETS',
] as const;
type ActionCode = (typeof ACTION_CODES)[number];

@Injectable()
export class InformerBotService {
  private readonly logger = new Logger(InformerBotService.name);
  private readonly lastAction = new Map<string, number>(); // userId+code → ts

  constructor(
    private readonly prisma: PrismaService,
    private readonly client: InformerClient,
    private readonly messenger: MessengerService,
    @Inject(forwardRef(() => MessengerGateway))
    private readonly gateway: MessengerGateway,
  ) {}

  private async assertAccess(userId: string): Promise<void> {
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile?.informerAccess) {
      throw new Error('informer-access-denied');
    }
  }

  async getOrCreateChat(userId: string): Promise<string> {
    await this.assertAccess(userId);
    const existing = await this.prisma.conversation.findFirst({
      where: { type: 'AI_INFORMER', participants: { some: { userId } } },
    });
    if (existing) return existing.id;
    const conv = await this.prisma.conversation.create({
      data: {
        type: 'AI_INFORMER',
        name: 'Informer',
        createdById: userId,
        participants: { create: { userId, role: 'OWNER' } },
      },
    });
    await this.publishBotMessage(userId, conv.id, formatWelcome());
    this.logger.log(`Created AI_INFORMER conversation ${conv.id} for ${userId}`);
    return conv.id;
  }

  async handleUserMessage(
    userId: string,
    conversationId: string,
    content: string,
  ): Promise<void> {
    try {
      await this.assertAccess(userId);
    } catch {
      await this.publishBotMessage(
        userId,
        conversationId,
        '⛔ Доступ к Informer отозван.',
      );
      return;
    }

    const action = this.parseActionCode(content);
    if (!action) {
      await this.publishBotMessage(userId, conversationId, formatButtonsOnlyHint());
      return;
    }

    const flKey = `${userId}:${action}`;
    const last = this.lastAction.get(flKey) ?? 0;
    if (Date.now() - last < ANTI_FLOOD_MS) {
      this.logger.warn(`anti-flood throttle for ${flKey}`);
      return;
    }
    this.lastAction.set(flKey, Date.now());

    try {
      let md: string;
      switch (action) {
        case 'OPERATOR_WALLETS':
          md = formatOperatorWalletsList(
            await this.client.getOperatorRequiredList(1, 50),
          );
          break;
        case 'MINI_ACQUIRING':
          md = formatMiniAcquiringBalances(
            await this.client.getMiniAcquiringBalances(),
          );
          break;
        case 'GATEWAY_WALLETS':
          md = formatGatewayWallets(
            await this.client.getGatewaySystemWalletBalances(),
          );
          break;
      }
      await this.publishBotMessage(userId, conversationId, md);
    } catch (e) {
      const md = this.errorToMessage(e, action);
      await this.publishBotMessage(userId, conversationId, md);
    }
  }

  parseActionCode(content: string): ActionCode | null {
    const m = content.match(/\[ACTION:(?:RETRY:)?([A-Z_]+)\]/);
    if (!m) return null;
    const code = m[1] as ActionCode;
    return (ACTION_CODES as readonly string[]).includes(code) ? code : null;
  }

  errorToMessage(e: unknown, retryCode?: string): string {
    if (e instanceof InformerAuthError) {
      return formatClientError(
        'Informer: ошибка аутентификации. Сообщи администратору.',
      );
    }
    if (e instanceof InformerNotConfiguredError) {
      return formatClientError('Informer на этом стенде не настроен.');
    }
    if (e instanceof InformerNonceStoreError) {
      return formatClientError(
        'Informer: временная ошибка, попробуй снова.',
        retryCode,
      );
    }
    if (e instanceof InformerTimeoutError) {
      return formatClientError('Informer не ответил вовремя.', retryCode);
    }
    if (e instanceof InformerUnavailableError) {
      return formatClientError(
        'Informer недоступен, попробуй через минуту.',
        retryCode,
      );
    }
    this.logger.error(`unexpected informer error: ${(e as any)?.stack || e}`);
    return formatClientError('Что-то пошло не так. Попробуй ещё раз.', retryCode);
  }

  /**
   * Mirrors the AI Analyst pattern in messenger.gateway.ts:
   * createMessage(..., isSystem=true) then emit to user:<userId> room.
   */
  async publishBotMessage(
    userId: string,
    conversationId: string,
    content: string,
  ): Promise<void> {
    const botMsg = await this.messenger.createMessage(
      conversationId,
      userId,
      content,
      undefined,
      undefined,
      true,
    );
    this.gateway.server.to(`user:${userId}`).emit('new_message', {
      ...botMsg,
      senderName: 'Informer',
      isSystem: true,
    });
  }

  async listWhitelistedUserIds(): Promise<string[]> {
    const profiles = await this.prisma.profile.findMany({
      where: { informerAccess: true },
      select: { userId: true },
    });
    return profiles.map((p) => p.userId);
  }
}
