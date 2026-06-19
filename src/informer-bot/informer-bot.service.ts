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
  formatRefillSnoozed,
  formatRefillDisabled,
  formatRefillEnabled,
  formatRefillSettings,
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
  // ── refill alerter (Sub-3) ──
  'REFILL_ACK',
  'REFILL_SNOOZE_1H',
  'REFILL_SNOOZE_MORNING',
  'REFILL_DISABLE',
  'REFILL_ENABLE',
  'REFILL_SETTINGS',
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
        case 'REFILL_ACK': {
          const until = new Date(Date.now() + 30 * 60 * 1000);
          await this.upsertAlertConfig(userId, { snoozedUntil: until });
          md = formatRefillSnoozed('30 минут', '[B:green]✅ Принято[/B]');
          break;
        }
        case 'REFILL_SNOOZE_1H': {
          const until = new Date(Date.now() + 60 * 60 * 1000);
          await this.upsertAlertConfig(userId, { snoozedUntil: until });
          md = formatRefillSnoozed('1 час');
          break;
        }
        case 'REFILL_SNOOZE_MORNING': {
          const until = this.nextMorningInBerlin();
          await this.upsertAlertConfig(userId, { snoozedUntil: until });
          md = formatRefillSnoozed(`до ${until.toISOString()}`);
          break;
        }
        case 'REFILL_DISABLE':
          await this.upsertAlertConfig(userId, {
            enabled: false,
            snoozedUntil: null,
          });
          md = formatRefillDisabled();
          break;
        case 'REFILL_ENABLE':
          await this.upsertAlertConfig(userId, {
            enabled: true,
            snoozedUntil: null,
          });
          md = formatRefillEnabled();
          break;
        case 'REFILL_SETTINGS': {
          const cfg = await this.prisma.informerAlertConfig.findUnique({
            where: { userId },
          });
          md = formatRefillSettings(cfg);
          break;
        }
      }
      await this.publishBotMessage(userId, conversationId, md);
    } catch (e) {
      this.logger.error(
        `informer action ${action} failed: ${(e as Error)?.message || e}`,
      );
      const md = this.errorToMessage(e, action);
      await this.publishBotMessage(userId, conversationId, md);
    }
  }

  parseActionCode(content: string): ActionCode | null {
    // Two input shapes are supported because the mobile [ACTION:...] renderer
    // sends the EXACT text inside the brackets as the message content. The
    // legacy code-style payloads (OPERATOR_WALLETS) keep working for tests
    // and any external integrations; the new human-label buttons land here
    // as plain strings like "📋 Кошельки оператора" or "🔄 Повторить
    // OPERATOR_WALLETS".
    const lower = content.toLowerCase();
    // Direct code matches (also handles "[ACTION:OPERATOR_WALLETS]" or
    // "[ACTION:RETRY:OPERATOR_WALLETS]" patterns).
    if (lower.includes('operator_wallets') || lower.includes('кошельки оператора') || lower.includes('все ожидающие')) {
      return 'OPERATOR_WALLETS';
    }
    if (lower.includes('mini_acquiring') || lower.includes('mini-acquiring')) {
      return 'MINI_ACQUIRING';
    }
    if (lower.includes('gateway_wallets') || lower.includes('gateway') || lower.includes('системные кошельки')) {
      return 'GATEWAY_WALLETS';
    }
    // Refill alerter — Sub-3
    if (lower.includes('refill_ack') || lower.includes('понял, работаю')) {
      return 'REFILL_ACK';
    }
    if (lower.includes('refill_snooze_1h') || lower.includes('заглушить 1 час')) {
      return 'REFILL_SNOOZE_1H';
    }
    if (lower.includes('refill_snooze_morning') || lower.includes('до утра')) {
      return 'REFILL_SNOOZE_MORNING';
    }
    if (lower.includes('refill_disable') || lower.includes('совсем отключить')) {
      return 'REFILL_DISABLE';
    }
    if (lower.includes('refill_enable') || lower.includes('включить обратно')) {
      return 'REFILL_ENABLE';
    }
    if (
      lower.includes('refill_settings') ||
      lower.includes('настройки алёртов') ||
      lower.includes('настройки алертов')
    ) {
      return 'REFILL_SETTINGS';
    }
    return null;
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

  private async upsertAlertConfig(
    userId: string,
    patch: Partial<{
      enabled: boolean;
      snoozedUntil: Date | null;
      lastDigestStage: number;
      lastDigestAt: Date | null;
    }>,
  ): Promise<void> {
    await this.prisma.informerAlertConfig.upsert({
      where: { userId },
      update: patch,
      create: { userId, ...patch },
    });
  }

  /**
   * Returns the next instant of 09:00 in Europe/Berlin time, expressed as a
   * UTC Date. DST-aware via Intl.DateTimeFormat. If `now` is already past
   * 09:00 in Berlin, returns 09:00 of the following day.
   */
  private nextMorningInBerlin(now: Date = new Date()): Date {
    const tz = 'Europe/Berlin';
    const targetHour = 9;

    const fmt = new Intl.DateTimeFormat('en-CA', {
      timeZone: tz,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });

    // Step 1: read current Berlin wall-clock date components.
    const parts = fmt.formatToParts(now);
    const get = (t: string) =>
      parseInt(parts.find((p) => p.type === t)!.value, 10);
    const year = get('year');
    const month = get('month');
    const day = get('day');
    const hour = get('hour');

    // Step 2: pick today or tomorrow's calendar day in Berlin.
    const targetDate = new Date(Date.UTC(year, month - 1, day));
    if (hour >= targetHour) {
      targetDate.setUTCDate(targetDate.getUTCDate() + 1);
    }
    const ty = targetDate.getUTCFullYear();
    const tm = targetDate.getUTCMonth() + 1;
    const td = targetDate.getUTCDate();

    // Step 3: find the UTC instant that Berlin renders as ty-tm-td 09:00.
    // Take a UTC guess of 09:00 on that day, compute Berlin's reading offset,
    // adjust by that offset.
    const guess = new Date(Date.UTC(ty, tm - 1, td, targetHour, 0, 0));
    const berlinParts = fmt.formatToParts(guess);
    const bh = parseInt(
      berlinParts.find((p) => p.type === 'hour')!.value,
      10,
    );
    const bm = parseInt(
      berlinParts.find((p) => p.type === 'minute')!.value,
      10,
    );
    const offsetHours = bh + bm / 60 - targetHour;
    return new Date(guess.getTime() - offsetHours * 3600 * 1000);
  }
}
