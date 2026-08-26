import { Inject, Injectable, Logger, forwardRef } from '@nestjs/common';
import BigNumber from 'bignumber.js';
import { PrismaService } from '../prisma/prisma.service';
import { MessengerService } from '../messenger/messenger.service';
import { MessengerGateway } from '../messenger/messenger.gateway';
import { InformerClient } from './informer.client';
import { InformerRatesService } from './informer.rates';
import { InformerRefundService } from './informer.refund.service';
import { parseRefundEntry } from './informer.refund-flow';
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
  formatFiatBalances,
  formatOperatorWalletRetryResult,
  formatRetryAwaitingTotp,
  formatRetryCancelled,
  formatRetryTotpRejected,
} from './informer.formatters';
import {
  InformerAuthError,
  InformerBadRequestError,
  InformerNotConfiguredError,
  InformerNonceStoreError,
  InformerTotpError,
  InformerUnavailableError,
  InformerTimeoutError,
  InformerOperatorInterventionError,
  upstreamMessageFrom,
  FiatBalancesResult,
  FiatPoolDigest,
  MiniAcquiringBalances,
  GatewaySystemWalletBalances,
} from './informer.types';
import {
  PendingOp,
  PendingStateStore,
  PENDING_OP_TTL_SEC,
} from './informer.pending-state';

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
  // ── fiat balances (Sub-2c) ──
  'FIAT_BALANCES',
  'FIAT_BALANCES_REFRESH',
  // ── retry operator wallet (Sub-4) ──
  'RETRY_OPERATOR_WALLET',
  'CANCEL_TOTP',
  'SUBMIT_TOTP',
] as const;
type ActionCode = (typeof ACTION_CODES)[number];

interface ParsedAction {
  code: ActionCode;
  walletId?: number;
  totpCode?: string;
}

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
    private readonly rates: InformerRatesService,
    private readonly pending: PendingStateStore,
    private readonly refund: InformerRefundService,
  ) {}

  /**
   * Shared logging shape for every catch in this class: `upstreamStatus`/
   * `upstreamBody` alongside the message, when the error carries them. Used
   * by the outer switch's catch AND by the refund dispatch catches — before
   * this, refund failures other than the truly unrecognised one left no
   * trace in pm2 logs, unlike every other informer action.
   */
  private logActionError(label: string, e: unknown): void {
    const ue = e as { upstreamStatus?: number; upstreamBody?: string };
    const upstream =
      ue?.upstreamStatus != null
        ? ` upstreamStatus=${ue.upstreamStatus} upstreamBody=${(ue.upstreamBody ?? '').slice(0, 300)}`
        : '';
    this.logger.error(
      `informer action ${label} failed: ${(e as Error)?.message || (e as any)}${upstream}`,
    );
  }

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

    // The refund wizard owns the conversation while it's pending: its steps
    // consume free text (address, TOTP) that the generic action parser would
    // otherwise misread. Entry button is checked first so a new refund can
    // always start, even mid-wizard.
    const refundEntry = parseRefundEntry(content);
    if (refundEntry != null) {
      // Anti-flood keyed by wallet, mirroring the retry button: a double-tap
      // must not fire two list fetches, but refunds on two different
      // wallets in quick succession stay allowed.
      const flKey = `${userId}:REFUND_ENTRY:${refundEntry}`;
      if (Date.now() - (this.lastAction.get(flKey) ?? 0) < ANTI_FLOOD_MS) {
        this.logger.warn(`anti-flood throttle for ${flKey}`);
        return;
      }
      this.lastAction.set(flKey, Date.now());
      try {
        for (const m of await this.refund.startWizard(userId, refundEntry)) {
          await this.publishBotMessage(userId, conversationId, m);
        }
      } catch (e) {
        // Nothing was sent yet — startWizard only calls
        // getOperatorRequiredList, never the refund endpoint — so the
        // generic error message (with its retry hint) is safe here.
        this.logActionError('REFUND_ENTRY', e);
        await this.publishBotMessage(
          userId,
          conversationId,
          this.errorToMessage(e),
        );
      }
      return;
    }

    // Loaded ONCE per message and passed down — both the refund dispatcher
    // and the retry parser need it, and reading Redis twice for the same
    // message would be pure waste.
    const pending = await this.pending.load(userId);

    if (pending?.kind === 'refund') {
      // A navigation label tapped from an older message (e.g. «📋 Кошельки
      // оператора») arrives as plain text like any other input. On the
      // `address` step the wizard would take it for a refund address, burn
      // the TOTP step and confuse the operator. The wizard cannot guard
      // against this itself without knowing every button the bot renders —
      // so a known static label always wins over wizard input, and clearing
      // the pending state is the honest reading of "the operator navigated
      // away".
      if (this.parseAction(content) === null) {
        try {
          for (const m of await this.refund.runStep(userId, pending, content)) {
            await this.publishBotMessage(userId, conversationId, m);
          }
        } catch (e) {
          // runStep itself no longer throws for refund-API failures —
          // InformerRefundService.handleError renders those as messages.
          // Whatever lands here is something else (e.g. Redis), so the
          // generic error message stands, but it still needs to reach the
          // logs like every other action's failure does.
          this.logActionError('REFUND_STEP', e);
          await this.publishBotMessage(
            userId,
            conversationId,
            this.errorToMessage(e),
          );
        }
        return;
      }
      await this.pending.clear(userId);
    }

    // Detect a bare 6-digit message as TOTP submission ONLY when there's an
    // active pending state for this user — otherwise it falls through to the
    // normal action parser (and likely gets the "buttons only" hint).
    const parsed = this.parseActionWithPendingState(pending, content);
    if (!parsed) {
      await this.publishBotMessage(userId, conversationId, formatButtonsOnlyHint());
      return;
    }
    const { code: action, walletId, totpCode } = parsed;

    // Anti-flood is per (user, code). For retry buttons we also key by
    // walletId so that hitting retry for different wallets in quick
    // succession is not blocked.
    const flKey =
      action === 'RETRY_OPERATOR_WALLET'
        ? `${userId}:${action}:${walletId ?? '?'}`
        : `${userId}:${action}`;
    const last = this.lastAction.get(flKey) ?? 0;
    if (Date.now() - last < ANTI_FLOOD_MS) {
      this.logger.warn(`anti-flood throttle for ${flKey}`);
      return;
    }
    this.lastAction.set(flKey, Date.now());

    try {
      let md: string;
      switch (action) {
        case 'OPERATOR_WALLETS': {
          const messages = formatOperatorWalletsList(
            await this.client.getOperatorRequiredList(1, 50),
          );
          for (const m of messages) {
            await this.publishBotMessage(userId, conversationId, m);
          }
          return; // formatter emits N+1 messages; skip the single-publish below
        }
        case 'RETRY_OPERATOR_WALLET': {
          if (walletId == null) {
            md = formatClientError(
              'Не понял какой кошелёк ретраить — wallet_id не пришёл с кнопкой.',
            );
            break;
          }
          // Stage 1: ask the operator for the 6-digit code. The pending
          // state lives in Redis with TTL so an orphaned prompt expires on
          // its own. A new retry button overwrites any earlier pending
          // state — last button wins.
          await this.pending.save(userId, {
            kind: 'retry',
            step: 'totp',
            walletId,
          });
          md = formatRetryAwaitingTotp(walletId, PENDING_OP_TTL_SEC);
          break;
        }
        case 'SUBMIT_TOTP': {
          // Stage 2: code arrived — fire the retry, clear the state once
          // (Redis del) so the same code can't be replayed.
          if (walletId == null || !totpCode) {
            // Unreachable in practice — parser only emits SUBMIT_TOTP when
            // both fields are present.
            md = formatClientError('Неполный TOTP-запрос.');
            break;
          }
          await this.pending.clear(userId);
          try {
            const result = await this.client.retryOperatorWallet(
              walletId,
              totpCode,
            );
            md = formatOperatorWalletRetryResult(result);
          } catch (e) {
            if (e instanceof InformerTotpError) {
              // Re-arm pending for the same wallet so the operator can
              // submit a fresh code without going back to the wallet list.
              await this.pending.save(userId, {
                kind: 'retry',
                step: 'totp',
                walletId,
              });
              md = formatRetryTotpRejected(walletId, PENDING_OP_TTL_SEC);
              break;
            }
            throw e; // generic admin-API errors bubble to outer catch
          }
          break;
        }
        case 'CANCEL_TOTP': {
          await this.pending.clear(userId);
          md = formatRetryCancelled();
          break;
        }
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
        case 'FIAT_BALANCES_REFRESH':
        case 'FIAT_BALANCES': {
          if (action === 'FIAT_BALANCES_REFRESH') {
            this.rates.invalidateCache();
          }
          const result = await this.computeFiatBalances();
          md = formatFiatBalances(result);
          break;
        }
      }
      await this.publishBotMessage(userId, conversationId, md);
    } catch (e) {
      const ue = e as { upstreamStatus?: number; upstreamBody?: string };
      const upstream =
        ue?.upstreamStatus != null
          ? ` upstreamStatus=${ue.upstreamStatus} upstreamBody=${(ue.upstreamBody ?? '').slice(0, 300)}`
          : '';
      this.logger.error(
        `informer action ${action} failed: ${(e as Error)?.message || e}${upstream}`,
      );
      const md = this.errorToMessage(e, action);
      await this.publishBotMessage(userId, conversationId, md);
    }
  }

  /**
   * Parser variant aware of pending-op state. A bare 6-digit message is
   * promoted to SUBMIT_TOTP only when the pending operation is a retry — a
   * refund TOTP must never start a retry instead. State is passed in rather
   * than loaded here: the caller already read it once for this message.
   */
  parseActionWithPendingState(
    pending: PendingOp | null,
    content: string,
  ): ParsedAction | null {
    const trimmed = content.trim();
    if (/^\d{6}$/.test(trimmed) && pending?.kind === 'retry') {
      return {
        code: 'SUBMIT_TOTP',
        walletId: pending.walletId,
        totpCode: trimmed,
      };
    }
    return this.parseAction(content);
  }

  parseAction(content: string): ParsedAction | null {
    // Two input shapes are supported because the mobile [ACTION:...] renderer
    // sends the EXACT text inside the brackets as the message content. The
    // legacy code-style payloads (OPERATOR_WALLETS) keep working for tests
    // and any external integrations; the new human-label buttons land here
    // as plain strings like "📋 Кошельки оператора" or "🔁 Повторить #613".
    const lower = content.toLowerCase();
    // Cancel any pending TOTP prompt — keep before the retry matcher so
    // the "повторить" substring inside "отмена повтора" doesn't get
    // misinterpreted.
    if (
      lower.includes('cancel_totp') ||
      lower.includes('отмена ретрая') ||
      lower.includes('отмена ввода кода')
    ) {
      return { code: 'CANCEL_TOTP' };
    }
    // Retry per-wallet: format "🔁 Повторить #613" or legacy code form
    // "RETRY_OPERATOR_WALLET:613". Match before other "повторить"-style
    // matchers so the id can be extracted.
    const retryMatch =
      lower.match(/retry_operator_wallet[:\s]+(\d+)/) ||
      lower.match(/повторить\s*#?(\d+)/);
    if (retryMatch) {
      return {
        code: 'RETRY_OPERATOR_WALLET',
        walletId: parseInt(retryMatch[1], 10),
      };
    }
    // Fiat balances — Sub-2c (placed early so REFRESH check fires before
    // any future code adds an "обновить" matcher in unrelated context).
    if (
      lower.includes('fiat_balances_refresh') ||
      lower.includes('обновить курсы')
    ) {
      return { code: 'FIAT_BALANCES_REFRESH' };
    }
    if (lower.includes('fiat_balances') || lower.includes('балансы в евро')) {
      return { code: 'FIAT_BALANCES' };
    }
    // Direct code matches (also handles "[ACTION:OPERATOR_WALLETS]" or
    // "[ACTION:RETRY:OPERATOR_WALLETS]" patterns).
    if (lower.includes('operator_wallets') || lower.includes('кошельки оператора') || lower.includes('все ожидающие')) {
      return { code: 'OPERATOR_WALLETS' };
    }
    if (lower.includes('mini_acquiring') || lower.includes('mini-acquiring')) {
      return { code: 'MINI_ACQUIRING' };
    }
    if (lower.includes('gateway_wallets') || lower.includes('gateway') || lower.includes('системные кошельки')) {
      return { code: 'GATEWAY_WALLETS' };
    }
    // Refill alerter — Sub-3
    if (lower.includes('refill_ack') || lower.includes('понял, работаю')) {
      return { code: 'REFILL_ACK' };
    }
    if (lower.includes('refill_snooze_1h') || lower.includes('заглушить 1 час')) {
      return { code: 'REFILL_SNOOZE_1H' };
    }
    if (lower.includes('refill_snooze_morning') || lower.includes('до утра')) {
      return { code: 'REFILL_SNOOZE_MORNING' };
    }
    if (lower.includes('refill_disable') || lower.includes('совсем отключить')) {
      return { code: 'REFILL_DISABLE' };
    }
    if (lower.includes('refill_enable') || lower.includes('включить обратно')) {
      return { code: 'REFILL_ENABLE' };
    }
    if (
      lower.includes('refill_settings') ||
      lower.includes('настройки алёртов') ||
      lower.includes('настройки алертов')
    ) {
      return { code: 'REFILL_SETTINGS' };
    }
    return null;
  }

  errorToMessage(e: unknown, retryCode?: string): string {
    // TOTP-flow actions (RETRY_OPERATOR_WALLET / SUBMIT_TOTP / CANCEL_TOTP)
    // need a wallet_id to be meaningful; we don't know it here in the outer
    // catch (parsed is out of scope), so skip the retry button rather than
    // render "🔄 Повторить SUBMIT_TOTP" which the parser can't act on.
    if (
      retryCode === 'RETRY_OPERATOR_WALLET' ||
      retryCode === 'SUBMIT_TOTP' ||
      retryCode === 'CANCEL_TOTP'
    ) {
      retryCode = undefined;
    }
    if (e instanceof InformerBadRequestError) {
      return formatClientError(
        `Informer отверг запрос (400). ${e.upstreamBody?.slice(0, 200) ?? ''}`.trim(),
      );
    }
    if (e instanceof InformerAuthError) {
      return formatClientError(
        'Informer: ошибка аутентификации. Сообщи администратору.',
      );
    }
    if (e instanceof InformerTotpError) {
      return formatClientError(
        'Informer: TOTP-код не принят (часы или секрет разъехались). ' +
          'Сверь время, попробуй ещё раз через 30 секунд.',
        retryCode,
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
    if (e instanceof InformerOperatorInterventionError) {
      // 422 = the operation needs a human. The upstream message says exactly
      // what to do (e.g. "insufficient USDT balance on gas wallet ... have X,
      // need Y") — show it verbatim so the operator can act without going to
      // the server logs. No retry button: retrying without fixing the cause
      // will 422 again.
      const detail = upstreamMessageFrom(e.upstreamBody);
      return formatClientError(
        '⚠️ Требуется вмешательство оператора — Informer не смог выполнить операцию:\n\n' +
          `\`${detail || 'причина не указана'}\`\n\n` +
          'Устрани причину и повтори вручную.',
      );
    }
    if (e instanceof InformerUnavailableError) {
      // Include upstream status+message so operators can distinguish "their
      // backend service is down" (e.g. 502 mini-crypto-acquiring unavailable)
      // from generic network noise without reading pm2 logs.
      const detail = upstreamMessageFrom(e.upstreamBody, 200);
      return formatClientError(
        'Informer недоступен, попробуй через минуту.' +
          (detail ? `\n(${e.upstreamStatus ?? '?'}: ${detail})` : ''),
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

  private async computeFiatBalances(): Promise<FiatBalancesResult> {
    const [miniRaw, gatewayRaw] = await Promise.all([
      this.client.getMiniAcquiringBalances(),
      this.client.getGatewaySystemWalletBalances(),
    ]);

    const assets = new Set<string>();
    for (const chain of miniRaw.chains) {
      for (const role of chain.roles ?? []) {
        if (role.error) continue;
        for (const bal of role.balances ?? []) {
          if (!bal.error) assets.add(bal.asset.toLowerCase());
        }
      }
    }
    for (const item of gatewayRaw.items) {
      assets.add(item.asset_symbol.toLowerCase());
    }

    const rates = await this.rates.getEurRates([...assets]);

    const miniDigest = this.buildMiniDigest(miniRaw, rates);
    const gatewayDigest = this.buildGatewayDigest(gatewayRaw, rates);

    const cacheAgeMs = this.rates.getCacheAgeMs();
    return {
      pools: [miniDigest, gatewayDigest],
      ratesCacheAgeMin:
        cacheAgeMs != null ? Math.floor(cacheAgeMs / 60000) : null,
      coingeckoStatus: this.rates.getCoingeckoStatus(),
    };
  }

  private buildMiniDigest(
    raw: MiniAcquiringBalances,
    rates: Record<string, BigNumber | null>,
  ): FiatPoolDigest {
    const chains: FiatPoolDigest['chains'] = [];
    const unpriced: FiatPoolDigest['unpricedAssets'] = [];
    let poolTotal = new BigNumber(0);

    for (const chain of raw.chains) {
      let chainTotal = new BigNumber(0);
      const roles: NonNullable<FiatPoolDigest['chains'][0]['roles']> = [];
      for (const role of chain.roles ?? []) {
        if (role.error) continue;
        let roleTotal = new BigNumber(0);
        const tokens: { asset: string; native: string; eur: string | null }[] =
          [];
        for (const bal of role.balances ?? []) {
          if (bal.error) continue;
          const asset = bal.asset.toLowerCase();
          const rate = rates[asset] ?? null;
          if (rate === null) {
            unpriced.push({ asset, chain: chain.chain, native: bal.balance });
            continue;
          }
          const eur = new BigNumber(bal.balance).times(rate);
          roleTotal = roleTotal.plus(eur);
          tokens.push({ asset, native: bal.balance, eur: eur.toFixed(2) });
        }
        if (tokens.length === 0) continue;
        roles.push({
          role: role.role as 'hot_wallet' | 'cold_wallet' | 'gas_funding',
          eurTotal: roleTotal.toFixed(2),
          tokens,
        });
        chainTotal = chainTotal.plus(roleTotal);
      }
      if (roles.length === 0) continue;
      chains.push({
        chain: chain.chain,
        eurTotal: chainTotal.toFixed(2),
        roles,
      });
      poolTotal = poolTotal.plus(chainTotal);
    }

    return {
      poolName: 'mini-acquiring',
      eurTotal: poolTotal.toFixed(2),
      chains,
      unpricedAssets: unpriced,
    };
  }

  private buildGatewayDigest(
    raw: GatewaySystemWalletBalances,
    rates: Record<string, BigNumber | null>,
  ): FiatPoolDigest {
    const byChain = new Map<string, FiatPoolDigest['chains'][0]>();
    const unpriced: FiatPoolDigest['unpricedAssets'] = [];
    let poolTotal = new BigNumber(0);

    for (const item of raw.items) {
      const asset = item.asset_symbol.toLowerCase();
      const rate = rates[asset] ?? null;
      if (rate === null) {
        unpriced.push({ asset, chain: item.blockchain, native: item.balance });
        continue;
      }
      const eur = new BigNumber(item.balance).times(rate);
      let entry = byChain.get(item.blockchain);
      if (!entry) {
        entry = { chain: item.blockchain, eurTotal: '0', flatTokens: [] };
        byChain.set(item.blockchain, entry);
      }
      entry.flatTokens!.push({
        asset,
        walletType: item.wallet_type,
        native: item.balance,
        eur: eur.toFixed(2),
      });
      entry.eurTotal = new BigNumber(entry.eurTotal).plus(eur).toFixed(2);
      poolTotal = poolTotal.plus(eur);
    }

    return {
      poolName: 'gateway',
      eurTotal: poolTotal.toFixed(2),
      chains: [...byChain.values()],
      unpricedAssets: unpriced,
    };
  }
}
