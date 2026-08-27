import type { InformerAlertConfig } from '@prisma/client';
import BigNumber from 'bignumber.js';
import {
  OperatorRequiredList,
  OperatorRequiredItem,
  OperatorWalletRetryResult,
  MiniAcquiringBalances,
  GatewaySystemWalletBalances,
  RefillDeficit,
  FiatBalancesResult,
  FiatPoolDigest,
} from './informer.types';

// Human-readable labels in brackets so the mobile renderer (which uses the
// captured text as the button label) shows friendly buttons. Parser does
// substring matching to map back to action codes.
// Main menu — appears as the footer of every response from the bot so the
// operator can pivot between sections without scrolling up to the welcome.
export const OPERATOR_BUTTONS =
  '[ACTION:📋 Кошельки оператора]\n' +
  '[ACTION:💰 Балансы mini-acquiring]\n' +
  '[ACTION:🏦 Системные кошельки gateway]\n' +
  '[ACTION:💶 Балансы в евро]\n' +
  '[ACTION:⚙️ Настройки алёртов]';

export const ACK_BUTTONS =
  '[ACTION:✅ Понял, работаю]\n' +
  '[ACTION:🔕 Заглушить 1 час]\n' +
  '[ACTION:🔕 До утра 9:00]\n' +
  '[ACTION:🔇 Совсем отключить]';

export const SETTINGS_BUTTON = '[ACTION:⚙️ Настройки алёртов]';

const STAGE_BADGES: Record<1 | 2 | 3, string> = {
  1: '[B:yellow]STAGE 1[/B]',
  2: '[B:red]STAGE 2 — UNRESOLVED[/B]',
  3: '[B:red]STAGE 3 — ESCALATED[/B]',
};

export const LOW_POOL_EUR_THRESHOLD = new BigNumber('10000');

export const FIAT_FOOTER_BUTTONS =
  '[ACTION:🔄 Обновить курсы]\n' +
  '[ACTION:📋 Кошельки оператора]\n' +
  '[ACTION:💰 Балансы mini-acquiring]\n' +
  '[ACTION:🏦 Системные кошельки gateway]';

/** ISO-8601 → человекочитаемое «2026-08-24 17:03:40 UTC». */
function formatTimestamp(iso: string): string {
  return iso.replace('T', ' ').replace('Z', ' UTC');
}

const REASON_INDENT = '   ';

/**
 * Renders the last recorded failure. Returns an empty array when all three
 * fields are absent — they disappear both when nothing ever failed AND when
 * the platform's journal is down, so absence must render as nothing at all,
 * never as "no problems here". This is the one case this function does NOT
 * change based on which subset of fields is present.
 *
 * When ANY field is present, the block always opens with the ⚠️ marker so a
 * reader can tell "this is a failure note" at a glance, even from a partial
 * record:
 *   - event present            → ⚠️ `event`, then text (indented, if any),
 *                                 then time (indented, if any)
 *   - no event, but text       → ⚠️ text, then time (indented, if any)
 *   - only time                → ⚠️ Отказ зафиксирован: <time> — the honest
 *                                 version of "something failed, we just don't
 *                                 know what", better than a bare date or
 *                                 silence
 */
function reasonLines(item: OperatorRequiredItem): string[] {
  const text = stringifyLastError(item.last_error);
  const at = item.last_error_at ? formatTimestamp(item.last_error_at) : '';

  if (item.last_error_event) {
    const lines = [`⚠️ \`${item.last_error_event}\``];
    if (text) lines.push(`${REASON_INDENT}${text}`);
    if (at) lines.push(`${REASON_INDENT}${at}`);
    return lines;
  }
  if (text) {
    const lines = [`⚠️ ${text}`];
    if (at) lines.push(`${REASON_INDENT}${at}`);
    return lines;
  }
  if (at) {
    return [`⚠️ Отказ зафиксирован: ${at}`];
  }
  return [];
}

/**
 * `last_error` is prose for most events, but gate rejections send their
 * details-payload instead, e.g. {"reason":"withdrawal_intent_exists"}.
 * Render either as text — the guide is explicit that clients should not
 * parse it. Must never fall back to `String(obj)` — that yields the
 * useless `[object Object]`, which is exactly what an absent-reason screen
 * must not show.
 */
function stringifyLastError(
  err: string | Record<string, unknown> | undefined,
): string {
  if (err == null) return '';
  if (typeof err === 'string') return err.trim();
  try {
    return JSON.stringify(err);
  } catch {
    // Unreachable under the current contract — `last_error` comes from
    // JSON.parse of an HTTP response, which never yields circular refs or
    // BigInt, so JSON.stringify can't throw here. Kept as a cheap guard.
    return '(нечитаемый payload)';
  }
}

/**
 * Groups wallets by `last_error_event` so ten wallets sharing one event read
 * as one incident instead of ten problems. Sorted by count descending.
 */
function reasonSummaryLines(items: OperatorRequiredItem[]): string[] {
  const counts = new Map<string, number>();
  for (const i of items) {
    if (!i.last_error_event) continue;
    counts.set(i.last_error_event, (counts.get(i.last_error_event) ?? 0) + 1);
  }
  if (counts.size === 0) return [];
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  return ['', 'Причины:', ...sorted.map(([ev, n]) => `• ${n}× \`${ev}\``)];
}

/**
 * Returns a list of messages: a summary header + one card per wallet (with
 * its own retry button) + a trailer with navigation buttons. The reason it's
 * split into multiple messages instead of one is the mobile renderer
 * collects ALL `[ACTION:...]` markers from a single message into one button
 * stack at the bottom — visually disconnecting each button from its row.
 * One-message-per-wallet keeps the retry button tied to the wallet
 * description it belongs to.
 */
export function formatOperatorWalletsList(
  data: OperatorRequiredList,
): string[] {
  if (data.items.length === 0) {
    return [
      [
        '📋 **Кошельки, требующие оператора**',
        '',
        'Всего: **0**. Очередь пуста — ничего делать не надо.',
        '',
        OPERATOR_BUTTONS,
      ].join('\n'),
    ];
  }
  const header = [
    '📋 **Кошельки, требующие оператора**',
    '',
    `Всего: **${data.total}** (стр. ${data.page}, по ${data.per_page})`,
    ...reasonSummaryLines(data.items),
  ].join('\n');

  const cards = data.items.map((i) => {
    const at = formatTimestamp(i.created_at);
    const idLine =
      i.wallet_id != null
        ? `🪪 **#${i.wallet_id}** · ${i.withdraw_network} / ${i.withdraw_token}`
        : `🪪 ${i.withdraw_network} / ${i.withdraw_token}`;
    const lines = [
      idLine,
      // Deposit side (added by the platform 2026-08-24, see
      // informer-deposit-side-client-changes.md): what we're waiting to
      // receive, and where to check for it. Omitted entirely — not
      // rendered as "nothing pending" — when absent, which happens on an
      // older admin-API stand or if the platform rolls this release back.
      // `deposit_amount` is worded as an expectation ("ждём"), never as a
      // confirmed receipt: it's captured at request creation, not updated
      // when money actually arrives.
      ...(i.deposit_network
        ? [
            `Пополнение (ждём): \`${i.deposit_amount ?? '?'}\` ${i.deposit_token ?? ''} ` +
              `в сети \`${i.deposit_network}\``,
            `Адрес пополнения: \`${i.deposit_address ?? '?'}\` _(сверить поступление в эксплорере)_`,
          ]
        : []),
      // Explicitly "вывода"/"не прошёл": this is the failed withdrawal's
      // target address/amount, a different operation from the deposit
      // above — the refund wizard reached from `💸 Вернуть` below returns
      // the deposit, it does not retry or undo this withdrawal.
      `Вывод (не прошёл): \`${i.withdraw_amount}\` ${i.withdraw_token} в сети \`${i.withdraw_network}\``,
      `Адрес вывода: \`${i.withdraw_address}\``,
      `Создан: ${at}`,
      ...reasonLines(i),
    ];
    if (i.wallet_id != null) {
      lines.push(
        '',
        `[ACTION:🔁 Повторить #${i.wallet_id}]`,
        `[ACTION:💸 Вернуть #${i.wallet_id}]`,
      );
    }
    return lines.join('\n');
  });

  // Trailer carries the navigation buttons so they don't pile up on every
  // wallet card.
  const trailer = OPERATOR_BUTTONS;

  return [header, ...cards, trailer];
}

export function formatOperatorWalletRetryResult(
  result: OperatorWalletRetryResult,
): string {
  return [
    `[B:green]✅ Повтор запущен[/B] для кошелька **#${result.wallet_id}**`,
    '',
    `Статус: \`${result.status}\``,
    '',
    OPERATOR_BUTTONS,
  ].join('\n');
}

export function formatRetryAwaitingTotp(
  walletId: number,
  ttlSeconds: number,
): string {
  return [
    `🔐 **Подтверди ретрай кошелька #${walletId}**`,
    '',
    `Введи 6-значный код из Google Authenticator в течение ${ttlSeconds} секунд.`,
    'Код одноразовый и не должен светиться в чате после — стирать не надо, я не храню.',
    '',
    '[ACTION:❌ Отмена ретрая]',
  ].join('\n');
}

export function formatRetryCancelled(): string {
  return [
    '[B:blue]❌ Ретрай отменён.[/B]',
    'Pending-код сброшен. Нажми «🔁 Повторить» в листе кошельков ещё раз, когда нужно.',
    '',
    OPERATOR_BUTTONS,
  ].join('\n');
}

/**
 * Renders the «code rejected, try again» card. Pending state is re-armed
 * on the same wallet so the operator can submit a fresh code without
 * navigating back to the wallet list.
 */
export function formatRetryTotpRejected(
  walletId: number,
  ttlSeconds: number,
): string {
  return [
    `⚠️ **Код не принят** для кошелька **#${walletId}**.`,
    '',
    'Часы расходятся или код истёк. Возьми свежий 6-значный код из ' +
      `аутентификатора и пришли в течение ${ttlSeconds} секунд.`,
    '',
    '[ACTION:❌ Отмена ретрая]',
  ].join('\n');
}

export function formatMiniAcquiringBalances(
  data: MiniAcquiringBalances,
): string {
  const blocks: string[] = ['💰 **Балансы mini-acquiring**', ''];
  for (const chain of data.chains) {
    const flag = chain.supported ? '' : ' _(не поддерживается)_';
    blocks.push(`### ${chain.chain}${flag}`);
    // Non-EVM chains (Bitcoin, Litecoin, Polkadot, Taler) may omit `roles`
    // entirely. Skip them with a marker instead of crashing the whole reply.
    const roles = Array.isArray(chain.roles) ? chain.roles : [];
    if (roles.length === 0) {
      blocks.push('_(нет ролей в ответе API)_');
      blocks.push('');
      continue;
    }
    for (const role of roles) {
      if (role.error) {
        blocks.push(`- **${role.role}**: ⚠️ ${role.error}`);
        continue;
      }
      const addr = role.address ? ` \`${role.address}\`` : '';
      blocks.push(`- **${role.role}**${addr}`);
      for (const bal of role.balances ?? []) {
        if (bal.error) {
          blocks.push(`  - ${bal.asset} (${bal.kind}): ⚠️ ${bal.error}`);
        } else {
          blocks.push(`  - ${bal.asset} (${bal.kind}): ${bal.balance}`);
        }
      }
    }
    blocks.push('');
  }
  blocks.push(OPERATOR_BUTTONS);
  return blocks.join('\n');
}

export function formatGatewayWallets(
  data: GatewaySystemWalletBalances,
): string {
  if (data.items.length === 0) {
    return [
      '🏦 **Системные кошельки gateway**',
      '',
      'Кошельки не найдены.',
      '',
      OPERATOR_BUTTONS,
    ].join('\n');
  }
  const grouped = new Map<string, typeof data.items>();
  for (const it of data.items) {
    const key = it.blockchain;
    const list = grouped.get(key) ?? [];
    list.push(it);
    grouped.set(key, list);
  }
  const blocks: string[] = ['🏦 **Системные кошельки gateway**', ''];
  for (const [chain, items] of grouped) {
    blocks.push(`### ${chain}`);
    for (const it of items) {
      const updated = new Date(it.updated_at * 1000).toISOString();
      blocks.push(
        `- ${it.asset_symbol} **${it.wallet_type}**: ${it.balance} · \`${it.address}\` · ${updated}`,
      );
    }
    blocks.push('');
  }
  blocks.push(OPERATOR_BUTTONS);
  return blocks.join('\n');
}

export function formatNewOperatorWalletAlert(
  item: OperatorRequiredItem,
): string {
  const at = formatTimestamp(item.created_at);
  const reason = reasonLines(item);
  return [
    '🚨 **Новый кошелёк ждёт оператора**',
    '',
    `Сеть: \`${item.withdraw_network}\``,
    `Токен: \`${item.withdraw_token}\``,
    `Адрес: \`${item.withdraw_address}\``,
    `Сумма: \`${item.withdraw_amount}\``,
    `Создан: ${at}`,
    ...(reason.length > 0 ? ['', ...reason] : []),
    '',
    '[ACTION:📋 Все ожидающие]',
    '[ACTION:🏦 Балансы gateway]',
  ].join('\n');
}

export function formatDowntimeAlert(): string {
  return [
    '⚠️ **Informer API недоступен 15+ минут**',
    '',
    'Watcher временно остановлен. Алёрты о новых кошельках могут запаздывать.',
    'Когда API восстановится, watcher автоматически продолжит работу.',
  ].join('\n');
}

export function formatRefillDigest(
  items: RefillDeficit[],
  stage: 1 | 2 | 3,
): string {
  const lines = items.map(
    (d) =>
      `- ${d.chain}-${d.token} [HOT_BADGE]HOT[/HOT_BADGE] \`${d.hotAddress}\`: ` +
      `[HOT]${d.hotBalance}[/HOT] / pending ${d.pendingTotal} / [C:red]−${d.deficit}[/C] ` +
      `(доступно ${d.availableForWithdrawal} при 10% буфере)`,
  );
  return [
    `🔴 **Refill needed** ${STAGE_BADGES[stage]}`,
    '',
    ...lines,
    '',
    ACK_BUTTONS,
  ].join('\n');
}

export function formatRefillSnoozed(
  humanDuration: string,
  prefix: string = '[B:blue]🔕 Заглушено[/B]',
): string {
  return [
    `${prefix} на ${humanDuration}.`,
    'Если что-то пойдёт совсем плохо — никто не разбудит, имей в виду.',
    '',
    '[ACTION:🔔 Включить обратно]',
    SETTINGS_BUTTON,
  ].join('\n');
}

export function formatRefillDisabled(): string {
  return [
    '[B:red]🔇 Отключено[/B]',
    'Алёрты про дефициты hot-кошельков больше не приходят.',
    '',
    '[ACTION:🔔 Включить обратно]',
  ].join('\n');
}

export function formatRefillEnabled(): string {
  return [
    '[B:green]🔔 Включено[/B]',
    'Снова мониторю дефициты hot-кошельков. Если deficit есть прямо сейчас — увидишь его в следующие 5 минут.',
    '',
    SETTINGS_BUTTON,
  ].join('\n');
}

export function formatRefillSettings(cfg: InformerAlertConfig | null): string {
  const enabled = cfg?.enabled ?? true;
  const snoozedUntil = cfg?.snoozedUntil ?? null;
  const snoozed = snoozedUntil !== null && snoozedUntil > new Date();
  let status: string;
  let toggleButton: string;
  if (!enabled) {
    status = '[B:red]🔇 Отключено[/B]';
    toggleButton = '[ACTION:🔔 Включить обратно]';
  } else if (snoozed) {
    status = `[B:blue]🔕 Заглушено до ${snoozedUntil.toISOString()}[/B]`;
    toggleButton = '[ACTION:🔔 Включить обратно]';
  } else {
    status = '[B:green]🔔 Активно[/B]';
    toggleButton = '[ACTION:🔇 Совсем отключить]';
  }
  return [
    '⚙️ **Настройки алёртов про refill**',
    '',
    `Текущее состояние: ${status}`,
    '',
    toggleButton,
    '[ACTION:🔕 Заглушить 1 час]',
    '[ACTION:🔕 До утра 9:00]',
  ].join('\n');
}

function formatEur(amount: string): string {
  const n = new BigNumber(amount);
  const integer = n.integerValue(BigNumber.ROUND_DOWN).toString();
  const grouped = integer.replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
  const frac = n.minus(integer).toString();
  return frac === '0' ? `€${grouped}` : `€${grouped}${frac.substring(1)}`;
}

function poolTotalBadge(eurTotal: string): string {
  const tot = new BigNumber(eurTotal);
  const fmt = formatEur(eurTotal);
  if (tot.gt(LOW_POOL_EUR_THRESHOLD)) {
    return `[B:green]≈ ${fmt}[/B]`;
  }
  return `[B:yellow]≈ ${fmt}[/B]`;
}

function nativeWithTokenSuffix(native: string, asset: string): string {
  const n = new BigNumber(native);
  const integer = n.integerValue(BigNumber.ROUND_DOWN).toString();
  const grouped = integer.replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
  const frac = n.minus(integer).toString();
  const formatted = frac === '0' ? grouped : `${grouped}${frac.substring(1)}`;
  return `${formatted} ${asset.toUpperCase()}`;
}

function renderMiniAcquiringPool(
  pool: FiatPoolDigest,
  cgStatus: 'ok' | 'stale' | 'failed',
): string[] {
  const lines: string[] = ['## 💰 Mini-acquiring'];
  if (pool.chains.length === 0) {
    lines.push(`**Total: [B:yellow]≈ €0[/B]** _(пул пуст)_`);
    return lines;
  }
  lines.push(`**Total: ${poolTotalBadge(pool.eurTotal)}**`);
  lines.push('');
  for (const chain of pool.chains) {
    lines.push(`- **${chain.chain}** — ${formatEur(chain.eurTotal)}`);
    for (const role of chain.roles ?? []) {
      if (role.role === 'gas_funding') continue;
      const badge =
        role.role === 'hot_wallet'
          ? '[HOT_BADGE]HOT[/HOT_BADGE]'
          : '[COLD_BADGE]COLD[/COLD_BADGE]';
      const tint =
        role.role === 'hot_wallet'
          ? `[HOT]${formatEur(role.eurTotal)}[/HOT]`
          : `[COLD]${formatEur(role.eurTotal)}[/COLD]`;
      const eurPart = cgStatus === 'failed' ? '' : `${tint} `;
      const natives = role.tokens
        .map((t) => nativeWithTokenSuffix(t.native, t.asset))
        .join(' + ');
      lines.push(`  - ${badge} ${eurPart}(${natives})`);
    }
  }
  return lines;
}

function renderGatewayPool(
  pool: FiatPoolDigest,
  cgStatus: 'ok' | 'stale' | 'failed',
): string[] {
  const lines: string[] = ['## 🏦 Gateway'];
  if (pool.chains.length === 0) {
    lines.push(`**Total: [B:yellow]≈ €0[/B]** _(пул пуст)_`);
    return lines;
  }
  lines.push(`**Total: ${poolTotalBadge(pool.eurTotal)}**`);
  lines.push('');
  for (const chain of pool.chains) {
    const tokenSummary = (chain.flatTokens ?? [])
      .map((t) => nativeWithTokenSuffix(t.native, t.asset))
      .join(' + ');
    if (cgStatus === 'failed') {
      lines.push(`- **${chain.chain}**: ${tokenSummary}`);
    } else {
      lines.push(
        `- **${chain.chain}**: ${formatEur(chain.eurTotal)} (${tokenSummary})`,
      );
    }
  }
  return lines;
}

export function formatFiatBalances(r: FiatBalancesResult): string {
  const header = (() => {
    if (r.ratesCacheAgeMin === null) {
      return '💶 **Балансы в евро** _(курсы CoinGecko, впервые получены сейчас)_';
    }
    if (r.ratesCacheAgeMin === 0) {
      return '💶 **Балансы в евро** _(курсы CoinGecko, только что обновлены)_';
    }
    return `💶 **Балансы в евро** _(курсы CoinGecko, обновлены ${r.ratesCacheAgeMin} мин назад)_`;
  })();

  const statusBanner =
    r.coingeckoStatus === 'stale'
      ? `[C:yellow]⚠️ Курсы из старого кэша (последнее успешное обновление ${r.ratesCacheAgeMin ?? '?'} минут назад)[/C]`
      : r.coingeckoStatus === 'failed'
        ? '[C:red]⚠️ Курсы недоступны, показываю только native[/C]'
        : '';

  const sections: string[] = [header, ''];
  if (statusBanner) {
    sections.push(statusBanner, '');
  }

  const mini = r.pools.find((p) => p.poolName === 'mini-acquiring');
  const gateway = r.pools.find((p) => p.poolName === 'gateway');
  if (mini)
    sections.push(...renderMiniAcquiringPool(mini, r.coingeckoStatus), '');
  if (gateway)
    sections.push(...renderGatewayPool(gateway, r.coingeckoStatus), '');

  const allUnpriced = r.pools.flatMap((p) => p.unpricedAssets);
  if (allUnpriced.length > 0) {
    sections.push(
      "_Asset'ы не пересчитанные в EUR (нет mapping'а в CoinGecko):_",
    );
    for (const u of allUnpriced) {
      sections.push(
        `- [C:yellow]${u.native} ${u.asset.toUpperCase()} на ${u.chain}[/C]`,
      );
    }
    sections.push('');
  }

  sections.push(FIAT_FOOTER_BUTTONS);
  return sections.join('\n');
}

export function formatClientError(
  humanMessage: string,
  retryCode?: string,
): string {
  const retryBtn = retryCode ? `\n\n[ACTION:🔄 Повторить ${retryCode}]` : '';
  return `⚠️ ${humanMessage}${retryBtn}`;
}

export function formatButtonsOnlyHint(): string {
  return ['Я понимаю только кнопки 👇', '', OPERATOR_BUTTONS].join('\n');
}

export function formatWelcome(): string {
  return [
    'Я бот мониторинга Informer. Что нужно проверить?',
    '',
    OPERATOR_BUTTONS,
  ].join('\n');
}
