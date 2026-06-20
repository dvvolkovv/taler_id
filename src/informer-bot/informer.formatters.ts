import type { InformerAlertConfig } from '@prisma/client';
import BigNumber from 'bignumber.js';
import {
  OperatorRequiredList,
  OperatorRequiredItem,
  MiniAcquiringBalances,
  GatewaySystemWalletBalances,
  RefillDeficit,
  FiatBalancesResult,
  FiatPoolDigest,
} from './informer.types';

// Human-readable labels in brackets so the mobile renderer (which uses the
// captured text as the button label) shows friendly buttons. Parser does
// substring matching to map back to action codes.
export const OPERATOR_BUTTONS =
  '[ACTION:📋 Кошельки оператора]\n' +
  '[ACTION:💰 Балансы mini-acquiring]\n' +
  '[ACTION:🏦 Системные кошельки gateway]';

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

function formatRow(item: OperatorRequiredItem): string {
  const at = item.created_at.replace('T', ' ').replace('Z', ' UTC');
  return [
    `**${item.withdraw_network} / ${item.withdraw_token}**`,
    `\`${item.withdraw_address}\``,
    `${item.withdraw_amount}`,
    at,
  ].join(' · ');
}

export function formatOperatorWalletsList(data: OperatorRequiredList): string {
  if (data.items.length === 0) {
    return [
      '📋 **Кошельки, требующие оператора**',
      '',
      'Всего: **0**. Очередь пуста — ничего делать не надо.',
      '',
      OPERATOR_BUTTONS,
    ].join('\n');
  }
  const lines = data.items.map((i) => `- ${formatRow(i)}`);
  return [
    '📋 **Кошельки, требующие оператора**',
    '',
    `Всего: **${data.total}** (стр. ${data.page}, по ${data.per_page})`,
    '',
    ...lines,
    '',
    OPERATOR_BUTTONS,
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
  const at = item.created_at.replace('T', ' ').replace('Z', ' UTC');
  return [
    '🚨 **Новый кошелёк ждёт оператора**',
    '',
    `Сеть: \`${item.withdraw_network}\``,
    `Токен: \`${item.withdraw_token}\``,
    `Адрес: \`${item.withdraw_address}\``,
    `Сумма: \`${item.withdraw_amount}\``,
    `Создан: ${at}`,
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

export function formatRefillSettings(
  cfg: InformerAlertConfig | null,
): string {
  const enabled = cfg?.enabled ?? true;
  const snoozedUntil = cfg?.snoozedUntil ?? null;
  const snoozed = snoozedUntil !== null && snoozedUntil > new Date();
  let status: string;
  let toggleButton: string;
  if (!enabled) {
    status = '[B:red]🔇 Отключено[/B]';
    toggleButton = '[ACTION:🔔 Включить обратно]';
  } else if (snoozed) {
    status = `[B:blue]🔕 Заглушено до ${snoozedUntil!.toISOString()}[/B]`;
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
  if (mini) sections.push(...renderMiniAcquiringPool(mini, r.coingeckoStatus), '');
  if (gateway) sections.push(...renderGatewayPool(gateway, r.coingeckoStatus), '');

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
    '',
    SETTINGS_BUTTON,
  ].join('\n');
}
