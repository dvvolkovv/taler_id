import {
  OperatorRequiredList,
  OperatorRequiredItem,
  MiniAcquiringBalances,
  GatewaySystemWalletBalances,
  RefillDeficit,
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
