/** Максимальная длина логина, которую готовы принять за упоминание. */
const MAX_HANDLE = 32;

/**
 * Упоминания вида `@login` в тексте.
 *
 * `(?<![\w@])` отсекает два ложных срабатывания разом: адрес почты
 * (`anna@taler.test` — перед @ буква) и двойную собаку. Логин — буквы, цифры и
 * подчёркивание, минимум два символа: одиночная буква после @ почти всегда
 * опечатка, а не обращение.
 *
 * Возвращает логины в нижнем регистре и без повторов — сравнение всё равно
 * регистронезависимое, а порядок сохраняется по первому появлению.
 */
export function extractMentionHandles(content: string | null | undefined): string[] {
  if (!content) return [];
  const re = new RegExp(`(?<![\\w@])@([A-Za-z0-9_]{2,${MAX_HANDLE}})`, 'g');
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of content.matchAll(re)) {
    const handle = m[1].toLowerCase();
    if (seen.has(handle)) continue;
    seen.add(handle);
    out.push(handle);
  }
  return out;
}

/**
 * Кого из участников беседы упомянули.
 *
 * Разрешаем только по участникам: иначе упоминанием можно было бы пробить
 * уведомление постороннему человеку, которого в беседе нет. Автора самого себя
 * не упоминаем — это уведомление самому себе.
 */
export function resolveMentions(
  content: string | null | undefined,
  participants: Array<{ userId: string; username?: string | null }>,
  authorId: string,
): string[] {
  const handles = extractMentionHandles(content);
  if (handles.length === 0) return [];

  const byHandle = new Map<string, string>();
  for (const p of participants) {
    if (!p.username) continue;
    byHandle.set(p.username.toLowerCase(), p.userId);
  }

  const out: string[] = [];
  for (const h of handles) {
    const userId = byHandle.get(h);
    if (!userId || userId === authorId) continue;
    out.push(userId);
  }
  return out;
}
