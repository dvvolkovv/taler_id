/** Столбиков в дорожке: больше и не нарисуешь в пузыре. */
export const WAVEFORM_MAX_BARS = 64;

/** Два часа — заведомо не голосовое сообщение, а ошибка клиента. */
const MAX_DURATION_MS = 2 * 3600_000;

export interface VoiceMeta {
  waveform?: number[];
  durationMs?: number;
}

/**
 * Приводит присланные клиентом данные голосового к безопасному виду.
 *
 * Нужен по двум причинам. Во-первых, `Message.metadata` используется
 * служебными путями (сшивки аналитика, тип новости) — принимать оттуда что
 * попало нельзя, поэтому берутся ровно два известных ключа, остальное
 * отбрасывается молча.
 *
 * Во-вторых, дорожка идёт прямо в отрисовку: строка вместо числа или массив на
 * пять тысяч значений — это либо сломанный экран, либо мегабайт мусора в базе
 * на каждое сообщение.
 *
 * Возвращает null, если ничего пригодного не осталось — тогда сообщение просто
 * сохраняется без метаданных, как раньше.
 */
export function sanitizeVoiceMeta(input: VoiceMeta | undefined | null): VoiceMeta | null {
  if (!input || typeof input !== 'object') return null;
  const out: VoiceMeta = {};

  if (Array.isArray(input.waveform)) {
    const bars = input.waveform
      .filter((v): v is number => typeof v === 'number' && Number.isFinite(v))
      .map((v) => Math.min(1, Math.max(0, v)))
      .slice(0, WAVEFORM_MAX_BARS);
    if (bars.length > 0) out.waveform = bars;
  }

  const d = input.durationMs;
  if (typeof d === 'number' && Number.isFinite(d) && d > 0) {
    out.durationMs = Math.min(MAX_DURATION_MS, Math.round(d));
  }

  return Object.keys(out).length > 0 ? out : null;
}
