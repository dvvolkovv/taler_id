'use strict';
/**
 * Numbers and the markdown page for bench/interpreter-bench.js. Pure, so the
 * arithmetic is tested; the bench itself needs LiveKit, OpenAI and the embed
 * service.
 */

function percentile(values, p) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

function summarize(values) {
  if (values.length === 0) return { n: 0 };
  return {
    n: values.length,
    min: percentile(values, 0),
    p10: percentile(values, 10),
    median: percentile(values, 50),
    p90: percentile(values, 90),
    max: percentile(values, 100),
  };
}

/** ms from `from` to the first 10 ms frame at or above `threshold` RMS, before `until`; null if none. */
function firstVoicedAfter(frames, from, until, threshold = 300) {
  for (const f of frames) if (f.t >= from && f.t < until && f.rms >= threshold) return f.t - from;
  return null;
}

/**
 * Milliseconds of frames at or above `threshold` RMS inside [from, to). Each
 * frame counts for its own `ms`: LiveKit picks the frame size
 * (speaker-timeline.js), and a flat 10 ms on 20 ms frames would halve the
 * leak this measures. A frame without `ms` counts as `defaultMs`.
 */
function voicedMs(frames, from, to, threshold = 300, defaultMs = 10) {
  let ms = 0;
  for (const f of frames) if (f.t >= from && f.t < to && f.rms >= threshold) ms += f.ms ?? defaultMs;
  return ms;
}

// A fail-open chunk has no score (own and other both null) and says nothing
// about anyone's voice; left in, it would shift a percentile.
const hasScore = (s) => Number.isFinite(s.own) && Number.isFinite(s.other);

/**
 * Thresholds that would separate the owner's own speech from sound intruding
 * on the owner's phone (the partner's voice, the earpiece's translation):
 * midpoints between the owner's 10th percentile and the intruders' 90th.
 */
function suggestThresholds(own, intruder) {
  const round = (x) => Math.round(x * 100) / 100;
  const o = own.filter(hasScore);
  const i = intruder.filter(hasScore);
  const ownSim = percentile(o.map((s) => s.own), 10);
  const intSim = percentile(i.map((s) => s.own), 90);
  const ownGap = percentile(o.map((s) => s.own - s.other), 10);
  const intGap = percentile(i.map((s) => s.own - s.other), 90);
  if (ownSim === null || intSim === null) return null;
  return {
    threshold: round((ownSim + intSim) / 2),
    margin: round((ownGap + intGap) / 2),
    thresholdSeparates: ownSim > intSim,
    marginSeparates: ownGap > intGap,
  };
}

const fmt = (x) => (x === null || x === undefined ? '—' : typeof x === 'number' && !Number.isInteger(x) ? x.toFixed(2) : String(x));
const five = (s) => (s.n === 0 ? '—' : [s.min, s.p10, s.median, s.p90, s.max].map(fmt).join(' / '));

/**
 * Captions and transcripts are model output: a `|` would open a table column
 * and a newline would start a row or a list item of its own. A missing value
 * gives '', so `mdEscape(x) || '—'` still falls back.
 */
function mdEscape(text) {
  if (text === null || text === undefined) return '';
  return String(text)
    .replace(/\\/g, '\\\\')
    .replace(/[|*_`]/g, '\\$&')
    .replace(/\s*[\r\n]+\s*/g, ' ')
    .trim();
}

function renderReport(r) {
  const c = r.config;
  const lines = [
    `# Стенд переводчика — ${r.pair} — ${r.startedAt}`,
    '',
    `Синхронная модель \`${c.model}\`, фразовая \`${c.fallbackModel}\`; τ=${c.threshold}, δ=${c.margin}, кусок ${c.chunkMs} мс, гистерезис ${c.hysteresis}.`,
    '',
    '## Задержка: от начала фразы до первого звука перевода',
    '',
    '| Фраза | Направление | Движок | мс |',
    '|---|---|---|---|',
    ...r.latencies.map((l) => `| ${mdEscape(l.phrase)} | ${mdEscape(l.direction)} | ${mdEscape(l.engine)} | ${fmt(l.ms)} |`),
    '',
    '## Должно быть тихо',
    '',
    '| Ситуация | Слышно у слушателя, мс |',
    '|---|---|',
    ...r.silentChecks.map((s) => `| ${mdEscape(s.situation)} | ${fmt(s.voicedMs)} |`),
    '',
    '## Сверка голоса',
    '',
    '| Группа | n | s_own: min / p10 / медиана / p90 / max | s_own − s_other: min / p10 / медиана / p90 / max | пропущено |',
    '|---|---|---|---|---|',
    ...r.scoreGroups.map((g) => {
      const own = summarize(g.scores.map((s) => s.own));
      const gap = summarize(g.scores.map((s) => s.own - s.other));
      return `| ${mdEscape(g.group)} | ${g.scores.length} | ${five(own)} | ${five(gap)} | ${g.scores.filter((s) => s.pass).length} |`;
    }),
    '',
    '## Предлагаемые пороги',
    '',
    r.suggestion
      ? `τ = ${r.suggestion.threshold} (разделяет: ${r.suggestion.thresholdSeparates ? 'да' : 'нет'}), δ = ${r.suggestion.margin} (разделяет: ${r.suggestion.marginSeparates ? 'да' : 'нет'})`
      : 'Недостаточно данных.',
    '',
    '## Субтитры',
    '',
    ...r.captions.map((cap) => `- ${mdEscape(cap.listener)} / ${mdEscape(cap.role)}: «${mdEscape(cap.text)}»`),
    '',
    '## Речь, уже на языке перевода',
    '',
    '| Вход | Цель | Озвучено, с | Текст на выходе |',
    '|---|---|---|---|',
    ...r.sameLanguage.map((s) => `| ${mdEscape(s.input)} | ${mdEscape(s.target)} | ${fmt(s.voicedSeconds)} | ${mdEscape(s.transcript) || '—'} |`),
    '',
    '## Сервис сверки',
    '',
    `Время ответа, мс (min / p10 / медиана / p90 / max): ${five(r.embedLatency)}`,
    '',
    '## Пропуски без проверки (fail-open)',
    '',
    String(r.failOpen),
    '',
  ];
  return lines.join('\n');
}

module.exports = { percentile, summarize, firstVoicedAfter, voicedMs, suggestThresholds, renderReport };
