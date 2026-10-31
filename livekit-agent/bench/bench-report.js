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

/** Milliseconds of 10 ms frames at or above `threshold` RMS inside [from, to). */
function voicedMs(frames, from, to, threshold = 300) {
  let n = 0;
  for (const f of frames) if (f.t >= from && f.t < to && f.rms >= threshold) n += 1;
  return n * 10;
}

/**
 * Thresholds that would separate the owner's own speech from sound intruding
 * on the owner's phone (the partner's voice, the earpiece's translation):
 * midpoints between the owner's 10th percentile and the intruders' 90th.
 */
function suggestThresholds(own, intruder) {
  const round = (x) => Math.round(x * 100) / 100;
  const ownSim = percentile(own.map((s) => s.own), 10);
  const intSim = percentile(intruder.map((s) => s.own), 90);
  const ownGap = percentile(own.map((s) => s.own - s.other), 10);
  const intGap = percentile(intruder.map((s) => s.own - s.other), 90);
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
    ...r.latencies.map((l) => `| ${l.phrase} | ${l.direction} | ${l.engine} | ${fmt(l.ms)} |`),
    '',
    '## Должно быть тихо',
    '',
    '| Ситуация | Слышно у слушателя, мс |',
    '|---|---|',
    ...r.silentChecks.map((s) => `| ${s.situation} | ${s.voicedMs} |`),
    '',
    '## Сверка голоса',
    '',
    '| Группа | n | s_own: min / p10 / медиана / p90 / max | s_own − s_other: min / p10 / медиана / p90 / max | пропущено |',
    '|---|---|---|---|---|',
    ...r.scoreGroups.map((g) => {
      const own = summarize(g.scores.map((s) => s.own));
      const gap = summarize(g.scores.map((s) => s.own - s.other));
      return `| ${g.group} | ${g.scores.length} | ${five(own)} | ${five(gap)} | ${g.scores.filter((s) => s.pass).length} |`;
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
    ...r.captions.map((cap) => `- ${cap.listener} / ${cap.role}: «${cap.text}»`),
    '',
    '## Речь, уже на языке перевода',
    '',
    '| Вход | Цель | Озвучено, с | Текст на выходе |',
    '|---|---|---|---|',
    ...r.sameLanguage.map((s) => `| ${s.input} | ${s.target} | ${fmt(s.voicedSeconds)} | ${s.transcript || '—'} |`),
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
