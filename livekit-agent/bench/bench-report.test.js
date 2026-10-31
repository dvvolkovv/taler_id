// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const r = require('./bench-report');

test('percentile and summary', () => {
  assert.strictEqual(r.percentile([], 50), null);
  assert.strictEqual(r.percentile([5, 1, 3], 0), 1);
  assert.strictEqual(r.percentile([5, 1, 3], 100), 5);
  assert.deepStrictEqual(r.summarize([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), { n: 10, min: 1, p10: 1, median: 5, p90: 9, max: 10 });
  assert.deepStrictEqual(r.summarize([]), { n: 0 });
});

test('first voiced frame and voiced time inside a window', () => {
  const frames = [
    { t: 100, rms: 10 }, { t: 110, rms: 900 }, { t: 120, rms: 800 }, { t: 300, rms: 1000 },
  ];
  assert.strictEqual(r.firstVoicedAfter(frames, 100, 200), 10);
  assert.strictEqual(r.firstVoicedAfter(frames, 130, 200), null);
  assert.strictEqual(r.voicedMs(frames, 100, 200), 20);
  assert.strictEqual(r.voicedMs(frames, 0, 1000), 30);
});

test('thresholds sit between the owner and the intruders', () => {
  const own = Array.from({ length: 10 }, (_, i) => ({ own: 0.6 + i * 0.02, other: 0.1 }));
  const intruder = Array.from({ length: 10 }, (_, i) => ({ own: 0.04 + i * 0.01, other: 0.5 }));
  // owner: s_own p10 0.60, gap p10 0.50; intruders: s_own p90 0.12, gap p90 -0.38
  assert.deepStrictEqual(r.suggestThresholds(own, intruder), {
    threshold: 0.36, margin: 0.06, thresholdSeparates: true, marginSeparates: true,
  });
});

test('overlapping scores are reported as not separating', () => {
  const own = [{ own: 0.3, other: 0.25 }];
  const intruder = [{ own: 0.35, other: 0.2 }];
  const s = r.suggestThresholds(own, intruder);
  assert.strictEqual(s.thresholdSeparates, false);
  assert.strictEqual(s.marginSeparates, false);
  assert.strictEqual(r.suggestThresholds([], intruder), null);
});

test('the report page carries every section', () => {
  const md = r.renderReport({
    pair: 'ru-de',
    startedAt: '2026-11-01T10:00:00.000Z',
    config: { model: 'gpt-realtime-translate', fallbackModel: 'gpt-realtime-2025-08-28', threshold: 0.25, margin: 0.05, chunkMs: 500, hysteresis: 2 },
    latencies: [{ phrase: 'ru-1', direction: 'ru→de', engine: 'simultaneous', ms: 1840 }],
    silentChecks: [{ situation: 'leak', voicedMs: 0 }],
    scoreGroups: [{ group: 'own A', scores: [{ own: 0.7, other: 0.1, pass: true }] }],
    suggestion: { threshold: 0.36, margin: 0.21, thresholdSeparates: true, marginSeparates: true },
    captions: [{ listener: 'bench-b', role: 'translation', text: 'Guten Tag' }],
    sameLanguage: [{ input: 'de-1', target: 'de', voicedSeconds: 0, transcript: '' }],
    embedLatency: { n: 3, min: 20, p10: 20, median: 31, p90: 55, max: 55 },
    failOpen: 0,
  });
  for (const part of ['ru-de', '1840', 'leak', 'own A', '0.36', 'Guten Tag', 'de-1', '20 / 20 / 31 / 55 / 55', 'fail-open']) {
    assert.ok(md.includes(part), part);
  }
});

const emptyReport = (over) => ({
  pair: 'ru-sk',
  startedAt: '2026-11-01T10:00:00.000Z',
  config: { model: 'm', fallbackModel: 'm2', threshold: 0.25, margin: 0.05, chunkMs: 500, hysteresis: 2 },
  latencies: [],
  silentChecks: [],
  scoreGroups: [],
  suggestion: null,
  captions: [],
  sameLanguage: [],
  embedLatency: { n: 0 },
  failOpen: 0,
  ...over,
});

test('percentile of a single value is that value', () => {
  for (const p of [0, 37, 100]) assert.strictEqual(r.percentile([7], p), 7);
});

test('no intruder chunks is not enough data to suggest thresholds', () => {
  assert.strictEqual(r.suggestThresholds([{ own: 0.6, other: 0.1 }], []), null);
});

test('fail-open chunks (no score) do not move the suggested thresholds', () => {
  const clean = Array.from({ length: 20 }, (_, i) => ({ own: 0.6 + i * 0.01, other: 0.1 }));
  // Few intruder chunks: two unscored ones would move their percentiles past rounding.
  const intruder = Array.from({ length: 5 }, (_, i) => ({ own: 0.1 + i * 0.05, other: 0.6 }));
  const failOpen = { own: null, other: null };
  assert.deepStrictEqual(
    r.suggestThresholds([...clean, failOpen, failOpen], [...intruder, failOpen, failOpen]),
    r.suggestThresholds(clean, intruder),
  );
});

test('voiced time counts each frame for its own length', () => {
  const frames = [{ t: 100, rms: 10, ms: 10 }, { t: 110, rms: 900, ms: 20 }, { t: 130, rms: 800, ms: 5 }, { t: 300, rms: 1000, ms: 10 }];
  assert.strictEqual(r.voicedMs(frames, 100, 200), 25);
  assert.strictEqual(r.voicedMs([{ t: 0, rms: 900 }, { t: 10, rms: 900 }], 0, 100), 20); // no ms: 10 each
});

test('model text cannot break a table row or a list item', () => {
  const md = r.renderReport(emptyReport({
    captions: [{ listener: 'bench-b', role: 'translation', text: 'raz | dva\ntri * štyri_ pať' }],
    sameLanguage: [{ input: 'sk-1', target: 'sk', voicedSeconds: 1, transcript: 'a | b\nc' }],
  }));
  assert.ok(!md.includes('raz | dva') && !md.includes('dva\ntri'), md);
  assert.ok(!md.includes('a | b\nc'), md);
  assert.ok(md.includes('raz \\| dva') && md.includes('a \\| b'), md);
});

test('a missing transcript shows as —, not as "undefined"', () => {
  const md = r.renderReport(emptyReport({ sameLanguage: [{ input: 'de-1', target: 'de', voicedSeconds: 0, transcript: undefined }] }));
  const row = md.split('\n').find((l) => l.includes('de-1'));
  assert.ok(row.endsWith('| — |') && !row.includes('undefined'), row);
});

test('without a suggestion the report says there is not enough data', () => {
  const md = r.renderReport(emptyReport({}));
  assert.ok(md.includes('Недостаточно данных.'));
  assert.ok(!md.includes('разделяет'));
});
