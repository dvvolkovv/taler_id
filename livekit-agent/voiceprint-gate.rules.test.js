// Run with: node --test  (from livekit-agent/)
//
// The gate's rules one by one — the knobs the bench will turn (threshold,
// margin, hysteresis, window) must each be pinned, or a slip in one of them
// goes unnoticed until it leaks a voice.
const test = require('node:test');
const assert = require('node:assert');
const { createVoiceprintGate } = require('./voiceprint-gate');

const CHUNK = 100;
const speech = (v = 2000) => new Int16Array(CHUNK).fill(v);
const silence = () => new Int16Array(CHUNK);
const tick = () => new Promise((r) => setImmediate(r));
const isSpeech = (c) => c.length === CHUNK && c.some((x) => x !== 0);
const isZero = (c) => c.every((x) => x === 0);
const shape = (out) => out.map((c) => (isZero(c) ? '0' : 'S')).join('');

const OWN = { own: 0.8, other: 0.1 };
const LEAK = { own: 0.1, other: 0.7 };

function gate(scores, extra = {}) {
  const out = [];
  const speaking = [];
  const decisions = [];
  const windows = [];
  let i = 0;
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    speechRms: 400,
    threshold: 0.25,
    margin: 0.05,
    hysteresis: 2,
    score: async (w) => {
      windows.push(w);
      const s = scores[i++];
      if (s instanceof Error) throw s;
      return s;
    },
    onOutput: (c) => out.push(c),
    onSpeaking: (on) => speaking.push(on),
    onDecision: (d) => decisions.push(d),
    ...extra,
  });
  return { g, out, speaking, decisions, windows };
}

async function feed(g, chunks) {
  for (const c of chunks) g.push(c);
  await tick();
  await tick();
}

test('A1 speech after a pause is new speech again: its first chunk gets no benefit of the doubt', async () => {
  const { g, out } = gate([OWN, OWN, LEAK, OWN]);
  await feed(g, [speech(), speech(), silence(), speech(), speech(), silence()]);
  assert.strictEqual(shape(out), 'SS00S');
});

test('A2 only failures in a row count: a pass in between resets the streak', async () => {
  const { g, out } = gate([OWN, LEAK, OWN, LEAK]);
  await feed(g, [speech(), speech(), speech(), speech(), silence()]);
  assert.strictEqual(shape(out), 'SSSS');
});

test('A3 a margin over the partner is not enough without sounding like the owner', async () => {
  const { g, out } = gate([{ own: 0.2, other: 0.0 }]);
  await feed(g, [speech(), silence()]);
  assert.strictEqual(shape(out), '0');
});

test('A4 the window is the previous chunk, the chunk and the next one, in that order', async () => {
  const { g, windows } = gate([OWN, OWN, OWN]);
  await feed(g, [speech(1000), speech(1100), speech(1200), speech(1300)]);
  const parts = (w) => Array.from({ length: w.length / CHUNK }, (_, k) => w[k * CHUNK]);
  assert.deepStrictEqual(windows.map(parts), [[1000, 1100], [1000, 1100, 1200], [1100, 1200, 1300]]);
});

test('A5 hysteresis is a setting: 1 cuts at the first failure, 3 at the third', async () => {
  const one = gate([OWN, LEAK, OWN], { hysteresis: 1 });
  await feed(one.g, [speech(), speech(), speech(), silence()]);
  assert.strictEqual(shape(one.out), 'S0S');
  const three = gate([OWN, LEAK, LEAK, LEAK, OWN], { hysteresis: 3 });
  await feed(three.g, [speech(), speech(), speech(), speech(), speech(), silence()]);
  assert.strictEqual(shape(three.out), 'SSS0S');
});

test('A6 one quiet chunk between phrases does not switch speaking off', async () => {
  const { g, speaking } = gate([OWN, OWN, OWN, OWN]);
  await feed(g, [speech(), speech(), silence(), speech(), speech(), silence(), silence(), silence()]);
  assert.deepStrictEqual(speaking, [true, false]);
});

test('A7 answers coming back in reverse order give the same output as in order', async () => {
  const pending = [];
  const out = [];
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    score: () => new Promise((resolve) => pending.push(resolve)),
    onOutput: (c) => out.push(c),
  });
  await feed(g, [speech(), speech(), speech(), silence()]);
  pending[2](LEAK);
  pending[1](LEAK);
  await tick();
  assert.strictEqual(out.length, 0);
  pending[0](OWN);
  await tick();
  assert.strictEqual(shape(out), 'SS0');
});

test('A8 after close no decision is reported either', async () => {
  const pending = [];
  const decisions = [];
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    score: () => new Promise((resolve) => pending.push(resolve)),
    onOutput: () => {},
    onDecision: (d) => decisions.push(d),
  });
  await feed(g, [speech(), speech()]);
  g.close();
  pending[0](OWN);
  await tick();
  assert.strictEqual(decisions.length, 0);
});
