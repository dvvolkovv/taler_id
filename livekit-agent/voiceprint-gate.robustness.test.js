// Run with: node --test  (from livekit-agent/)
//
// The gate under bad weather: the embed service failing, a callback throwing,
// the audio stopping mid-phrase, a configuration that would spin forever.
const test = require('node:test');
const assert = require('node:assert');
const { createVoiceprintGate } = require('./voiceprint-gate');

const CHUNK = 100;
const speech = (v = 2000) => new Int16Array(CHUNK).fill(v);
const silence = () => new Int16Array(CHUNK);
const tick = () => new Promise((r) => setImmediate(r));
const isZero = (c) => c.every((x) => x === 0);
const shape = (out) => out.map((c) => (isZero(c) ? '0' : 'S')).join('');
const OWN = { own: 0.8, other: 0.1 };
const LEAK = { own: 0.1, other: 0.7 };

function gate(scores, extra = {}) {
  const out = [];
  const speaking = [];
  let i = 0;
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    score: async () => {
      const s = scores[i++];
      if (s instanceof Error) throw s;
      return s;
    },
    onOutput: (c) => out.push(c),
    onSpeaking: (on) => speaking.push(on),
    ...extra,
  });
  return { g, out, speaking };
}

async function feed(g, chunks) {
  for (const c of chunks) g.push(c);
  await tick();
  await tick();
}

test('F1 an embed failure inside the partner\'s speech lets through that chunk only', async () => {
  const { g, out } = gate([LEAK, LEAK, new Error('timeout'), LEAK, LEAK]);
  await feed(g, [speech(), speech(), speech(), speech(), speech(), silence()]);
  assert.strictEqual(shape(out), '00S00');
});

test('F2 a throwing callback neither stops the stream nor escapes as an unhandled rejection', async () => {
  let calls = 0;
  const { g } = gate([OWN, OWN, OWN], {
    onOutput: () => {
      calls += 1;
      if (calls === 1) throw new Error('engine hiccup');
    },
    onDecision: () => { throw new Error('log sink closed'); },
  });
  const rejections = [];
  const onRejection = (e) => rejections.push(e);
  process.on('unhandledRejection', onRejection);
  try {
    await feed(g, [speech(), speech(), speech(), silence()]);
    await new Promise((r) => setTimeout(r, 10));
  } finally {
    process.off('unhandledRejection', onRejection);
  }
  assert.strictEqual(rejections.length, 0, rejections.map((e) => e.message).join('; '));
  assert.strictEqual(calls, 3);
});

test('F3 end() lets out what was held, switches speaking off, and what follows is new speech', async () => {
  const { g, out, speaking } = gate([OWN, OWN, OWN, LEAK, OWN]);
  await feed(g, [speech(), speech()]);
  g.push(new Int16Array(40).fill(2000));
  g.end();
  await tick();
  await tick();
  assert.deepStrictEqual(out.map((c) => c.length), [100, 100, 40]);
  assert.deepStrictEqual(speaking, [true, false]);
  await feed(g, [speech(), speech(), silence()]);
  assert.strictEqual(shape(out.slice(3)), '0S', 'the first chunk after end() must pass on its own');
});

test('F4 a chunk length that rounds to no samples is refused instead of spinning forever', () => {
  assert.throws(
    () => createVoiceprintGate({ sampleRate: 24000, chunkMs: 0, score: async () => OWN, onOutput: () => {} }),
    RangeError,
  );
});

// X1/X2 need the judged windows, so they use their own small helper.
function gateWithWindows(scores) {
  const out = [];
  const windows = [];
  let i = 0;
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    score: async (w) => {
      windows.push(w);
      const s = scores[i++];
      if (s instanceof Error) throw s;
      return s;
    },
    onOutput: (c) => out.push(c),
  });
  return { g, out, windows };
}

test('X1 an embed failure on the first chunk of the partner\'s speech does not open the gate for the rest', async () => {
  const { g, out } = gateWithWindows([new Error('timeout'), LEAK, LEAK]);
  await feed(g, [silence(), speech(), speech(), speech(), silence()]);
  assert.strictEqual(shape(out), '0S00');
});

test('X2 after end() the next window does not reach back across the gap', async () => {
  const { g, windows } = gateWithWindows([OWN, OWN, OWN]);
  await feed(g, [speech(1000), speech(1100)]);
  g.end();
  await tick();
  await feed(g, [speech(1500), speech(1600)]);
  const first = (w) => w[0];
  assert.deepStrictEqual(windows.map(first), [1000, 1000, 1500], 'the window after the gap starts at the new audio');
  assert.strictEqual(windows[2].length, 2 * CHUNK);
});


test('F5 a callback that throws something other than an Error is still only logged', async () => {
  // eslint-disable-next-line no-throw-literal
  const { g } = gate([OWN, OWN, OWN], { onOutput: () => { throw undefined; } });
  const rejections = [];
  const onRejection = (e) => rejections.push(e);
  const errors = [];
  const saved = console.error;
  console.error = (...a) => errors.push(a.join(' '));
  process.on('unhandledRejection', onRejection);
  try {
    await feed(g, [speech(), speech(), speech(), silence()]);
    await new Promise((r) => setTimeout(r, 10));
  } finally {
    process.off('unhandledRejection', onRejection);
    console.error = saved;
  }
  assert.strictEqual(rejections.length, 0, String(rejections[0]));
  assert.ok(errors.some((m) => m.includes('onOutput callback failed: undefined')), errors.join('\n'));
});