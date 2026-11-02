// Run with: node --test  (from livekit-agent/)
//
// A 1 kHz "sample rate" keeps chunks tiny: chunkMs 100 → 100 samples. Speech
// is a constant 2000 (RMS 2000), quiet is 200 (below the 400 speech level).
const test = require('node:test');
const assert = require('node:assert');
const { createVoiceprintGate } = require('./voiceprint-gate');

const CHUNK = 100;
const speech = () => new Int16Array(CHUNK).fill(2000);
const silence = () => new Int16Array(CHUNK);
const quiet = () => new Int16Array(CHUNK).fill(200);
const tick = () => new Promise((r) => setImmediate(r));
const isSpeech = (c) => c.length === CHUNK && c.every((x) => x === 2000);
const isZero = (c) => c.length === CHUNK && c.every((x) => x === 0);

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
      windows.push(w.length);
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
}

test('silence goes out one chunk late and never asks the embed service', async () => {
  const { g, out, windows } = gate([]);
  g.push(silence());
  await tick();
  assert.strictEqual(out.length, 0, 'waits for its look-ahead');
  await feed(g, [silence(), silence()]);
  assert.strictEqual(out.length, 2);
  assert.ok(out.every(isZero));
  assert.strictEqual(windows.length, 0);
});

test('audio below the speech level goes out as true silence', async () => {
  const { g, out } = gate([]);
  await feed(g, [quiet(), quiet()]);
  assert.ok(isZero(out[0]));
});

test("the owner's speech passes unchanged; speaking turns on, then off after two quiet chunks", async () => {
  const { g, out, speaking } = gate([OWN, OWN]);
  await feed(g, [speech(), speech(), silence(), silence(), silence()]);
  assert.strictEqual(out.length, 4);
  assert.ok(isSpeech(out[0]) && isSpeech(out[1]));
  assert.ok(isZero(out[2]) && isZero(out[3]));
  assert.deepStrictEqual(speaking, [true, false]);
});

test("the partner's voice on this phone is replaced with silence", async () => {
  const { g, out, speaking } = gate([LEAK, LEAK, LEAK]);
  await feed(g, [speech(), speech(), speech(), silence()]);
  assert.strictEqual(out.length, 3);
  assert.ok(out.every(isZero));
  assert.deepStrictEqual(speaking, []);
});

test('sounding like the owner is not enough without the margin over the partner', async () => {
  const { g, out } = gate([{ own: 0.5, other: 0.48 }]);
  await feed(g, [speech(), silence()]);
  assert.ok(isZero(out[0]));
});

test('one doubtful chunk inside speech is let through, the second in a row is not', async () => {
  const { g, out } = gate([OWN, LEAK, LEAK, OWN]);
  await feed(g, [speech(), speech(), speech(), speech(), silence()]);
  assert.strictEqual(out.length, 4);
  assert.ok(isSpeech(out[0]));
  assert.ok(isSpeech(out[1]), 'first failure tolerated');
  assert.ok(isZero(out[2]), 'second failure in a row cuts');
  assert.ok(isSpeech(out[3]), 'a passing chunk reopens');
});

test('the first chunk of new speech must pass on its own', async () => {
  const { g, out } = gate([LEAK, OWN]);
  await feed(g, [silence(), speech(), speech(), silence()]);
  assert.ok(isZero(out[0]));
  assert.ok(isZero(out[1]), 'no benefit of the doubt at the start');
  assert.ok(isSpeech(out[2]));
});

test('when the embed service fails the chunk is let through and the failure is reported', async () => {
  const { g, out, decisions } = gate([new Error('connection refused')]);
  await feed(g, [speech(), silence()]);
  assert.ok(isSpeech(out[0]));
  assert.strictEqual(decisions[0].failOpen, true);
  assert.strictEqual(decisions[0].error, 'connection refused');
});

test('chunks go out in order even when their answers come back out of order', async () => {
  const pending = [];
  const out = [];
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    score: () => new Promise((resolve) => pending.push(resolve)),
    onOutput: (c) => out.push(c),
  });
  await feed(g, [speech(), speech(), silence()]);
  assert.strictEqual(pending.length, 2);
  pending[1](OWN);
  await tick();
  assert.strictEqual(out.length, 0, 'chunk 1 is ready but chunk 0 is not');
  pending[0](OWN);
  await tick();
  assert.strictEqual(out.length, 2);
});

test('each judged window holds the chunk with its neighbours', async () => {
  const { g, windows } = gate([OWN, OWN]);
  await feed(g, [speech(), speech(), speech()]);
  assert.deepStrictEqual(windows, [200, 300]); // first chunk has no "before"
});

test('frames of any size are re-cut into whole chunks', async () => {
  const { g, out } = gate([OWN, OWN, OWN]);
  g.push(new Int16Array(250).fill(2000));
  g.push(new Int16Array(150).fill(2000));
  await tick();
  assert.strictEqual(out.length, 3);
  assert.ok(out.every((c) => c.length === CHUNK));
});

test('after close nothing more comes out', async () => {
  const pending = [];
  const out = [];
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    score: () => new Promise((resolve) => pending.push(resolve)),
    onOutput: (c) => out.push(c),
  });
  await feed(g, [speech(), speech()]);
  g.close();
  pending[0](OWN);
  await tick();
  g.push(speech());
  await tick();
  assert.strictEqual(out.length, 0);
});

test('a decision record carries the chunk, when it started, both scores and the embed time', async () => {
  // now(): 1010 chunk 0 starts, 1020 chunk 1 starts, 1030 chunk 0 is sent to
  // the embed service, 1040 its answer is in.
  let t = 1000;
  const { g, decisions } = gate([OWN], { now: () => (t += 10) });
  await feed(g, [speech(), silence()]);
  assert.deepStrictEqual(decisions[0], {
    index: 0, startedAt: 1010, own: 0.8, other: 0.1, pass: true, failOpen: false, error: null, latencyMs: 10,
  });
});
