// Run with: node --test  (from livekit-agent/)
//
// The bug these cover: while the model spoke a translation, the input buffer
// was left uncut, so everything said meanwhile piled into one commit and came
// back as a fragment. Assertions are about each utterance getting its own cut.
const test = require('node:test');
const assert = require('node:assert');
const { createTurnTaker } = require('./translator-turns');

const SILENCE_MS = 600;
const FORCE_MS = 7000;

/** Records what the turn taker asked the session to do, in order. */
function taker(opts = {}) {
  const calls = [];
  const t = createTurnTaker({
    silenceMs: SILENCE_MS,
    forceMs: FORCE_MS,
    onCommit: (r) => calls.push(['commit', r]),
    onRespond: (r) => calls.push(['respond', r]),
    onDrop: (r) => calls.push(['drop', r]),
    ...opts,
  });
  return { t, calls, kinds: () => calls.map((c) => c[0]) };
}

/** Speech from `from` to `to`, then silence long enough to close the turn. */
function utterance(t, from, durationMs) {
  let now = from;
  for (; now < from + durationMs; now += 20) t.feed(true, now);
  for (let i = 0; i <= SILENCE_MS / 20 + 1; i++, now += 20) t.feed(false, now);
  return now;
}

test('a pause closes the turn and asks for the translation', () => {
  const { t, calls } = taker();

  utterance(t, 0, 1000);

  assert.deepStrictEqual(calls, [
    ['commit', 'silence'],
    ['respond', 'silence'],
  ]);
});

test('speech is cut while the model is still speaking — the buffer never piles up', () => {
  const { t, calls } = taker();

  let now = utterance(t, 0, 1000); // turn 1 → commit + respond
  t.responseCreated();
  calls.length = 0;

  now = utterance(t, now, 1000); // turn 2, mid-response
  utterance(t, now, 1000); // turn 3, still mid-response

  // Both were cut at their own boundary. This is the fix: before it, neither
  // commit happened and turns 2 and 3 fused into one lump on response.done.
  assert.deepStrictEqual(calls, [
    ['commit', 'silence'],
    ['commit', 'silence'],
  ]);
  assert.strictEqual(t.queued, 2);
});

test('queued turns are spoken one at a time as the model frees up', () => {
  const { t, calls } = taker();

  let now = utterance(t, 0, 1000);
  t.responseCreated();
  now = utterance(t, now, 1000);
  utterance(t, now, 1000);
  calls.length = 0;

  t.responseDone();
  assert.deepStrictEqual(calls, [['respond', 'queued']]);
  assert.strictEqual(t.queued, 1);

  t.responseCreated();
  t.responseDone();
  assert.deepStrictEqual(calls, [['respond', 'queued'], ['respond', 'queued']]);
  assert.strictEqual(t.queued, 0);
});

test('nothing is requested when the queue is empty', () => {
  const { t, calls } = taker();

  utterance(t, 0, 1000);
  t.responseCreated();
  calls.length = 0;

  t.responseDone();

  assert.deepStrictEqual(calls, []);
});

test('a backlog past the cap is dropped loudly, not allowed to drift', () => {
  const { t, calls } = taker({ maxQueued: 1 });

  let now = utterance(t, 0, 1000);
  t.responseCreated();
  calls.length = 0;

  now = utterance(t, now, 1000); // queued
  utterance(t, now, 1000); // over the cap

  assert.deepStrictEqual(calls, [
    ['commit', 'silence'],
    ['commit', 'silence'],
    ['drop', 'silence'],
  ]);
  assert.strictEqual(t.queued, 1);
});

test('an overflowing turn is still committed, so its audio is not lost', () => {
  const { t, calls } = taker({ maxQueued: 0 });

  let now = utterance(t, 0, 1000);
  t.responseCreated();
  calls.length = 0;

  utterance(t, now, 1000);

  // Commit before drop: the words reach the conversation even when we decline
  // to have them spoken.
  assert.deepStrictEqual(calls.map((c) => c[0]), ['commit', 'drop']);
});

test('a short silence inside a sentence does not cut it', () => {
  const { t, kinds } = taker();

  let now = 0;
  for (; now < 1000; now += 20) t.feed(true, now);
  for (let i = 0; i < 10; i++, now += 20) t.feed(false, now); // 200 ms
  for (; now < 3000; now += 20) t.feed(true, now);

  assert.deepStrictEqual(kinds(), []);
  assert.ok(t.speaking);
});

test('someone who never pauses is still cut into pieces', () => {
  const { t, calls } = taker();

  for (let now = 0; now <= FORCE_MS + 100; now += 20) t.feed(true, now);

  assert.deepStrictEqual(calls, [
    ['commit', 'force'],
    ['respond', 'force'],
  ]);
});

test('silence alone never produces a commit', () => {
  const { t, kinds } = taker();

  for (let now = 0; now < 5000; now += 20) t.feed(false, now);

  assert.deepStrictEqual(kinds(), []);
});

test('flush closes an open turn when frames stop arriving', () => {
  const { t, calls } = taker();

  for (let now = 0; now < 1000; now += 20) t.feed(true, now);
  const closed = t.flush('mute');

  assert.ok(closed);
  assert.deepStrictEqual(calls, [['commit', 'mute'], ['respond', 'mute']]);
});

test('flush on a closed turn does nothing', () => {
  const { t, kinds } = taker();

  assert.strictEqual(t.flush('mute'), false);
  assert.deepStrictEqual(kinds(), []);
});

test('reset clears a stuck response so a reconnect starts clean', () => {
  const { t } = taker();

  utterance(t, 0, 1000);
  t.responseCreated();
  utterance(t, 2000, 1000);
  assert.strictEqual(t.queued, 1);

  t.reset();

  assert.strictEqual(t.queued, 0);
  assert.strictEqual(t.responding, false);
  assert.strictEqual(t.speaking, false);
});
