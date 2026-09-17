// Run with: node --test livekit-agent/
//
// The bug these cover: two participants' tracks were appended to the same
// Realtime input buffer as they arrived, so the model heard an interleave of
// both and locked onto one. Every assertion below is about the mix holding
// both voices on one continuous timeline.
const test = require('node:test');
const assert = require('node:assert');
const { createAudioMixer } = require('./audio-mixer');

const SAMPLE_RATE = 24000;
const FRAME_MS = 20;
const FRAME = (SAMPLE_RATE / 1000) * FRAME_MS; // 480

const mixer = (opts) =>
  createAudioMixer({ sampleRate: SAMPLE_RATE, frameMs: FRAME_MS, ...opts });

/** `n` samples at a constant level. */
const tone = (n, level) => Int16Array.from(new Array(n).fill(level));

test('both participants land in the same frame', () => {
  const m = mixer();
  m.add('alice');
  m.add('bob');
  m.push('alice', tone(FRAME, 1000));
  m.push('bob', tone(FRAME, 300));

  const frame = m.take();

  assert.strictEqual(frame.length, FRAME);
  // Summed, not one winning over the other — this is the whole point.
  assert.strictEqual(frame[0], 1300);
  assert.strictEqual(frame[FRAME - 1], 1300);
});

test('a silent participant does not erase the one who is talking', () => {
  const m = mixer();
  m.add('alice');
  m.add('bob'); // present, nothing pushed
  m.push('alice', tone(FRAME, 5000));

  assert.strictEqual(m.take()[0], 5000);
});

test('overlapping loud speech clamps instead of wrapping', () => {
  const m = mixer();
  m.add('alice');
  m.add('bob');
  m.push('alice', tone(FRAME, 30000));
  m.push('bob', tone(FRAME, 30000));

  const frame = m.take();

  assert.strictEqual(frame[0], 32767);
  assert.ok(frame.every((v) => v === 32767));
});

test('negative overlap clamps at the floor', () => {
  const m = mixer();
  m.add('alice');
  m.add('bob');
  m.push('alice', tone(FRAME, -30000));
  m.push('bob', tone(FRAME, -30000));

  assert.strictEqual(m.take()[0], -32768);
});

test('a frame longer than the tick is drained across ticks, in order', () => {
  const m = mixer();
  m.add('alice');
  // LiveKit chunking is not ours to choose: 60 ms arriving at once.
  m.push('alice', Int16Array.from([...new Array(FRAME).fill(100), ...new Array(FRAME).fill(200), ...new Array(FRAME).fill(300)]));

  assert.strictEqual(m.take()[0], 100);
  assert.strictEqual(m.take()[0], 200);
  assert.strictEqual(m.take()[0], 300);
  assert.strictEqual(m.take()[0], 0); // drained
});

test('a frame shorter than the tick is padded with silence, not stretched', () => {
  const m = mixer();
  m.add('alice');
  m.push('alice', tone(10, 700));

  const frame = m.take();

  assert.strictEqual(frame[0], 700);
  assert.strictEqual(frame[9], 700);
  assert.strictEqual(frame[10], 0);
  assert.strictEqual(frame.length, FRAME);
});

test('a burst drops the oldest audio rather than falling behind the call', () => {
  const m = mixer({ maxBacklogMs: 40 }); // two frames
  m.add('alice');
  m.push('alice', tone(FRAME, 111));
  m.push('alice', tone(FRAME, 222));
  m.push('alice', tone(FRAME, 333));

  // The 111 frame is gone; what plays next is the most recent audio.
  assert.strictEqual(m.take()[0], 222);
  assert.strictEqual(m.take()[0], 333);
});

test('pushed samples are copied, so a reused LiveKit buffer cannot rewrite them', () => {
  const m = mixer();
  m.add('alice');
  const reused = tone(FRAME, 900);
  m.push('alice', reused);
  reused.fill(-1); // LiveKit hands the same buffer to the next frame

  assert.strictEqual(m.take()[0], 900);
});

test('a participant who leaves stops contributing and frees the lane', () => {
  const m = mixer();
  m.add('alice');
  m.add('bob');
  m.push('alice', tone(FRAME, 400));
  m.push('bob', tone(FRAME, 400));

  m.remove('bob');

  assert.strictEqual(m.size, 1);
  assert.strictEqual(m.take()[0], 400);
});

test('size reports lanes, so an empty room can be told from a quiet one', () => {
  const m = mixer();
  assert.strictEqual(m.size, 0);
  m.add('alice');
  assert.strictEqual(m.size, 1);
  m.add('alice'); // re-subscribe must not double-count
  assert.strictEqual(m.size, 1);
  m.clear();
  assert.strictEqual(m.size, 0);
});

test('a single participant is passed through unchanged', () => {
  // The one-participant case has to stay bit-identical to the old behaviour,
  // which shipped and worked — the fix is only about the second voice.
  const m = mixer();
  m.add('alice');
  const speech = Int16Array.from(
    new Array(FRAME).fill(0).map((_, i) => Math.round(8000 * Math.sin(i / 7))),
  );
  m.push('alice', speech);

  assert.deepStrictEqual(Array.from(m.take()), Array.from(speech));
});
