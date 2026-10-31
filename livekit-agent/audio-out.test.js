// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { applyGain, createFrameQueue } = require('./audio-out');

test('gain 1 leaves the samples alone', () => {
  const s = Int16Array.from([1, -2, 3]);
  assert.strictEqual(applyGain(s, 1), s);
  assert.deepStrictEqual(Array.from(s), [1, -2, 3]);
});

test('gain scales in place and clamps at full scale', () => {
  const s = Int16Array.from([1000, -1000, 30000, -30000]);
  applyGain(s, 2);
  assert.deepStrictEqual(Array.from(s), [2000, -2000, 32767, -32768]);
});

test('frames reach captureFrame one at a time, in order', async () => {
  const started = [];
  let active = 0;
  let maxActive = 0;
  const source = {
    async captureFrame(frame) {
      active += 1;
      maxActive = Math.max(maxActive, active);
      started.push(frame);
      await new Promise((r) => setImmediate(r));
      active -= 1;
    },
  };
  const queue = createFrameQueue(source, 'en');
  queue.push('a');
  queue.push('b');
  queue.push('c');
  await new Promise((r) => setTimeout(r, 20));
  assert.deepStrictEqual(started, ['a', 'b', 'c']);
  assert.strictEqual(maxActive, 1);
});
