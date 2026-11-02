// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { createPresenceWatch } = require('./presence-watch');

function setup({ graceMs = 60000, onGone, log } = {}) {
  const timers = [];
  const gone = [];
  const watch = createPresenceWatch({
    people: ['a', 'b'],
    graceMs,
    onGone: onGone || ((p) => gone.push(p)),
    setTimer: (fn, ms) => {
      const t = { fn, ms, cleared: false };
      timers.push(t);
      return t;
    },
    clearTimer: (t) => { t.cleared = true; },
    ...(log ? { log } : {}),
  });
  const live = () => timers.filter((t) => !t.cleared && !t.fired);
  const fire = (t) => { t.fired = true; t.fn(); };
  return { watch, timers, gone, live, fire };
}

test('both people get the grace period to show up at all', () => {
  const { watch, live, fire, gone } = setup();
  assert.strictEqual(live().length, 2);
  watch.arrive('a#phone');
  assert.strictEqual(live().length, 1);
  fire(live()[0]);
  assert.deepStrictEqual(gone, ['b']);
});

test('leaving starts the clock and coming back stops it', () => {
  const { watch, live, gone } = setup();
  watch.arrive('a#phone');
  watch.arrive('b#phone');
  watch.leave('b#phone');
  assert.strictEqual(live().length, 1);
  assert.strictEqual(live()[0].ms, 60000);
  watch.arrive('b#phone');
  assert.strictEqual(live().length, 0);
  assert.deepStrictEqual(gone, []);
});

test('a person on two devices is present until the last one leaves', () => {
  const { watch, live } = setup();
  watch.arrive('a#phone');
  watch.arrive('a#tablet');
  watch.arrive('b#phone');
  watch.leave('a#phone');
  assert.strictEqual(live().length, 0);
  assert.deepStrictEqual(watch.identitiesOf('a'), ['a#tablet']);
  watch.leave('a#tablet');
  assert.strictEqual(live().length, 1);
  assert.deepStrictEqual(watch.presentPeople(), ['b']);
});

test('strangers are ignored', () => {
  const { watch } = setup();
  watch.arrive('voice-interpreter');
  watch.arrive('c#phone');
  assert.deepStrictEqual(watch.presentPeople(), []);
  assert.deepStrictEqual(watch.identitiesOf('c'), []);
});

test('after close nobody is reported gone', () => {
  const { watch, timers, gone } = setup();
  watch.close();
  assert.ok(timers.every((t) => t.cleared));
  timers[0].fn();
  assert.deepStrictEqual(gone, []);
});

// --- review 13 ---

test('the clock runs for graceMs, not a built-in minute', () => {
  const { watch, live } = setup({ graceMs: 45000 });
  assert.deepStrictEqual(live().map((t) => t.ms), [45000, 45000]);
  watch.arrive('a#phone');
  watch.leave('a#phone');
  assert.deepStrictEqual(live().map((t) => t.ms), [45000, 45000]);
});

test("one person showing up does not stop the other one's clock", () => {
  const { watch, live, fire, gone } = setup();
  watch.arrive('b#phone');
  assert.strictEqual(live().length, 1);
  fire(live()[0]);
  assert.deepStrictEqual(gone, ['a']);
});

test('a departure while already away neither restarts nor doubles the clock', () => {
  // The interpreter's case: someone present at connect leaves before the
  // post-connect snapshot reached the watch, then comes back.
  const { watch, live, fire, gone } = setup();
  watch.leave('b#phone');
  assert.strictEqual(live().length, 2);
  watch.arrive('b#phone');
  assert.strictEqual(live().length, 1);
  fire(live()[0]);
  assert.deepStrictEqual(gone, ['a']);
});

test('strangers leaving are ignored too', () => {
  const { watch, live } = setup();
  watch.leave('voice-interpreter');
  watch.leave('c#phone');
  watch.leave(undefined);
  assert.strictEqual(live().length, 2);
  assert.deepStrictEqual(watch.presentPeople(), []);
});

test('a throwing onGone is logged and does not escape the timer', () => {
  const errors = [];
  const log = { error: (m) => errors.push(m) };
  const thrown = [new Error('boom'), undefined];
  const { live, fire } = setup({ onGone: () => { throw thrown.shift(); }, log });
  assert.doesNotThrow(() => fire(live()[0]));
  assert.doesNotThrow(() => fire(live()[0]));
  assert.strictEqual(errors.length, 2);
  assert.match(errors[0], /onGone\(a\) failed: boom/);
  assert.match(errors[1], /onGone\(b\) failed/);
});

test('default timers: the clock really runs, and close() really stops it', async () => {
  const gone = [];
  const watch = createPresenceWatch({ people: ['a', 'b'], graceMs: 20, onGone: (p) => gone.push(p) });
  watch.arrive('a#phone');
  const stopped = createPresenceWatch({ people: ['c'], graceMs: 20, onGone: (p) => gone.push(p) });
  stopped.close();
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.deepStrictEqual(gone, ['b']);
  watch.close();
});
