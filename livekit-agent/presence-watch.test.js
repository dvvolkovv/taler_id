// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { createPresenceWatch } = require('./presence-watch');

function setup() {
  const timers = [];
  const gone = [];
  const watch = createPresenceWatch({
    people: ['a', 'b'],
    graceMs: 60000,
    onGone: (p) => gone.push(p),
    setTimer: (fn, ms) => {
      const t = { fn, ms, cleared: false };
      timers.push(t);
      return t;
    },
    clearTimer: (t) => { t.cleared = true; },
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
