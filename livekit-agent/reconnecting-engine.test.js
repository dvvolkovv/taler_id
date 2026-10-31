// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { createReconnectingEngine } = require('./reconnecting-engine');

function fakeTimers() {
  const timers = [];
  return {
    setTimer: (fn, ms) => {
      const t = { fn, ms, cleared: false, fired: false };
      timers.push(t);
      return t;
    },
    clearTimer: (t) => { t.cleared = true; },
    fireNext() {
      const t = timers.find((x) => !x.cleared && !x.fired);
      if (!t) return null;
      t.fired = true;
      t.fn();
      return t.ms;
    },
    active: () => timers.filter((x) => !x.cleared && !x.fired).length,
  };
}

function fakeFactory() {
  const made = [];
  const factory = (handlers) => {
    const engine = {
      handlers,
      sent: [],
      closed: false,
      sendAudio(x) { this.sent.push(x); },
      close() { this.closed = true; },
    };
    made.push(engine);
    return engine;
  };
  return { made, factory };
}

function setup() {
  const timers = fakeTimers();
  const { made, factory } = fakeFactory();
  const statuses = [];
  const engine = createReconnectingEngine({
    factory,
    onStatus: (s) => statuses.push(s),
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
  });
  return { timers, made, statuses, engine };
}

test('audio goes to the current engine', () => {
  const { made, engine } = setup();
  engine.sendAudio('x');
  assert.deepStrictEqual(made[0].sent, ['x']);
});

test('an unexpected close reconnects after a second and reports it', () => {
  const { timers, made, statuses, engine } = setup();
  made[0].handlers.onClose({ unexpected: true });
  engine.sendAudio('lost'); // no socket: dropped
  assert.deepStrictEqual(statuses, ['reconnecting']);
  assert.strictEqual(timers.fireNext(), 1000);
  made[1].handlers.onReady();
  assert.deepStrictEqual(statuses, ['reconnecting', 'ok']);
  engine.sendAudio('y');
  assert.deepStrictEqual(made[1].sent, ['y']);
});

test('three failures in a row back off 1, 2, 4 s and then give up', () => {
  const { timers, made, statuses } = setup();
  const delays = [];
  for (let i = 0; i < 3; i++) {
    made[i].handlers.onClose({ unexpected: true });
    delays.push(timers.fireNext());
  }
  made[3].handlers.onClose({ unexpected: true });
  assert.deepStrictEqual(delays, [1000, 2000, 4000]);
  assert.deepStrictEqual(statuses, ['reconnecting', 'failed']);
  assert.strictEqual(timers.active(), 0);
});

test('a successful reconnect resets the back-off', () => {
  const { timers, made } = setup();
  made[0].handlers.onClose({ unexpected: true });
  timers.fireNext();
  made[1].handlers.onReady();
  made[1].handlers.onClose({ unexpected: true });
  assert.strictEqual(timers.fireNext(), 1000);
});

test('an expected close does not reconnect', () => {
  const { timers, made, statuses } = setup();
  made[0].handlers.onClose({ unexpected: false });
  assert.strictEqual(timers.active(), 0);
  assert.deepStrictEqual(statuses, []);
});

test('closing cancels a pending reconnect and closes the engine', () => {
  const { timers, made, engine } = setup();
  made[0].handlers.onClose({ unexpected: true });
  engine.close();
  assert.strictEqual(timers.active(), 0);
  assert.strictEqual(made.length, 1);

  const second = setup();
  second.engine.close();
  assert.strictEqual(second.made[0].closed, true);
});
