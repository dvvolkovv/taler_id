// Run with: node --test  (from livekit-agent/)
//
// LiveKit, OpenAI and the embed service are all faked: these check the wiring
// — which track goes to which gate and engine, what gets published, who gets
// which message. The real thing runs in bench/interpreter-bench.js.
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { fakeWsFactory } = require('./testing/fake-ws');
const interpreter = require('./interpreter');

const print = (k) => Array.from({ length: 192 }, (_, i) => (i === k ? 1 : 0));
const people = (langB = 'de') => [
  { userId: 'a', lang: 'ru', embedding: print(0) },
  { userId: 'b', lang: langB, embedding: print(1) },
];

/**
 * @livekit/rtc-node as far as the interpreter can tell the difference:
 * - disconnect() does nothing until connect() has finished, and drops every
 *   listener once it has;
 * - an AudioStream is a ReadableStream; a `live` track, like a real remote
 *   one, never ends its stream by itself — only cancel() does;
 * - localParticipant exists only after connect().
 * Hooks let a test stall or fail connect, publishTrack and disconnect.
 */
function fakeRtc() {
  const CONN = { CONN_DISCONNECTED: 0, CONN_CONNECTED: 1, CONN_RECONNECTING: 2 };
  const rtc = {
    rooms: [],
    duringConnect: null,
    connectError: null,
    publishHook: null,
    disconnectHook: null,
    RoomEvent: {
      ParticipantConnected: 'participantConnected',
      ParticipantDisconnected: 'participantDisconnected',
      TrackSubscribed: 'trackSubscribed',
      TrackUnsubscribed: 'trackUnsubscribed',
      Disconnected: 'disconnected',
      Reconnecting: 'reconnecting',
      Reconnected: 'reconnected',
    },
    ConnectionState: CONN,
    DisconnectReason: { 0: 'UNKNOWN_REASON', 1: 'CLIENT_INITIATED', 2: 'DUPLICATE_IDENTITY', 5: 'ROOM_DELETED' },
    TrackKind: { KIND_AUDIO: 1 },
    TrackSource: { SOURCE_MICROPHONE: 2 },
    AudioSource: class {
      constructor() { this.frames = []; this.closed = false; }
      async captureFrame(frame) {
        if (this.closed) throw new Error('AudioSource is closed');
        this.frames.push(frame);
      }
      async close() { this.closed = true; }
    },
    AudioFrame: class {
      constructor(data, sampleRate, channels, samplesPerChannel) {
        Object.assign(this, { data, sampleRate, channels, samplesPerChannel });
      }
    },
    LocalAudioTrack: {
      createAudioTrack: (name, source) => ({
        name,
        source,
        closed: false,
        async close() {
          this.closed = true;
          await source.close();
        },
      }),
    },
    TrackPublishOptions: class { constructor(init) { Object.assign(this, init); } },
    AudioStream: class extends ReadableStream {
      constructor(track) {
        super({
          start(controller) {
            track.controller = controller;
            for (const data of track.frames || []) controller.enqueue({ data });
            if (!track.live) controller.close();
          },
          cancel() { track.cancelled = (track.cancelled || 0) + 1; },
        });
      }
    },
  };
  rtc.Room = class extends EventEmitter {
    constructor() {
      super();
      rtc.rooms.push(this);
      this.remoteParticipants = new Map();
      this.published = [];
      this.data = [];
      this.connectionState = CONN.CONN_DISCONNECTED;
      this.disconnected = false;
    }
    get isConnected() { return this.connectionState !== CONN.CONN_DISCONNECTED; }
    async connect(url, token, opts) {
      this.connectArgs = { url, token, opts };
      if (rtc.duringConnect) await rtc.duringConnect(this);
      if (rtc.connectError) throw rtc.connectError;
      this.connectionState = CONN.CONN_CONNECTED;
      this.localParticipant = {
        publishTrack: async (track, options) => {
          if (rtc.publishHook) await rtc.publishHook(track, this);
          this.published.push({ name: track.name, track, options });
        },
        publishData: async (payload, options) => {
          this.data.push({ msg: JSON.parse(Buffer.from(payload).toString()), options });
          if (rtc.publishDataError) throw rtc.publishDataError;
        },
      };
    }
    async disconnect() {
      if (!this.isConnected) return; // what rtc-node does while connect() is still running
      this.disconnectCalls = (this.disconnectCalls || 0) + 1;
      if (rtc.disconnectHook) await rtc.disconnectHook(this);
      this.disconnected = true;
      this.connectionState = CONN.CONN_DISCONNECTED;
      this.removeAllListeners();
    }
  };
  return rtc;
}

function setup(config = {}) {
  const rtc = fakeRtc();
  const made = [];
  const engine = (kind) => (opts) => {
    const e = { kind, opts, sent: [], closed: false, sendAudio(x) { this.sent.push(x); }, close() { this.closed = true; } };
    made.push(e);
    return e;
  };
  const deps = {
    rtc,
    engines: { simultaneous: engine('simultaneous'), phrase: engine('phrase') },
    credentials: { apiKey: 'devkey', apiSecret: 'x'.repeat(32) },
    embed: { embedPcm: async () => print(0) }, // every window sounds like a
    config: { chunkMs: 100, backendUrl: null, openaiKey: 'sk-test', ...config },
  };
  return { rtc, made, deps };
}

// 400 ms of loud speech in 10 ms frames at 24 kHz: four 100 ms chunks.
const speechFrames = (n = 40) => Array.from({ length: n }, () => new Int16Array(240).fill(3000));
const settle = (ms = 30) => new Promise((r) => setTimeout(r, ms));
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
};

/** Collects console output for the duration of fn. */
async function capture(fn) {
  const lines = [];
  const saved = { log: console.log, warn: console.warn, error: console.error };
  for (const k of Object.keys(saved)) console[k] = (...a) => lines.push(a.join(' '));
  try {
    await fn(lines);
  } finally {
    Object.assign(console, saved);
  }
  return lines;
}

/** Replaces fetch for agent-ended callbacks; returns the reasons sent. */
function captureCallbacks(t) {
  const reasons = [];
  const saved = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    reasons.push(JSON.parse(init.body).reason);
    return { ok: true, status: 200, body: null };
  };
  t.after(() => { globalThis.fetch = saved; });
  return reasons;
}

test('configuration falls back to the documented defaults', () => {
  const c = interpreter.readConfig({});
  assert.deepStrictEqual(
    [c.model, c.fallbackModel, c.transcribeModel, c.noiseReduction, c.embedUrl, c.threshold, c.margin, c.chunkMs, c.gateTimeoutMs, c.hysteresis, c.speechRms, c.gain, c.presenceGraceMs],
    ['gpt-realtime-translate', 'gpt-realtime-2025-08-28', 'gpt-4o-mini-transcribe', 'near_field', 'http://127.0.0.1:18082', 0.25, 0.05, 500, 300, 2, 400, 1.4, 60000],
  );
});

test('configuration reads the environment and keeps values in range', () => {
  const c = interpreter.readConfig({
    INTERPRETER_VOICE_THRESHOLD: '0.4', INTERPRETER_GAIN: '9', INTERPRETER_GATE_HYSTERESIS: '0', INTERPRETER_NOISE_REDUCTION: 'off',
    INTERPRETER_GATE_CHUNK_MS: '0',
  });
  assert.strictEqual(c.chunkMs, 100);
  assert.strictEqual(c.threshold, 0.4);
  assert.strictEqual(c.gain, 4);
  assert.strictEqual(c.hysteresis, 1);
  assert.strictEqual(c.noiseReduction, null);
  assert.strictEqual(c.transcribeModel, 'gpt-4o-mini-transcribe');
});

test('a bad request is a 400 and opens no room', async () => {
  const { rtc, deps } = setup();
  await assert.rejects(interpreter.startInterpreter({ roomName: 'r0' }, deps), (e) => e.statusCode === 400);
  await assert.rejects(
    interpreter.startInterpreter({ sessionId: 's', roomName: 'r0', participants: [people()[0]] }, deps),
    (e) => e.statusCode === 400 && /exactly two/.test(e.message),
  );
  assert.strictEqual(rtc.rooms.length, 0);
});

test('it publishes a track per listener and reports itself without voice prints', async () => {
  const { rtc, made, deps } = setup();
  assert.deepStrictEqual(
    await interpreter.startInterpreter({ sessionId: 's1', roomName: 'r-tracks', participants: people() }, deps),
    { status: 'started' },
  );
  try {
    const room = rtc.rooms[0];
    assert.strictEqual(room.connectArgs.opts.autoSubscribe, true);
    assert.deepStrictEqual(room.published.map((p) => p.name).sort(), ['interp-for-a', 'interp-for-b']);
    assert.deepStrictEqual(made.map((e) => [e.kind, e.opts.targetLang]).sort(), [['simultaneous', 'de'], ['simultaneous', 'ru']]);
    assert.match(made[0].opts.safetyId, /^[0-9a-f]{32}$/);
    assert.strictEqual(made[0].opts.transcribeModel, 'gpt-4o-mini-transcribe');
    assert.strictEqual(made[0].opts.noiseReduction, 'near_field');
    const status = interpreter.getInterpreterStatus('r-tracks');
    assert.strictEqual(status.running, true);
    assert.strictEqual(status.directions.length, 2);
    assert.ok(!JSON.stringify(status).includes('mbedding'));
    assert.deepStrictEqual(
      await interpreter.startInterpreter({ sessionId: 's1', roomName: 'r-tracks', participants: people() }, deps),
      { status: 'already_running' },
    );
  } finally {
    assert.deepStrictEqual(await interpreter.stopInterpreter('r-tracks'), { status: 'stopped' });
  }
  assert.strictEqual(rtc.rooms[0].disconnected, true);
  assert.ok(made.every((e) => e.closed));
  assert.deepStrictEqual(await interpreter.stopInterpreter('r-tracks'), { status: 'not_running' });
});

test('a pair the model cannot speak runs that direction on the phrase engine', async () => {
  const { made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's2', roomName: 'r-sk', participants: people('sk') }, deps);
  try {
    const toSk = made.find((e) => e.opts.targetLang === 'sk');
    assert.strictEqual(toSk.kind, 'phrase');
    assert.strictEqual(toSk.opts.model, 'gpt-realtime-2025-08-28');
    assert.strictEqual(toSk.opts.sourceLang, 'ru');
  } finally {
    await interpreter.stopInterpreter('r-sk');
  }
});

test("the owner's speech reaches only the engine that translates them", async () => {
  const { rtc, made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's3', roomName: 'r-flow', participants: people() }, deps);
  try {
    rtc.rooms[0].emit('trackSubscribed', { kind: 1, frames: speechFrames() }, { name: 'mic' }, { identity: 'a#dev1' });
    await settle();
    const toB = made.find((e) => e.opts.targetLang === 'de');
    const toA = made.find((e) => e.opts.targetLang === 'ru');
    // Three chunks are judged as the frames arrive; the fourth only because the
    // stream ended and listen() called gate.end().
    assert.strictEqual(toB.sent.length, 4, `a→b got ${toB.sent.length} chunks`);
    assert.ok(toB.sent.every((c) => c.some((x) => x !== 0)), 'speech, not silence');
    assert.strictEqual(toA.sent.length, 0);
  } finally {
    await interpreter.stopInterpreter('r-flow');
  }
});

test('a track that arrives while the room is still connecting is not lost', async () => {
  const { rtc, made, deps } = setup();
  rtc.duringConnect = (room) => room.emit('trackSubscribed', { kind: 1, frames: speechFrames() }, { name: 'mic' }, { identity: 'a#dev1' });
  await interpreter.startInterpreter({ sessionId: 's4', roomName: 'r-early', participants: people() }, deps);
  try {
    await settle();
    assert.strictEqual(made.find((e) => e.opts.targetLang === 'de').sent.length, 4);
  } finally {
    await interpreter.stopInterpreter('r-early');
  }
});

test('translated audio reaches the listener track in 20 ms frames that own their buffers', async () => {
  const { rtc, made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's6', roomName: 'r-frames', participants: people() }, deps);
  try {
    const toB = made.find((e) => e.opts.targetLang === 'de');
    toB.opts.onAudio(new Int16Array(9600).fill(5)); // one 400 ms delta
    await settle();
    const source = rtc.rooms[0].published.find((p) => p.name === 'interp-for-b').track.source;
    assert.strictEqual(source.frames.length, 20);
    assert.ok(source.frames.every((f) => f.samplesPerChannel === 480 && f.data.byteOffset === 0 && f.data.buffer.byteLength === 960));
    assert.strictEqual(source.frames[0].data[0], 7); // gain 1.4 applied: 5 * 1.4 = 7
  } finally {
    await interpreter.stopInterpreter('r-frames');
  }
});

test('captions go to their listener, recognised speech back to its speaker', async () => {
  const { rtc, made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's5', roomName: 'r-captions', participants: people() }, deps);
  try {
    const room = rtc.rooms[0];
    room.emit('participantConnected', { identity: 'a#dev1' });
    room.emit('participantConnected', { identity: 'b#dev1' });
    const toB = made.find((e) => e.opts.targetLang === 'de');
    toB.opts.onTranslationText('Guten Tag', false);
    toB.opts.onSourceText('Добрый день', false);
    await settle();
    assert.deepStrictEqual(room.data.map((d) => [d.msg.role, d.msg.speaker, d.msg.text, d.options.destination_identities]), [
      ['translation', 'a', 'Guten Tag', ['b#dev1']],
      ['source', 'a', 'Добрый день', ['a#dev1']],
    ]);
    assert.ok(room.data.every((d) => d.options.topic === 'interp' && d.options.reliable === true));
  } finally {
    await interpreter.stopInterpreter('r-captions');
  }
});

// ── review 16: lifecycle, native handles, LiveKit weather ──────────────────

test('a second start for a room that is still starting joins nothing and answers with the first one', async () => {
  const { rtc, made, deps } = setup();
  const body = { sessionId: 's-dup', roomName: 'r-dup', participants: people() };
  const results = await Promise.all([interpreter.startInterpreter(body, deps), interpreter.startInterpreter(body, deps)]);
  try {
    assert.deepStrictEqual(results, [{ status: 'started' }, { status: 'already_running' }]);
    assert.strictEqual(rtc.rooms.length, 1, 'one agent in the room, not two');
    assert.strictEqual(made.length, 2);
  } finally {
    await interpreter.stopInterpreter('r-dup');
  }
  assert.ok(made.every((e) => e.closed), 'no engine outlives the stop');
});

test('a start waiting on one that fails fails too, and the room is free again', async () => {
  const { rtc, deps } = setup();
  rtc.connectError = new Error('signal refused');
  const body = { sessionId: 's-dup2', roomName: 'r-dup2', participants: people() };
  const results = await Promise.allSettled([interpreter.startInterpreter(body, deps), interpreter.startInterpreter(body, deps)]);
  assert.deepStrictEqual(results.map((r) => r.status), ['rejected', 'rejected']);
  assert.match(results[0].reason.message, /signal refused/);
  assert.strictEqual(results[1].reason.statusCode, 503);
  assert.strictEqual(rtc.rooms.length, 1);
  assert.deepStrictEqual(interpreter.getInterpreterStatus('r-dup2'), { running: false });
});

test('a stop that arrives while LiveKit is connecting: nothing is opened, the room is left, no "started"', async () => {
  const { rtc, made, deps } = setup();
  rtc.duringConnect = async () => {
    assert.deepStrictEqual(await interpreter.stopInterpreter('r-stop-connect'), { status: 'stopped' });
  };
  try {
    await assert.rejects(
      interpreter.startInterpreter({ sessionId: 's7', roomName: 'r-stop-connect', participants: people() }, deps),
      (e) => e.statusCode === 503 && /ended while starting \(stopped\)/.test(e.message),
    );
    await settle();
    assert.strictEqual(made.length, 0, 'no OpenAI session for a session that is gone');
    assert.deepStrictEqual(rtc.rooms[0].published, []);
    assert.strictEqual(rtc.rooms[0].disconnected, true, 'the connect that landed after the stop left the room again');
  } finally {
    await interpreter.stopInterpreter('r-stop-connect');
  }
});

test('a grace period that runs out during the connect ends the start as agent_lost', async (t) => {
  const reasons = captureCallbacks(t);
  const { rtc, made, deps } = setup({ presenceGraceMs: 20, backendUrl: 'http://backend.invalid', secret: 'sec' });
  rtc.duringConnect = () => settle(80);
  try {
    await assert.rejects(
      interpreter.startInterpreter({ sessionId: 's8', roomName: 'r-gone-connect', participants: people() }, deps),
      (e) => e.statusCode === 503 && /agent_lost/.test(e.message),
    );
    await settle();
    assert.deepStrictEqual(reasons, ['agent_lost'], 'the agent was never in the room: nobody "left"');
    assert.strictEqual(made.length, 0);
    assert.strictEqual(rtc.rooms[0].disconnected, true);
  } finally {
    await interpreter.stopInterpreter('r-gone-connect');
  }
});

test('someone away past the grace period is partner_left, unless the agent itself is off LiveKit', async (t) => {
  const reasons = captureCallbacks(t);
  for (const [roomName, state, expected] of [['r-away-ok', 1, 'partner_left'], ['r-away-lost', 2, 'agent_lost']]) {
    const { rtc, deps } = setup({ presenceGraceMs: 40, backendUrl: 'http://backend.invalid', secret: 'sec' });
    await interpreter.startInterpreter({ sessionId: `s-${roomName}`, roomName, participants: people() }, deps);
    rtc.rooms[0].connectionState = state; // 2: CONN_RECONNECTING
    await settle(120);
    assert.deepStrictEqual(interpreter.getInterpreterStatus(roomName), { running: false });
    assert.strictEqual(reasons.at(-1), expected, `${roomName}: ${reasons.join(',')}`);
  }
});

test('a stop while the second track is publishing opens no engine for it and releases both tracks', async () => {
  const { rtc, made, deps } = setup();
  rtc.publishHook = async (track) => {
    if (track.name === 'interp-for-a') await interpreter.stopInterpreter('r-stop-publish');
  };
  try {
    await assert.rejects(
      interpreter.startInterpreter({ sessionId: 's9', roomName: 'r-stop-publish', participants: people() }, deps),
      (e) => e.statusCode === 503,
    );
    await settle();
    assert.strictEqual(made.length, 1, 'the second direction never reached OpenAI');
    assert.ok(made.every((e) => e.closed));
    const tracks = rtc.rooms[0].published.map((p) => p.track);
    assert.strictEqual(tracks.length, 2);
    assert.ok(tracks.every((tr) => tr.closed && tr.source.closed), 'native track and source handles released');
  } finally {
    await interpreter.stopInterpreter('r-stop-publish');
  }
});

test('a lane that fails to publish releases its own track and everything opened before it', async () => {
  const { rtc, made, deps } = setup();
  const tracks = [];
  rtc.publishHook = async (track) => {
    tracks.push(track);
    if (track.name === 'interp-for-a') throw new Error('publish timed out');
  };
  await assert.rejects(
    interpreter.startInterpreter({ sessionId: 's10', roomName: 'r-publish-fails', participants: people() }, deps),
    /publish timed out/,
  );
  await settle();
  assert.strictEqual(tracks.length, 2);
  assert.ok(tracks.every((tr) => tr.closed && tr.source.closed));
  assert.ok(made.every((e) => e.closed));
  assert.deepStrictEqual(interpreter.getInterpreterStatus('r-publish-fails'), { running: false });
});

test('stop cancels the audio streams, which never end by themselves, and closes the published tracks', async () => {
  const { rtc, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's11', roomName: 'r-release', participants: people() }, deps);
  const room = rtc.rooms[0];
  const micA = { kind: 1, live: true, frames: speechFrames(5) };
  const micB = { kind: 1, live: true, frames: speechFrames(5) };
  room.emit('trackSubscribed', micA, { name: 'mic' }, { identity: 'a#dev1' });
  room.emit('trackSubscribed', micB, { name: 'mic' }, { identity: 'b#dev1' });
  await settle();
  const published = room.published.map((p) => p.track);
  await interpreter.stopInterpreter('r-release');
  await settle();
  assert.ok(micA.cancelled >= 1 && micB.cancelled >= 1, 'both remote streams released');
  assert.ok(published.every((tr) => tr.closed && tr.source.closed), 'both local tracks and sources released');
});

test('a track that goes away lets the held audio out and releases its stream', async () => {
  const { rtc, made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's12', roomName: 'r-unsub', participants: people() }, deps);
  try {
    const room = rtc.rooms[0];
    const mic = { kind: 1, live: true, frames: speechFrames(25) }; // 2.5 chunks
    room.emit('trackSubscribed', mic, { name: 'mic' }, { identity: 'a#dev1' });
    await settle();
    const toB = made.find((e) => e.opts.targetLang === 'de');
    assert.strictEqual(toB.sent.length, 1, 'one chunk out, one and a half held');
    room.emit('trackUnsubscribed', mic, { name: 'mic' }, { identity: 'a#dev1' });
    await settle();
    assert.strictEqual(toB.sent.length, 3, 'the held audio went out when the track went away');
    assert.strictEqual(mic.cancelled, 1);
  } finally {
    await interpreter.stopInterpreter('r-unsub');
  }
});

test('a participant leaving releases their stream even without an unsubscription', async () => {
  const { rtc, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's13', roomName: 'r-left', participants: people() }, deps);
  try {
    const room = rtc.rooms[0];
    const mic = { kind: 1, live: true, frames: [] };
    room.emit('participantConnected', { identity: 'a#dev1', sid: 'PA_1' });
    room.emit('trackSubscribed', mic, { name: 'mic' }, { identity: 'a#dev1' });
    await settle();
    room.emit('participantDisconnected', { identity: 'a#dev1', sid: 'PA_1', disconnectReason: 1 });
    await settle();
    assert.strictEqual(mic.cancelled, 1);
  } finally {
    await interpreter.stopInterpreter('r-left');
  }
});

test("a second device takes over: the first device's held audio goes out first and its stream is released", async () => {
  const { rtc, made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's14', roomName: 'r-takeover', participants: people() }, deps);
  try {
    const room = rtc.rooms[0];
    const phone = { kind: 1, live: true, frames: speechFrames(15) }; // 1.5 chunks, all held
    const tablet = { kind: 1, live: true, frames: [] };
    room.emit('trackSubscribed', phone, { name: 'mic' }, { identity: 'a#phone' });
    await settle();
    const toB = made.find((e) => e.opts.targetLang === 'de');
    assert.strictEqual(toB.sent.length, 0);
    room.emit('trackSubscribed', tablet, { name: 'mic' }, { identity: 'a#tablet' });
    await settle();
    assert.strictEqual(toB.sent.length, 2, "the phone's held audio went out before the tablet's");
    assert.strictEqual(phone.cancelled, 1);
    for (const f of speechFrames(20)) tablet.controller.enqueue({ data: f });
    await settle();
    assert.strictEqual(toB.sent.length, 3, 'the tablet is listened to');
  } finally {
    await interpreter.stopInterpreter('r-takeover');
  }
});

test('nothing is sent while LiveKit reconnects, and a run of failed messages is logged once', async () => {
  const { rtc, made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's15', roomName: 'r-reconnect', participants: people() }, deps);
  try {
    const room = rtc.rooms[0];
    room.emit('participantConnected', { identity: 'a#dev1', sid: 'PA_a' });
    room.emit('participantConnected', { identity: 'b#dev1', sid: 'PA_b' });
    const toB = made.find((e) => e.opts.targetLang === 'de');
    rtc.publishDataError = new Error('engine is closed');
    const lines = await capture(async () => {
      room.emit('reconnecting');
      for (let i = 0; i < 30; i++) toB.opts.onTranslationText(`d${i}`, false);
      await settle();
      assert.strictEqual(room.data.length, 0, 'not attempted while reconnecting');
      room.emit('reconnected');
      for (let i = 0; i < 30; i++) toB.opts.onTranslationText(`e${i}`, false);
      await settle();
    });
    assert.strictEqual(room.data.length, 30, 'attempted again once reconnected');
    assert.strictEqual(lines.filter((l) => l.includes('failed: engine is closed')).length, 1, lines.join('\n'));
  } finally {
    rtc.publishDataError = null;
    await interpreter.stopInterpreter('r-reconnect');
  }
});

test('arrivals, departures and losing LiveKit are logged with sid and reason', async (t) => {
  captureCallbacks(t);
  const { rtc, deps } = setup({ backendUrl: 'http://backend.invalid', secret: 'sec' });
  await interpreter.startInterpreter({ sessionId: 's16', roomName: 'r-logs', participants: people() }, deps);
  const room = rtc.rooms[0];
  const lines = await capture(async () => {
    room.emit('participantConnected', { identity: 'a#dev1', sid: 'PA_a1' });
    room.emit('participantDisconnected', { identity: 'a#dev1', sid: 'PA_a1', disconnectReason: 2 });
    room.emit('disconnected', 5);
    await settle();
  });
  assert.ok(lines.some((l) => l.includes('a#dev1') && l.includes('PA_a1') && /joined/.test(l)), lines.join('\n'));
  assert.ok(lines.some((l) => l.includes('PA_a1') && l.includes('DUPLICATE_IDENTITY')), lines.join('\n'));
  assert.ok(lines.some((l) => l.includes('ROOM_DELETED')), lines.join('\n'));
});

test('an end that fails part-way still closes the rest, leaves the room and says what failed', async () => {
  const { rtc, made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's17', roomName: 'r-end-fails', participants: people() }, deps);
  const toB = made.find((e) => e.opts.targetLang === 'de');
  toB.close = () => { throw new Error('socket gone'); };
  const lines = await capture(async () => {
    rtc.rooms[0].emit('disconnected', 9);
    await settle();
  });
  assert.strictEqual(made.find((e) => e.opts.targetLang === 'ru').closed, true);
  assert.strictEqual(rtc.rooms[0].disconnected, true);
  assert.ok(lines.some((l) => l.includes('socket gone')), lines.join('\n'));
  assert.deepStrictEqual(interpreter.getInterpreterStatus('r-end-fails'), { running: false });
});

test('without an OpenAI key the start fails at once and joins no room', async () => {
  const { rtc, deps } = setup({ openaiKey: '' });
  await assert.rejects(
    interpreter.startInterpreter({ sessionId: 's18', roomName: 'r-nokey', participants: people() }, deps),
    (e) => e.statusCode === 503 && /OPENAI_API_KEY/.test(e.message),
  );
  assert.strictEqual(rtc.rooms.length, 0);
});

test('configuration keeps out values that would end every conversation or switch the gate off', () => {
  const grace = (v) => interpreter.readConfig({ INTERPRETER_PRESENCE_GRACE_MS: v }).presenceGraceMs;
  assert.deepStrictEqual([grace('0'), grace('-5'), grace('9999999999'), grace('30000')], [10_000, 10_000, 600_000, 30_000]);
  const timeout = (v) => interpreter.readConfig({ INTERPRETER_GATE_TIMEOUT_MS: v }).gateTimeoutMs;
  assert.deepStrictEqual([timeout('0'), timeout('-1'), timeout('60000'), timeout('250')], [100, 100, 3000, 250]);
  const rmsFloor = (v) => interpreter.readConfig({ INTERPRETER_SPEECH_RMS: v }).speechRms;
  assert.deepStrictEqual([rmsFloor('0'), rmsFloor('40000'), rmsFloor('600')], [50, 5000, 600]);
});

test('a connect that never settles fails the start in time, and if it lands later the room is left', async () => {
  const { rtc, made, deps } = setup({ connectTimeoutMs: 40 });
  const landed = deferred();
  rtc.duringConnect = () => landed.promise;
  try {
    const outcome = await Promise.race([
      interpreter.startInterpreter({ sessionId: 's19', roomName: 'r-hung', participants: people() }, deps).then(() => 'started', (e) => e),
      settle(400).then(() => 'still hanging'),
    ]);
    assert.ok(outcome instanceof Error && /did not settle/.test(outcome.message), String(outcome));
    assert.deepStrictEqual(interpreter.getInterpreterStatus('r-hung'), { running: false });
    landed.resolve();
    await settle();
    assert.strictEqual(rtc.rooms[0].disconnected, true);
    assert.strictEqual(made.length, 0);
  } finally {
    landed.resolve();
    await interpreter.stopInterpreter('r-hung');
  }
});

test('stop does not hang on a disconnect that never settles', async () => {
  const { rtc, deps } = setup({ disconnectTimeoutMs: 40 });
  await interpreter.startInterpreter({ sessionId: 's20', roomName: 'r-hung-stop', participants: people() }, deps);
  rtc.disconnectHook = () => new Promise(() => {});
  const outcome = await Promise.race([
    interpreter.stopInterpreter('r-hung-stop'),
    settle(400).then(() => 'still hanging'),
  ]);
  assert.deepStrictEqual(outcome, { status: 'stopped' });
});

test('selftest opens both engines, and a refused phrase model fails it', async () => {
  const { factory, sockets } = fakeWsFactory();
  const result = interpreter.selftest({ config: { openaiKey: 'k' }, wsFactory: factory });
  const translate = sockets.find((s) => s.url.includes('/realtime/translations'));
  const phrase = sockets.find((s) => s.url.includes('/v1/realtime?model=gpt-realtime-2025-08-28'));
  assert.ok(translate && phrase, sockets.map((s) => s.url).join(', '));
  translate.open();
  translate.serverSends({ type: 'session.updated' });
  phrase.open();
  phrase.serverSends({ type: 'error', error: { message: 'The model gpt-realtime-2025-08-28 does not exist' } });
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.simultaneous.ok, true);
  assert.strictEqual(r.phrase.ok, false);
  assert.match(r.reason, /gpt-realtime-2025-08-28.*does not exist/);
});

test('selftest passes when both engines accept their sessions, and closes both sockets', async () => {
  const { factory, sockets } = fakeWsFactory();
  const result = interpreter.selftest({ config: { openaiKey: 'k' }, wsFactory: factory });
  for (const s of sockets) {
    s.open();
    s.serverSends({ type: 'session.updated' });
  }
  const r = await result;
  assert.strictEqual(r.ok, true, r.reason);
  assert.strictEqual(typeof r.reason, 'string');
  assert.strictEqual(sockets.length, 2);
  assert.ok(sockets.every((s) => s.readyState === 3), 'both sockets closed');
});

test('gate fail-open is logged once per outage, FATAL after a minute, and again for a later outage', async () => {
  const { rtc, deps } = setup();
  let embedUp = false;
  deps.embed = { embedPcm: async () => { if (!embedUp) throw new Error('voice-embed HTTP 502'); return print(0); } };
  await interpreter.startInterpreter({ sessionId: 's21', roomName: 'r-failopen', participants: people() }, deps);
  const room = rtc.rooms[0];
  const realNow = Date.now;
  let clock = realNow();
  Date.now = () => clock;
  try {
    const speak = async (identity, frames) => {
      room.emit('trackSubscribed', { kind: 1, frames }, { name: 'mic' }, { identity });
      await settle();
    };
    const lines = await capture(async () => {
      await speak('a#dev1', speechFrames(40)); // four unchecked chunks
      clock += 61_000;
      await speak('a#dev1', speechFrames(20)); // still down, a minute on
      embedUp = true;
      await speak('a#dev1', speechFrames(20)); // back
      embedUp = false;
      await speak('a#dev1', speechFrames(20));
      clock += 61_000;
      await speak('a#dev1', speechFrames(20));
    });
    assert.strictEqual(lines.filter((l) => l.includes('gate fail-open')).length, 2, lines.join('\n'));
    assert.strictEqual(lines.filter((l) => l.startsWith('FATAL interpreter: voice-embed unavailable')).length, 2, lines.join('\n'));
  } finally {
    Date.now = realNow;
    await interpreter.stopInterpreter('r-failopen');
  }
});

test('the agent routes of Task 17 drive this module the way index.js wires them', async () => {
  const express = require('express');
  const { registerInterpreterRoutes } = require('./interpreter-routes');
  const { deps } = setup();
  const { factory, sockets } = fakeWsFactory();
  const app = express();
  app.use(express.json());
  registerInterpreterRoutes(app, {
    secret: 's3cret',
    start: (body) => interpreter.startInterpreter(body, deps),
    stop: (roomName) => interpreter.stopInterpreter(roomName),
    status: (roomName) => interpreter.getInterpreterStatus(roomName),
    selftest: () => interpreter.selftest({ config: { openaiKey: 'k' }, wsFactory: factory }),
  });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body) => {
    const res = await fetch(`${url}${path}`, {
      method,
      headers: { 'content-type': 'application/json', 'x-interpreter-secret': 's3cret' },
      body: body && JSON.stringify(body),
    });
    return [res.status, await res.json()];
  };
  try {
    const body = { sessionId: 's-http', roomName: 'r-http', participants: people() };
    assert.deepStrictEqual(await call('POST', '/interpreter/start', { roomName: 'r-http' }), [400, { error: 'sessionId and roomName required' }]);
    assert.deepStrictEqual(await call('POST', '/interpreter/start', body), [200, { status: 'started' }]);
    assert.deepStrictEqual(await call('POST', '/interpreter/start', body), [200, { status: 'already_running' }]);
    const [, status] = await call('GET', '/interpreter/status/r-http');
    assert.strictEqual(status.running, true);
    assert.deepStrictEqual(await call('POST', '/interpreter/stop', { roomName: 'r-http' }), [200, { status: 'stopped' }]);
    assert.deepStrictEqual(await call('POST', '/interpreter/stop', { roomName: 'r-http' }), [200, { status: 'not_running' }]);
    const selftest = call('GET', '/interpreter/selftest');
    for (let i = 0; i < 40 && sockets.length < 2; i++) await settle(5);
    assert.strictEqual(sockets.length, 2, 'the selftest opened both engines');
    for (const s of sockets) {
      s.open();
      s.serverSends({ type: 'session.updated' });
    }
    const [code, result] = await selftest;
    assert.strictEqual(code, 200);
    assert.strictEqual(result.ok, true, result.reason);
    assert.strictEqual(typeof result.latencyMs, 'number');
    assert.deepStrictEqual([result.simultaneous.ok, result.phrase.ok], [true, true]);
  } finally {
    server.close();
    await interpreter.stopInterpreter('r-http');
  }
});

test('a room LiveKit dropped by itself no longer holds the session through our handlers', async (t) => {
  captureCallbacks(t);
  const { rtc, deps } = setup({ backendUrl: 'http://backend.invalid', secret: 'sec' });
  await interpreter.startInterpreter({ sessionId: 's22', roomName: 'r-kicked', participants: people() }, deps);
  const room = rtc.rooms[0];
  // rtc-node has already marked it disconnected, so its disconnect() returns
  // early and never takes the room off the process-wide FFI emitter.
  room.connectionState = rtc.ConnectionState.CONN_DISCONNECTED;
  room.emit('disconnected', 5);
  await settle();
  assert.deepStrictEqual(interpreter.getInterpreterStatus('r-kicked'), { running: false });
  assert.deepStrictEqual(room.eventNames(), [], 'no handler of ours left on a room the SDK keeps alive');
});