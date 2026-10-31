// Run with: node --test  (from livekit-agent/)
//
// LiveKit, OpenAI and the embed service are all faked: these check the wiring
// — which track goes to which gate and engine, what gets published, who gets
// which message. The real thing runs in bench/interpreter-bench.js.
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const interpreter = require('./interpreter');

const print = (k) => Array.from({ length: 192 }, (_, i) => (i === k ? 1 : 0));
const people = (langB = 'de') => [
  { userId: 'a', lang: 'ru', embedding: print(0) },
  { userId: 'b', lang: langB, embedding: print(1) },
];

function fakeRtc() {
  const rtc = {
    rooms: [],
    duringConnect: null,
    RoomEvent: {
      ParticipantConnected: 'participantConnected',
      ParticipantDisconnected: 'participantDisconnected',
      TrackSubscribed: 'trackSubscribed',
      Disconnected: 'disconnected',
    },
    TrackKind: { KIND_AUDIO: 1 },
    TrackSource: { SOURCE_MICROPHONE: 2 },
    AudioSource: class {
      constructor() { this.frames = []; }
      async captureFrame(frame) { this.frames.push(frame); }
    },
    AudioFrame: class {
      constructor(data, sampleRate, channels, samplesPerChannel) {
        Object.assign(this, { data, sampleRate, channels, samplesPerChannel });
      }
    },
    LocalAudioTrack: { createAudioTrack: (name, source) => ({ name, source }) },
    TrackPublishOptions: class { constructor(init) { Object.assign(this, init); } },
    AudioStream: class {
      constructor(track) { this.track = track; }
      async *[Symbol.asyncIterator]() { for (const data of this.track.frames) yield { data }; }
    },
  };
  rtc.Room = class extends EventEmitter {
    constructor() {
      super();
      rtc.rooms.push(this);
      this.remoteParticipants = new Map();
      this.published = [];
      this.data = [];
      this.localParticipant = {
        publishTrack: async (track, options) => { this.published.push({ name: track.name, track, options }); },
        publishData: async (payload, options) => {
          this.data.push({ msg: JSON.parse(Buffer.from(payload).toString()), options });
        },
      };
    }
    async connect(url, token, opts) {
      this.connectArgs = { url, token, opts };
      if (rtc.duringConnect) rtc.duringConnect(this);
    }
    async disconnect() { this.disconnected = true; }
  };
  return rtc;
}

function setup() {
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
    config: { chunkMs: 100, backendUrl: null },
  };
  return { rtc, made, deps };
}

// 400 ms of loud speech in 10 ms frames at 24 kHz: four 100 ms chunks.
const speechFrames = () => Array.from({ length: 40 }, () => new Int16Array(240).fill(3000));
const settle = () => new Promise((r) => setTimeout(r, 30));

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
