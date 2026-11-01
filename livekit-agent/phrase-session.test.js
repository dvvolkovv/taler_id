// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { fakeWsFactory } = require('./testing/fake-ws');
const { createPhraseSession } = require('./phrase-session');

const quietLog = { error() {}, warn() {} };

function session(extra = {}, { open = true } = {}) {
  const { factory, last } = fakeWsFactory();
  const seen = { audio: [], translation: [], source: [], ready: 0, closes: [] };
  const s = createPhraseSession({
    apiKey: 'k',
    model: 'gpt-realtime-2025-08-28',
    sourceLang: 'ru',
    targetLang: 'sk',
    wsFactory: factory,
    onAudio: (a) => seen.audio.push(a),
    onTranslationText: (t, f) => seen.translation.push([t, f]),
    onSourceText: (t, f) => seen.source.push([t, f]),
    onReady: () => { seen.ready += 1; },
    onClose: (c) => seen.closes.push(c),
    log: quietLog,
    ...extra,
  });
  const fake = last();
  if (open) fake.open();
  return { s, fake, seen };
}

const appends = (fake) => fake.sentOfType('input_audio_buffer.append');
// 500 ms of PCM16 at 24 kHz, as the voice-print gate hands it over.
const chunk = (value) => new Int16Array(12000).fill(value);
const loud = () => chunk(3000);
const quiet = () => chunk(0);
const firstSample = (msg) => Buffer.from(msg.audio, 'base64').readInt16LE(0);
// A 500 ms chunk goes in as 25 frames of 20 ms: one value per frame.
const framed = (...values) => values.flatMap((v) => new Array(25).fill(v));

/** How many 20 ms frames went in before the first commit, the frame that made the cut included. */
function framesBeforeCommit(fake) {
  const kinds = fake.sent.map((m) => m.type);
  const cut = kinds.indexOf('input_audio_buffer.commit');
  assert.ok(cut >= 0, 'nothing was committed');
  return kinds.slice(0, cut).filter((k) => k === 'input_audio_buffer.append').length;
}

test('it runs the given model with the known source language', () => {
  const { fake } = session();
  assert.strictEqual(fake.url, 'wss://api.openai.com/v1/realtime?model=gpt-realtime-2025-08-28');
  assert.ok(fake.sentOfType('session.update')[0].session.instructions.includes('spoken Russian audio into spoken Slovak'));
});

test('audio goes in as base64 PCM16 once the session is ready', () => {
  const { s, fake, seen } = session();
  fake.serverSends({ type: 'session.updated' });
  assert.strictEqual(seen.ready, 1);
  s.sendAudio(Int16Array.from([1, -1, 2]));
  const back = Buffer.from(fake.sentOfType('input_audio_buffer.append')[0].audio, 'base64');
  assert.deepStrictEqual([back.readInt16LE(0), back.readInt16LE(2), back.readInt16LE(4)], [1, -1, 2]);
});

test('translated audio comes back as samples and transcripts as whole phrases', () => {
  const { fake, seen } = session();
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'response.output_audio.delta', delta: Buffer.from(Int16Array.from([9, -9]).buffer).toString('base64') });
  fake.serverSends({ type: 'conversation.item.input_audio_transcription.completed', transcript: 'Добрый день' });
  fake.serverSends({ type: 'response.output_audio_transcript.done', transcript: 'Dobrý deň' });
  assert.deepStrictEqual(Array.from(seen.audio[0]), [9, -9]);
  assert.deepStrictEqual(seen.source, [['Добрый день', true]]);
  assert.deepStrictEqual(seen.translation, [['Dobrý deň', true]]);
});

test('spoken phrases are pruned from the conversation', () => {
  const { fake } = session();
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'input_audio_buffer.committed', item_id: 'in1' });
  fake.serverSends({ type: 'response.created', response: { id: 'r1' } });
  fake.serverSends({ type: 'response.done', response: { id: 'r1', status: 'completed', output: [{ id: 'out1' }] } });
  assert.deepStrictEqual(fake.sentOfType('conversation.item.delete').map((m) => m.item_id), ['in1', 'out1']);
});

test('closing it ourselves is not unexpected; the server closing is', () => {
  const a = session();
  a.s.close();
  assert.deepStrictEqual(a.seen.closes, [{ unexpected: false, code: 1005 }]);
  const b = session();
  b.fake.serverCloses(1006);
  assert.deepStrictEqual(b.seen.closes, [{ unexpected: true, code: 1006 }]);
});

// ── review of task 11 ──

test('the safety identifier goes out as a header next to the key', () => {
  const { fake } = session({ safetyId: 'abc' });
  assert.deepStrictEqual(fake.options.headers, { Authorization: 'Bearer k', 'OpenAI-Safety-Identifier': 'abc' });
});

test('a refused session.update lets no audio out and drops the socket as unexpected', () => {
  const { s, fake, seen } = session();
  s.sendAudio(loud());
  fake.serverSends({ type: 'session.created' });
  fake.serverSends({ type: 'error', error: { type: 'invalid_request_error', param: 'session.audio.input.transcription.model' } });
  s.sendAudio(loud());
  assert.strictEqual(appends(fake).length, 0);
  assert.strictEqual(seen.ready, 0);
  assert.deepStrictEqual(seen.closes, [{ unexpected: true, code: 1006 }]);
});

test('an error after the session is confirmed is only logged', () => {
  const { fake, seen } = session();
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'error', error: { code: 'item_not_found' } });
  assert.deepStrictEqual(seen.closes, []);
  assert.strictEqual(fake.readyState, 1);
});

test('a session that never confirms is dropped as unexpected', async () => {
  const { fake, seen } = session({ readyTimeoutMs: 20 });
  await new Promise((r) => setTimeout(r, 40));
  assert.deepStrictEqual(seen.closes, [{ unexpected: true, code: 1006 }]);
  assert.strictEqual(fake.readyState, 3);
});

test('a confirmed session outlives the ready timeout', async () => {
  const { fake, seen } = session({ readyTimeoutMs: 20 });
  fake.serverSends({ type: 'session.updated' });
  await new Promise((r) => setTimeout(r, 40));
  assert.deepStrictEqual(seen.closes, []);
  assert.strictEqual(fake.readyState, 1);
});

test('a socket whose writes pile up is dropped as unexpected', () => {
  const { s, fake, seen } = session();
  fake.serverSends({ type: 'session.updated' });
  fake.bufferedAmount = 2 * 1024 * 1024;
  s.sendAudio(loud());
  assert.deepStrictEqual(seen.closes, [{ unexpected: true, code: 1006 }]);
  assert.strictEqual(appends(fake).length, 0);
});

test('audio that waited for the session goes out whole, in order, and is cut into turns', (t) => {
  let now = 0;
  t.mock.method(Date, 'now', () => now);
  const { s, fake } = session({}, { open: false });
  const at = (ms, c) => { now = ms; s.sendAudio(c); };
  at(0, quiet()); at(500, loud()); at(1000, loud()); // the handshake is still running
  fake.open();
  at(1500, quiet()); // open, not yet confirmed: used to be dropped, splicing a gap into the phrase
  now = 1800;
  fake.serverSends({ type: 'session.updated' });
  assert.deepStrictEqual(appends(fake).map(firstSample), framed(0, 3000, 3000, 0));
  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 0);
  // The turn-taker heard the replay: live silence ends that phrase as usual
  // (before the fix it never saw the speech and nothing was ever committed).
  at(2000, quiet()); at(2500, quiet());
  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 1);
  assert.strictEqual(fake.sentOfType('response.create').length, 1);
});

test('at most 4 s waits for the session; older audio is dropped', () => {
  const { s, fake } = session({}, { open: false });
  for (let i = 1; i <= 12; i++) s.sendAudio(chunk(i)); // 6 s of handshake
  fake.open();
  fake.serverSends({ type: 'session.updated' });
  assert.deepStrictEqual(appends(fake).map(firstSample), framed(5, 6, 7, 8, 9, 10, 11, 12));
});

// ── pauses measured in audio, not in the gate's 500 ms deliveries ──

test('a pause is cut after 600 ms of audio: inside the second quiet chunk, not on the third', (t) => {
  // The wall clock stands still: only the audio can tell how long the pause is.
  // Before, every chunk was one reading of Date.now(), so here the pause never
  // grew at all; on the bench the cut came only with a third quiet chunk.
  t.mock.method(Date, 'now', () => 0);
  const { s, fake } = session();
  fake.serverSends({ type: 'session.updated' });
  const commits = () => fake.sentOfType('input_audio_buffer.commit').length;
  s.sendAudio(loud());
  s.sendAudio(loud());
  s.sendAudio(quiet());
  assert.strictEqual(commits(), 0, '500 ms of silence is still inside the phrase');
  s.sendAudio(quiet());
  assert.strictEqual(commits(), 1);
  // 50 frames of speech, 30 of silence (600 ms) and the frame that ends the wait.
  assert.strictEqual(framesBeforeCommit(fake), 50 + 30 + 1);
  assert.ok(appends(fake).every((m) => Buffer.from(m.audio, 'base64').length === 960), 'in 20 ms frames');
});

test('someone who does not pause is cut after 7 s of their audio', (t) => {
  t.mock.method(Date, 'now', () => 0);
  const lines = [];
  t.mock.method(console, 'log', (...args) => lines.push(args.join(' ')));
  const { s, fake } = session();
  fake.serverSends({ type: 'session.updated' });
  for (let i = 0; i < 14; i++) s.sendAudio(loud()); // 7 s
  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 0);
  s.sendAudio(loud());
  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 1);
  assert.strictEqual(framesBeforeCommit(fake), 350 + 1, 'cut on the frame that starts 7 s into the speech');
  assert.ok(lines.some((l) => l.endsWith('Committing (force)')), lines.join('\n'));
});

test('audio that waited for the session counts on the audio clock too', (t) => {
  t.mock.method(Date, 'now', () => 0);
  const { s, fake } = session({}, { open: false });
  s.sendAudio(loud());
  s.sendAudio(quiet()); // the handshake is still running: the pause begins in the queue
  fake.open();
  fake.serverSends({ type: 'session.updated' });
  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 0);
  s.sendAudio(quiet());
  assert.strictEqual(fake.sentOfType('input_audio_buffer.commit').length, 1);
  // 25 frames of speech; 30 of silence, 500 ms of it from the queue and 100 ms
  // live; and the frame that ends the wait.
  assert.strictEqual(framesBeforeCommit(fake), 25 + 30 + 1);
});

test('a throwing callback is logged, not thrown into the socket or passed off as a parse error', () => {
  const errors = [];
  const boom = () => { throw new Error('boom'); };
  const { fake } = session({
    onAudio: boom, onTranslationText: boom, onSourceText: boom, onReady: boom, onClose: boom,
    log: { error: (m) => errors.push(m), warn() {} },
  });
  const consoleErrors = [];
  const saved = console.error;
  console.error = (...a) => consoleErrors.push(a.join(' '));
  try {
    assert.doesNotThrow(() => {
      fake.serverSends({ type: 'session.updated' });
      fake.serverSends({ type: 'response.output_audio.delta', delta: 'AAAA' });
      fake.serverSends({ type: 'response.output_audio_transcript.done', transcript: 'a' });
      fake.serverSends({ type: 'conversation.item.input_audio_transcription.completed', transcript: 'бэ' });
      fake.serverCloses(1011);
    });
  } finally {
    console.error = saved;
  }
  assert.strictEqual(errors.length, 5);
  assert.ok(errors.some((m) => /onAudio callback failed: boom/.test(m)));
  assert.ok(!consoleErrors.some((m) => m.includes('parse error')), consoleErrors.join('\n'));
});

test('nothing is delivered after we closed it', () => {
  const { s, fake, seen } = session();
  fake.serverSends({ type: 'session.updated' });
  s.close();
  fake.readyState = 1; // real ws keeps reading until the server answers the close frame
  fake.serverSends({ type: 'response.output_audio.delta', delta: 'AAAA' });
  fake.serverSends({ type: 'response.output_audio_transcript.done', transcript: 'late' });
  assert.strictEqual(seen.audio.length, 0);
  assert.deepStrictEqual(seen.translation, []);
});

test('frames read after a refusal count for nothing', () => {
  const { fake, seen } = session();
  fake.serverSends({ type: 'error', error: { message: 'refused' } });
  fake.readyState = 1; // real ws still parses what came in the same read
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'response.output_audio.delta', delta: 'AAAA' });
  assert.strictEqual(seen.ready, 0);
  assert.strictEqual(seen.audio.length, 0);
});

test('stopping during the handshake is not a failure and sends nothing later', () => {
  const { s, fake, seen } = session({}, { open: false });
  s.sendAudio(loud());
  s.close();
  s.close();
  assert.deepStrictEqual(seen.closes, [{ unexpected: false, code: 1006 }]);
  assert.deepStrictEqual(fake.sent, []);
});

test('what was said reaches the subtitles but not the log', (t) => {
  const lines = [];
  t.mock.method(console, 'log', (...args) => lines.push(args.join(' ')));
  const { fake, seen } = session();
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'conversation.item.input_audio_transcription.completed', transcript: 'Добрый день' });
  fake.serverSends({ type: 'response.output_audio_transcript.done', transcript: 'Dobrý deň' });
  assert.deepStrictEqual(seen.source, [['Добрый день', true]]);
  assert.deepStrictEqual(seen.translation, [['Dobrý deň', true]]);
  assert.ok(!lines.some((l) => l.includes('Добрый') || l.includes('Dobrý')), lines.join('\n'));
});

test('a callback that throws something other than an Error is logged as such, not as a parse error', () => {
  const errors = [];
  // eslint-disable-next-line no-throw-literal
  const { fake } = session({ onAudio: () => { throw undefined; }, log: { error: (m) => errors.push(m), warn() {} } });
  const consoleErrors = [];
  const saved = console.error;
  console.error = (...a) => consoleErrors.push(a.join(' '));
  try {
    fake.serverSends({ type: 'session.updated' });
    fake.serverSends({ type: 'response.output_audio.delta', delta: 'AAAA' });
  } finally {
    console.error = saved;
  }
  assert.ok(errors.some((m) => m.includes('onAudio callback failed: undefined')), errors.join('\n'));
  assert.ok(!consoleErrors.some((m) => m.includes('parse error')), consoleErrors.join('\n'));
});

// ── selftestPhrase: the phrase engine's model, checked after a deploy ──

const { selftestPhrase } = require('./phrase-session');

test('selftest passes once the session accepts its configuration, and closes the socket', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestPhrase({ apiKey: 'k', model: 'gpt-realtime-2025-08-28', wsFactory: factory, log: quietLog });
  assert.match(last().url, /\/v1\/realtime\?model=gpt-realtime-2025-08-28$/);
  last().open();
  assert.deepStrictEqual(last().sent.map((m) => m.type), ['session.update']);
  last().serverSends({ type: 'session.updated' });
  assert.deepStrictEqual(await result, { ok: true, reason: 'session.updated received' });
  assert.strictEqual(last().readyState, 3);
});

test('selftest fails with the refusal when OpenAI refuses the session', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestPhrase({ apiKey: 'k', model: 'gpt-realtime-2025-08-28', wsFactory: factory, log: quietLog });
  last().open();
  last().serverSends({ type: 'error', error: { message: 'model not found' } });
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /model not found/);
});

test('selftest fails when the socket closes first, and without a key at once', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestPhrase({ apiKey: 'k', model: 'm', wsFactory: factory, log: quietLog });
  last().serverCloses(1006);
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /closed code=1006/);
  assert.deepStrictEqual(await selftestPhrase({ apiKey: '' }), { ok: false, reason: 'OPENAI_API_KEY not set' });
});

test('selftest gives up after timeoutMs and closes its socket', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestPhrase({ apiKey: 'k', model: 'm', wsFactory: factory, timeoutMs: 30, log: quietLog });
  last().open();
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /timeout|no session confirmation/);
  assert.strictEqual(last().readyState, 3);
});
