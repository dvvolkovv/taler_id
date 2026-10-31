// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { fakeWsFactory } = require('./testing/fake-ws');
const { createTranslateSession, selftestTranslate } = require('./translate-session');

const quietLog = { error() {}, warn() {} };

function session(extra = {}) {
  const { factory, last } = fakeWsFactory();
  const seen = { audio: [], translation: [], source: [], ready: 0, closes: [] };
  const s = createTranslateSession({
    apiKey: 'k',
    targetLang: 'de',
    safetyId: 'abc',
    wsFactory: factory,
    onAudio: (a) => seen.audio.push(a),
    onTranslationText: (t, f) => seen.translation.push([t, f]),
    onSourceText: (t, f) => seen.source.push([t, f]),
    onReady: () => { seen.ready += 1; },
    onClose: (c) => seen.closes.push(c),
    log: quietLog,
    ...extra,
  });
  return { s, fake: last(), seen };
}

const appends = (fake) => fake.sentOfType('session.input_audio_buffer.append');

test('connects to the translations endpoint with the key and a safety identifier', () => {
  const { fake } = session();
  assert.strictEqual(fake.url, 'wss://api.openai.com/v1/realtime/translations?model=gpt-realtime-translate');
  assert.deepStrictEqual(fake.options, { headers: { Authorization: 'Bearer k', 'OpenAI-Safety-Identifier': 'abc' } });
});

test('asks for the listener language, input transcription and near-field noise reduction on open', () => {
  const { fake } = session();
  fake.open();
  assert.deepStrictEqual(fake.sent[0], {
    type: 'session.update',
    session: {
      audio: {
        input: { transcription: { model: 'gpt-4o-mini-transcribe' }, noise_reduction: { type: 'near_field' } },
        output: { language: 'de' },
      },
    },
  });
});

test('the transcription model can be changed and both extras switched off', () => {
  const other = session({ transcribeModel: 'whisper-1' });
  other.fake.open();
  assert.deepStrictEqual(other.fake.sent[0].session.audio.input.transcription, { model: 'whisper-1' });

  const bare = session({ transcribeModel: null, noiseReduction: null });
  bare.fake.open();
  assert.deepStrictEqual(bare.fake.sent[0], { type: 'session.update', session: { audio: { output: { language: 'de' } } } });
});

test('audio waits for the session and then goes out in 100 ms pieces', () => {
  const { s, fake, seen } = session();
  fake.open();
  s.sendAudio(new Int16Array(6000).fill(7));
  assert.strictEqual(appends(fake).length, 0);
  fake.serverSends({ type: 'session.created' });
  assert.deepStrictEqual(appends(fake).map((a) => Buffer.from(a.audio, 'base64').length), [4800, 4800, 2400]);
  assert.strictEqual(seen.ready, 1);
  s.sendAudio(new Int16Array(2400));
  assert.strictEqual(appends(fake).length, 4);
});

test('at most 4 s waits for the session; older audio is dropped', () => {
  const { s, fake } = session();
  fake.open();
  for (let i = 0; i < 50; i++) s.sendAudio(new Int16Array(2400).fill(i));
  fake.serverSends({ type: 'session.created' });
  assert.strictEqual(appends(fake).length, 40);
  assert.strictEqual(Buffer.from(appends(fake)[0].audio, 'base64').readInt16LE(0), 10);
});

test('translated audio and both transcripts reach their callbacks', () => {
  const { fake, seen } = session();
  fake.open();
  fake.serverSends({ type: 'session.created' });
  const pcm = Int16Array.from([5, -5, 300]);
  fake.serverSends({ type: 'session.output_audio.delta', delta: Buffer.from(pcm.buffer).toString('base64') });
  fake.serverSends({ type: 'session.output_transcript.delta', delta: 'Guten ' });
  fake.serverSends({ type: 'session.input_transcript.delta', delta: 'Добрый ' });
  assert.deepStrictEqual(Array.from(seen.audio[0]), [5, -5, 300]);
  assert.deepStrictEqual(seen.translation, [['Guten ', false]]);
  assert.deepStrictEqual(seen.source, [['Добрый ', false]]);
});

test('closing it ourselves says goodbye and is not unexpected', () => {
  const { s, fake, seen } = session();
  fake.open();
  s.close();
  assert.strictEqual(fake.sentOfType('session.close').length, 1);
  assert.deepStrictEqual(seen.closes, [{ unexpected: false, code: 1005 }]);
});

test('the server dropping the socket is unexpected', () => {
  const { fake, seen } = session();
  fake.open();
  fake.serverCloses(1011);
  assert.deepStrictEqual(seen.closes, [{ unexpected: true, code: 1011 }]);
});

test('selftest passes on session.updated', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, quietMs: 1000 });
  last().open();
  last().serverSends({ type: 'session.updated' });
  assert.deepStrictEqual(await result, { ok: true, reason: 'session.updated received' });
});

test('selftest passes when session.created is followed by quiet', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, quietMs: 20 });
  last().open();
  last().serverSends({ type: 'session.created' });
  const r = await result;
  assert.strictEqual(r.ok, true);
  assert.match(r.reason, /no error within 20 ms/);
});

test('selftest sends a session.update and a little silence', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, quietMs: 1000 });
  last().open();
  assert.deepStrictEqual(last().sent.map((m) => m.type), ['session.update', 'session.input_audio_buffer.append']);
  last().serverSends({ type: 'session.updated' });
  await result;
});

test('selftest fails on an error event', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000 });
  last().open();
  last().serverSends({ type: 'error', error: { message: 'model not found' } });
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /model not found/);
});

test('selftest fails if the socket closes first', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000 });
  last().serverCloses(1006);
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /closed code=1006/);
});

test('selftest without a key fails at once', async () => {
  assert.deepStrictEqual(await selftestTranslate({ apiKey: '' }), { ok: false, reason: 'OPENAI_API_KEY not set' });
});
