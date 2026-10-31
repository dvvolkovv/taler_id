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
  assert.strictEqual(appends(fake).length, 0, 'session.created alone does not prove the update applied');
  fake.serverSends({ type: 'session.updated', session: { audio: { output: { language: 'de' } } } });
  assert.deepStrictEqual(appends(fake).map((a) => Buffer.from(a.audio, 'base64').length), [4800, 4800, 2400]);
  assert.strictEqual(seen.ready, 1);
  s.sendAudio(new Int16Array(2400));
  assert.strictEqual(appends(fake).length, 4);
});

test('at most 4 s waits for the session; older audio is dropped', () => {
  const { s, fake } = session();
  fake.open();
  for (let i = 0; i < 50; i++) s.sendAudio(new Int16Array(2400).fill(i));
  fake.serverSends({ type: 'session.updated' });
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
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, quietMs: 1000, appendCheckMs: 10 });
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
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, quietMs: 1000, appendCheckMs: 10 });
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


// ── after review (task 10b) ──

test('session.created followed by quiet is accepted when session.updated never comes', async () => {
  const { s, fake, seen } = session({ createdGraceMs: 20 });
  fake.open();
  s.sendAudio(new Int16Array(2400));
  fake.serverSends({ type: 'session.created' });
  assert.strictEqual(appends(fake).length, 0);
  await new Promise((r) => setTimeout(r, 40));
  assert.strictEqual(seen.ready, 1);
  assert.strictEqual(appends(fake).length, 1);
});

test('ready fires once even though both session events arrive', () => {
  const { fake, seen } = session();
  fake.open();
  fake.serverSends({ type: 'session.created' });
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'session.updated' });
  assert.strictEqual(seen.ready, 1);
});

test('a refused session.update lets no audio out and drops the socket as unexpected', () => {
  const { s, fake, seen } = session();
  fake.open();
  s.sendAudio(new Int16Array(4800));
  fake.serverSends({ type: 'session.created' });
  fake.serverSends({ type: 'error', error: { message: 'unknown transcription model' } });
  s.sendAudio(new Int16Array(2400));
  assert.strictEqual(appends(fake).length, 0);
  assert.strictEqual(seen.ready, 0);
  assert.deepStrictEqual(seen.closes, [{ unexpected: true, code: 1006 }]);
});

test('an echo in another language is not ready', () => {
  const { fake, seen } = session();
  fake.open();
  fake.serverSends({ type: 'session.updated', session: { audio: { output: { language: 'es' } } } });
  assert.strictEqual(seen.ready, 0);
  assert.deepStrictEqual(seen.closes, [{ unexpected: true, code: 1006 }]);
});

test('an error after the session is confirmed is only logged', () => {
  const errors = [];
  const { fake, seen } = session({ log: { error: (m) => errors.push(m), warn() {} } });
  fake.open();
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'error', error: { message: 'bad append' } });
  assert.deepStrictEqual(seen.closes, []);
  assert.strictEqual(errors.length, 1);
});

test('a session that never confirms is dropped as unexpected', async () => {
  const { fake, seen } = session({ readyTimeoutMs: 20 });
  fake.open();
  await new Promise((r) => setTimeout(r, 40));
  assert.deepStrictEqual(seen.closes, [{ unexpected: true, code: 1006 }]);
});

test('a socket whose writes pile up is dropped as unexpected', () => {
  const { s, fake, seen } = session();
  fake.open();
  fake.serverSends({ type: 'session.updated' });
  fake.bufferedAmount = 2 * 1024 * 1024;
  s.sendAudio(new Int16Array(2400));
  assert.deepStrictEqual(seen.closes, [{ unexpected: true, code: 1006 }]);
});

test('a throwing callback is logged, not thrown into the socket', () => {
  const errors = [];
  const boom = () => { throw new Error('boom'); };
  const { fake } = session({
    onAudio: boom, onTranslationText: boom, onSourceText: boom, onReady: boom, onClose: boom,
    log: { error: (m) => errors.push(m), warn() {} },
  });
  fake.open();
  assert.doesNotThrow(() => {
    fake.serverSends({ type: 'session.updated' });
    fake.serverSends({ type: 'session.output_audio.delta', delta: 'AAAA' });
    fake.serverSends({ type: 'session.output_transcript.delta', delta: 'a' });
    fake.serverSends({ type: 'session.input_transcript.delta', delta: 'b' });
    fake.emit('message', Buffer.from('null'));
    fake.serverCloses(1011);
  });
  assert.strictEqual(errors.length, 5);
});

test('nothing is delivered after we closed it', () => {
  const { s, fake, seen } = session();
  fake.open();
  fake.serverSends({ type: 'session.updated' });
  s.close();
  fake.readyState = 1; // real ws keeps reading until the server answers the close frame
  fake.serverSends({ type: 'session.output_audio.delta', delta: 'AAAA' });
  assert.strictEqual(seen.audio.length, 0);
});

test('decoded audio owns its buffer: AudioFrame hands data.buffer to native from byte 0', () => {
  const { fake, seen } = session();
  fake.open();
  fake.serverSends({ type: 'session.output_audio.delta', delta: Buffer.from(Int16Array.from([1, 2, 3]).buffer).toString('base64') });
  assert.strictEqual(seen.audio[0].byteOffset, 0);
  assert.strictEqual(seen.audio[0].buffer.byteLength, 6);
});

for (const [transcribeModel, noiseReduction] of [[undefined, undefined], [null, null], ['whisper-1', null]]) {
  test(`the selftest asks for exactly what a live session asks for (${transcribeModel}, ${noiseReduction})`, async () => {
    const live = session({ transcribeModel, noiseReduction });
    live.fake.open();
    const { factory, last } = fakeWsFactory();
    const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, appendCheckMs: 10, transcribeModel, noiseReduction });
    last().open();
    assert.deepStrictEqual(last().sentOfType('session.update')[0].session.audio.input, live.fake.sent[0].session.audio.input);
    last().serverSends({ type: 'session.updated' });
    await result;
  });
}

test('selftest fails on an error that follows session.created, and closes its socket', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, quietMs: 200 });
  last().open();
  last().serverSends({ type: 'session.created' });
  last().serverSends({ type: 'error', error: { message: 'bad field' } });
  assert.strictEqual((await result).ok, false);
  assert.strictEqual(last().readyState, 3);
});

test('selftest gives up after timeoutMs and closes its socket', async () => {
  const { factory, last } = fakeWsFactory();
  const r = await selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 20 });
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /timeout/);
  assert.strictEqual(last().readyState, 3);
});

test('selftest fails when the echo dropped what we asked for', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000 });
  last().open();
  last().serverSends({ type: 'session.updated', session: { audio: { input: { transcription: null, noise_reduction: { type: 'near_field' } }, output: { language: 'en' } } } });
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /transcription/);
});

// ── after re-review (task 10c) ──

test('a confirmed session outlives the ready timeout', async () => {
  const { fake, seen } = session({ readyTimeoutMs: 20 });
  fake.open();
  fake.serverSends({ type: 'session.updated' });
  await new Promise((r) => setTimeout(r, 40));
  assert.deepStrictEqual(seen.closes, []);
  assert.strictEqual(fake.readyState, 1);
});

test('selftest fails when the echo answers in another language or drops noise reduction, and survives a null frame', async () => {
  for (const [echo, why] of [
    [{ audio: { input: { transcription: { model: 'x' }, noise_reduction: { type: 'near_field' } }, output: { language: 'es' } } }, /language es/],
    [{ audio: { input: { transcription: { model: 'x' }, noise_reduction: null }, output: { language: 'en' } } }, /noise reduction/],
  ]) {
    const { factory, last } = fakeWsFactory();
    const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000 });
    last().open();
    assert.doesNotThrow(() => last().emit('message', Buffer.from('null')));
    last().serverSends({ type: 'session.updated', session: echo });
    const r = await result;
    assert.strictEqual(r.ok, false);
    assert.match(r.reason, why);
  }
});

test('frames read after fail() count for nothing', () => {
  const { fake, seen } = session();
  fake.open();
  fake.serverSends({ type: 'error', error: { message: 'refused' } });
  fake.readyState = 1; // real ws still parses what came in the same read (re-review, exp-f)
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'session.output_audio.delta', delta: 'AAAA' });
  assert.strictEqual(seen.ready, 0);
  assert.strictEqual(seen.audio.length, 0);
});

test('a regional form of the asked language is the same answer', () => {
  const { fake, seen } = session();
  fake.open();
  fake.serverSends({ type: 'session.updated', session: { audio: { output: { language: 'de-DE' } } } });
  assert.strictEqual(seen.ready, 1);
});

test('selftest fails on an error that follows session.updated within the append check', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, appendCheckMs: 200 });
  last().open();
  last().serverSends({ type: 'session.updated' });
  last().serverSends({ type: 'error', error: { message: 'unknown event session.input_audio_buffer.append' } });
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /unknown event/);
});
