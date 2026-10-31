// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { fakeWsFactory } = require('./testing/fake-ws');
const { createPhraseSession } = require('./phrase-session');

function session() {
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
  });
  const fake = last();
  fake.open();
  return { s, fake, seen };
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
