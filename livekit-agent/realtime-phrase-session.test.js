// Run with: node --test  (from livekit-agent/)
//
// createRealtimeSession moved out of translator.js. These pin what the
// in-call translator has always sent to OpenAI, so neither the move nor the
// options the interpreter adds can change it unnoticed.
const test = require('node:test');
const assert = require('node:assert');
const { fakeWsFactory } = require('./testing/fake-ws');
const { createRealtimeSession } = require('./realtime-phrase-session');

function open(source, target, opts = {}) {
  const { factory, last } = fakeWsFactory();
  const audio = [];
  const ws = createRealtimeSession(source, target, (pcm) => audio.push(pcm), () => {}, {
    wsFactory: factory,
    apiKey: 'test-key',
    ...opts,
  });
  const fake = last();
  fake.open();
  return { ws, fake, audio };
}

test('called the old way it opens gpt-realtime-mini with the key from the environment', () => {
  const saved = process.env.OPENAI_API_KEY;
  process.env.OPENAI_API_KEY = 'env-key';
  try {
    const { factory, last } = fakeWsFactory();
    createRealtimeSession('auto', 'en', () => {}, () => {}, { wsFactory: factory });
    assert.strictEqual(last().url, 'wss://api.openai.com/v1/realtime?model=gpt-realtime-mini');
    assert.deepStrictEqual(last().options, { headers: { Authorization: 'Bearer env-key' } });
  } finally {
    if (saved === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = saved;
  }
});

test('the session.update the in-call translator sends is unchanged', () => {
  const { fake } = open('auto', 'en');
  const [update] = fake.sentOfType('session.update');
  assert.strictEqual(update.session.type, 'realtime');
  assert.deepStrictEqual(update.session.output_modalities, ['audio']);
  assert.deepStrictEqual(update.session.audio, {
    input: {
      format: { type: 'audio/pcm', rate: 24000 },
      transcription: { model: 'whisper-1' },
      turn_detection: null,
    },
    output: { format: { type: 'audio/pcm', rate: 24000 }, voice: 'echo' },
  });
  const lines = update.session.instructions.split('\n');
  assert.strictEqual(lines[0], 'TRANSLATE ONLY. OUTPUT NOTHING EXCEPT THE TRANSLATION.');
  assert.ok(lines.includes(
    'You are a machine that converts spoken audio into spoken English. You are NOT an assistant. You do NOT think. You do NOT respond. You ONLY translate.',
  ));
  assert.ok(lines.includes('- Speech already in English → output NOTHING'));
});

test('a known source language goes into the instructions', () => {
  const { fake } = open('ru', 'sk');
  const { instructions } = fake.sentOfType('session.update')[0].session;
  assert.ok(instructions.includes('converts spoken Russian audio into spoken Slovak'));
  assert.ok(instructions.includes('- Speech NOT in Russian → output NOTHING'));
});

test('another model can be asked for', () => {
  const { fake } = open('ru', 'sk', { model: 'gpt-realtime-2025-08-28' });
  assert.strictEqual(fake.url, 'wss://api.openai.com/v1/realtime?model=gpt-realtime-2025-08-28');
});

test('audio sent while the socket is still connecting waits for session.updated', () => {
  const { factory, last } = fakeWsFactory();
  const ws = createRealtimeSession('ru', 'de', () => {}, () => {}, { wsFactory: factory, apiKey: 'k' });
  const fake = last();
  ws.sendAudio(Buffer.alloc(960).toString('base64')); // still CONNECTING
  fake.open();
  assert.strictEqual(fake.sentOfType('input_audio_buffer.append').length, 0);
  fake.serverSends({ type: 'session.updated' });
  assert.strictEqual(fake.sentOfType('input_audio_buffer.append').length, 1);
});

test('translated audio deltas reach the callback as bytes', () => {
  const { fake, audio } = open('ru', 'de');
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'response.output_audio.delta', delta: Buffer.from([1, 0, 2, 0]).toString('base64') });
  assert.strictEqual(audio.length, 1);
  assert.deepStrictEqual(Array.from(audio[0]), [1, 0, 2, 0]);
});

const { isHallucination } = require('./realtime-phrase-session');

test('only real hallucinations are filtered, ordinary phrases are not', () => {
  assert.strictEqual(isHallucination('Добрый день'), false);
  assert.strictEqual(isHallucination('Guten Tag, wie geht es Ihnen?'), false);
  assert.strictEqual(isHallucination('thank you for watching'), true);
  assert.strictEqual(isHallucination('да да да'), true);
  assert.strictEqual(isHallucination('ok ok ok ok'), true);
  assert.strictEqual(isHallucination(' '), true);
});

test('onReady fires once the session is configured', () => {
  let ready = 0;
  const { fake } = open('ru', 'sk', { onReady: () => { ready += 1; } });
  assert.strictEqual(ready, 0);
  fake.serverSends({ type: 'session.updated' });
  assert.strictEqual(ready, 1);
});

test('recognised speech and its translation are reported, hallucinations are not', () => {
  const seen = [];
  const { fake } = open('ru', 'sk', { onTranscript: (t) => seen.push(t) });
  fake.serverSends({ type: 'conversation.item.input_audio_transcription.completed', transcript: ' Добрый день ' });
  fake.serverSends({ type: 'conversation.item.input_audio_transcription.completed', transcript: 'thank you for watching' });
  fake.serverSends({ type: 'response.output_audio_transcript.done', transcript: ' Dobrý deň ' });
  assert.deepStrictEqual(seen, [
    { role: 'source', text: 'Добрый день' },
    { role: 'translation', text: 'Dobrý deň' },
  ]);
});

test('onClose reports the close code', () => {
  const closes = [];
  const { fake } = open('ru', 'sk', { onClose: (c) => closes.push(c) });
  fake.serverCloses(1011);
  assert.deepStrictEqual(closes, [{ code: 1011 }]);
});

test('with pruneHistory a spoken phrase is deleted and a queued one is kept', () => {
  const { fake } = open('ru', 'sk', { pruneHistory: true });
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'input_audio_buffer.committed', item_id: 'in1' });
  fake.serverSends({ type: 'response.created', response: { id: 'r1' } });
  fake.serverSends({ type: 'input_audio_buffer.committed', item_id: 'in2' }); // cut while r1 speaks
  fake.serverSends({ type: 'response.done', response: { id: 'r1', status: 'completed', output: [{ id: 'out1' }] } });
  assert.deepStrictEqual(fake.sentOfType('conversation.item.delete').map((m) => m.item_id), ['in1', 'out1']);

  fake.serverSends({ type: 'response.created', response: { id: 'r2' } });
  fake.serverSends({ type: 'response.done', response: { id: 'r2', status: 'completed', output: [{ id: 'out2' }] } });
  assert.deepStrictEqual(
    fake.sentOfType('conversation.item.delete').map((m) => m.item_id),
    ['in1', 'out1', 'in2', 'out2'],
  );
});

test('log lines carry the caller tag; the in-call translator keeps [TRANSLATOR]', (t) => {
  const lines = [];
  t.mock.method(console, 'log', (...args) => lines.push(args.join(' ')));
  open('ru', 'sk', { logTag: 'INTERPRETER' });
  open('ru', 'sk');
  assert.ok(lines.some((l) => l.startsWith('[INTERPRETER] Opening WS for ru→sk')));
  assert.ok(lines.some((l) => l.startsWith('[TRANSLATOR] Opening WS for ru→sk')));
});

test('without pruneHistory nothing is deleted', () => {
  const { fake } = open('ru', 'sk');
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'input_audio_buffer.committed', item_id: 'in1' });
  fake.serverSends({ type: 'response.created', response: { id: 'r1' } });
  fake.serverSends({ type: 'response.done', response: { id: 'r1', status: 'completed', output: [{ id: 'out1' }] } });
  assert.strictEqual(fake.sentOfType('conversation.item.delete').length, 0);
});
