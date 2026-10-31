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
