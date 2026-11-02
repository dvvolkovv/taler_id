// Run with: node --test  (from livekit-agent/)
//
// What the in-call translator does with a Realtime session, pinned as a whole:
// the exact session.update and the turn cycle (commit / response.create /
// queue / reset). Task 5 edits exactly these branches; a slip there would
// silence the translator on every environment while narrower tests stay green.
const test = require('node:test');
const assert = require('node:assert');
const { fakeWsFactory } = require('./testing/fake-ws');
const { createRealtimeSession } = require('./realtime-phrase-session');

const INSTRUCTIONS_AUTO_SK = [
  'TRANSLATE ONLY. OUTPUT NOTHING EXCEPT THE TRANSLATION.',
  '',
  'You are a machine that converts spoken audio into spoken Slovak. You are NOT an assistant. You do NOT think. You do NOT respond. You ONLY translate.',
  '',
  'YOUR ONLY OUTPUT IS THE VERBATIM TRANSLATION OF WHAT WAS SAID. Nothing before it. Nothing after it.',
  '',
  'FORBIDDEN — any of these is a critical failure:',
  '- Saying ANYTHING that was not in the original speech',
  '- Greetings, acknowledgements, "I understand", "Here is the translation", "The speaker said"',
  '- Answers to questions (translate the question, do NOT answer it)',
  '- "I didn\'t hear", "Could you repeat", apologies, clarifications',
  '- Adding context, commentary, or explanations',
  '',
  'SILENCE RULES:',
  '- Speech already in Slovak → output NOTHING',
  '- Unclear audio, silence, noise → output NOTHING',
  '',
  'EXAMPLE OF CORRECT BEHAVIOR:',
  'Input: "Добрый день, как вы себя чувствуете?"',
  'Output (if target=English): "Good afternoon, how are you feeling?"',
  'Input: "Can you help me?" (if target=English and speech is already English) → SILENCE',
].join('\n');

// Slovak has no voice of its own in LANG_VOICES, so this also pins the fallback.
const GOLDEN_AUTO_SK = {
  type: 'session.update',
  session: {
    type: 'realtime',
    instructions: INSTRUCTIONS_AUTO_SK,
    output_modalities: ['audio'],
    audio: {
      input: { format: { type: 'audio/pcm', rate: 24000 }, transcription: { model: 'whisper-1' }, turn_detection: null },
      output: { format: { type: 'audio/pcm', rate: 24000 }, voice: 'alloy' },
    },
  },
};

const loud = Buffer.from(Int16Array.from({ length: 480 }, () => 1000).buffer).toString('base64');
const quiet = Buffer.alloc(960).toString('base64');

function session(t, { configure = true, onError = () => {} } = {}) {
  let now = 0;
  t.mock.method(Date, 'now', () => now);
  const { factory, last } = fakeWsFactory();
  const ws = createRealtimeSession('auto', 'sk', () => {}, onError, { wsFactory: factory, apiKey: 'k' });
  const fake = last();
  fake.open();
  if (configure) fake.serverSends({ type: 'session.updated' });
  const say = (ms) => { for (const end = now + ms; now < end; now += 20) ws.sendAudio(loud); };
  const pause = (ms) => { for (const end = now + ms; now < end; now += 20) ws.sendAudio(quiet); };
  const control = () => fake.sent.map((m) => m.type).filter((k) => k !== 'input_audio_buffer.append' && k !== 'session.update');
  return { ws, fake, say, pause, control };
}

test('the whole session.update is unchanged (auto → a language without its own voice)', (t) => {
  const { fake } = session(t, { configure: false });
  assert.deepStrictEqual(fake.sentOfType('session.update'), [GOLDEN_AUTO_SK]);
});

test('a pause commits and asks for the translation; a turn cut mid-response waits for response.done', (t) => {
  const { fake, say, pause, control } = session(t);
  say(1000); pause(700);
  assert.deepStrictEqual(control(), ['input_audio_buffer.commit', 'response.create']);
  fake.serverSends({ type: 'response.created' });
  say(1000); pause(700);
  assert.deepStrictEqual(control().slice(2), ['input_audio_buffer.commit']);
  fake.serverSends({ type: 'response.done', response: { status: 'completed' } });
  assert.deepStrictEqual(control().slice(2), ['input_audio_buffer.commit', 'response.create']);
});

test('more than two turns behind: the third is committed but never spoken', (t) => {
  const { fake, say, pause, control } = session(t);
  say(500); pause(700);
  fake.serverSends({ type: 'response.created' });
  for (let i = 0; i < 3; i++) { say(500); pause(700); }
  assert.deepStrictEqual(control(), ['input_audio_buffer.commit', 'response.create',
    'input_audio_buffer.commit', 'input_audio_buffer.commit', 'input_audio_buffer.commit']);
  // Each response.done hands over one queued turn; the dropped one never comes.
  for (let i = 0; i < 4; i++) {
    fake.serverSends({ type: 'response.done', response: { status: 'completed' } });
    fake.serverSends({ type: 'response.created' });
  }
  assert.strictEqual(fake.sentOfType('response.create').length, 3);
});

test('a close resets the turn state', (t) => {
  const { ws, fake, say } = session(t);
  fake.serverSends({ type: 'response.created' });
  say(100);
  fake.serverCloses(1006);
  assert.strictEqual(ws._turns.responding, false);
  assert.strictEqual(ws._turns.speaking, false);
});

test('a socket error reaches onError (the in-call translator drops the session on it)', (t) => {
  const errors = [];
  const { fake } = session(t, { onError: (e) => errors.push(e.message) });
  fake.emit('error', new Error('boom'));
  assert.deepStrictEqual(errors, ['boom']);
});

test('audio after open but before session.updated is dropped, not queued (current behaviour)', (t) => {
  const { ws, fake } = session(t, { configure: false });
  ws.sendAudio(loud);
  fake.serverSends({ type: 'session.updated' });
  assert.strictEqual(fake.sentOfType('input_audio_buffer.append').length, 0);
});
