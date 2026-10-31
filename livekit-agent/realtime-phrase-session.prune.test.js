// Run with: node --test  (from livekit-agent/)
//
// pruneHistory against the real turn taker, with a server stand-in that
// acknowledges commits and response.create in order.
const test = require('node:test');
const assert = require('node:assert');
const { fakeWsFactory } = require('./testing/fake-ws');
const { createRealtimeSession } = require('./realtime-phrase-session');

const loud = Buffer.from(Int16Array.from({ length: 480 }, () => 1000).buffer).toString('base64');
const quiet = Buffer.alloc(960).toString('base64');

function pruning(t) {
  let now = 0;
  t.mock.method(console, 'log', () => {});
  t.mock.method(console, 'warn', () => {});
  t.mock.method(Date, 'now', () => now);
  const { factory, last } = fakeWsFactory();
  const ws = createRealtimeSession('ru', 'sk', () => {}, () => {}, { wsFactory: factory, apiKey: 'k', pruneHistory: true });
  const fake = last();
  fake.open();
  fake.serverSends({ type: 'session.updated' });
  let seen = 0;
  let nIn = 0;
  let nResp = 0;
  const serve = () => {
    for (; seen < fake.sent.length; seen++) {
      const m = fake.sent[seen];
      if (m.type === 'input_audio_buffer.commit') fake.serverSends({ type: 'input_audio_buffer.committed', item_id: `in${++nIn}` });
      if (m.type === 'response.create') fake.serverSends({ type: 'response.created', response: { id: `r${++nResp}` } });
    }
  };
  const phrase = () => {
    for (const end = now + 600; now < end; now += 20) ws.sendAudio(loud);
    for (const end = now + 700; now < end; now += 20) ws.sendAudio(quiet);
    serve();
  };
  const done = (id) => {
    fake.serverSends({ type: 'response.done', response: { id, status: 'completed', output: [{ id: `out_${id}` }] } });
    serve();
  };
  const control = () => fake.sent
    .filter((m) => m.type !== 'input_audio_buffer.append' && m.type !== 'session.update')
    .map((m) => (m.item_id ? `delete ${m.item_id}` : m.type));
  return { phrase, done, control };
}

test('the spoken phrase is deleted before the queued phrase is asked for', (t) => {
  const { phrase, done, control } = pruning(t);
  phrase();
  phrase(); // cut while r1 speaks
  done('r1');
  assert.deepStrictEqual(control().slice(-3), ['delete in1', 'delete out_r1', 'response.create']);
});

test('two phrases cut during one response: no response is asked for on an empty conversation', (t) => {
  const { phrase, done, control } = pruning(t);
  phrase();
  phrase();
  phrase(); // phrases 2 and 3 both cut while r1 speaks
  done('r1'); // r2 is created over in2 and in3
  done('r2'); // both are deleted with it
  assert.strictEqual(control().filter((c) => c === 'response.create').length, 2);
});
