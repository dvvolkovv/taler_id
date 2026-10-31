// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const messages = require('./interpreter-messages');

test('message shapes', () => {
  assert.deepStrictEqual(messages.caption('translation', 'u1', 'Hallo', 0), {
    type: 'caption', role: 'translation', speaker: 'u1', text: 'Hallo', final: false,
  });
  assert.deepStrictEqual(messages.speaking('u1', 1), { type: 'speaking', speaker: 'u1', on: true });
  assert.deepStrictEqual(messages.status('reconnecting'), { type: 'status', state: 'reconnecting' });
});

test('send publishes reliable JSON on the interp topic to exactly the given identities', async () => {
  const calls = [];
  const participant = { publishData: async (payload, opts) => calls.push({ payload, opts }) };
  assert.strictEqual(await messages.send(participant, ['u1#phone'], messages.status('ok')), true);
  assert.deepStrictEqual(JSON.parse(Buffer.from(calls[0].payload).toString()), { type: 'status', state: 'ok' });
  assert.deepStrictEqual(calls[0].opts, { reliable: true, topic: 'interp', destination_identities: ['u1#phone'] });
});

test('nobody to send to means nothing is published', async () => {
  const participant = { publishData: async () => { throw new Error('must not be called'); } };
  assert.strictEqual(await messages.send(participant, [], messages.status('ok')), false);
  assert.strictEqual(await messages.send(undefined, ['u1#phone'], messages.status('ok')), false);
});
