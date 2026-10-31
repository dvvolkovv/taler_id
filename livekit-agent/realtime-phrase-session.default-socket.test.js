// Run with: node --test  (from livekit-agent/)
//
// The production path: called with four arguments, the session builds a real
// `ws` socket with exactly the URL and options the in-call translator always
// used. `ws` is swapped in require.cache — no network.
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');

const wsPath = require.resolve('ws');
const calls = [];
class SpyWs extends EventEmitter {
  constructor(url, options) {
    super();
    calls.push({ url, options, argc: arguments.length });
    this.readyState = 0;
  }
}
SpyWs.CONNECTING = 0;
SpyWs.OPEN = 1;
SpyWs.CLOSING = 2;
SpyWs.CLOSED = 3;
require.cache[wsPath] = { id: wsPath, filename: wsPath, loaded: true, exports: SpyWs };
const { createRealtimeSession } = require('./realtime-phrase-session');

test('the four-argument call builds the same socket the in-call translator always did', () => {
  const saved = process.env.OPENAI_API_KEY;
  process.env.OPENAI_API_KEY = 'env-key';
  try {
    createRealtimeSession('auto', 'en', () => {}, () => {});
  } finally {
    if (saved === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = saved;
  }
  assert.deepStrictEqual(calls, [{
    url: 'wss://api.openai.com/v1/realtime?model=gpt-realtime-mini',
    options: { headers: { Authorization: 'Bearer env-key' } },
    argc: 2,
  }]);
});
