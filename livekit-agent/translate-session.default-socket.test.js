// Run with: node --test  (from livekit-agent/)
// The production socket: `ws` swapped in require.cache — no network.
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');

const wsPath = require.resolve('ws');
const calls = [];
class SpyWs extends EventEmitter {
  constructor(url, options) { super(); calls.push({ url, options }); this.readyState = 0; }
}
Object.assign(SpyWs, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });
require.cache[wsPath] = { id: wsPath, filename: wsPath, loaded: true, exports: SpyWs };
const { createTranslateSession, selftestTranslate } = require('./translate-session');

test('the default socket times out a stalled handshake, in a live session and in the selftest', () => {
  createTranslateSession({ apiKey: 'k', targetLang: 'de' });
  selftestTranslate({ apiKey: 'k', timeoutMs: 1 });
  assert.deepStrictEqual(calls.map((c) => c.options.handshakeTimeout), [10000, 10000]);
});
