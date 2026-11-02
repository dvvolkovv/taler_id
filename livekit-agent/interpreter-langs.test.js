// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { chooseEngine, isSupported, SIMULTANEOUS_TARGETS } = require('./interpreter-langs');
const { SUPPORTED_LANGS } = require('./lang-names');

test('Russian and German both ways are simultaneous', () => {
  assert.strictEqual(chooseEngine('ru', 'de'), 'simultaneous');
  assert.strictEqual(chooseEngine('de', 'ru'), 'simultaneous');
});

test('a listener the model cannot speak to goes phrase by phrase', () => {
  assert.strictEqual(chooseEngine('ru', 'sk'), 'phrase'); // Slovak is input-only
  assert.strictEqual(chooseEngine('sk', 'ru'), 'simultaneous');
});

test('a speaker the model cannot hear goes phrase by phrase', () => {
  assert.strictEqual(chooseEngine('am', 'en'), 'phrase'); // Amharic is not an input
});

test('every simultaneous target is a language the agent knows', () => {
  for (const lang of SIMULTANEOUS_TARGETS) assert.ok(SUPPORTED_LANGS.includes(lang), lang);
  assert.strictEqual(SIMULTANEOUS_TARGETS.size, 13);
});

test('only the agent languages are supported', () => {
  assert.strictEqual(isSupported('ru'), true);
  assert.strictEqual(isSupported('xx'), false);
  assert.strictEqual(isSupported(undefined), false);
});
