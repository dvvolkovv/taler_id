// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { planDirections, trackNameFor } = require('./interpreter-routing');

const print = (k) => Array.from({ length: 192 }, (_, i) => (i === k ? 1 : 0));
const anna = { userId: 'u-anna', lang: 'de', embedding: print(1) };
const ivan = { userId: 'u-ivan', lang: 'ru', embedding: print(0) };

test('two people make two directions, each onto the listener track', () => {
  const [toAnna, toIvan] = planDirections([ivan, anna]);
  assert.deepStrictEqual(
    { ...toAnna, ownEmbedding: undefined, otherEmbedding: undefined },
    {
      speaker: 'u-ivan', listener: 'u-anna', sourceLang: 'ru', targetLang: 'de',
      engine: 'simultaneous', trackName: 'interp-for-u-anna', ownEmbedding: undefined, otherEmbedding: undefined,
    },
  );
  assert.strictEqual(toAnna.ownEmbedding, ivan.embedding);
  assert.strictEqual(toAnna.otherEmbedding, anna.embedding);
  assert.strictEqual(toIvan.speaker, 'u-anna');
  assert.strictEqual(toIvan.trackName, trackNameFor('u-ivan'));
  assert.strictEqual(toIvan.ownEmbedding, anna.embedding);
});

test('the engine is chosen per direction', () => {
  const laura = { userId: 'u-laura', lang: 'sk', embedding: print(2) };
  const [toLaura, toIvan] = planDirections([ivan, laura]);
  assert.strictEqual(toLaura.engine, 'phrase');
  assert.strictEqual(toIvan.engine, 'simultaneous');
});

test('anything but two different people with different known languages is refused', () => {
  assert.throws(() => planDirections([ivan]), /exactly two/);
  assert.throws(() => planDirections('x'), /exactly two/);
  assert.throws(() => planDirections([ivan, { ...ivan }]), /two different people/);
  assert.throws(() => planDirections([ivan, { ...anna, lang: 'ru' }]), /same language/);
  assert.throws(() => planDirections([ivan, { ...anna, lang: 'xx' }]), /unsupported language/);
  assert.throws(() => planDirections([ivan, { ...anna, userId: 'u-anna#dev' }]), /bare user id/);
});

test('a missing or malformed voice print is refused', () => {
  assert.throws(() => planDirections([ivan, { ...anna, embedding: undefined }]), /192 finite numbers/);
  assert.throws(() => planDirections([ivan, { ...anna, embedding: print(1).slice(1) }]), /192 finite numbers/);
  assert.throws(() => planDirections([ivan, { ...anna, embedding: [...print(1).slice(1), NaN] }]), /192 finite numbers/);
});
