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

test('the first participant is checked as strictly as the second', () => {
  // Unchecked, an empty print reaches the gate, cosine() throws on the length
  // mismatch and the gate fails open: that person's direction runs unfiltered.
  assert.throws(() => planDirections([{ ...ivan, embedding: [] }, anna]), /192 finite numbers/);
  assert.throws(() => planDirections([{ ...ivan, lang: 'xx' }, anna]), /unsupported language/);
  assert.throws(() => planDirections([{ ...ivan, userId: '' }, anna]), /bare user id/);
  assert.throws(() => planDirections([null, anna]), /bare user id/);
});

test('a third participant is refused, not ignored', () => {
  assert.throws(() => planDirections([ivan, anna, { userId: 'u-olga', lang: 'en', embedding: print(3) }]), /exactly two/);
});

test('a user id that is not a plain id is refused', () => {
  for (const userId of ['', ' ', 'u anna', 'u-anna\n', '\u0000', 'x'.repeat(129), 42, null, undefined]) {
    assert.throws(() => planDirections([ivan, { ...anna, userId }]), /bare user id/, JSON.stringify(userId));
  }
  // What the backend actually sends.
  const [toAnna] = planDirections([ivan, { ...anna, userId: 'aaaaaaaa-1111-2222-3333-444444444444' }]);
  assert.strictEqual(toAnna.trackName, 'interp-for-aaaaaaaa-1111-2222-3333-444444444444');
});

test('every number of the print is checked, holes and nulls included', () => {
  const bad = [
    [], // Profile.ownerEmbedding default: "no print"
    print(1).map((x, i) => (i === 7 ? null : x)), // JSON turns NaN into null
    [...print(1).slice(1), Infinity],
    print(1).map(String),
    new Array(192), // every() skips holes
    [...print(1), 0], // 193
  ];
  for (const embedding of bad) {
    assert.throws(() => planDirections([ivan, { ...anna, embedding }]), /192 finite numbers/);
  }
});

test('a print with no usable length is refused: its owner could never pass the gate', () => {
  for (const value of [0, 1e-170, 1e200]) {
    // 0 and an underflowing square both give |v| = 0, so cosine() scores 0 against
    // any voice; an overflowing square gives 0 or NaN.
    assert.throws(
      () => planDirections([ivan, { ...anna, embedding: new Array(192).fill(value) }]),
      /usable length/,
      String(value),
    );
  }
});

test('two prints the gate cannot tell apart are refused', () => {
  assert.throws(() => planDirections([ivan, { ...anna, embedding: ivan.embedding }]), /same voice print/);
  assert.throws(() => planDirections([ivan, { ...anna, embedding: ivan.embedding.map((x) => x * 3) }]), /same voice print/);
  // Alike is fine — telling alike voices apart is the gate's job. Cosine 0.8:
  const alike = print(0).map((x, i) => (i === 1 ? 0.75 : x));
  assert.doesNotThrow(() => planDirections([ivan, { ...anna, embedding: alike }]));
});

test('an error message never carries a voice print or a forged log line', () => {
  const vector = Array.from({ length: 192 }, (_, i) => 0.123456789 + i);
  const clean = (e) => {
    assert.ok(!e.message.includes('0.123456789'), e.message);
    assert.ok(!e.message.includes('\n'), e.message);
    assert.ok(e.message.length < 120, e.message);
    return true;
  };
  // A field mix-up: the print sent as the language.
  for (const lang of [vector, 'x'.repeat(5000), 'ru\nFATAL forged', { toString: 1 }]) {
    assert.throws(() => planDirections([ivan, { ...anna, lang }]), (e) => /unsupported language/.test(e.message) && clean(e));
  }
  assert.throws(() => planDirections([ivan, { ...anna, embedding: [...vector.slice(1), NaN] }]), clean);
  assert.throws(() => planDirections([ivan, { ...anna, embedding: vector.map(() => 0) }]), clean);
  assert.throws(() => planDirections([ivan, { ...anna, embedding: ivan.embedding }]), clean);
});
