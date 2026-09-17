// Run with: node --test  (from livekit-agent/)
//
// Two bugs are pinned here. One: the same person arrived under two keys
// (`userId` from set-lang, `userId#device` from room metadata), so their own
// language counted as somebody else's and their speech was rendered into the
// language they were already speaking — which the instructions turn into
// silence. Two: one person switching the translator on could not get their own
// speech translated at all.
const test = require('node:test');
const assert = require('node:assert');
const { baseIdentity, translationTargets } = require('./translator-targets');

const ALICE = 'aaaaaaaa-1111-2222-3333-444444444444';
const BOB = 'bbbbbbbb-5555-6666-7777-888888888888';
const aliceId = `${ALICE}#1d5589ab`;
const bobId = `${BOB}#89455dbf`;

const targets = (langs, speaks, speaker) =>
  [...translationTargets(new Map(langs), new Map(speaks), speaker)].sort();

test('the device suffix is not part of who someone is', () => {
  assert.strictEqual(baseIdentity(aliceId), ALICE);
  assert.strictEqual(baseIdentity(ALICE), ALICE);
  assert.strictEqual(baseIdentity(''), '');
  assert.strictEqual(baseIdentity(undefined), '');
});

test('a listener is rendered the other party, not themselves', () => {
  // Alice wants Russian; only Bob's speech has anywhere to go.
  assert.deepStrictEqual(targets([[ALICE, 'ru']], [], bobId), ['ru']);
  assert.deepStrictEqual(targets([[ALICE, 'ru']], [], aliceId), []);
});

test('a preference set by bare userId still belongs to that person', () => {
  // The regression: set-lang keys by userId, capture by userId#device. Alice
  // used to see her own 'ru' as someone else's request and was translated
  // Russian→Russian, which comes out as silence.
  assert.deepStrictEqual(targets([[ALICE, 'ru']], [], aliceId), []);
});

test('a preference set by full identity is the same preference', () => {
  assert.deepStrictEqual(targets([[aliceId, 'ru']], [], aliceId), []);
  assert.deepStrictEqual(targets([[aliceId, 'ru']], [], bobId), ['ru']);
});

test('the two sources agree instead of doubling the person', () => {
  // Metadata wrote the identity key, set-lang wrote the userId key.
  assert.deepStrictEqual(targets([[aliceId, 'ru'], [ALICE, 'ru']], [], aliceId), []);
});

test('both sides declaring gives both directions', () => {
  const langs = [[ALICE, 'ru'], [BOB, 'de']];
  assert.deepStrictEqual(targets(langs, [], aliceId), ['de']);
  assert.deepStrictEqual(targets(langs, [], bobId), ['ru']);
});

test('one person naming a pair sets up both directions alone', () => {
  // "переводи с русского на немецкий и обратно", said by Alice, with Bob
  // having touched nothing.
  const langs = [[ALICE, 'ru']];
  const speaks = [[ALICE, 'de']];
  assert.deepStrictEqual(targets(langs, speaks, aliceId), ['de']);
  assert.deepStrictEqual(targets(langs, speaks, bobId), ['ru']);
});

test('a pair declared on one device applies to that person on any device', () => {
  const langs = [[ALICE, 'ru']];
  const speaks = [[aliceId, 'de']];
  assert.deepStrictEqual(targets(langs, speaks, `${ALICE}#otherdev`), ['de']);
});

test("one person's speakTo does not leak onto anyone else", () => {
  const langs = [[ALICE, 'ru']];
  const speaks = [[ALICE, 'de']];
  // Bob is still rendered only into what listeners asked for.
  assert.deepStrictEqual(targets(langs, speaks, bobId), ['ru']);
});

test('several listeners wanting the same language cost one session', () => {
  const langs = [[ALICE, 'ru'], [BOB, 'ru']];
  assert.deepStrictEqual(targets(langs, [], 'cccccccc#dev'), ['ru']);
});

test('three languages in the room produce three renderings', () => {
  const langs = [[ALICE, 'ru'], [BOB, 'de'], ['cccccccc', 'en']];
  assert.deepStrictEqual(targets(langs, [], aliceId), ['de', 'en']);
});

test('nobody declaring anything asks for nothing', () => {
  assert.deepStrictEqual(targets([], [], aliceId), []);
});

test('an empty language is not a target', () => {
  assert.deepStrictEqual(targets([[ALICE, '']], [], bobId), []);
  assert.deepStrictEqual(targets([[ALICE, 'ru']], [[ALICE, '']], aliceId), []);
});

test('speakTo matching what listeners already want does not duplicate', () => {
  const langs = [[ALICE, 'ru'], [BOB, 'de']];
  const speaks = [[ALICE, 'de']];
  assert.deepStrictEqual(targets(langs, speaks, aliceId), ['de']);
});
