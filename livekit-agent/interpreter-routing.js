'use strict';
/**
 * Turns the two participants the backend sends into the two directions the
 * interpreter runs: who speaks, who listens, in which languages, by which
 * engine, onto which track.
 *
 * Exactly two different people with different languages the agent knows and a
 * 192-number voice print each — the gate cannot tell them apart without both
 * prints, and a same-language pair needs no interpreter. User ids arrive bare
 * (no "#device"): the track and the gate belong to the person, not the phone.
 *
 * A print the gate cannot score against is refused here rather than found out
 * in the room, where it fails without a word: a zero-length print scores 0
 * against every voice, so its owner never passes, and two prints alike enough
 * score every voice the same, so nobody does.
 */
const { isSupported, chooseEngine } = require('./interpreter-langs');
const { cosine } = require('./voice-embed-client');

const EMBEDDING_DIM = 192;
// The gate lets a chunk through only if it is closer to the owner than to the
// partner by a margin. Prints this alike leave nothing to measure. Different
// people's ECAPA prints sit far below it; a duplicate or a rescaled copy of one
// print sits at 1.
const SAME_PRINT_COSINE = 0.99;
// Matched exactly against `<userId>#<device>` identities, and part of a track
// name and of log lines. Backend ids are UUIDs.
const USER_ID = /^[A-Za-z0-9_-]{1,128}$/;
const LANG_SHAPE = /^[A-Za-z0-9_-]{1,16}$/;

function trackNameFor(listenerUserId) {
  return `interp-for-${listenerUserId}`;
}

/** The language as given, for an error message — never a long or odd value: a mixed-up field could hold a voice print. */
function shownLang(lang) {
  if (typeof lang === 'string' && LANG_SHAPE.test(lang)) return lang;
  return `(${lang === null ? 'null' : typeof lang})`;
}

function checkPerson(p) {
  if (!p || typeof p.userId !== 'string' || !USER_ID.test(p.userId)) {
    throw new Error('participant userId must be a bare user id');
  }
  if (!isSupported(p.lang)) throw new Error(`participant ${p.userId}: unsupported language ${shownLang(p.lang)}`);
  const e = p.embedding;
  let ok = Array.isArray(e) && e.length === EMBEDDING_DIM;
  let sumSq = 0;
  // An index loop, not every(): every() skips holes, and new Array(192) would pass.
  for (let i = 0; ok && i < EMBEDDING_DIM; i++) {
    if (Number.isFinite(e[i])) sumSq += e[i] * e[i];
    else ok = false;
  }
  if (!ok) throw new Error(`participant ${p.userId}: embedding must be ${EMBEDDING_DIM} finite numbers`);
  // cosine() gives a zero-length vector 0 against anything; a print whose
  // squares underflow scores the same, and one whose squares overflow scores 0 or NaN.
  if (!(sumSq > 0) || !Number.isFinite(sumSq)) {
    throw new Error(`participant ${p.userId}: embedding has no usable length`);
  }
}

function planDirections(participants) {
  if (!Array.isArray(participants) || participants.length !== 2) {
    throw new Error('exactly two participants required');
  }
  const [a, b] = participants;
  checkPerson(a);
  checkPerson(b);
  if (a.userId === b.userId) throw new Error('participants must be two different people');
  if (a.lang === b.lang) throw new Error('participants speak the same language');
  if (cosine(a.embedding, b.embedding) >= SAME_PRINT_COSINE) {
    throw new Error('participants have the same voice print');
  }

  const direction = (speaker, listener) => ({
    speaker: speaker.userId,
    listener: listener.userId,
    sourceLang: speaker.lang,
    targetLang: listener.lang,
    engine: chooseEngine(speaker.lang, listener.lang),
    trackName: trackNameFor(listener.userId),
    ownEmbedding: speaker.embedding,
    otherEmbedding: listener.embedding,
  });
  return [direction(a, b), direction(b, a)];
}

module.exports = { planDirections, trackNameFor, EMBEDDING_DIM, SAME_PRINT_COSINE };
