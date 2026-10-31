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
 */
const { isSupported, chooseEngine } = require('./interpreter-langs');

const EMBEDDING_DIM = 192;

function trackNameFor(listenerUserId) {
  return `interp-for-${listenerUserId}`;
}

function checkPerson(p) {
  if (!p || typeof p.userId !== 'string' || p.userId === '' || p.userId.includes('#')) {
    throw new Error('participant userId must be a bare user id');
  }
  if (!isSupported(p.lang)) throw new Error(`participant ${p.userId}: unsupported language ${p.lang}`);
  const e = p.embedding;
  if (!Array.isArray(e) || e.length !== EMBEDDING_DIM || !e.every(Number.isFinite)) {
    throw new Error(`participant ${p.userId}: embedding must be ${EMBEDDING_DIM} finite numbers`);
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

module.exports = { planDirections, trackNameFor, EMBEDDING_DIM };
