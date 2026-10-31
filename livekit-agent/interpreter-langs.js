'use strict';
/**
 * Which engine renders a language pair.
 *
 * gpt-realtime-translate interprets simultaneously — it speaks while the
 * person is still talking — but only INTO 13 languages and only FROM the ones
 * it can hear. Every other pair runs on the phrase engine
 * (realtime-phrase-session.js), which waits for a pause.
 *
 * Both lists are copied from OpenAI's realtime translation guide on
 * 2026-10-31. A stale list only costs a pair that runs phrase by phrase when
 * it did not have to; re-check when OpenAI adds languages.
 */
const { SUPPORTED_LANGS } = require('./lang-names');

const SIMULTANEOUS_TARGETS = new Set([
  'en', 'es', 'pt', 'fr', 'ja', 'ru', 'zh', 'de', 'ko', 'hi', 'id', 'vi', 'it',
]);

const SIMULTANEOUS_SOURCES = new Set([
  'af', 'ar', 'az', 'be', 'bg', 'bn', 'bs', 'ca', 'cs', 'cy', 'da', 'de', 'dz',
  'el', 'en', 'eo', 'es', 'et', 'eu', 'fa', 'fi', 'fr', 'gl', 'gu', 'he', 'hi',
  'hr', 'ht', 'hu', 'hy', 'id', 'it', 'ja', 'jv', 'ka', 'kk', 'ko', 'ku', 'la',
  'lt', 'lv', 'mi', 'mk', 'ml', 'mn', 'ms', 'my', 'ne', 'nl', 'nn', 'no', 'pa',
  'pl', 'pt', 'ro', 'ru', 'sk', 'sl', 'sn', 'sq', 'sr', 'sv', 'sw', 'te', 'th',
  'tl', 'tr', 'uk', 'uz', 'vi', 'yo', 'zh',
]);

function isSupported(lang) {
  return SUPPORTED_LANGS.includes(lang);
}

/** 'simultaneous' or 'phrase' for speech in sourceLang heard in targetLang. */
function chooseEngine(sourceLang, targetLang) {
  return SIMULTANEOUS_TARGETS.has(targetLang) && SIMULTANEOUS_SOURCES.has(sourceLang)
    ? 'simultaneous'
    : 'phrase';
}

module.exports = { SIMULTANEOUS_TARGETS, SIMULTANEOUS_SOURCES, isSupported, chooseEngine };
