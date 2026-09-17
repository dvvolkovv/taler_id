/**
 * Decides which languages one person's speech has to be rendered into.
 *
 * Two things live here, and both were getting in each other's way.
 *
 * Identity. A LiveKit participant joins as `userId#deviceHash` (see
 * makeParticipantIdentity in the backend), but the language preference arrives
 * from two directions: the room metadata, keyed by the full identity, and
 * POST /translator/set-lang, keyed by the bare userId. The same person ended up
 * under two keys, so their own declared language read as "some other
 * participant wants this", and their speech was handed a target equal to the
 * language they were already speaking. The instructions say to stay silent when
 * the speech is already in the target — so that person came out translated
 * nowhere at all. Every key here is reduced to the part before the '#', which
 * makes the two sources agree, and collapses one person's two devices onto the
 * one preference they obviously share.
 *
 * Direction. Declaring a language says "render everyone else into this for me".
 * That is one-directional on purpose, and it works when both sides declare. It
 * does not work when one person switches the translator on for a conversation,
 * which is what people actually do: their own speech then has nowhere to go.
 * `speakTo` is the other half — "and render MY speech into that" — so one
 * person naming a pair out loud sets up both directions.
 */

/** The person behind a participant identity, ignoring which device they used. */
function baseIdentity(id) {
  if (typeof id !== 'string') return '';
  const hash = id.indexOf('#');
  return hash === -1 ? id : id.slice(0, hash);
}

/**
 * @param speakerLang Map<identity|userId, lang> — "render others into this for me"
 * @param speakTo     Map<identity|userId, lang> — "render my own speech into this"
 * @param speaker     identity of whoever is talking
 * @returns Set<lang> — one realtime session per entry
 */
function translationTargets(speakerLang, speakTo, speaker) {
  const self = baseIdentity(speaker);
  const targets = new Set();

  for (const [id, lang] of speakerLang) {
    // A listener's own language is not a target for their own voice: rendering
    // Russian into Russian produces silence and burns a session doing it.
    if (baseIdentity(id) === self) continue;
    if (lang) targets.add(lang);
  }

  for (const [id, lang] of speakTo) {
    if (baseIdentity(id) !== self) continue;
    if (lang) targets.add(lang);
  }

  return targets;
}

module.exports = { baseIdentity, translationTargets };
