/**
 * Decides where one person's speech is cut into turns, and when each turn is
 * handed to the model for translation.
 *
 * The translator runs its Realtime sessions without server VAD, so the cutting
 * is ours to do. The rule that matters is the one about cutting *during* a
 * response: the model speaks one translation at a time, and while it speaks the
 * person keeps talking. Holding the buffer uncut until the response ends piles
 * several utterances into a single commit, and the model then renders a
 * fragment of the lump — the rest of what was said never comes out anywhere.
 * That is the "it loses text, it only translates the last phrase" complaint.
 *
 * So the buffer is always cut at the boundary. What waits is only the request
 * to speak, and it waits in a queue that is deliberately short: a translation
 * arriving a minute late is not a translation, so beyond `maxQueued` turns the
 * overflow is dropped loudly rather than allowed to drift further behind.
 */

const DEFAULT_SILENCE_MS = 600;
const DEFAULT_FORCE_MS = 7000;
/** Turns allowed to wait. Past this the translation is no longer live. */
const DEFAULT_MAX_QUEUED = 2;

function createTurnTaker(opts = {}) {
  const silenceMs = opts.silenceMs ?? DEFAULT_SILENCE_MS;
  const forceMs = opts.forceMs ?? DEFAULT_FORCE_MS;
  const maxQueued = opts.maxQueued ?? DEFAULT_MAX_QUEUED;
  const onCommit = opts.onCommit ?? (() => {});
  const onRespond = opts.onRespond ?? (() => {});
  const onDrop = opts.onDrop ?? (() => {});

  let hasSpeech = false;
  let speechStartMs = null;
  let silenceSinceMs = null;
  let responding = false;
  let queued = 0;

  function boundary(reason) {
    hasSpeech = false;
    speechStartMs = null;
    silenceSinceMs = null;

    // Cut first, always — this is the part that must not wait on the model.
    onCommit(reason);

    if (!responding) {
      onRespond(reason);
      return;
    }
    if (queued < maxQueued) {
      queued++;
      return;
    }
    // Committed, so the audio is still on the conversation; we just never ask
    // for it to be spoken. Saying so out loud beats a silent gap.
    onDrop(reason);
  }

  return {
    get queued() {
      return queued;
    },
    get responding() {
      return responding;
    },
    /** True between the first speech frame and the boundary that closes it. */
    get speaking() {
      return hasSpeech;
    },

    /** One audio frame's worth of "was this speech", on the wall clock. */
    feed(isSpeech, nowMs) {
      if (isSpeech) {
        if (!hasSpeech) {
          hasSpeech = true;
          speechStartMs = nowMs;
        }
        silenceSinceMs = null;
        // Someone who does not pause still has to be translated in pieces.
        if (speechStartMs !== null && nowMs - speechStartMs >= forceMs) {
          boundary('force');
        }
        return;
      }
      if (!hasSpeech) return;
      if (silenceSinceMs === null) {
        silenceSinceMs = nowMs;
        return;
      }
      if (nowMs - silenceSinceMs >= silenceMs) {
        boundary('silence');
      }
    },

    /**
     * Closes the current turn without waiting for more frames — for when the
     * audio stops arriving at all (mute, unpublish) and `feed` goes quiet.
     */
    flush(reason = 'flush') {
      if (!hasSpeech) return false;
      boundary(reason);
      return true;
    },

    responseCreated() {
      responding = true;
    },

    responseDone() {
      responding = false;
      if (queued > 0) {
        queued--;
        onRespond('queued');
      }
    },

    reset() {
      hasSpeech = false;
      speechStartMs = null;
      silenceSinceMs = null;
      responding = false;
      queued = 0;
    },
  };
}

module.exports = { createTurnTaker };
