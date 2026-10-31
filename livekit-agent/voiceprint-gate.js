'use strict';
/**
 * Lets through only the phone owner's own speech, judged a chunk at a time
 * against two voice prints: the owner's and the partner's.
 *
 * Two people sit at one table, each with their own phone, so each microphone
 * hears both of them. Only the owner's speech may reach the interpreter: the
 * partner's voice on this phone would be "translated" back at them, and so
 * would the translation playing in this phone's own earpiece. The assistant's
 * gate asks one question, "does this sound like the owner?". With both prints
 * at hand this gate also asks "more like the owner than the partner?", which
 * is the question that actually separates two people at one table.
 *
 * A chunk is judged on a window that includes its neighbours — the embedding
 * model needs about a second of audio to say anything — so a chunk goes out
 * only after the next one has arrived. That, plus the embed call, is the
 * gate's whole delay (~1 s with 500 ms chunks).
 *
 * Out comes either the original chunk or the same length of zeros, in order,
 * so the engine downstream gets a steady stream. Chunks too quiet to count as
 * speech go out as zeros too: a neighbour below the speech threshold is still
 * intelligible to a translation model.
 *
 * If the embed service fails, the chunk is let through (fail-open) without
 * counting as a pass: unjudged audio is no evidence, so the hysteresis stays
 * where it was. A dead conversation is worse than an occasional leak, and a
 * leak is mostly in the listener's own language, on which gpt-realtime-
 * translate stays silent (bench/PROBE.md).
 *
 * When the audio stops — the track ends, the participant reconnects — end()
 * lets out what is held instead of splicing it onto whatever comes next, and
 * the next audio starts as new speech.
 */
const { rms } = require('./wav');

// Quiet chunks before the speaking indicator goes off: one quiet chunk is a
// pause inside a phrase and must not make the indicator blink.
const SPEAKING_OFF_AFTER = 2;

function concat(parts) {
  let length = 0;
  for (const p of parts) length += p.length;
  const out = new Int16Array(length);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * @param opts.score      async (windowInt16) => ({ own, other }) cosine similarities; may throw,
 *                        must settle — a score that never settles stalls this direction
 *                        (the embed client's timeout guarantees it does)
 * @param opts.onOutput   (chunkInt16) => void — the original chunk or silence, in order; the
 *                        chunk is also the next window's "before", so do not modify it
 * @param opts.onSpeaking (on) => void — the owner started / stopped being let through
 * @param opts.onDecision (record) => void — one per judged chunk, for logs and the bench
 */
function createVoiceprintGate(opts) {
  const sampleRate = opts.sampleRate ?? 24000;
  const chunkSamples = Math.round((sampleRate * (opts.chunkMs ?? 500)) / 1000);
  // A zero-sample chunk would spin push() forever and freeze the whole agent.
  if (!(chunkSamples >= 1)) throw new RangeError(`voiceprint gate: ${opts.chunkMs} ms at ${sampleRate} Hz is no chunk at all`);
  const speechRms = opts.speechRms ?? 400;
  const threshold = opts.threshold ?? 0.25;
  const margin = opts.margin ?? 0.05;
  const h = Number(opts.hysteresis ?? 2);
  const hysteresis = Number.isFinite(h) ? Math.max(1, Math.round(h)) : 2;
  const { score } = opts;
  const now = opts.now ?? Date.now;
  if (typeof score !== 'function' || typeof opts.onOutput !== 'function') {
    throw new TypeError('createVoiceprintGate needs score and onOutput');
  }
  // A throwing callback must not stall the stream or, from inside a promise
  // handler, take the whole agent process down with an unhandled rejection.
  const safe = (name, fn) => (arg) => {
    if (!fn) return;
    try {
      fn(arg);
    } catch (e) {
      console.error(`[INTERPRETER] voiceprint gate: ${name} callback failed: ${e && e.message}`);
    }
  };
  const onOutput = safe('onOutput', opts.onOutput);
  const onSpeaking = safe('onSpeaking', opts.onSpeaking);
  const onDecision = safe('onDecision', opts.onDecision);

  let filling = new Int16Array(chunkSamples);
  let filled = 0;
  let fillStartedAt = 0;
  let nextIndex = 0;
  let previous = null;
  let awaiting = null; // the newest chunk, still waiting for its look-ahead
  const queue = [];
  let closed = false;

  // Release-side state; advanced strictly in stream order.
  let inSpeech = false;
  let open = false;
  let failStreak = 0;
  let speaking = false;
  let quietRun = 0;

  function push(samples) {
    if (closed) return;
    let offset = 0;
    // closed is checked per chunk: a callback may close the gate mid-push.
    while (offset < samples.length && !closed) {
      if (filled === 0) fillStartedAt = now();
      const take = Math.min(chunkSamples - filled, samples.length - offset);
      filling.set(samples.subarray(offset, offset + take), filled);
      filled += take;
      offset += take;
      if (filled === chunkSamples) {
        complete(filling, fillStartedAt);
        filling = new Int16Array(chunkSamples);
        filled = 0;
      }
    }
  }

  function complete(samples, startedAt) {
    const chunk = {
      index: nextIndex++,
      samples,
      startedAt,
      before: previous,
      speech: rms(samples) >= speechRms,
      decided: false,
      pass: false,
    };
    previous = samples;
    queue.push(chunk);
    // The chunk before this one now has its look-ahead and can be judged.
    if (awaiting) judge(awaiting, samples);
    awaiting = chunk;
  }

  /**
   * The audio stopped (track ended, participant reconnecting): judge what is
   * held without its look-ahead, let it out now rather than spliced in front
   * of whatever comes next, and start the next audio as new speech.
   */
  function end() {
    if (closed) return;
    if (filled > 0) {
      complete(filling.slice(0, filled), fillStartedAt);
      filling = new Int16Array(chunkSamples);
      filled = 0;
    }
    if (awaiting) judge(awaiting, null);
    awaiting = null;
    previous = null;
    queue.push({ boundary: true, decided: true });
    release();
  }

  function judge(chunk, after) {
    if (!chunk.speech) {
      chunk.decided = true;
      release();
      return;
    }
    const window = concat([chunk.before, chunk.samples, after].filter(Boolean));
    const askedAt = now();
    Promise.resolve()
      .then(() => score(window))
      .then(
        (s) => {
          const own = Number(s && s.own);
          const other = Number(s && s.other);
          if (!Number.isFinite(own) || !Number.isFinite(other)) {
            settle(chunk, true, null, new Error('score gave no similarities'), askedAt);
          } else {
            settle(chunk, own >= threshold && own - other >= margin, { own, other }, null, askedAt);
          }
        },
        (err) => settle(chunk, true, null, err, askedAt),
      );
  }

  function settle(chunk, pass, s, err, askedAt) {
    if (closed) return;
    chunk.pass = pass;
    chunk.failOpen = Boolean(err);
    chunk.decided = true;
    onDecision({
      index: chunk.index,
      startedAt: chunk.startedAt,
      own: s ? s.own : null,
      other: s ? s.other : null,
      pass,
      failOpen: Boolean(err),
      error: err ? String(err.message || err) : null,
      latencyMs: now() - askedAt,
    });
    release();
  }

  function release() {
    while (!closed && queue.length > 0 && queue[0].decided) {
      const chunk = queue.shift();
      if (chunk.boundary) {
        inSpeech = false;
        open = false;
        failStreak = 0;
        quietRun = 0;
        if (speaking) {
          speaking = false;
          onSpeaking(false);
        }
        continue;
      }
      let letThrough = false;
      if (!chunk.speech) {
        inSpeech = false;
        failStreak = 0;
      } else if (chunk.failOpen) {
        // Unjudged is no evidence either way: this chunk goes through, the
        // hysteresis stays where it was.
        letThrough = true;
      } else {
        if (!inSpeech) {
          // New speech gets no benefit of the doubt.
          inSpeech = true;
          open = chunk.pass;
          failStreak = chunk.pass ? 0 : 1;
        } else if (chunk.pass) {
          open = true;
          failStreak = 0;
        } else {
          failStreak += 1;
          if (failStreak >= hysteresis) open = false;
        }
        letThrough = open;
      }
      if (letThrough) {
        quietRun = 0;
        if (!speaking) {
          speaking = true;
          onSpeaking(true);
        }
      } else {
        quietRun += 1;
        if (speaking && quietRun >= SPEAKING_OFF_AFTER) {
          speaking = false;
          onSpeaking(false);
        }
      }
      onOutput(letThrough ? chunk.samples : new Int16Array(chunk.samples.length));
    }
  }

  return {
    push,
    end,
    close() {
      closed = true;
      queue.length = 0;
    },
  };
}

module.exports = { createVoiceprintGate };
