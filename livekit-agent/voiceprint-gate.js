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
 * If the embed service fails, the chunk is let through (fail-open). A dead
 * conversation is worse than an occasional leak, and a leak is mostly already
 * in the listener's own language, which the model is not expected to repeat.
 */
const { rms } = require('./wav');

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
 * @param opts.score      async (windowInt16) => ({ own, other }) cosine similarities; may throw
 * @param opts.onOutput   (chunkInt16) => void — the original chunk or silence, in order
 * @param opts.onSpeaking (on) => void — the owner started / stopped being let through
 * @param opts.onDecision (record) => void — one per judged chunk, for logs and the bench
 */
function createVoiceprintGate(opts) {
  const sampleRate = opts.sampleRate ?? 24000;
  const chunkSamples = Math.round((sampleRate * (opts.chunkMs ?? 500)) / 1000);
  const speechRms = opts.speechRms ?? 400;
  const threshold = opts.threshold ?? 0.25;
  const margin = opts.margin ?? 0.05;
  const hysteresis = Math.max(1, opts.hysteresis ?? 2);
  const { score, onOutput } = opts;
  const onSpeaking = opts.onSpeaking ?? (() => {});
  const onDecision = opts.onDecision ?? (() => {});
  const now = opts.now ?? Date.now;
  if (typeof score !== 'function' || typeof onOutput !== 'function') {
    throw new TypeError('createVoiceprintGate needs score and onOutput');
  }

  let filling = new Int16Array(chunkSamples);
  let filled = 0;
  let fillStartedAt = 0;
  let nextIndex = 0;
  let previous = null;
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
    while (offset < samples.length) {
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
    if (queue.length >= 2) judge(queue[queue.length - 2], samples);
  }

  function judge(chunk, after) {
    if (!chunk.speech) {
      chunk.decided = true;
      release();
      return;
    }
    const window = concat(chunk.before ? [chunk.before, chunk.samples, after] : [chunk.samples, after]);
    const askedAt = now();
    Promise.resolve()
      .then(() => score(window))
      .then(
        (s) => settle(chunk, s.own >= threshold && s.own - s.other >= margin, s, null, askedAt),
        (err) => settle(chunk, true, null, err, askedAt),
      );
  }

  function settle(chunk, pass, s, err, askedAt) {
    if (closed) return;
    chunk.pass = pass;
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
      let letThrough = false;
      if (!chunk.speech) {
        inSpeech = false;
        failStreak = 0;
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
        if (speaking && quietRun >= 2) {
          speaking = false;
          onSpeaking(false);
        }
      }
      onOutput(letThrough ? chunk.samples : new Int16Array(chunk.samples.length));
    }
  }

  return {
    push,
    close() {
      closed = true;
      queue.length = 0;
    },
  };
}

module.exports = { createVoiceprintGate };
