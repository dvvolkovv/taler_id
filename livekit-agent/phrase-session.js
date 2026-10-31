'use strict';
/**
 * The phrase engine (realtime-phrase-session.js) behind the same interface as
 * translate-session.js, for the pairs gpt-realtime-translate cannot speak.
 * It waits for a pause and speaks whole phrases, so its transcripts arrive
 * whole as well (final = true). Spoken phrases are pruned from the
 * conversation: an interpreted talk can last an hour.
 *
 * The reconnecting wrapper learns that a direction has gone silent only from
 * onClose({ unexpected: true }). So, as in translate-session.js, each way this
 * session can go silent ends in such a close: a stalled handshake, a
 * session.update OpenAI refuses, a session that never confirms, a socket whose
 * writes pile up. These rules live here rather than in
 * realtime-phrase-session.js, so the in-call translator keeps its behaviour.
 */
const WebSocket = require('ws');
const { createRealtimeSession } = require('./realtime-phrase-session');

const SAMPLE_RATE = 24000;
const HANDSHAKE_TIMEOUT_MS = 10000;
const READY_TIMEOUT_MS = 10000;
const MAX_BUFFERED_BYTES = 1 << 20; // ~16 s of base64 audio at 64 KB/s
// Audio that waits for the session, as in translate-session.js: at most 4 s,
// older audio is dropped. It goes out through the engine's own path once the
// session is ready, so the turn-taker hears it as well.
const MAX_QUEUED_SAMPLES = 4 * SAMPLE_RATE;

const defaultWsFactory = (url, options) => new WebSocket(url, { ...options, handshakeTimeout: HANDSHAKE_TIMEOUT_MS });

function toBase64(int16) {
  return Buffer.from(int16.buffer, int16.byteOffset, int16.byteLength).toString('base64');
}

function toInt16(buf) {
  const even = buf.byteLength - (buf.byteLength % 2);
  // Copy: a short decode is a view into Node's shared 8 KB pool, and the
  // interpreter applies gain in place and hands data.buffer to LiveKit, which
  // reads from byte 0.
  return new Int16Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + even));
}

function createPhraseSession(opts) {
  const { sourceLang, targetLang, safetyId, log = console } = opts;
  const tag = `${sourceLang}→${targetLang}`;
  // Every callback reaches into the interpreter (gain, frame queue, data
  // channel). A throw must be logged as what it is and must not reach the
  // socket's handlers.
  const safe = (name, fn) => (...args) => {
    if (!fn) return;
    try {
      fn(...args);
    } catch (e) {
      log.error(`[INTERPRETER] phrase ${tag}: ${name} callback failed: ${e && e.message}`);
    }
  };
  const onAudio = safe('onAudio', opts.onAudio);
  const onTranslationText = safe('onTranslationText', opts.onTranslationText);
  const onSourceText = safe('onSourceText', opts.onSourceText);
  const onReady = safe('onReady', opts.onReady);
  const onClose = safe('onClose', opts.onClose);
  const readyTimeoutMs = opts.readyTimeoutMs ?? READY_TIMEOUT_MS;

  const baseFactory = opts.wsFactory || defaultWsFactory;
  // OpenAI takes the per-end-user id on Realtime connections as a header too.
  const wsFactory = safetyId
    ? (url, options = {}) => baseFactory(url, {
      ...options,
      headers: { ...options.headers, 'OpenAI-Safety-Identifier': safetyId },
    })
    : baseFactory;

  let ready = false;
  let closedByUs = false;
  let dropped = false; // fail() decided; frames already read must not count
  let ended = false; // the socket has closed
  let readyTimer = null;
  let queue = [];
  let queuedSamples = 0;
  const live = () => !closedByUs && !dropped && !ended;

  function forget() {
    clearTimeout(readyTimer);
    readyTimer = null;
    queue = [];
    queuedSamples = 0;
  }

  // Ends the socket at once (terminate, not close: a stalled socket would hold
  // the close frame behind its backlog) and reports it as unexpected, so the
  // wrapper reconnects and, past its limits, the interpreter ends.
  function fail(reason) {
    if (!live()) return;
    dropped = true;
    log.error(`[INTERPRETER] phrase ${tag}: ${reason}, dropping the socket`);
    forget();
    try {
      ws.terminate();
    } catch (_) { /* already closed */ }
  }

  const ws = createRealtimeSession(
    sourceLang,
    targetLang,
    (pcm) => {
      if (live()) onAudio(toInt16(pcm));
    },
    () => {}, // socket errors are followed by 'close', which is what the caller acts on
    {
      apiKey: opts.apiKey,
      model: opts.model,
      wsFactory,
      pruneHistory: true,
      logTag: 'INTERPRETER',
      logText: false, // the subtitles carry the words; the log does not need them
      onReady: () => {
        if (ready || !live()) return;
        ready = true;
        const waiting = queue;
        forget();
        for (const { b64 } of waiting) ws.sendAudio(b64);
        onReady();
      },
      // Before the session is confirmed nothing but our session.update has
      // gone out, so an error is that update being refused: carrying on would
      // leave this direction silent for the whole conversation. After it, an
      // error concerns one request; the engine has logged it.
      onServerError: (error) => {
        if (!ready) fail(`session.update refused: ${JSON.stringify(error)}`);
      },
      onTranscript: ({ role, text }) => {
        if (!live()) return;
        if (role === 'source') onSourceText(text, true);
        else onTranslationText(text, true);
      },
      onClose: ({ code }) => {
        ended = true;
        forget();
        onClose({ unexpected: !closedByUs, code });
      },
    },
  );

  ws.on('open', () => {
    if (ready || !live()) return;
    readyTimer = setTimeout(() => fail(`no session confirmation within ${readyTimeoutMs} ms`), readyTimeoutMs);
    if (readyTimer.unref) readyTimer.unref();
  });

  return {
    sendAudio(int16) {
      if (!live() || !int16.length) return;
      if (ready) {
        if (ws.readyState === WebSocket.OPEN && ws.bufferedAmount > MAX_BUFFERED_BYTES) {
          fail(`${ws.bufferedAmount} bytes not taken by the server`);
          return;
        }
        ws.sendAudio(toBase64(int16));
        return;
      }
      queue.push({ b64: toBase64(int16), samples: int16.length });
      queuedSamples += int16.length;
      while (queuedSamples > MAX_QUEUED_SAMPLES && queue.length > 1) queuedSamples -= queue.shift().samples;
    },
    close() {
      if (closedByUs) return;
      closedByUs = true;
      forget();
      try {
        ws.close();
      } catch (_) { /* already closed */ }
    },
  };
}

/**
 * Post-deploy smoke for the phrase engine, the counterpart of
 * selftestTranslate: opens a session the way the interpreter does and waits
 * for it to accept its configuration. The model is a dated snapshot
 * (INTERPRETER_FALLBACK_MODEL); once OpenAI withdraws it, every pair outside
 * gpt-realtime-translate's languages fails in every conversation, and the
 * simultaneous engine's selftest has no way to notice.
 */
function selftestPhrase({ apiKey, model, wsFactory, timeoutMs = 10000, log = console } = {}) {
  if (!apiKey) return Promise.resolve({ ok: false, reason: 'OPENAI_API_KEY not set' });
  return new Promise((resolve) => {
    let done = false;
    let session = null;
    let refusal = null;
    let timer = null;
    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (session) session.close();
      resolve(result);
    };
    timer = setTimeout(() => finish({ ok: false, reason: `timeout: no session.updated within ${timeoutMs} ms` }), timeoutMs);
    try {
      session = createPhraseSession({
        apiKey,
        model,
        sourceLang: 'ru',
        targetLang: 'sk',
        safetyId: 'interpreter-selftest',
        wsFactory,
        readyTimeoutMs: timeoutMs,
        // fail() names what OpenAI refused; the close that follows has only a code.
        log: { error: (m) => { refusal = m; log.error(m); }, warn: (m) => log.warn(m) },
        onReady: () => finish({ ok: true, reason: 'session.updated received' }),
        onClose: ({ code }) => finish({ ok: false, reason: refusal || `ws closed code=${code} before confirmation` }),
      });
      if (done) session.close();
    } catch (e) {
      finish({ ok: false, reason: `phrase session did not open: ${e && e.message}` });
    }
  });
}

module.exports = { createPhraseSession, selftestPhrase };
