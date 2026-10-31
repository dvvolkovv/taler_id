'use strict';
/**
 * One direction of simultaneous interpretation through OpenAI's
 * gpt-realtime-translate: one person's (already gated) speech in, the other
 * person's language out while the speaker is still talking.
 *
 * Unlike the phrase engine there are no turns: no commits, no response.create,
 * no conversation to prune. The session takes a continuous 24 kHz PCM16 stream
 * — silence included — and answers with translated audio and running
 * transcripts of both sides. Its voice follows the speaker's tone and pitch,
 * which is how the listener can still tell the two voices apart.
 *
 * The guide names the server events but not their fields. The accessors below
 * match what bench/probe-translate.js printed on DEV (bench/PROBE.md).
 */
const WebSocket = require('ws');

const ENDPOINT = 'wss://api.openai.com/v1/realtime/translations';
const DEFAULT_MODEL = 'gpt-realtime-translate';
// The speaker's own words (shown back to them as a subtitle) only arrive when
// input transcription is on; without it the session sends no
// session.input_transcript.delta at all (bench/PROBE.md, probe 2).
const DEFAULT_TRANSCRIBE_MODEL = 'gpt-4o-mini-transcribe';
// The phone is at its owner's ear: near-field noise reduction favours that one
// close voice and dampens the partner across the table.
const DEFAULT_NOISE_REDUCTION = 'near_field';
const PIECE_SAMPLES = 2400; // 100 ms at 24 kHz, the size OpenAI's guide appends
const MAX_QUEUED_PIECES = 40; // 4 s may wait for the socket; older audio is dropped

const audioOf = (event) => event.delta;
const textOf = (event) => event.delta;
// A handshake that stalls without an error would leave the direction silent
// and never retried; the timeout turns it into an ordinary close.
const HANDSHAKE_TIMEOUT_MS = 10000;
// After the handshake: a session that never confirms its configuration, or a
// socket whose writes pile up (stalled peer, half-open TCP), is as silent as a
// stalled handshake and must also end in a close the wrapper can retry.
const READY_TIMEOUT_MS = 10000;
const MAX_BUFFERED_BYTES = 1 << 20; // ~16 s of base64 audio at 64 KB/s
// session.updated is what proves the update applied (bench/PROBE.md: it always
// came). If it ever stops coming, session.created plus this long without an
// error counts instead — the selftest's rule.
const CREATED_GRACE_MS = 1500;

// 'pt' and 'pt-BR' are the same answer; only a different language is a refusal.
const baseLang = (lang) => String(lang).toLowerCase().split(/[-_]/)[0];

function defaultWsFactory(url, options) {
  return new WebSocket(url, { ...options, handshakeTimeout: HANDSHAKE_TIMEOUT_MS });
}

function toBase64(int16) {
  return Buffer.from(int16.buffer, int16.byteOffset, int16.byteLength).toString('base64');
}

function fromBase64(b64) {
  const buf = Buffer.from(b64, 'base64');
  const even = buf.byteLength - (buf.byteLength % 2);
  // Copy: a short decode is a view into Node's shared 8 KB pool, and LiveKit's
  // AudioFrame hands data.buffer to the native side from byte 0, ignoring
  // byteOffset. The copy also makes the caller's in-place gain safe.
  return new Int16Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + even));
}

/** The session.update body. null switches transcription or noise reduction off. */
function sessionConfig({ targetLang, transcribeModel = DEFAULT_TRANSCRIBE_MODEL, noiseReduction = DEFAULT_NOISE_REDUCTION }) {
  const audio = { output: { language: targetLang } };
  if (transcribeModel || noiseReduction) {
    audio.input = {};
    if (transcribeModel) audio.input.transcription = { model: transcribeModel };
    if (noiseReduction) audio.input.noise_reduction = { type: noiseReduction };
  }
  return { audio };
}

function connect({ apiKey, model, safetyId, wsFactory }) {
  const headers = { Authorization: `Bearer ${apiKey}` };
  if (safetyId) headers['OpenAI-Safety-Identifier'] = safetyId;
  return wsFactory(`${ENDPOINT}?model=${encodeURIComponent(model)}`, { headers });
}

function createTranslateSession(opts) {
  const { targetLang, log = console } = opts;
  if (!targetLang) throw new TypeError('createTranslateSession needs targetLang');
  // Every callback reaches into the interpreter (gain, frame queue, data
  // channel). Called from inside ws's handlers, a throw would escape into the
  // socket's stream and take the whole agent process down.
  const safe = (name, fn) => (...args) => {
    if (!fn) return;
    try {
      fn(...args);
    } catch (e) {
      log.error(`[INTERPRETER] translate →${targetLang}: ${name} callback failed: ${e.message}`);
    }
  };
  const onAudio = safe('onAudio', opts.onAudio);
  const onTranslationText = safe('onTranslationText', opts.onTranslationText);
  const onSourceText = safe('onSourceText', opts.onSourceText);
  const onReady = safe('onReady', opts.onReady);
  const onClose = safe('onClose', opts.onClose);
  const readyTimeoutMs = opts.readyTimeoutMs ?? READY_TIMEOUT_MS;
  const createdGraceMs = opts.createdGraceMs ?? CREATED_GRACE_MS;

  const ws = connect({
    apiKey: opts.apiKey,
    model: opts.model || DEFAULT_MODEL,
    safetyId: opts.safetyId,
    wsFactory: opts.wsFactory || defaultWsFactory,
  });
  let ready = false;
  let closedByUs = false;
  let dropped = false; // fail() decided; frames already read must not count
  let readyTimer = null;
  let graceTimer = null;
  const queue = [];

  const append = (b64) => ws.send(JSON.stringify({ type: 'session.input_audio_buffer.append', audio: b64 }));
  const clearTimers = () => {
    clearTimeout(readyTimer);
    clearTimeout(graceTimer);
    readyTimer = graceTimer = null;
  };
  // Ends the socket at once (terminate, not close: a stalled socket would hold
  // the close frame behind its backlog for closeTimeout) — reported as
  // unexpected, so the reconnecting wrapper retries and, past its limits,
  // the interpreter ends instead of running a broken direction.
  function fail(reason) {
    if (closedByUs || dropped) return;
    dropped = true;
    log.error(`[INTERPRETER] translate →${targetLang}: ${reason}, dropping the socket`);
    clearTimers();
    try {
      ws.terminate();
    } catch (_) { /* already closed */ }
  }
  function becomeReady() {
    if (ready) return;
    ready = true;
    clearTimers();
    while (queue.length) append(queue.shift());
    onReady();
  }

  ws.on('open', () => {
    ws.send(JSON.stringify({
      type: 'session.update',
      session: sessionConfig({ targetLang, transcribeModel: opts.transcribeModel, noiseReduction: opts.noiseReduction }),
    }));
    readyTimer = setTimeout(() => fail(`no session confirmation within ${readyTimeoutMs} ms`), readyTimeoutMs);
    if (readyTimer.unref) readyTimer.unref();
  });

  ws.on('message', (raw) => {
    if (closedByUs || dropped) return; // in flight after close() or fail()
    let event;
    try {
      event = JSON.parse(raw.toString());
    } catch (_) {
      return;
    }
    if (!event || typeof event !== 'object') return;
    switch (event.type) {
      case 'session.created':
        // A new session translates into Spanish until our session.update
        // applies. That update went out on 'open', ahead of any audio, but
        // only session.updated shows it was accepted.
        if (!ready && !graceTimer) {
          graceTimer = setTimeout(becomeReady, createdGraceMs);
          if (graceTimer.unref) graceTimer.unref();
        }
        break;
      case 'session.updated': {
        const lang = event.session && event.session.audio && event.session.audio.output
          && event.session.audio.output.language;
        if (lang && baseLang(lang) !== baseLang(targetLang)) fail(`session answers in ${lang}, asked for ${targetLang}`);
        else becomeReady();
        break;
      }
      case 'session.output_audio.delta': {
        const b64 = audioOf(event);
        if (typeof b64 === 'string' && b64) onAudio(fromBase64(b64));
        break;
      }
      case 'session.output_transcript.delta': {
        const text = textOf(event);
        if (typeof text === 'string' && text) onTranslationText(text, false);
        break;
      }
      case 'session.input_transcript.delta': {
        const text = textOf(event);
        if (typeof text === 'string' && text) onSourceText(text, false);
        break;
      }
      case 'error':
        // Before the session is confirmed, an error is our configuration being
        // refused: carrying on would translate into the default language.
        if (!ready) fail(`session.update refused: ${JSON.stringify(event.error || event)}`);
        else log.error(`[INTERPRETER] translate →${targetLang} error: ${JSON.stringify(event.error || event)}`);
        break;
      default:
        break;
    }
  });

  ws.on('error', (err) => {
    if (!closedByUs) log.warn(`[INTERPRETER] translate →${targetLang} socket error: ${err.message}`);
  });
  ws.on('close', (code) => {
    clearTimers();
    onClose({ unexpected: !closedByUs, code });
  });

  return {
    sendAudio(int16) {
      if (ready && ws.readyState === WebSocket.OPEN && ws.bufferedAmount > MAX_BUFFERED_BYTES) {
        fail(`${ws.bufferedAmount} bytes not taken by the server`);
        return;
      }
      for (let i = 0; i < int16.length; i += PIECE_SAMPLES) {
        const b64 = toBase64(int16.subarray(i, i + PIECE_SAMPLES));
        if (ready && ws.readyState === WebSocket.OPEN) {
          append(b64);
        } else {
          queue.push(b64);
          if (queue.length > MAX_QUEUED_PIECES) queue.shift();
        }
      }
    },
    close() {
      closedByUs = true;
      clearTimers();
      try {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'session.close' }));
      } catch (_) { /* closing anyway */ }
      try {
        ws.close();
      } catch (_) { /* already closed */ }
    },
  };
}

/**
 * What a session.updated echo lacks of what we asked for (bench/PROBE.md: the
 * echo carries the language and turns the input fields from null into
 * objects). A field OpenAI silently ignores fails here instead of quietly
 * switching off subtitles in every conversation.
 */
function echoProblem(echo, asked) {
  const audio = (echo && echo.audio) || {};
  const out = audio.output || {};
  const input = audio.input || {};
  if (out.language !== undefined && baseLang(out.language) !== baseLang(asked.audio.output.language)) return `has language ${out.language}`;
  const want = asked.audio.input || {};
  if (want.transcription && audio.input && !input.transcription) return 'dropped input transcription';
  if (want.noise_reduction && audio.input && !input.noise_reduction) return 'dropped noise reduction';
  return null;
}

/**
 * Post-deploy smoke: opens a session the way the interpreter does and waits
 * for it to be accepted. Catches the model being renamed or withdrawn and the
 * session shape being refused — what broke the in-call translator in 1.0.78.
 * Passes on a session.updated whose echo carries what was asked, followed by
 * appendCheckMs with no error — by then the appended silence has been read —
 * or, should session.updated ever stop coming, on session.created followed by
 * quietMs with no error.
 */
function selftestTranslate({
  apiKey,
  model = DEFAULT_MODEL,
  transcribeModel,
  noiseReduction,
  wsFactory = defaultWsFactory,
  timeoutMs = 10000,
  quietMs = 1500,
  appendCheckMs = 500,
} = {}) {
  if (!apiKey) return Promise.resolve({ ok: false, reason: 'OPENAI_API_KEY not set' });
  return new Promise((resolve) => {
    let done = false;
    let quietTimer = null;
    const ws = connect({ apiKey, model, safetyId: 'interpreter-selftest', wsFactory });
    const timer = setTimeout(() => finish({ ok: false, reason: `timeout: no session event within ${timeoutMs} ms` }), timeoutMs);
    function finish(result) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(quietTimer);
      try {
        ws.close();
      } catch (_) { /* already closed */ }
      resolve(result);
    }
    const asked = sessionConfig({ targetLang: 'en', transcribeModel, noiseReduction });
    ws.on('open', () => {
      // The same session shape the interpreter uses, so a refused field fails here too.
      ws.send(JSON.stringify({ type: 'session.update', session: asked }));
      ws.send(JSON.stringify({
        type: 'session.input_audio_buffer.append',
        audio: Buffer.alloc(PIECE_SAMPLES * 2 * 5).toString('base64'),
      }));
    });
    ws.on('message', (raw) => {
      let event;
      try {
        event = JSON.parse(raw.toString());
      } catch (_) {
        return;
      }
      if (!event || typeof event !== 'object') return;
      if (event.type === 'error') {
        finish({ ok: false, reason: `OpenAI error: ${JSON.stringify(event.error || event)}` });
      } else if (event.type === 'session.updated') {
        const problem = echoProblem(event.session, asked);
        if (problem) {
          finish({ ok: false, reason: `session.updated ${problem}` });
        } else {
          // The silence appended on 'open' is read after the update: an error
          // about it (say, a renamed append event) arrives within this window.
          clearTimeout(quietTimer);
          quietTimer = setTimeout(() => finish({ ok: true, reason: 'session.updated received' }), appendCheckMs);
        }
      } else if (event.type === 'session.created' && !quietTimer) {
        quietTimer = setTimeout(() => finish({ ok: true, reason: `session.created, no error within ${quietMs} ms` }), quietMs);
      }
    });
    ws.on('error', (err) => finish({ ok: false, reason: `ws error: ${err.message}` }));
    ws.on('close', (code) => finish({ ok: false, reason: `ws closed code=${code} before confirmation` }));
  });
}

module.exports = { createTranslateSession, selftestTranslate, PIECE_SAMPLES };
