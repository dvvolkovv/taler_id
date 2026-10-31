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

function defaultWsFactory(url, options) {
  return new WebSocket(url, { ...options, handshakeTimeout: HANDSHAKE_TIMEOUT_MS });
}

function toBase64(int16) {
  return Buffer.from(int16.buffer, int16.byteOffset, int16.byteLength).toString('base64');
}

function fromBase64(b64) {
  const buf = Buffer.from(b64, 'base64');
  const even = buf.byteLength - (buf.byteLength % 2);
  // Copy: a base64-decoded Buffer may sit at an odd offset in the pool.
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
  const {
    targetLang,
    onAudio = () => {},
    onTranslationText = () => {},
    onSourceText = () => {},
    onReady = () => {},
    onClose = () => {},
    log = console,
  } = opts;
  const ws = connect({
    apiKey: opts.apiKey,
    model: opts.model || DEFAULT_MODEL,
    safetyId: opts.safetyId,
    wsFactory: opts.wsFactory || defaultWsFactory,
  });
  let ready = false;
  let closedByUs = false;
  const queue = [];

  const append = (b64) => ws.send(JSON.stringify({ type: 'session.input_audio_buffer.append', audio: b64 }));

  ws.on('open', () => {
    ws.send(JSON.stringify({
      type: 'session.update',
      session: sessionConfig({ targetLang, transcribeModel: opts.transcribeModel, noiseReduction: opts.noiseReduction }),
    }));
  });

  ws.on('message', (raw) => {
    let event;
    try {
      event = JSON.parse(raw.toString());
    } catch (_) {
      return;
    }
    switch (event.type) {
      case 'session.created':
      case 'session.updated':
        // A new session starts out translating into Spanish. Our
        // session.update went out on 'open', ahead of any audio on the same
        // socket, so the queued audio is never read in the default language.
        if (!ready) {
          ready = true;
          while (queue.length) append(queue.shift());
          onReady();
        }
        break;
      case 'session.output_audio.delta': {
        const b64 = audioOf(event);
        if (b64) onAudio(fromBase64(b64));
        break;
      }
      case 'session.output_transcript.delta': {
        const text = textOf(event);
        if (text) onTranslationText(text, false);
        break;
      }
      case 'session.input_transcript.delta': {
        const text = textOf(event);
        if (text) onSourceText(text, false);
        break;
      }
      case 'error':
        log.error(`[INTERPRETER] translate →${targetLang} error: ${JSON.stringify(event.error || event)}`);
        break;
      default:
        break;
    }
  });

  ws.on('error', (err) => log.warn(`[INTERPRETER] translate →${targetLang} socket error: ${err.message}`));
  ws.on('close', (code) => onClose({ unexpected: !closedByUs, code }));

  return {
    sendAudio(int16) {
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
 * Post-deploy smoke: opens a session the way the interpreter does and waits
 * for it to be accepted. Catches the model being renamed or withdrawn and the
 * session shape being refused — what broke the in-call translator in 1.0.78.
 * Passes on session.updated, or on session.created followed by quietMs with
 * no error (the guide does not promise a session.updated).
 */
function selftestTranslate({
  apiKey,
  model = DEFAULT_MODEL,
  transcribeModel,
  noiseReduction,
  wsFactory = defaultWsFactory,
  timeoutMs = 10000,
  quietMs = 1500,
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
    ws.on('open', () => {
      // The same session shape the interpreter uses, so a refused field fails here too.
      ws.send(JSON.stringify({
        type: 'session.update',
        session: sessionConfig({ targetLang: 'en', transcribeModel, noiseReduction }),
      }));
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
      if (event.type === 'error') {
        finish({ ok: false, reason: `OpenAI error: ${JSON.stringify(event.error || event)}` });
      } else if (event.type === 'session.updated') {
        finish({ ok: true, reason: 'session.updated received' });
      } else if (event.type === 'session.created' && !quietTimer) {
        quietTimer = setTimeout(() => finish({ ok: true, reason: `session.created, no error within ${quietMs} ms` }), quietMs);
      }
    });
    ws.on('error', (err) => finish({ ok: false, reason: `ws error: ${err.message}` }));
    ws.on('close', (code) => finish({ ok: false, reason: `ws closed code=${code} before confirmation` }));
  });
}

module.exports = { createTranslateSession, selftestTranslate, PIECE_SAMPLES };
