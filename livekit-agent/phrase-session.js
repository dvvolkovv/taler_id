'use strict';
/**
 * The phrase engine (realtime-phrase-session.js) behind the same interface as
 * translate-session.js, for the pairs gpt-realtime-translate cannot speak.
 * It waits for a pause and speaks whole phrases, so its transcripts arrive
 * whole as well (final = true). Spoken phrases are pruned from the
 * conversation: an interpreted talk can last an hour.
 */
const WebSocket = require('ws');
const { createRealtimeSession } = require('./realtime-phrase-session');

// As in translate-session.js: a stalled handshake must end in a close the
// reconnecting wrapper can retry. Set here rather than in
// realtime-phrase-session.js, so the in-call translator keeps its behaviour.
const HANDSHAKE_TIMEOUT_MS = 10000;
const defaultWsFactory = (url, options) => new WebSocket(url, { ...options, handshakeTimeout: HANDSHAKE_TIMEOUT_MS });

function toInt16(buf) {
  const even = buf.byteLength - (buf.byteLength % 2);
  return new Int16Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + even));
}

function createPhraseSession({
  apiKey,
  model,
  sourceLang,
  targetLang,
  wsFactory,
  onAudio = () => {},
  onTranslationText = () => {},
  onSourceText = () => {},
  onReady = () => {},
  onClose = () => {},
}) {
  let closedByUs = false;
  const ws = createRealtimeSession(
    sourceLang,
    targetLang,
    (pcm) => onAudio(toInt16(pcm)),
    () => {}, // errors are followed by 'close', which is what the caller acts on
    {
      apiKey,
      model,
      wsFactory: wsFactory || defaultWsFactory,
      pruneHistory: true,
      logTag: 'INTERPRETER',
      onReady,
      onTranscript: ({ role, text }) => (role === 'source' ? onSourceText(text, true) : onTranslationText(text, true)),
      onClose: ({ code }) => onClose({ unexpected: !closedByUs, code }),
    },
  );
  return {
    sendAudio(int16) {
      ws.sendAudio(Buffer.from(int16.buffer, int16.byteOffset, int16.byteLength).toString('base64'));
    },
    close() {
      closedByUs = true;
      try {
        ws.close();
      } catch (_) { /* already closed */ }
    },
  };
}

module.exports = { createPhraseSession };
