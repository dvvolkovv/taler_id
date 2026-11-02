'use strict';
/**
 * Client for voice-embed-service (ECAPA speaker embeddings on :18082) and the
 * cosine similarity the gate compares embeddings with.
 *
 * The service accepts a WAV at any sample rate and resamples to 16 kHz itself,
 * so the gate sends its 24 kHz audio as it is — the same way the assistant's
 * realtime proxy does. Anything but a non-empty vector is an error; what an
 * error means is the caller's business (the gate lets the audio through).
 */
const { wrapWavMono } = require('./wav');

function createVoiceEmbedClient({ baseUrl, timeoutMs = 300, fetchFn = fetch }) {
  const url = `${String(baseUrl).replace(/\/+$/, '')}/embed`;

  async function embedWav(wav, { windowSec, timeout = timeoutMs } = {}) {
    const form = new FormData();
    form.append('audio', new Blob([wav], { type: 'audio/wav' }), 'audio.wav');
    if (windowSec) form.append('window_sec', String(windowSec));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetchFn(url, { method: 'POST', body: form, signal: controller.signal });
      if (!res.ok) throw new Error(`voice-embed HTTP ${res.status}`);
      const body = await res.json();
      if (!Array.isArray(body.vector) || body.vector.length === 0) throw new Error('voice-embed returned no vector');
      return body.vector;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    embedWav,
    embedPcm: (int16, sampleRate, options) => embedWav(wrapWavMono(int16, sampleRate), options),
  };
}

function cosine(a, b) {
  if (a.length !== b.length) throw new Error(`cosine: vector length mismatch (${a.length} vs ${b.length})`);
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  return denom === 0 ? 0 : dot / denom;
}

module.exports = { createVoiceEmbedClient, cosine };
