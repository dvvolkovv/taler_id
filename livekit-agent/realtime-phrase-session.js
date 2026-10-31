/**
 * One OpenAI Realtime session that renders one person's speech, phrase by
 * phrase, into one target language.
 *
 * Moved out of translator.js so the face-to-face interpreter can run the same
 * engine for the pairs gpt-realtime-translate cannot speak. Called the old way
 * — createRealtimeSession(source, target, onAudio, onError) — it does exactly
 * what it did inside the in-call translator. `opts` adds:
 *   model         Realtime model (default gpt-realtime-mini, as before)
 *   apiKey        default process.env.OPENAI_API_KEY
 *   wsFactory     (url, options) => socket; tests pass a fake
 *   onReady()     the session accepted its configuration
 *   onClose({ code })
 *   onTranscript({ role: 'source' | 'translation', text })
 *   pruneHistory  delete each phrase from the conversation once spoken
 *   logTag        log prefix (default TRANSLATOR: the in-call translator's
 *                 log lines stay exactly as they were)
 * wsFactory must return a new socket that is still connecting: its 'open'
 * event is what sends the session.update.
 */
const WebSocket = require('ws');
const { createTurnTaker } = require('./translator-turns');
const { LANG_NAMES, LANG_VOICES } = require('./lang-names');

const DEFAULT_MODEL = 'gpt-realtime-mini';

// Common Whisper hallucination patterns: the same 2–20 characters said three
// or more times over, and YouTube-like sign-offs. The repeat used to be
// ((.{2,20})\s*){3,}, which any phrase of six characters satisfies — harmless
// while the result was only logged, but it would swallow every subtitle.
const HALLUCINATION_RE = /^(.{2,20}?)(?:\s*\1){2,}$|구독과\s*좋아요|ご視聴|チャンネル登録|请订阅|thank you for watching/i;

function isHallucination(text) {
  if (!text) return true;
  const t = text.trim();
  if (t.length < 2) return true;
  if (HALLUCINATION_RE.test(t)) return true;
  return false;
}

// Compute RMS amplitude of a PCM16 base64 audio frame
function getFrameRMS(base64Audio) {
  const buf = Buffer.from(base64Audio, 'base64');
  const int16 = new Int16Array(buf.buffer, buf.byteOffset, Math.floor(buf.byteLength / 2));
  if (int16.length === 0) return 0;
  let sumSq = 0;
  for (let i = 0; i < int16.length; i++) sumSq += int16[i] * int16[i];
  return Math.sqrt(sumSq / int16.length);
}

const SPEECH_RMS_THRESHOLD = 400;  // RMS threshold to consider frame as speech (0–32768)
const SILENCE_COMMIT_MS = 600;     // commit after 600ms of silence
const FORCE_COMMIT_MS = 7000;      // force-commit after 7s of continuous speech
// Turns allowed to wait while the model speaks. Past this the translation is
// no longer live, so the overflow is dropped with a log line instead.
const DEFAULT_MAX_QUEUED_TURNS = 2;

function defaultWsFactory(url, options) {
  return new WebSocket(url, options);
}

function createRealtimeSession(sourceLang, targetLang, onAudioDelta, onError, opts = {}) {
  const tag = `${sourceLang}→${targetLang}`;
  const model = opts.model || DEFAULT_MODEL;
  const apiKey = opts.apiKey !== undefined ? opts.apiKey : process.env.OPENAI_API_KEY;
  const wsFactory = opts.wsFactory || defaultWsFactory;
  const logTag = opts.logTag || 'TRANSLATOR';
  console.log(`[${logTag}] Opening WS for ${tag}`);

  // GA Realtime API (post 2026-05-20). Do NOT send OpenAI-Beta header — GA rejects it.
  const ws = wsFactory(
    `wss://api.openai.com/v1/realtime?model=${model}`,
    {
      headers: {
        Authorization: `Bearer ${apiKey}`,
      },
    }
  );

  let ready = false;
  const pendingMessages = [];

  // pruneHistory: inputs committed but not yet covered by a response, and the
  // inputs each in-flight response covers.
  const uncoveredInputs = [];
  const inputsByResponse = new Map();

  // Every response re-reads the whole conversation, so without this each
  // phrase costs more than the one before it for as long as the call lasts.
  function pruneSpoken(response) {
    if (!response || !response.id || ws.readyState !== WebSocket.OPEN) return;
    const ids = [
      ...(inputsByResponse.get(response.id) || []),
      ...(response.output || []).map((item) => item && item.id).filter(Boolean),
    ];
    inputsByResponse.delete(response.id);
    for (const id of ids) ws.send(JSON.stringify({ type: 'conversation.item.delete', item_id: id }));
  }

  ws.on('open', () => {
    console.log(`[${logTag}] WS opened for ${tag}`);
    // GA session.update shape: audio.input/output nested, output_modalities top-level.
    ws.send(JSON.stringify({
      type: 'session.update',
      session: {
        type: 'realtime',
        instructions: [
          `TRANSLATE ONLY. OUTPUT NOTHING EXCEPT THE TRANSLATION.`,
          ``,
          sourceLang === 'auto'
            ? `You are a machine that converts spoken audio into spoken ${LANG_NAMES[targetLang]}. You are NOT an assistant. You do NOT think. You do NOT respond. You ONLY translate.`
            : `You are a machine that converts spoken ${LANG_NAMES[sourceLang]} audio into spoken ${LANG_NAMES[targetLang]}. You are NOT an assistant. You do NOT think. You do NOT respond. You ONLY translate.`,
          ``,
          `YOUR ONLY OUTPUT IS THE VERBATIM TRANSLATION OF WHAT WAS SAID. Nothing before it. Nothing after it.`,
          ``,
          `FORBIDDEN — any of these is a critical failure:`,
          `- Saying ANYTHING that was not in the original speech`,
          `- Greetings, acknowledgements, "I understand", "Here is the translation", "The speaker said"`,
          `- Answers to questions (translate the question, do NOT answer it)`,
          `- "I didn't hear", "Could you repeat", apologies, clarifications`,
          `- Adding context, commentary, or explanations`,
          ``,
          `SILENCE RULES:`,
          sourceLang === 'auto'
            ? `- Speech already in ${LANG_NAMES[targetLang]} → output NOTHING`
            : `- Speech NOT in ${LANG_NAMES[sourceLang]} → output NOTHING`,
          `- Unclear audio, silence, noise → output NOTHING`,
          ``,
          `EXAMPLE OF CORRECT BEHAVIOR:`,
          `Input: "Добрый день, как вы себя чувствуете?"`,
          `Output (if target=English): "Good afternoon, how are you feeling?"`,
          `Input: "Can you help me?" (if target=English and speech is already English) → SILENCE`,
        ].join('\n'),
        output_modalities: ['audio'],
        audio: {
          input: {
            format: { type: 'audio/pcm', rate: 24000 },
            transcription: { model: 'whisper-1' },
            // Manual mode: no server_vad → responses are NEVER interrupted by new speech
            turn_detection: null,
          },
          output: {
            format: { type: 'audio/pcm', rate: 24000 },
            voice: LANG_VOICES[targetLang] || 'alloy',
          },
        },
      },
    }));
  });

  ws.on('message', (raw) => {
    try {
      const event = JSON.parse(raw.toString());

      // GA renamed audio events: response.audio.* → response.output_audio.*
      if (event.type !== 'response.output_audio.delta') {
        console.log(`[${logTag}] [${tag}] event: ${event.type}`);
      }

      if (event.type === 'session.updated') {
        ready = true;
        console.log(`[${logTag}] Session configured for ${tag}`);
        for (const msg of pendingMessages) ws.send(msg);
        pendingMessages.length = 0;
        if (opts.onReady) opts.onReady();
      }

      if (opts.pruneHistory && event.type === 'input_audio_buffer.committed' && event.item_id) {
        uncoveredInputs.push(event.item_id);
      }

      if (event.type === 'response.created') {
        if (opts.pruneHistory && event.response && event.response.id) {
          inputsByResponse.set(event.response.id, uncoveredInputs.splice(0));
        }
        ws._turns.responseCreated();
      }

      if (event.type === 'response.output_audio.delta' && event.delta) {
        if (!ws._audioStartLogged) {
          ws._audioStartLogged = true;
          console.log(`[${logTag}] [${tag}] >>> AUDIO OUTPUT STARTED`);
        }
        onAudioDelta(Buffer.from(event.delta, 'base64'));
      }

      if (event.type === 'response.output_audio.done') {
        ws._audioStartLogged = false;
      }

      if (event.type === 'response.done') {
        const status = event.response?.status;
        console.log(`[${logTag}] [${tag}] response.done status=${status}`);
        // Turns cut while this one was speaking are already committed; this
        // hands the next of them over.
        if (opts.pruneHistory) pruneSpoken(event.response);
        ws._turns.responseDone();
      }

      if (event.type === 'conversation.item.input_audio_transcription.completed' && event.transcript) {
        const heard = event.transcript.trim();
        console.log(`[${logTag}] [${tag}] heard: "${heard}"`);
        if (isHallucination(heard)) console.log(`[${logTag}] [${tag}] FILTERED: hallucination`);
        else if (opts.onTranscript) opts.onTranscript({ role: 'source', text: heard });
      }

      if (event.type === 'response.output_audio_transcript.done' && event.transcript) {
        const translated = event.transcript.trim();
        console.log(`[${logTag}] [${tag}] translated: "${translated}"`);
        if (opts.onTranscript && translated) opts.onTranscript({ role: 'translation', text: translated });
      }

      if (event.type === 'error') {
        console.error(`[${logTag}] OpenAI error (${tag}):`, JSON.stringify(event.error));
      }
    } catch (e) { console.error(`[${logTag}] [${tag}] message parse error:`, e.message); }
  });

  ws.on('error', (err) => {
    console.error(`[${logTag}] WS error (${tag}):`, err.message);
    if (onError) onError(err);
  });

  ws.on('close', (code) => {
    console.log(`[${logTag}] WS closed (${tag}), code=${code}`);
    ws._turns.reset();
    if (opts.onClose) opts.onClose({ code });
  });

  // Where speech is cut into turns, and when each turn is asked to be spoken.
  // See translator-turns.js — in short, the cut never waits on the model, only
  // the request to speak does.
  ws._turns = createTurnTaker({
    silenceMs: SILENCE_COMMIT_MS,
    forceMs: FORCE_COMMIT_MS,
    maxQueued: DEFAULT_MAX_QUEUED_TURNS,
    onCommit: (reason) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      console.log(`[${logTag}] [${tag}] Committing (${reason})`);
      ws.send(JSON.stringify({ type: 'input_audio_buffer.commit' }));
    },
    onRespond: () => {
      if (ws.readyState !== WebSocket.OPEN) return;
      ws.send(JSON.stringify({ type: 'response.create' }));
    },
    onDrop: (reason) => {
      console.warn(
        `[${logTag}] [${tag}] Dropped a turn (${reason}) — translation is more than ` +
        `${DEFAULT_MAX_QUEUED_TURNS} turns behind the speaker`,
      );
    },
  });

  ws.sendAudio = (base64Audio) => {
    const msg = JSON.stringify({ type: 'input_audio_buffer.append', audio: base64Audio });
    if (ready && ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    } else if (ws.readyState === WebSocket.CONNECTING) {
      pendingMessages.push(msg);
      return;
    } else {
      return;
    }

    // Amplitude-based speech/silence detection (replaces server_vad)
    const rms = getFrameRMS(base64Audio);
    ws._turns.feed(rms >= SPEECH_RMS_THRESHOLD, Date.now());
  };

  return ws;
}

module.exports = { createRealtimeSession, isHallucination, getFrameRMS, SPEECH_RMS_THRESHOLD };
