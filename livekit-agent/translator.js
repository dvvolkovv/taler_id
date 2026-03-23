/**
 * Real-time Voice Translator Module for Taler ID
 * Powered by gpt-realtime-mini via WebSocket
 *
 * Joins a LiveKit room as 'voice-translator', captures audio from each
 * participant, streams it to gpt-realtime-mini for STT+translation+TTS,
 * and publishes per-language audio tracks (translation-ru, translation-en, etc.)
 */

const { AccessToken } = require('livekit-server-sdk');
const WebSocket = require('ws');

const LK_URL = process.env.LIVEKIT_WS_URL || 'ws://localhost:7880';
const LK_API_KEY = process.env.LIVEKIT_API_KEY || 'lkdevkey';
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || 'lkSecret2024TalerID';
const OPENAI_KEY = process.env.OPENAI_API_KEY;

// All languages supported by Whisper + GPT Realtime for translation
const LANG_NAMES = {
  af: 'Afrikaans', am: 'Amharic', ar: 'Arabic', az: 'Azerbaijani',
  be: 'Belarusian', bg: 'Bulgarian', bn: 'Bengali', bs: 'Bosnian',
  ca: 'Catalan', cs: 'Czech', cy: 'Welsh', da: 'Danish',
  de: 'German', el: 'Greek', en: 'English', es: 'Spanish',
  et: 'Estonian', eu: 'Basque', fa: 'Persian', fi: 'Finnish',
  fr: 'French', ga: 'Irish', gl: 'Galician', gu: 'Gujarati',
  ha: 'Hausa', he: 'Hebrew', hi: 'Hindi', hr: 'Croatian',
  hu: 'Hungarian', hy: 'Armenian', id: 'Indonesian', is: 'Icelandic',
  it: 'Italian', ja: 'Japanese', jv: 'Javanese', ka: 'Georgian',
  kk: 'Kazakh', km: 'Khmer', kn: 'Kannada', ko: 'Korean',
  lo: 'Lao', lt: 'Lithuanian', lv: 'Latvian', mk: 'Macedonian',
  ml: 'Malayalam', mn: 'Mongolian', mr: 'Marathi', ms: 'Malay',
  mt: 'Maltese', my: 'Myanmar', ne: 'Nepali', nl: 'Dutch',
  no: 'Norwegian', pa: 'Punjabi', pl: 'Polish', ps: 'Pashto',
  pt: 'Portuguese', ro: 'Romanian', ru: 'Russian', si: 'Sinhala',
  sk: 'Slovak', sl: 'Slovenian', so: 'Somali', sq: 'Albanian',
  sr: 'Serbian', su: 'Sundanese', sv: 'Swedish', sw: 'Swahili',
  ta: 'Tamil', te: 'Telugu', tg: 'Tajik', th: 'Thai',
  tl: 'Filipino', tr: 'Turkish', uk: 'Ukrainian', ur: 'Urdu',
  uz: 'Uzbek', vi: 'Vietnamese', yo: 'Yoruba', zh: 'Chinese',
  zu: 'Zulu',
};
const SUPPORTED_LANGS = Object.keys(LANG_NAMES);
const LANG_NATIVE_NAMES = {}; // Not needed for agent — backend provides native names
const LANG_VOICES = { ru: 'alloy', en: 'echo', de: 'ash', it: 'coral', es: 'sage', zh: 'alloy', ar: 'shimmer', ja: 'ballad' };

const translatorSessions = new Map();

let livekitRtc = null;
try {
  livekitRtc = require('@livekit/rtc-node');
} catch (e) {
  console.warn('[TRANSLATOR] LiveKit RTC not available:', e.message);
}

// Common Whisper hallucination patterns (repeated phrases, YouTube-like text)
const HALLUCINATION_RE = /^((.{2,20})\s*){3,}$|구독과\s*좋아요|ご視聴|チャンネル登録|请订阅|thank you for watching/i;

function isHallucination(text) {
  if (!text) return true;
  const t = text.trim();
  if (t.length < 2) return true;
  if (HALLUCINATION_RE.test(t)) return true;
  return false;
}

// ─── OpenAI Realtime Session per Language ─────────────────

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

function createRealtimeSession(sourceLang, targetLang, onAudioDelta, onError) {
  const tag = `${sourceLang}→${targetLang}`;
  console.log(`[TRANSLATOR] Opening WS for ${tag}`);

  const ws = new WebSocket(
    'wss://api.openai.com/v1/realtime?model=gpt-realtime-mini',
    {
      headers: {
        Authorization: `Bearer ${OPENAI_KEY}`,
        'OpenAI-Beta': 'realtime=v1',
      },
    }
  );

  let ready = false;
  const pendingMessages = [];

  ws.on('open', () => {
    console.log(`[TRANSLATOR] WS opened for ${tag}`);
    ws.send(JSON.stringify({
      type: 'session.update',
      session: {
        modalities: ['audio', 'text'],
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
        temperature: 0.6,
        voice: LANG_VOICES[targetLang] || 'alloy',
        input_audio_format: 'pcm16',
        output_audio_format: 'pcm16',
        input_audio_transcription: { model: 'whisper-1' },
        // Manual mode: no server_vad → responses are NEVER interrupted by new speech
        turn_detection: null,
      },
    }));
  });

  ws.on('message', (raw) => {
    try {
      const event = JSON.parse(raw.toString());

      if (event.type !== 'response.audio.delta') {
        console.log(`[TRANSLATOR] [${tag}] event: ${event.type}`);
      }

      if (event.type === 'session.updated') {
        ready = true;
        console.log(`[TRANSLATOR] Session configured for ${tag}`);
        for (const msg of pendingMessages) ws.send(msg);
        pendingMessages.length = 0;
      }

      if (event.type === 'response.created') {
        ws._responding = true;
      }

      if (event.type === 'response.audio.delta' && event.delta) {
        if (!ws._audioStartLogged) {
          ws._audioStartLogged = true;
          console.log(`[TRANSLATOR] [${tag}] >>> AUDIO OUTPUT STARTED`);
        }
        onAudioDelta(Buffer.from(event.delta, 'base64'));
      }

      if (event.type === 'response.audio.done') {
        ws._audioStartLogged = false;
      }

      if (event.type === 'response.done') {
        const status = event.response?.status;
        console.log(`[TRANSLATOR] [${tag}] response.done status=${status}`);
        ws._responding = false;
        // If speech accumulated while we were responding, commit it now
        if (ws._pendingCommit) {
          ws._pendingCommit = false;
          ws._doCommit('post-response');
        }
      }

      if (event.type === 'conversation.item.input_audio_transcription.completed' && event.transcript) {
        const heard = event.transcript.trim();
        console.log(`[TRANSLATOR] [${tag}] heard: "${heard}"`);
        if (isHallucination(heard)) console.log(`[TRANSLATOR] [${tag}] FILTERED: hallucination`);
      }

      if (event.type === 'response.audio_transcript.done' && event.transcript) {
        console.log(`[TRANSLATOR] [${tag}] translated: "${event.transcript.trim()}"`);
      }

      if (event.type === 'error') {
        console.error(`[TRANSLATOR] OpenAI error (${tag}):`, JSON.stringify(event.error));
      }
    } catch (e) { console.error(`[TRANSLATOR] [${tag}] message parse error:`, e.message); }
  });

  ws.on('error', (err) => {
    console.error(`[TRANSLATOR] WS error (${tag}):`, err.message);
    if (onError) onError(err);
  });

  ws.on('close', (code) => {
    console.log(`[TRANSLATOR] WS closed (${tag}), code=${code}`);
    if (ws._silenceTimer) { clearTimeout(ws._silenceTimer); ws._silenceTimer = null; }
  });

  // Commit current buffer and request translation
  ws._doCommit = (reason) => {
    if (ws.readyState !== WebSocket.OPEN) return;
    if (ws._responding) {
      // Don't interrupt ongoing response — set flag to commit after it finishes
      ws._pendingCommit = true;
      return;
    }
    console.log(`[TRANSLATOR] [${tag}] Committing (${reason})`);
    ws._speechStartMs = null;
    ws.send(JSON.stringify({ type: 'input_audio_buffer.commit' }));
    ws.send(JSON.stringify({ type: 'response.create' }));
  };

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
    const isSpeech = rms >= SPEECH_RMS_THRESHOLD;
    const now = Date.now();

    if (isSpeech) {
      if (!ws._hasSpeech) {
        ws._hasSpeech = true;
        ws._speechStartMs = now;
      }
      // Cancel pending silence timer
      if (ws._silenceTimer) { clearTimeout(ws._silenceTimer); ws._silenceTimer = null; }
      // Force-commit if speech has been going on too long
      if (ws._speechStartMs && (now - ws._speechStartMs) >= FORCE_COMMIT_MS) {
        ws._speechStartMs = now;
        ws._doCommit('force-7s');
      }
    } else if (ws._hasSpeech && !ws._silenceTimer) {
      // Speech just ended — start silence timer
      ws._silenceTimer = setTimeout(() => {
        ws._silenceTimer = null;
        if (ws._hasSpeech) {
          ws._hasSpeech = false;
          ws._doCommit('silence');
        }
      }, SILENCE_COMMIT_MS);
    }
  };

  return ws;
}

// ─── Async Frame Queue (prevents concurrent captureFrame calls) ───

function createFrameQueue(audioSource, targetLang) {
  const queue = [];
  let processing = false;

  async function processQueue() {
    if (processing) return;
    processing = true;
    while (queue.length > 0) {
      const frame = queue.shift();
      try {
        await audioSource.captureFrame(frame);
      } catch (e) {
        if (!e.message.includes('closed')) {
          console.error(`[TRANSLATOR] captureFrame error (${targetLang}):`, e.message);
        }
        break; // stop processing if source is broken
      }
    }
    processing = false;
  }

  return {
    push(frame) {
      // Drop frames if queue gets too large (> 50 frames = ~1 sec at 24kHz/480)
      if (queue.length > 300) {
        queue.splice(0, queue.length - 200); // keep last 200 (~4s)
      }
      queue.push(frame);
      processQueue();
    }
  };
}

// ─── Helpers ──────────────────────────────────────────────

function parseLangFromMetadata(metadata) {
  try {
    if (!metadata) return null;
    const obj = JSON.parse(metadata);
    if (SUPPORTED_LANGS.includes(obj.lang)) return obj.lang;
  } catch (_) {}
  return null;
}

// ─── Per-Speaker Realtime Sessions ────────────────────────

// Get unique target languages needed for translating this speaker's audio.
// Returns languages chosen by OTHER participants who have enabled translation.
// A speaker's own lang (if set) is excluded — no need to translate into their own language.
function getTargetLangs(session, speakerIdentity) {
  const targets = new Set();
  for (const [id, lang] of session.speakerLang) {
    if (id !== speakerIdentity) {
      targets.add(lang);
    }
  }
  return targets;
}

// Ensure audio source + track exist for a language, publish if needed
async function ensureLangTrack(session, lang) {
  if (session.langSources.has(lang)) return;
  const { AudioSource, LocalAudioTrack, TrackPublishOptions } = livekitRtc;
  const src = new AudioSource(24000, 1);
  const track = LocalAudioTrack.createAudioTrack(`translation-${lang}`, src);
  session.langSources.set(lang, src);
  session.langTracks.set(lang, track);
  const opts = new TrackPublishOptions({ stream: `translation-${lang}` });
  try {
    await session.room.localParticipant.publishTrack(track, opts);
    console.log(`[TRANSLATOR] Published track: translation-${lang}`);
  } catch (e) {
    console.warn(`[TRANSLATOR] Failed to publish track ${lang}:`, e.message);
  }
}

async function ensureSpeakerSessions(session, speakerIdentity) {
  if (session.speakerSessions.has(speakerIdentity)) return false;

  // Get target languages — languages requested by OTHER participants
  const targetLangs = getTargetLangs(session, speakerIdentity);
  if (targetLangs.size === 0) {
    console.log(`[TRANSLATOR] No target langs for ${speakerIdentity} — no other participants have translation enabled`);
    return false;
  }

  // Source language: use 'auto' (GPT auto-detects) — no need to know speaker's language
  const sourceLang = 'auto';

  const sessions = new Map();

  for (const targetLang of targetLangs) {
    // Ensure track exists and is published (must await for captureFrame to work)
    await ensureLangTrack(session, targetLang);

    const audioSource = session.langSources.get(targetLang);
    if (!audioSource) continue;

    const frameQueue = createFrameQueue(audioSource, targetLang);

    const ws = createRealtimeSession(
      sourceLang,
      targetLang,
      (pcmBuffer) => {
        if (session.stopping) return;
        try {
          const { AudioFrame } = livekitRtc;
          const int16 = new Int16Array(
            pcmBuffer.buffer,
            pcmBuffer.byteOffset,
            Math.floor(pcmBuffer.byteLength / 2)
          );
          const frame = new AudioFrame(int16, 24000, 1, int16.length);
          frameQueue.push(frame);
        } catch (e) {
          console.error(`[TRANSLATOR] AudioFrame error (${targetLang}):`, e.message);
        }
      },
      () => {
        sessions.delete(targetLang);
      },
    );

    sessions.set(targetLang, ws);
  }

  session.speakerSessions.set(speakerIdentity, sessions);
  console.log(`[TRANSLATOR] Created ${sessions.size} realtime sessions for ${speakerIdentity} (auto→${[...targetLangs].join(',')})`);
  return true;
}

function closeSpeakerSessions(session, speakerIdentity) {
  const sessions = session.speakerSessions.get(speakerIdentity);
  if (!sessions) return;
  console.log(`[TRANSLATOR] Closing ${sessions.size} sessions for ${speakerIdentity}`);
  for (const ws of sessions.values()) {
    try { ws.close(); } catch (_) {}
  }
  session.speakerSessions.delete(speakerIdentity);
}

// ─── Speaker Audio Capture ────────────────────────────────

function captureParticipantAudio(session, track, participant) {
  const { AudioStream } = livekitRtc;
  const identity = participant.identity;

  console.log(`[TRANSLATOR] Capturing audio from ${identity}`);

  const audioStream = new AudioStream(track, 24000, 1);

  (async () => {
    // Try to create sessions now (may succeed if other participants already have lang set)
    await ensureSpeakerSessions(session, identity);

    let frameCount = 0;
    let streaming = false;
    for await (const frame of audioStream) {
      if (!translatorSessions.has(session.roomName) || session.stopping) break;

      // Lazy-create realtime sessions when target langs become available
      if (!session.speakerSessions.has(identity) && !session._langSwitching) {
        const targets = getTargetLangs(session, identity);
        if (targets.size > 0) {
          console.log(`[TRANSLATOR] Lazy-creating sessions for ${identity} (targets=${[...targets].join(',')})`);
          await ensureSpeakerSessions(session, identity);
        } else {
          frameCount++;
          if (frameCount % 5000 === 0) {
            console.log(`[TRANSLATOR] No translation targets for ${identity} yet (${frameCount} frames)`);
          }
          continue;
        }
      }

      const speakerSessions = session.speakerSessions.get(identity);
      if (!speakerSessions || speakerSessions.size === 0) continue;

      if (!streaming) {
        streaming = true;
        console.log(`[TRANSLATOR] Streaming audio from ${identity} to ${speakerSessions.size} sessions`);
      }

      // Convert frame to base64 and send to all target language sessions
      const b64 = Buffer.from(
        frame.data.buffer,
        frame.data.byteOffset,
        frame.data.byteLength
      ).toString('base64');

      for (const ws of speakerSessions.values()) {
        ws.sendAudio(b64);
      }
    }
    console.log(`[TRANSLATOR] Audio loop ended for ${identity}`);
  })().catch(e => console.log('[TRANSLATOR] Audio stream error:', identity, e.message));
}

// ─── Public API ───────────────────────────────────────────

async function startTranslator(roomName) {
  if (!livekitRtc) throw new Error('LiveKit RTC not available');
  if (translatorSessions.has(roomName)) return { status: 'already_running' };

  console.log('[TRANSLATOR] Starting for room:', roomName);

  const {
    Room, RoomEvent, TrackKind,
    AudioSource, LocalAudioTrack, TrackPublishOptions,
  } = livekitRtc;

  const at = new AccessToken(LK_API_KEY, LK_API_SECRET, {
    identity: 'voice-translator',
    name: 'Translator',
  });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true });
  const token = await at.toJwt();

  const room = new Room();

  // Audio sources and tracks are created dynamically when needed (per-language)
  const langSources = new Map();
  const langTracks = new Map();

  const session = {
    room,
    roomName,
    langSources,
    langTracks,
    speakerLang: new Map(),
    speakerSessions: new Map(),
    stopping: false,
  };
  translatorSessions.set(roomName, session);

  function registerParticipant(p) {
    console.log(`[TRANSLATOR] registerParticipant: ${p.identity} metadata=${JSON.stringify(p.metadata)}`);
    const lang = parseLangFromMetadata(p.metadata);
    if (lang) {
      const oldLang = session.speakerLang.get(p.identity);
      session.speakerLang.set(p.identity, lang);
      console.log(`[TRANSLATOR] ${p.identity} → lang=${lang} (from metadata)`);
      if (oldLang && oldLang !== lang) {
        closeSpeakerSessions(session, p.identity);
      }
    } else {
      console.log(`[TRANSLATOR] ${p.identity} — no lang in metadata`);
    }
  }

  const SKIP_IDS = new Set(['voice-translator', 'ai-assistant', 'meeting-recorder']);

  room.on(RoomEvent.ParticipantConnected, (p) => {
    console.log(`[TRANSLATOR] Participant connected: ${p.identity}`);
    registerParticipant(p);
  });

  room.on(RoomEvent.ParticipantMetadataChanged, async (metadata, p) => {
    const lang = parseLangFromMetadata(metadata);
    if (lang) {
      const oldLang = session.speakerLang.get(p.identity);
      session.speakerLang.set(p.identity, lang);
      console.log(`[TRANSLATOR] ${p.identity} metadata lang → ${lang}`);
      if (oldLang !== lang) {
        // Lang changed — must recreate ALL speakers' sessions (targets changed)
        session._langSwitching = true;
        const allSpeakers = [...session.speakerSessions.keys()];
        for (const id of allSpeakers) {
          closeSpeakerSessions(session, id);
        }
        for (const id of allSpeakers) {
          await ensureSpeakerSessions(session, id);
        }
        session._langSwitching = false;
        console.log(`[TRANSLATOR] Recreated sessions after ${p.identity} metadata lang changed to ${lang}`);
      }
    }
  });

  room.on(RoomEvent.ParticipantDisconnected, (p) => {
    console.log(`[TRANSLATOR] Participant disconnected: ${p.identity}`);
    closeSpeakerSessions(session, p.identity);
    // Keep speakerLang so reconnecting participants auto-create sessions
    const humans = Array.from(room.remoteParticipants.values())
      .filter(x => !SKIP_IDS.has(x.identity));
    if (humans.length === 0) {
      console.log('[TRANSLATOR] No participants left, stopping:', roomName);
      stopTranslator(roomName).catch(() => {});
    }
  });

  room.on(RoomEvent.Disconnected, () => {
    console.log('[TRANSLATOR] Room disconnected:', roomName);
    for (const [identity] of session.speakerSessions) {
      closeSpeakerSessions(session, identity);
    }
    translatorSessions.delete(roomName);
  });

  room.on(RoomEvent.TrackSubscribed, (track, pub, participant) => {
    console.log(`[TRANSLATOR] TrackSubscribed: ${participant.identity}, kind=${track.kind}`);
    if (track.kind !== TrackKind.KIND_AUDIO) return;
    if (SKIP_IDS.has(participant.identity)) return;
    captureParticipantAudio(session, track, participant);
  });

  await room.connect(LK_URL, token);
  console.log('[TRANSLATOR] Connected to room:', roomName);

  // Register participants already in the room
  const existing = Array.from(room.remoteParticipants.values());
  console.log(`[TRANSLATOR] Existing participants: ${existing.map(p => p.identity).join(', ') || 'none'}`);
  for (const p of existing) registerParticipant(p);

  // Tracks are created and published dynamically when participants set their languages
  console.log('[TRANSLATOR] Ready — tracks will be published on demand for room:', roomName);

  return { status: 'started' };
}

async function stopTranslator(roomName) {
  const session = translatorSessions.get(roomName);
  if (!session) return { status: 'not_running' };
  session.stopping = true;
  for (const [identity] of session.speakerSessions) {
    closeSpeakerSessions(session, identity);
  }
  try { session.room.disconnect(); } catch (_) {}
  translatorSessions.delete(roomName);
  console.log('[TRANSLATOR] Stopped for room:', roomName);
  return { status: 'stopped' };
}

async function updateParticipantLang(roomName, userId, lang) {
  const session = translatorSessions.get(roomName);
  if (!session) return { ok: false, reason: 'no session' };
  if (!SUPPORTED_LANGS.includes(lang)) return { ok: false, reason: 'unsupported lang' };

  const oldLang = session.speakerLang.get(userId);
  session.speakerLang.set(userId, lang);
  console.log(`[TRANSLATOR] Updated ${userId} → lang=${lang} (was ${oldLang || 'not set'}) in room ${roomName}`);

  if (oldLang !== lang) {
    // Block audio loop from recreating sessions during language switch
    session._langSwitching = true;

    // Collect all speaker IDs first (avoid mutating Map while iterating)
    const allSpeakers = [...session.speakerSessions.keys()];

    // Close ALL sessions first
    for (const id of allSpeakers) {
      closeSpeakerSessions(session, id);
    }

    // Then recreate all sessions with updated language map
    for (const id of allSpeakers) {
      await ensureSpeakerSessions(session, id);
    }

    session._langSwitching = false;
    console.log(`[TRANSLATOR] Recreated sessions after ${userId} changed lang to ${lang}`);
  }

  return { ok: true };
}

function getTranslatorStatus(roomName) {
  const session = translatorSessions.get(roomName);
  if (!session) return { running: false };
  return {
    running: true,
    speakers: Object.fromEntries(session.speakerLang),
    activeSessions: session.speakerSessions.size,
  };
}

function getTranslatorLanguages() {
  return SUPPORTED_LANGS.map(code => ({ code, name: LANG_NATIVE_NAMES[code] || LANG_NAMES[code] }));
}

module.exports = { startTranslator, stopTranslator, updateParticipantLang, getTranslatorStatus, getTranslatorLanguages };
