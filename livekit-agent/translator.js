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
const { baseIdentity, translationTargets } = require('./translator-targets');
const { LANG_NAMES, SUPPORTED_LANGS } = require('./lang-names');
const { createRealtimeSession } = require('./realtime-phrase-session');
const { applyGain, createFrameQueue } = require('./audio-out');

const LK_URL = process.env.LIVEKIT_WS_URL || 'ws://localhost:7880';
const { readLivekitCredentials } = require('./livekit-credentials');
// Throws on startup rather than silently signing tokens with the pair
// committed to this repository.
const { apiKey: LK_API_KEY, apiSecret: LK_API_SECRET } = readLivekitCredentials();
const OPENAI_KEY = process.env.OPENAI_API_KEY;
// Linear gain applied to translator PCM before publishing. OpenAI Realtime
// TTS output is noticeably quieter than live speech; combined with client-side
// peer ducking (0.15) this makes the translation clearly dominant.
const TRANSLATOR_GAIN = Math.max(
  0.1,
  Math.min(4, parseFloat(process.env.TRANSLATOR_GAIN || '1.4')),
);

const LANG_NATIVE_NAMES = {}; // Not needed for agent — backend provides native names

const translatorSessions = new Map();

let livekitRtc = null;
try {
  livekitRtc = require('@livekit/rtc-node');
} catch (e) {
  console.warn('[TRANSLATOR] LiveKit RTC not available:', e.message);
}

// The OpenAI Realtime session, the audio-out helpers and the language tables
// live in realtime-phrase-session.js, audio-out.js and lang-names.js: the
// face-to-face interpreter uses them too.

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
  return translationTargets(
    session.speakerLang,
    session.speakTo,
    speakerIdentity,
  );
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
          const int16 = applyGain(
            new Int16Array(
              pcmBuffer.buffer,
              pcmBuffer.byteOffset,
              Math.floor(pcmBuffer.byteLength / 2)
            ),
            TRANSLATOR_GAIN
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
    // identity → language this person's OWN speech is rendered into, set when
    // someone names a pair instead of just what they want to hear.
    speakTo: new Map(),
    speakerSessions: new Map(),
    stopping: false,
  };
  translatorSessions.set(roomName, session);

  function registerParticipant(p) {
    console.log(`[TRANSLATOR] registerParticipant: ${p.identity} metadata=${JSON.stringify(p.metadata)}`);
    const lang = parseLangFromMetadata(p.metadata);
    if (lang) {
      const oldLang = session.speakerLang.get(baseIdentity(p.identity));
      session.speakerLang.set(baseIdentity(p.identity), lang);
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
      const oldLang = session.speakerLang.get(baseIdentity(p.identity));
      session.speakerLang.set(baseIdentity(p.identity), lang);
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

async function updateParticipantLang(roomName, userId, lang, speakTo) {
  const session = translatorSessions.get(roomName);
  if (!session) return { ok: false, reason: 'no session' };
  if (!SUPPORTED_LANGS.includes(lang)) return { ok: false, reason: 'unsupported lang' };
  if (speakTo != null && !SUPPORTED_LANGS.includes(speakTo)) {
    return { ok: false, reason: 'unsupported speakTo lang' };
  }

  // Keyed by the person, not the device — this call carries a bare userId while
  // the room metadata path carries `userId#device`, and the two must land on
  // the same entry. See translator-targets.js.
  const key = baseIdentity(userId);
  const oldLang = session.speakerLang.get(key);
  const oldSpeakTo = session.speakTo.get(key);
  session.speakerLang.set(key, lang);
  if (speakTo != null) session.speakTo.set(key, speakTo);
  console.log(
    `[TRANSLATOR] Updated ${key} → lang=${lang} (was ${oldLang || 'not set'})` +
    (speakTo != null ? ` speakTo=${speakTo} (was ${oldSpeakTo || 'not set'})` : '') +
    ` in room ${roomName}`,
  );

  if (oldLang !== lang || (speakTo != null && oldSpeakTo !== speakTo)) {
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
    speakTo: Object.fromEntries(session.speakTo),
    activeSessions: session.speakerSessions.size,
  };
}

function getTranslatorLanguages() {
  return SUPPORTED_LANGS.map(code => ({ code, name: LANG_NATIVE_NAMES[code] || LANG_NAMES[code] }));
}

// ─── Selftest ─────────────────────────────────────────────
//
// Opens a brief WS to OpenAI Realtime with the EXACT session.update shape
// the translator uses, waits for `session.updated`. Catches OpenAI Realtime
// API regressions (header rejection, schema mismatch, model deprecation)
// without needing LiveKit / real audio / a running room.
async function selftest() {
  if (!OPENAI_KEY) return { ok: false, reason: 'OPENAI_API_KEY not set' };
  return await new Promise((resolve) => {
    let resolved = false;
    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      try { ws.close(); } catch (_) {}
      resolve(result);
    };

    const ws = new WebSocket(
      'wss://api.openai.com/v1/realtime?model=gpt-realtime-mini',
      { headers: { Authorization: `Bearer ${OPENAI_KEY}` } },
    );

    const timer = setTimeout(
      () => finish({ ok: false, reason: 'timeout: no session.updated within 10s' }),
      10000,
    );

    let sessionUpdated = false;

    ws.on('open', () => {
      ws.send(JSON.stringify({
        type: 'session.update',
        session: {
          type: 'realtime',
          instructions: 'TRANSLATE ONLY. Source=auto, target=English.',
          output_modalities: ['audio'],
          audio: {
            input: {
              format: { type: 'audio/pcm', rate: 24000 },
              transcription: { model: 'whisper-1' },
              turn_detection: null,
            },
            output: {
              format: { type: 'audio/pcm', rate: 24000 },
              voice: 'alloy',
            },
          },
        },
      }));
    });

    ws.on('message', (raw) => {
      try {
        const ev = JSON.parse(raw.toString());
        if (ev.type === 'session.updated') {
          sessionUpdated = true;
          finish({ ok: true, reason: 'session.updated received' });
        }
        if (ev.type === 'error') {
          finish({
            ok: false,
            reason: 'OpenAI error: ' + JSON.stringify(ev.error || ev),
          });
        }
      } catch (_) { /* ignore */ }
    });

    ws.on('error', (err) => finish({ ok: false, reason: 'ws error: ' + err.message }));

    ws.on('close', (code) => {
      if (!sessionUpdated) {
        finish({ ok: false, reason: 'ws closed code=' + code + ' before session.updated' });
      }
    });
  });
}

module.exports = { startTranslator, stopTranslator, updateParticipantLang, getTranslatorStatus, getTranslatorLanguages, selftest };
