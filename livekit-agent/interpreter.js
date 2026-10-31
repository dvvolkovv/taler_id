'use strict';
/**
 * Face-to-face interpreter: two people at one table, each on their own phone,
 * in one LiveKit room. See
 * docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md.
 *
 * For each of the two: their microphone → voice-print gate (only the phone
 * owner's speech goes on) → an engine that renders it into the other person's
 * language → a track named after the listener, interp-for-<userId>. Neither
 * microphone is forwarded anywhere else, and each phone plays only the track
 * named after its owner: that is how "only the translation in the earpiece"
 * is kept on the agent's side.
 */
const crypto = require('crypto');
const { AccessToken } = require('livekit-server-sdk');
const { readLivekitCredentials } = require('./livekit-credentials');
const { baseIdentity } = require('./translator-targets');
const { planDirections } = require('./interpreter-routing');
const { createVoiceprintGate } = require('./voiceprint-gate');
const { createVoiceEmbedClient, cosine } = require('./voice-embed-client');
const { createTranslateSession, selftestTranslate } = require('./translate-session');
const { createPhraseSession } = require('./phrase-session');
const { createReconnectingEngine } = require('./reconnecting-engine');
const { createPresenceWatch } = require('./presence-watch');
const messages = require('./interpreter-messages');
const { applyGain, createFrameQueue } = require('./audio-out');
const { notifyAgentEnded } = require('./backend-callback');

const AGENT_IDENTITY = 'voice-interpreter';
const SAMPLE_RATE = 24000;
// createFrameQueue bounds itself by frame count (300, trimmed to 200), sized
// for 20 ms frames. Fed whole 400 ms deltas it would allow two minutes of
// backlog; cut into 20 ms frames the bound stays at a few seconds.
const FRAME_SAMPLES = 480;
// The embed service failing is survivable chunk by chunk (the gate fails
// open); failing for this long means nobody's voice is being checked.
const FATAL_FAIL_OPEN_MS = 60_000;

const sessions = new Map(); // roomName → session

function num(value, fallback) {
  const n = parseFloat(value);
  return Number.isFinite(n) ? n : fallback;
}

/** Unset → fallback; 'off' → null (feature switched off). */
function optional(value, fallback) {
  if (value === undefined || value === '') return fallback;
  return value === 'off' ? null : value;
}

function readConfig(env = process.env) {
  return {
    lkUrl: env.LIVEKIT_WS_URL || 'ws://localhost:7880',
    openaiKey: env.OPENAI_API_KEY,
    model: env.INTERPRETER_MODEL || 'gpt-realtime-translate',
    fallbackModel: env.INTERPRETER_FALLBACK_MODEL || 'gpt-realtime-2025-08-28',
    transcribeModel: optional(env.INTERPRETER_TRANSCRIBE_MODEL, 'gpt-4o-mini-transcribe'),
    noiseReduction: optional(env.INTERPRETER_NOISE_REDUCTION, 'near_field'),
    embedUrl: env.VOICE_EMBED_URL || 'http://127.0.0.1:18082',
    threshold: num(env.INTERPRETER_VOICE_THRESHOLD, 0.25),
    margin: num(env.INTERPRETER_VOICE_MARGIN, 0.05),
    // A chunk under ~100 ms floods the embed service (shared with the assistant's
    // voice gate); a zero one would hang the gate.
    chunkMs: Math.max(100, Math.min(2000, num(env.INTERPRETER_GATE_CHUNK_MS, 500))),
    gateTimeoutMs: num(env.INTERPRETER_GATE_TIMEOUT_MS, 300),
    hysteresis: Math.max(1, Math.round(num(env.INTERPRETER_GATE_HYSTERESIS, 2))),
    speechRms: num(env.INTERPRETER_SPEECH_RMS, 400),
    gain: Math.max(0.1, Math.min(4, num(env.INTERPRETER_GAIN, 1.4))),
    presenceGraceMs: num(env.INTERPRETER_PRESENCE_GRACE_MS, 60_000),
    backendUrl: env.BACKEND_URL || null,
    secret: env.INTERPRETER_SHARED_SECRET || null,
  };
}

function httpError(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

/** OpenAI asks for a stable per-end-user id; a hash keeps ours out of their logs. */
function safetyId(userId) {
  return crypto.createHash('sha256').update(String(userId)).digest('hex').slice(0, 32);
}

async function startInterpreter(body, deps = {}) {
  const { sessionId, roomName, participants } = body || {};
  if (!sessionId || !roomName) throw httpError(400, 'sessionId and roomName required');
  if (sessions.has(roomName)) return { status: 'already_running' };
  let directions;
  try {
    directions = planDirections(participants);
  } catch (e) {
    throw httpError(400, e.message);
  }

  const cfg = { ...readConfig(), ...(deps.config || {}) };
  const rtc = deps.rtc || require('@livekit/rtc-node');
  const { apiKey, apiSecret } = deps.credentials || readLivekitCredentials();
  const embed = deps.embed || createVoiceEmbedClient({ baseUrl: cfg.embedUrl, timeoutMs: cfg.gateTimeoutMs });

  const at = new AccessToken(apiKey, apiSecret, { identity: AGENT_IDENTITY, name: 'Interpreter' });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true, canPublishData: true });
  const token = await at.toJwt();

  const room = new rtc.Room();
  const session = {
    sessionId,
    roomName,
    room,
    rtc,
    cfg,
    deps,
    embed,
    directions,
    lanes: new Map(), // speaker userId → lane
    ready: false,
    pendingTracks: [],
    stopping: false,
    failOpenSince: null,
    fatalLogged: false,
  };
  sessions.set(roomName, session);

  session.presence = createPresenceWatch({
    people: directions.map((d) => d.speaker),
    graceMs: cfg.presenceGraceMs,
    onGone: (userId) => {
      console.log(`[INTERPRETER] ${roomName}: ${userId} away for ${cfg.presenceGraceMs} ms — ending`);
      stopInterpreter(roomName, { reason: 'partner_left', notify: true }).catch(() => {});
    },
  });

  room.on(rtc.RoomEvent.ParticipantConnected, (p) => session.presence.arrive(p.identity));
  room.on(rtc.RoomEvent.ParticipantDisconnected, (p) => session.presence.leave(p.identity));
  room.on(rtc.RoomEvent.TrackSubscribed, (track, publication, participant) => {
    if (track.kind !== rtc.TrackKind.KIND_AUDIO) return;
    // Tracks already in the room are subscribed during connect, before the
    // lanes exist. Hold them until the lanes are open.
    if (!session.ready) {
      session.pendingTracks.push({ track, identity: participant.identity });
      return;
    }
    route(session, track, participant.identity);
  });
  room.on(rtc.RoomEvent.Disconnected, () => {
    if (session.stopping) return;
    console.warn(`[INTERPRETER] ${roomName}: lost the LiveKit connection`);
    stopInterpreter(roomName, { reason: 'agent_lost', notify: true }).catch(() => {});
  });

  try {
    await room.connect(cfg.lkUrl, token, { autoSubscribe: true, dynacast: false });
    for (const d of directions) session.lanes.set(d.speaker, await openLane(session, d));
  } catch (e) {
    await stopInterpreter(roomName, { reason: 'translation_failed', notify: false });
    throw e;
  }
  session.ready = true;
  for (const p of room.remoteParticipants.values()) session.presence.arrive(p.identity);
  for (const { track, identity } of session.pendingTracks.splice(0)) route(session, track, identity);

  console.log(
    `[INTERPRETER] ${roomName}: started — ${directions.map((d) => `${d.sourceLang}→${d.targetLang} (${d.engine})`).join(', ')}`,
  );
  return { status: 'started' };
}

async function openLane(session, d) {
  const { cfg, rtc, room, deps } = session;
  const source = new rtc.AudioSource(SAMPLE_RATE, 1);
  const track = rtc.LocalAudioTrack.createAudioTrack(d.trackName, source);
  await room.localParticipant.publishTrack(
    track,
    new rtc.TrackPublishOptions({ source: rtc.TrackSource.SOURCE_MICROPHONE, stream: d.trackName }),
  );
  const out = createFrameQueue(source, d.trackName);
  const lane = { direction: d, listening: null };

  const makeEngine = (deps.engines && deps.engines[d.engine])
    || (d.engine === 'simultaneous' ? createTranslateSession : createPhraseSession);
  lane.engine = createReconnectingEngine({
    factory: (handlers) => makeEngine({
      apiKey: cfg.openaiKey,
      model: d.engine === 'simultaneous' ? cfg.model : cfg.fallbackModel,
      sourceLang: d.sourceLang,
      targetLang: d.targetLang,
      safetyId: safetyId(d.speaker),
      // The phrase engine ignores these two.
      transcribeModel: cfg.transcribeModel,
      noiseReduction: cfg.noiseReduction,
      onAudio: (int16) => {
        if (session.stopping) return;
        applyGain(int16, cfg.gain);
        for (let i = 0; i < int16.length; i += FRAME_SAMPLES) {
          // slice, not subarray: AudioFrame hands data.buffer to the native
          // side from byte 0, ignoring byteOffset — a view would play the
          // wrong samples.
          const frame = int16.slice(i, i + FRAME_SAMPLES);
          out.push(new rtc.AudioFrame(frame, SAMPLE_RATE, 1, frame.length));
        }
      },
      onTranslationText: (text, final) => sendTo(session, d.listener, messages.caption('translation', d.speaker, text, final)),
      onSourceText: (text, final) => sendTo(session, d.speaker, messages.caption('source', d.speaker, text, final)),
      ...handlers,
    }),
    onStatus: (state) => {
      broadcast(session, messages.status(state));
      if (state === 'failed') {
        stopInterpreter(session.roomName, { reason: 'translation_failed', notify: true }).catch(() => {});
      }
    },
  });

  lane.gate = createVoiceprintGate({
    sampleRate: SAMPLE_RATE,
    chunkMs: cfg.chunkMs,
    speechRms: cfg.speechRms,
    threshold: cfg.threshold,
    margin: cfg.margin,
    hysteresis: cfg.hysteresis,
    score: async (window) => {
      const vector = await session.embed.embedPcm(window, SAMPLE_RATE);
      return { own: cosine(vector, d.ownEmbedding), other: cosine(vector, d.otherEmbedding) };
    },
    onOutput: (chunk) => lane.engine.sendAudio(chunk),
    onSpeaking: (on) => broadcast(session, messages.speaking(d.speaker, on)),
    onDecision: (record) => {
      noteFailOpen(session, record);
      if (deps.onDecision) deps.onDecision(d.speaker, record);
    },
  });
  return lane;
}

function route(session, track, identity) {
  const lane = session.lanes.get(baseIdentity(identity));
  if (lane) listen(session, lane, track, identity);
}

function listen(session, lane, track, identity) {
  // A second device of the same person replaces the first: the newest loop
  // owns the lane, an older one stops at its next frame.
  const token = {};
  lane.listening = token;
  console.log(`[INTERPRETER] ${session.roomName}: listening to ${identity}`);
  (async () => {
    try {
      for await (const frame of new session.rtc.AudioStream(track, SAMPLE_RATE, 1)) {
        if (session.stopping || lane.listening !== token) break;
        lane.gate.push(new Int16Array(frame.data));
      }
    } finally {
      // The track ended (left, reconnecting, unpublished): let the held audio
      // out now instead of splicing it onto whatever comes next. Not when a
      // newer device took the lane over — that would reset it mid-stream.
      if (lane.listening === token && !session.stopping) lane.gate.end();
    }
  })().catch((e) => console.warn(`[INTERPRETER] ${session.roomName}: audio from ${identity} ended: ${e.message}`));
}

function sendTo(session, userId, msg) {
  if (session.stopping) return;
  messages
    .send(session.room.localParticipant, session.presence.identitiesOf(userId), msg)
    .catch((e) => console.warn(`[INTERPRETER] ${session.roomName}: data to ${userId} failed: ${e.message}`));
}

function broadcast(session, msg) {
  for (const d of session.directions) sendTo(session, d.speaker, msg);
}

function noteFailOpen(session, record) {
  if (!record.failOpen) {
    session.failOpenSince = null;
    return;
  }
  const now = Date.now();
  console.warn(`[INTERPRETER] gate fail-open in ${session.roomName}: ${record.error}`);
  if (session.failOpenSince === null) session.failOpenSince = now;
  if (!session.fatalLogged && now - session.failOpenSince > FATAL_FAIL_OPEN_MS) {
    session.fatalLogged = true;
    console.error(
      `FATAL interpreter: voice-embed unavailable for ${Math.round((now - session.failOpenSince) / 1000)} s in ${session.roomName}`,
    );
  }
}

async function stopInterpreter(roomName, { reason = 'stopped', notify = false } = {}) {
  const session = sessions.get(roomName);
  if (!session) return { status: 'not_running' };
  sessions.delete(roomName);
  session.stopping = true;
  session.presence.close();
  for (const lane of session.lanes.values()) {
    lane.listening = null;
    lane.gate.close();
    lane.engine.close();
  }
  try {
    await session.room.disconnect();
  } catch (_) { /* already gone */ }
  console.log(`[INTERPRETER] ${roomName}: stopped (${reason})`);
  if (notify && session.cfg.backendUrl && session.cfg.secret) {
    await notifyAgentEnded({
      backendUrl: session.cfg.backendUrl,
      secret: session.cfg.secret,
      sessionId: session.sessionId,
      reason,
    });
  }
  return { status: 'stopped' };
}

function getInterpreterStatus(roomName) {
  const session = sessions.get(roomName);
  if (!session) return { running: false };
  return {
    running: true,
    sessionId: session.sessionId,
    directions: session.directions.map(({ speaker, listener, sourceLang, targetLang, engine }) => ({
      speaker, listener, sourceLang, targetLang, engine,
    })),
    present: session.presence.presentPeople(),
  };
}

function selftest(deps = {}) {
  const cfg = { ...readConfig(), ...(deps.config || {}) };
  return selftestTranslate({
    apiKey: cfg.openaiKey,
    model: cfg.model,
    transcribeModel: cfg.transcribeModel,
    noiseReduction: cfg.noiseReduction,
    wsFactory: deps.wsFactory,
  });
}

module.exports = { startInterpreter, stopInterpreter, getInterpreterStatus, selftest, readConfig, AGENT_IDENTITY };
