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
 *
 * A session can end at any moment, including while it is still starting: the
 * stop route, a person's grace period running out, LiveKit dropping the
 * agent, an engine giving up. So a session claims its room before its first
 * await — a second start for the room (a backend retrying one that timed out)
 * waits for this one instead of putting a second agent in — the start checks
 * after every await and releases whatever it opened after the end, and a
 * connect that lands after the end leaves the room again (rtc-node's
 * disconnect() does nothing while connect() is running). Room and engine
 * events end the session they belong to, never "whatever runs in this room
 * now".
 *
 * Native handles are released explicitly. An AudioStream from
 * @livekit/rtc-node 0.13 does not end when its participant leaves or when the
 * agent leaves the room: the native stream ends only when its own handle or
 * its track's handle is released. Left to itself it waits forever, holding
 * its session and a listener on the process-wide FFI emitter that every audio
 * frame in the agent then passes through. So streams are cancelled on
 * unsubscription, departure, takeover and stop, and the published tracks
 * (with their sources) are closed once the room is left.
 */
const crypto = require('crypto');
const { AccessToken } = require('livekit-server-sdk');
const { readLivekitCredentials } = require('./livekit-credentials');
const { baseIdentity } = require('./translator-targets');
const { planDirections } = require('./interpreter-routing');
const { createVoiceprintGate } = require('./voiceprint-gate');
const { createVoiceEmbedClient, cosine } = require('./voice-embed-client');
const { createTranslateSession, selftestTranslate } = require('./translate-session');
const { createPhraseSession, selftestPhrase } = require('./phrase-session');
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
// rtc-node's connect can stall without ever settling (recorder.js, the
// incident of 2026-05-18): unbounded, the start request and the room's claim
// would hang with it. A stalled disconnect would hang the stop route and,
// when the agent ends a session itself, the agent-ended callback that closes
// the host's billing.
const CONNECT_TIMEOUT_MS = 15_000;
const DISCONNECT_TIMEOUT_MS = 5_000;

const sessions = new Map(); // roomName → session, from the start's first step until its end

function num(value, fallback) {
  const n = parseFloat(value);
  return Number.isFinite(n) ? n : fallback;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
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
    chunkMs: clamp(num(env.INTERPRETER_GATE_CHUNK_MS, 500), 100, 2000),
    // Below ~100 ms the embed service never answers in time: every chunk fails
    // open, which switches the gate off without a word. Above a few seconds a
    // slow answer holds the whole direction back.
    gateTimeoutMs: clamp(num(env.INTERPRETER_GATE_TIMEOUT_MS, 300), 100, 3000),
    hysteresis: Math.max(1, Math.round(num(env.INTERPRETER_GATE_HYSTERESIS, 2))),
    // 0 sends silence to the embed service as speech; near full scale nothing
    // counts as speech and both directions go mute.
    speechRms: clamp(num(env.INTERPRETER_SPEECH_RMS, 400), 50, 5000),
    gain: clamp(num(env.INTERPRETER_GAIN, 1.4), 0.1, 4),
    // Node runs a timer of 0, a negative value or more than 2^31-1 ms after
    // 1 ms: every conversation would end right after it started.
    presenceGraceMs: clamp(num(env.INTERPRETER_PRESENCE_GRACE_MS, 60_000), 10_000, 600_000),
    connectTimeoutMs: CONNECT_TIMEOUT_MS,
    disconnectTimeoutMs: DISCONNECT_TIMEOUT_MS,
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

function withTimeout(promise, ms, what) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not settle within ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Runs one step of a teardown; a failure is logged and the teardown goes on. */
function quietly(session, what, fn) {
  const fail = (e) => console.warn(`[INTERPRETER] ${session.roomName}: ${what} failed: ${e && e.message}`);
  try {
    const result = fn();
    if (result && typeof result.then === 'function') result.then(undefined, fail);
  } catch (e) {
    fail(e);
  }
}

/** Whether the agent itself is in the room right now (not connecting, not reconnecting). */
function agentConnected(session) {
  const { room, rtc } = session;
  const connected = rtc.ConnectionState && rtc.ConnectionState.CONN_CONNECTED;
  return connected === undefined ? room.isConnected === true : room.connectionState === connected;
}

function reasonName(rtc, reason) {
  if (reason === undefined || reason === null) return 'reason unknown';
  return (rtc.DisconnectReason && rtc.DisconnectReason[reason]) || String(reason);
}

function sameTrack(a, b) {
  return a === b || Boolean(a && b && a.sid && a.sid === b.sid);
}

function ensureRunning(session) {
  if (session.stopping) {
    throw httpError(503, `interpreter for ${session.roomName} ended while starting (${session.stopReason})`);
  }
}

async function startInterpreter(body, deps = {}) {
  const { sessionId, roomName, participants } = body || {};
  if (!sessionId || !roomName) throw httpError(400, 'sessionId and roomName required');
  const existing = sessions.get(roomName);
  if (existing) return alreadyRunning(existing);
  let directions;
  try {
    directions = planDirections(participants);
  } catch (e) {
    throw httpError(400, e.message);
  }

  const cfg = { ...readConfig(), ...(deps.config || {}) };
  // Without a key every engine is refused, retried and given up on: the
  // conversation would end as translation_failed seconds after it started.
  if (!cfg.openaiKey) throw httpError(503, 'OPENAI_API_KEY is not set on the agent');
  const rtc = deps.rtc || require('@livekit/rtc-node');
  const { apiKey, apiSecret } = deps.credentials || readLivekitCredentials();
  const embed = deps.embed || createVoiceEmbedClient({ baseUrl: cfg.embedUrl, timeoutMs: cfg.gateTimeoutMs });
  const at = new AccessToken(apiKey, apiSecret, { identity: AGENT_IDENTITY, name: 'Interpreter' });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true, canPublishData: true });

  const session = {
    sessionId,
    roomName,
    room: new rtc.Room(),
    rtc,
    cfg,
    deps,
    embed,
    directions,
    lanes: new Map(), // speaker userId → lane
    ready: false,
    pendingTracks: [],
    stopping: false,
    stopReason: null,
    left: false,
    linkDown: false, // LiveKit is reconnecting the agent
    dataFailures: 0,
    failOpenSince: null,
    failOpenCount: 0,
    fatalLogged: false,
  };
  let settleStartup;
  session.startup = new Promise((resolve) => { settleStartup = resolve; });
  // Claimed before the first await: a second start for this room now waits
  // for this one (alreadyRunning) instead of joining a second agent.
  sessions.set(roomName, session);

  session.presence = createPresenceWatch({
    people: directions.map((d) => d.speaker),
    graceMs: cfg.presenceGraceMs,
    onGone: (userId) => {
      // While the agent itself is off LiveKit, nobody looks present to it.
      const reason = agentConnected(session) ? 'partner_left' : 'agent_lost';
      console.log(`[INTERPRETER] ${roomName}: ${userId} away for ${cfg.presenceGraceMs} ms — ending (${reason})`);
      endInBackground(session, reason);
    },
  });
  watchRoom(session);

  try {
    const token = await at.toJwt();
    ensureRunning(session);
    const connecting = session.room.connect(cfg.lkUrl, token, { autoSubscribe: true, dynacast: false });
    // However this start goes, a connect that lands after the end leaves again.
    connecting.then(() => { if (session.stopping) leaveRoom(session); }, () => {});
    await withTimeout(connecting, cfg.connectTimeoutMs, 'LiveKit connect');
    ensureRunning(session);
    // Who was in the room before us; events report everyone after.
    for (const p of session.room.remoteParticipants.values()) session.presence.arrive(p.identity);
    for (const d of directions) session.lanes.set(d.speaker, await openLane(session, d));
  } catch (e) {
    settleStartup(false);
    await endSession(session, { reason: 'translation_failed', notify: false });
    throw e;
  }
  session.ready = true;
  settleStartup(true);
  for (const { track, identity } of session.pendingTracks.splice(0)) route(session, track, identity);

  console.log(
    `[INTERPRETER] ${roomName}: started — ${directions.map((d) => `${d.sourceLang}→${d.targetLang} (${d.engine})`).join(', ')}`,
  );
  return { status: 'started' };
}

/** A start for a room that already has one, likely the backend retrying: the answer is how that one ends. */
async function alreadyRunning(session) {
  if ((await session.startup) && !session.stopping) return { status: 'already_running' };
  throw httpError(503, `interpreter for ${session.roomName} did not start`);
}

function watchRoom(session) {
  const { room, rtc, roomName } = session;
  room.on(rtc.RoomEvent.ParticipantConnected, (p) => {
    console.log(`[INTERPRETER] ${roomName}: ${p.identity} (${p.sid}) joined`);
    session.presence.arrive(p.identity);
  });
  room.on(rtc.RoomEvent.ParticipantDisconnected, (p) => {
    // The reason tells someone leaving (CLIENT_INITIATED) from LiveKit
    // removing them (DUPLICATE_IDENTITY, STATE_MISMATCH, ...).
    console.log(`[INTERPRETER] ${roomName}: ${p.identity} (${p.sid}) left: ${reasonName(rtc, p.disconnectReason)}`);
    session.presence.leave(p.identity);
    stopListening(session, (l) => l.identity === p.identity);
  });
  room.on(rtc.RoomEvent.TrackSubscribed, (track, publication, participant) => {
    if (session.stopping || track.kind !== rtc.TrackKind.KIND_AUDIO) return;
    // Tracks already in the room are subscribed during connect, before the
    // lanes exist. Hold them until the lanes are open.
    if (!session.ready) {
      session.pendingTracks.push({ track, identity: participant.identity });
      return;
    }
    route(session, track, participant.identity);
  });
  room.on(rtc.RoomEvent.TrackUnsubscribed, (track) => {
    session.pendingTracks = session.pendingTracks.filter((p) => !sameTrack(p.track, track));
    stopListening(session, (l) => sameTrack(l.track, track));
  });
  room.on(rtc.RoomEvent.Reconnecting, () => {
    session.linkDown = true;
    console.warn(`[INTERPRETER] ${roomName}: LiveKit is reconnecting the agent`);
  });
  room.on(rtc.RoomEvent.Reconnected, () => {
    session.linkDown = false;
    console.log(`[INTERPRETER] ${roomName}: LiveKit reconnected the agent`);
  });
  room.on(rtc.RoomEvent.Disconnected, (reason) => {
    if (session.stopping) return;
    console.warn(`[INTERPRETER] ${roomName}: lost the LiveKit connection: ${reasonName(rtc, reason)}`);
    endInBackground(session, 'agent_lost');
  });
}

async function openLane(session, d) {
  const { cfg, rtc, room, deps } = session;
  const source = new rtc.AudioSource(SAMPLE_RATE, 1);
  const lane = {
    direction: d,
    track: rtc.LocalAudioTrack.createAudioTrack(d.trackName, source),
    listening: null,
    engine: null,
    gate: null,
  };
  try {
    await room.localParticipant.publishTrack(
      lane.track,
      new rtc.TrackPublishOptions({ source: rtc.TrackSource.SOURCE_MICROPHONE, stream: d.trackName }),
    );
    // Ended while publishing: no OpenAI session for a conversation that is gone.
    ensureRunning(session);
    const out = createFrameQueue(source, d.trackName);
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
        if (state === 'failed') endInBackground(session, 'translation_failed');
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
  } catch (e) {
    // Not in session.lanes yet, so the end would not find what this opened.
    quietly(session, `closing the ${d.trackName} engine`, () => lane.engine && lane.engine.close());
    releaseTrack(session, lane);
    throw e;
  }
}

function route(session, track, identity) {
  const lane = session.lanes.get(baseIdentity(identity));
  if (lane) listen(session, lane, track, identity);
}

function listen(session, lane, track, identity) {
  const previous = lane.listening;
  if (previous) {
    // Another device of the same person (or the same mic again): the old
    // stream stops now, and what the gate holds from it goes out ahead of the
    // new audio instead of being spliced onto it.
    lane.listening = null;
    cancelReader(previous);
    lane.gate.end();
  }
  let reader;
  try {
    reader = new session.rtc.AudioStream(track, SAMPLE_RATE, 1).getReader();
  } catch (e) {
    console.warn(`[INTERPRETER] ${session.roomName}: cannot listen to ${identity}: ${e && e.message}`);
    return;
  }
  const listening = { reader, track, identity };
  lane.listening = listening;
  console.log(`[INTERPRETER] ${session.roomName}: listening to ${identity}`);
  (async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done || session.stopping || lane.listening !== listening) break;
        lane.gate.push(new Int16Array(value.data));
      }
    } finally {
      cancelReader(listening);
      if (lane.listening === listening) {
        // The track went away (left, unsubscribed, reconnecting): let the held
        // audio out now instead of splicing it onto whatever comes next.
        lane.listening = null;
        if (!session.stopping) lane.gate.end();
      }
    }
  })().catch((e) => console.warn(`[INTERPRETER] ${session.roomName}: audio from ${identity} ended: ${e && e.message}`));
}

/** Releases the native stream and its FFI listener; a pending read() returns done. */
function cancelReader(listening) {
  try {
    listening.reader.cancel().catch(() => {});
  } catch (_) { /* already released */ }
}

/** Ends the matching streams; each loop then lets its gate's held audio out. */
function stopListening(session, match) {
  for (const lane of session.lanes.values()) {
    if (lane.listening && match(lane.listening)) cancelReader(lane.listening);
  }
}

function sendTo(session, userId, msg) {
  // While LiveKit reconnects the agent nothing can be sent, and every caption
  // delta would fail and log on its own.
  if (session.stopping || session.linkDown) return;
  messages
    .send(session.room.localParticipant, session.presence.identitiesOf(userId), msg)
    .then(
      () => {
        if (session.dataFailures === 0) return;
        console.log(`[INTERPRETER] ${session.roomName}: data channel works again after ${session.dataFailures} failed messages`);
        session.dataFailures = 0;
      },
      (e) => {
        session.dataFailures += 1;
        if (session.dataFailures > 1) return; // one line per run of failures, not per delta
        console.warn(`[INTERPRETER] ${session.roomName}: data to ${userId} failed: ${e && e.message} (further failures counted until one gets through)`);
      },
    );
}

function broadcast(session, msg) {
  for (const d of session.directions) sendTo(session, d.speaker, msg);
}

/**
 * One line when the gate starts failing open, FATAL once that has lasted a
 * minute, one line when checks are back. Shared by the two lanes on purpose:
 * the embed service is shared, so a check that works on either lane means it
 * is up. A later outage in the same conversation is reported again.
 */
function noteFailOpen(session, record) {
  if (!record.failOpen) {
    if (session.failOpenSince !== null) {
      console.log(`[INTERPRETER] ${session.roomName}: voice checks back after ${session.failOpenCount} chunks let through unchecked`);
    }
    session.failOpenSince = null;
    session.failOpenCount = 0;
    session.fatalLogged = false;
    return;
  }
  const now = Date.now();
  session.failOpenCount += 1;
  if (session.failOpenSince === null) {
    session.failOpenSince = now;
    console.warn(`[INTERPRETER] gate fail-open in ${session.roomName}: ${record.error}`);
  }
  if (!session.fatalLogged && now - session.failOpenSince > FATAL_FAIL_OPEN_MS) {
    session.fatalLogged = true;
    console.error(
      `FATAL interpreter: voice-embed unavailable for ${Math.round((now - session.failOpenSince) / 1000)} s in ${session.roomName}`
      + ` (${session.failOpenCount} chunks let through unchecked)`,
    );
  }
}

function endInBackground(session, reason) {
  endSession(session, { reason, notify: true }).catch((e) => {
    console.error(`[INTERPRETER] ${session.roomName}: ending (${reason}) failed: ${e && e.message}`);
  });
}

/** Leaves the room once it is joined; a connect still running leaves when it lands (startInterpreter). */
async function leaveRoom(session) {
  if (session.left || session.room.isConnected === false) return;
  session.left = true;
  try {
    await withTimeout(session.room.disconnect(), session.cfg.disconnectTimeoutMs, 'LiveKit disconnect');
  } catch (e) {
    console.warn(`[INTERPRETER] ${session.roomName}: leaving the room failed: ${e && e.message}`);
  }
}

function closeLane(session, lane) {
  const { listening } = lane;
  lane.listening = null; // the loop is no longer the owner: no end() on a closed gate
  if (listening) cancelReader(listening);
  const name = lane.direction.trackName;
  quietly(session, `closing the ${name} gate`, () => lane.gate && lane.gate.close());
  quietly(session, `closing the ${name} engine`, () => lane.engine && lane.engine.close());
}

/** close() closes the track's AudioSource too. */
function releaseTrack(session, lane) {
  const { track } = lane;
  lane.track = null;
  if (track && typeof track.close === 'function') quietly(session, `closing ${lane.direction.trackName}`, () => track.close());
}

async function endSession(session, { reason = 'stopped', notify = false } = {}) {
  if (session.stopping) return { status: 'not_running' };
  session.stopping = true;
  session.stopReason = reason;
  if (sessions.get(session.roomName) === session) sessions.delete(session.roomName);
  quietly(session, 'closing the presence watch', () => session.presence && session.presence.close());
  session.pendingTracks = [];
  for (const lane of session.lanes.values()) closeLane(session, lane);
  await leaveRoom(session);
  // rtc-node detaches a room from its process-wide FFI emitter only in a
  // disconnect() that finds it connected. A room LiveKit dropped by itself is
  // never detached, so our handlers must not keep this session reachable.
  quietly(session, 'detaching from the room', () => session.room.removeAllListeners());
  // After leaving: a track's handle is not pulled from under a live publication.
  for (const lane of session.lanes.values()) releaseTrack(session, lane);
  console.log(`[INTERPRETER] ${session.roomName}: stopped (${reason})`);
  const { backendUrl, secret } = session.cfg;
  if (notify && backendUrl && secret) {
    await notifyAgentEnded({ backendUrl, secret, sessionId: session.sessionId, reason });
  }
  return { status: 'stopped' };
}

async function stopInterpreter(roomName, { reason = 'stopped', notify = false } = {}) {
  const session = sessions.get(roomName);
  if (!session) return { status: 'not_running' };
  return endSession(session, { reason, notify });
}

function getInterpreterStatus(roomName) {
  const session = sessions.get(roomName);
  if (!session) return { running: false };
  return {
    running: true,
    ready: session.ready,
    sessionId: session.sessionId,
    directions: session.directions.map(({ speaker, listener, sourceLang, targetLang, engine }) => ({
      speaker, listener, sourceLang, targetLang, engine,
    })),
    present: session.presence.presentPeople(),
  };
}

/**
 * Post-deploy smoke for both engines: gpt-realtime-translate for the pairs it
 * speaks, the phrase engine's model for the rest. { ok, reason } as before,
 * plus each engine's own result.
 */
async function selftest(deps = {}) {
  const cfg = { ...readConfig(), ...(deps.config || {}) };
  const [simultaneous, phrase] = await Promise.all([
    selftestTranslate({
      apiKey: cfg.openaiKey,
      model: cfg.model,
      transcribeModel: cfg.transcribeModel,
      noiseReduction: cfg.noiseReduction,
      wsFactory: deps.wsFactory,
    }),
    selftestPhrase({ apiKey: cfg.openaiKey, model: cfg.fallbackModel, wsFactory: deps.wsFactory }),
  ]);
  const ok = simultaneous.ok && phrase.ok;
  const reason = ok
    ? `${cfg.model}: ${simultaneous.reason}; ${cfg.fallbackModel}: ${phrase.reason}`
    : [!simultaneous.ok && `${cfg.model}: ${simultaneous.reason}`, !phrase.ok && `${cfg.fallbackModel}: ${phrase.reason}`]
      .filter(Boolean)
      .join('; ');
  return { ok, reason, simultaneous, phrase };
}

module.exports = { startInterpreter, stopInterpreter, getInterpreterStatus, selftest, readConfig, AGENT_IDENTITY };
