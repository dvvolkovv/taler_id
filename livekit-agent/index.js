require("dotenv").config();
const express = require('express');
const { AccessToken } = require('livekit-server-sdk');
const WebSocket = require('ws');
const { startRecording, stopRecording, getRecordingStatus } = require('./recorder');
const { startTranslator, stopTranslator, updateParticipantLang, getTranslatorStatus, getTranslatorLanguages } = require('./translator');

let livekitRtc = null;
try {
  livekitRtc = require('@livekit/rtc-node');
  console.log('LiveKit RTC Node loaded successfully');
} catch (e) {
  console.warn('LiveKit RTC Node not available:', e.message, '- AI will not join rooms');
}

const LK_URL = process.env.LIVEKIT_WS_URL || 'ws://localhost:7880';
const LK_API_KEY = process.env.LIVEKIT_API_KEY || 'lkdevkey';
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || 'lkSecret2024TalerID';
const OPENAI_KEY = process.env.OPENAI_API_KEY;
const BACKEND_URL = process.env.BACKEND_URL || 'https://id.taler.tirol';
const BACKEND_WS_URL = (process.env.BACKEND_URL || 'https://id.taler.tirol').replace(/^http/, 'ws');
const USE_REALTIME_PROXY = process.env.USE_REALTIME_PROXY === 'true';

const app = express();
app.use(express.json());
const sessions = new Map();

app.get('/health', (req, res) => res.json({ ok: true, sessions: sessions.size, lkRtcAvailable: !!livekitRtc }));

// ═══════════════════════════════════════════
// ── AI VOICE ASSISTANT ──
// ═══════════════════════════════════════════

app.post('/join', async (req, res) => {
  const { roomName, userId, userToken } = req.body;
  if (!roomName) return res.status(400).json({ error: 'roomName required' });
  if (sessions.has(roomName)) return res.json({ ok: true, status: 'already_joined' });
  joinRoom(roomName, userId, userToken).catch(e => console.error('Error joining ' + roomName + ':', e));
  res.json({ ok: true });
});

app.post('/leave', (req, res) => {
  const { roomName } = req.body;
  const session = sessions.get(roomName);
  if (session) {
    try { if (session.openaiWs) session.openaiWs.close(); } catch(e) {}
    try { if (session.room) session.room.disconnect(); } catch(e) {}
    sessions.delete(roomName);
  }
  res.json({ ok: true });
});

// ═══════════════════════════════════════════
// ── MEETING RECORDER ──
// ═══════════════════════════════════════════

app.post('/record', async (req, res) => {
  const { roomName } = req.body;
  if (!roomName) return res.status(400).json({ error: 'roomName required' });
  try {
    const withAi = req.body.withAi !== false;
    const result = await startRecording(roomName, withAi);
    res.json(result);
  } catch (e) {
    console.error('[RECORDER] Start error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/stop-record', async (req, res) => {
  const { roomName } = req.body;
  if (!roomName) return res.status(400).json({ error: 'roomName required' });
  try {
    const result = await stopRecording(roomName);
    res.json(result);
  } catch (e) {
    console.error('[RECORDER] Stop error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/record-status/:roomName', (req, res) => {
  const result = getRecordingStatus(req.params.roomName);
  res.json(result);
});


// ═══════════════════════════════════════════
// ── VOICE TRANSLATOR ──
// ═══════════════════════════════════════════

app.post('/translator/start', async (req, res) => {
  const { roomName } = req.body;
  if (!roomName) return res.status(400).json({ error: 'roomName required' });
  try {
    const result = await startTranslator(roomName);
    res.json(result);
  } catch (e) {
    console.error('[TRANSLATOR] Start error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/translator/stop', async (req, res) => {
  const { roomName } = req.body;
  if (!roomName) return res.status(400).json({ error: 'roomName required' });
  try {
    const result = await stopTranslator(roomName);
    res.json(result);
  } catch (e) {
    console.error('[TRANSLATOR] Stop error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/translator/set-lang', async (req, res) => {
  const { roomName, userId, lang } = req.body;
  if (!roomName || !userId || !lang) return res.status(400).json({ error: 'roomName, userId, lang required' });
  const result = await updateParticipantLang(roomName, userId, lang);
  res.json(result);
});

app.get('/translator/languages', (req, res) => {
  res.json(getTranslatorLanguages());
});

app.get('/translator/status/:roomName', (req, res) => {
  res.json(getTranslatorStatus(req.params.roomName));
});

// ═══════════════════════════════════════════
// ── AI VOICE ASSISTANT LOGIC ──
// ═══════════════════════════════════════════

async function joinRoom(roomName, userId, userToken) {
  console.log('AI Agent joining room:', roomName, 'user:', userId);

  const at = new AccessToken(LK_API_KEY, LK_API_SECRET, { identity: 'ai-assistant', name: 'AI Assistant' });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true });
  const token = await at.toJwt();

  const openaiWs = USE_REALTIME_PROXY && userToken
    ? new WebSocket(BACKEND_WS_URL + '/voice/realtime-proxy?token=' + encodeURIComponent(userToken))
    : new WebSocket(
        'wss://api.openai.com/v1/realtime?model=gpt-4o-realtime-preview-2024-12-17',
        { headers: { Authorization: 'Bearer ' + OPENAI_KEY, 'OpenAI-Beta': 'realtime=v1' } }
      );
  console.log('OpenAI connection via:', USE_REALTIME_PROXY && userToken ? 'backend proxy' : 'direct');

  const session = { openaiWs, roomName, userId, userToken, captureQueue: Promise.resolve() };
  sessions.set(roomName, session);

  openaiWs.on('open', () => {
    console.log('OpenAI connected for room:', roomName);
    openaiWs.send(JSON.stringify({
      type: 'session.update',
      session: {
        modalities: ['text', 'audio'],
        voice: 'alloy',
        instructions: 'You are Taler ID voice assistant. Be helpful, concise, and friendly. Speak in the language used by participants. Your name is Taler Assistant.',
        input_audio_transcription: { model: 'whisper-1' },
        turn_detection: { type: 'server_vad', threshold: 0.5, prefix_padding_ms: 300, silence_duration_ms: 800 },
        tools: [
          { type: 'function', name: 'get_profile', description: 'Get user profile information', parameters: { type: 'object', properties: {} } },
          { type: 'function', name: 'update_profile', description: 'Update user profile fields', parameters: { type: 'object', properties: { firstName: { type: 'string' }, lastName: { type: 'string' }, phone: { type: 'string' } } } }
        ],
        tool_choice: 'auto'
      }
    }));
    setTimeout(() => {
      if (openaiWs.readyState !== WebSocket.OPEN) return;
      openaiWs.send(JSON.stringify({
        type: 'conversation.item.create',
        item: {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'Hello' }]
        }
      }));
      openaiWs.send(JSON.stringify({ type: 'response.create' }));
    }, 700);
  });

  openaiWs.on('error', e => console.error('OpenAI WS error for room ' + roomName + ':', e.message));

  openaiWs.on('close', (code, reason) => {
    console.log('OpenAI disconnected for room:', roomName, 'code:', code, 'reason:', reason?.toString());
  });

  if (!livekitRtc) {
    console.warn('LiveKit RTC not available - AI will not join room:', roomName);
    return;
  }

  const { Room, RoomEvent, AudioStream, AudioSource, LocalAudioTrack, AudioFrame, TrackKind, TrackPublishOptions, TrackSource } = livekitRtc;

  const audioSource = new AudioSource(24000, 1);
  session.audioSource = audioSource;

  openaiWs.on('message', async (raw) => {
    try {
      const event = JSON.parse(raw.toString());

      if (event.type === 'response.audio.delta' && session.audioSource) {
        const pcmBuffer = Buffer.from(event.delta, 'base64');
        const samplesPerChannel = Math.floor(pcmBuffer.length / 2);
        if (samplesPerChannel === 0) return;
        const int16Data = new Int16Array(samplesPerChannel);
        new Uint8Array(int16Data.buffer).set(pcmBuffer);
        const frame = new AudioFrame(int16Data, 24000, 1, samplesPerChannel);
        if (session.audioSource) {
          session.captureQueue = session.captureQueue.then(async () => {
            if (!session.audioSource) return;
            try {
              await session.audioSource.captureFrame(frame);
            } catch(e) {
              if (sessions.has(roomName)) console.error('captureFrame error:', e.message);
            }
          });
        }
      }

      if (event.type === 'response.function_call_arguments.done') {
        const { name, call_id, arguments: argsStr } = event;
        let output = '{}';
        const args = JSON.parse(argsStr || '{}');
        if (name === 'get_profile' && session.userToken) {
          const r = await fetch(BACKEND_URL + '/profile', { headers: { Authorization: 'Bearer ' + session.userToken } });
          output = JSON.stringify(await r.json());
        }
        if (name === 'update_profile' && session.userToken) {
          const r = await fetch(BACKEND_URL + '/profile', {
            method: 'PUT',
            headers: { Authorization: 'Bearer ' + session.userToken, 'Content-Type': 'application/json' },
            body: JSON.stringify(args)
          });
          const json = await r.json();
          if (!r.ok) {
            console.error('[update_profile] Backend error:', r.status, JSON.stringify(json));
            output = JSON.stringify({ error: true, status: r.status, message: json.message ?? 'Failed to update profile' });
          } else {
            output = JSON.stringify({ success: true, ...json });
          }
        }
        openaiWs.send(JSON.stringify({ type: 'conversation.item.create', item: { type: 'function_call_output', call_id, output } }));
        openaiWs.send(JSON.stringify({ type: 'response.create' }));
      }
    } catch (e) { console.error('Message parse error:', e.message); }
  });

  const room = new Room();
  session.room = room;

  room.on(RoomEvent.TrackSubscribed, async (track, publication, participant) => {
    if (track.kind !== TrackKind.KIND_AUDIO) return;
    console.log('Subscribed to audio from:', participant.identity, 'in room:', roomName);
    try {
      const audioStream = new AudioStream(track, 24000, 1);
      for await (const frame of audioStream) {
        const s = sessions.get(roomName);
        if (!s || s.openaiWs.readyState !== WebSocket.OPEN) break;
        const b64 = Buffer.from(frame.data.buffer, frame.data.byteOffset, frame.data.byteLength).toString('base64');
        s.openaiWs.send(JSON.stringify({ type: 'input_audio_buffer.append', audio: b64 }));
      }
    } catch (e) {
      console.log('Audio stream ended for participant:', participant.identity, e.message);
    }
  });

  room.on(RoomEvent.ParticipantDisconnected, (participant) => {
    console.log('Participant left:', participant.identity, 'in room:', roomName);
    const humanParticipants = Array.from(room.remoteParticipants.values())
      .filter(p => p.identity !== 'ai-assistant');
    if (humanParticipants.length === 0) {
      console.log('No more participants in room:', roomName, '- AI leaving');
      session.audioSource = null;
      try { openaiWs.close(); } catch(e) {}
      try { room.disconnect(); } catch(e) {}
      sessions.delete(roomName);
    }
  });

  room.on(RoomEvent.Disconnected, () => {
    console.log('Room disconnected:', roomName);
    session.audioSource = null;
    try { openaiWs.close(); } catch(e) {}
    sessions.delete(roomName);
  });

  await room.connect(LK_URL, token);
  console.log('AI connected to LiveKit room:', roomName);

  const audioTrack = LocalAudioTrack.createAudioTrack('microphone', audioSource);
  const publishOpts = new TrackPublishOptions({ source: TrackSource.SOURCE_MICROPHONE });
  await room.localParticipant.publishTrack(audioTrack, publishOpts);
  console.log('AI audio track published to room:', roomName);
}

const PORT = process.env.PORT || 3100;
app.listen(PORT, () => console.log('AI Agent listening on :' + PORT));

process.on('SIGTERM', () => {
  sessions.forEach(s => {
    try { if (s.openaiWs) s.openaiWs.close(); } catch(e) {}
    try { if (s.room) s.room.disconnect(); } catch(e) {}
  });
  process.exit(0);
});
