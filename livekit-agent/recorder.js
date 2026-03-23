/**
 * Meeting Recorder Module for Taler ID
 *
 * Joins a LiveKit room as a silent observer, records each participant's
 * audio to disk (not RAM), then transcribes via Whisper and summarises via GPT-4o.
 *
 * IMPORTANT: Each audio TRACK gets its own PCM file. Participants like the
 * Translator may publish multiple tracks (one per language direction).
 * During processing, tracks from the same participant are mixed with ffmpeg.
 */

const { AccessToken } = require('livekit-server-sdk');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { randomUUID: uuidv4 } = require('crypto');

const LK_URL = process.env.LIVEKIT_WS_URL || 'ws://localhost:7880';
const LK_API_KEY = process.env.LIVEKIT_API_KEY || 'lkdevkey';
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || 'lkSecret2024TalerID';
const OPENAI_KEY = process.env.OPENAI_API_KEY;
const BACKEND_URL = process.env.BACKEND_URL || 'https://id.taler.tirol';
const RECORDINGS_DIR = process.env.RECORDINGS_DIR || '/var/www/recordings';

const SAMPLE_RATE = 48000; // LiveKit default
const CHANNELS = 1;
const BYTES_PER_SAMPLE = 2; // Int16

// Active recording sessions
const recorderSessions = new Map();

let livekitRtc = null;
try {
  livekitRtc = require('@livekit/rtc-node');
} catch (e) {
  console.warn('[RECORDER] LiveKit RTC not available:', e.message);
}

// ─── Public API ──────────────────────────────────────────

async function startRecording(roomName, withAi = true) {
  if (!livekitRtc) throw new Error('LiveKit RTC not available');
  if (recorderSessions.has(roomName)) {
    const existing = recorderSessions.get(roomName);
    if (existing.stopping) {
      recorderSessions.delete(roomName);
      console.log('[RECORDER] Cleared stale stopping session for:', roomName);
    } else {
      return { status: 'already_recording' };
    }
  }

  console.log('[RECORDER] Starting recording for room:', roomName);

  const { Room, RoomEvent, AudioStream, TrackKind } = livekitRtc;

  // Generate token – silent observer
  const at = new AccessToken(LK_API_KEY, LK_API_SECRET, {
    identity: 'meeting-recorder',
    name: 'Запись',
  });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true });
  const token = await at.toJwt();

  // Create temp directory for this recording session
  const tmpDir = path.join(os.tmpdir(), `recorder-${roomName}-${Date.now()}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  const room = new Room();
  // Key: trackKey (identity__trackIdx) → { identity, name, pcmPath, writeStream, bytesWritten, startTime }
  const trackAudio = new Map();
  // Counter per identity to generate unique track keys
  const trackCounters = new Map();
  const startTime = Date.now();

  const session = {
    room,
    roomName,
    trackAudio,
    trackCounters,
    startTime,
    stopping: false,
    withAi,
    tmpDir,
  };
  recorderSessions.set(roomName, session);

  // ── Helper: start capturing a single audio track to disk ──
  function captureTrack(track, participant) {
    if (track.kind !== TrackKind.KIND_AUDIO) return;
    if (participant.identity === 'meeting-recorder') return;
    if (participant.identity === 'ai-assistant') return;
    if (participant.identity === 'voice-translator') return;

    const identity = participant.identity;
    const name = participant.name || identity;

    // Generate unique key per track
    const idx = (trackCounters.get(identity) || 0);
    trackCounters.set(identity, idx + 1);
    const trackKey = `${identity}__t${idx}`;

    console.log('[RECORDER] Recording audio track', idx, 'from:', name, `(${identity})`);

    const pcmPath = path.join(tmpDir, `${trackKey}.pcm`);
    const writeStream = fs.createWriteStream(pcmPath);
    const entry = { identity, name, pcmPath, writeStream, bytesWritten: 0, startTime: Date.now() };
    trackAudio.set(trackKey, entry);

    (async () => {
      try {
        const audioStream = new AudioStream(track, SAMPLE_RATE, CHANNELS);
        for await (const frame of audioStream) {
          if (session.stopping) break;
          const buf = Buffer.from(frame.data.buffer, frame.data.byteOffset, frame.data.byteLength);
          entry.writeStream.write(buf);
          entry.bytesWritten += buf.length;
        }
      } catch (e) {
        console.log('[RECORDER] Audio stream ended for:', trackKey, e.message);
      }
    })();
  }

  // ── Track subscribed → start capturing audio to disk ──
  room.on(RoomEvent.TrackSubscribed, (track, publication, participant) => {
    captureTrack(track, participant);
  });

  // ── Participant connected — update name ──
  room.on(RoomEvent.ParticipantConnected, (participant) => {
    console.log('[RECORDER] Participant joined:', participant.name || participant.identity);
  });

  // ── Auto-stop when all humans leave ──
  room.on(RoomEvent.ParticipantDisconnected, (participant) => {
    console.log('[RECORDER] Participant left:', participant.identity);
    const humans = Array.from(room.remoteParticipants.values())
      .filter(p => p.identity !== 'meeting-recorder' && p.identity !== 'ai-assistant' && p.identity !== 'voice-translator');
    if (humans.length === 0 && !session.stopping) {
      console.log('[RECORDER] All humans left — auto-stopping');
      stopRecording(roomName);
    }
  });

  room.on(RoomEvent.Disconnected, () => {
    console.log('[RECORDER] Room disconnected:', roomName);
    if (!session.stopping) {
      session.stopping = true;
      closeAllStreams(session);
      processAndSave(session).catch(e => console.error('[RECORDER] Process error:', e));
    }
  });

  // Connect to room (no audio publishing — silent observer)
  await room.connect(LK_URL, token);
  console.log('[RECORDER] Connected to room:', roomName);

  // ── Capture already-published tracks (participants who joined before the recorder) ──
  for (const participant of room.remoteParticipants.values()) {
    for (const pub of participant.trackPublications.values()) {
      if (pub.track && pub.track.kind === TrackKind.KIND_AUDIO) {
        captureTrack(pub.track, participant);
      }
    }
  }

  // Broadcast recording status via DataChannel
  try {
    const encoder = new TextEncoder();
    const msg = JSON.stringify({ type: 'recorder_status', recording: true });
    await room.localParticipant.publishData(encoder.encode(msg), { reliable: true });
  } catch (e) {
    console.warn('[RECORDER] Failed to broadcast status:', e.message);
  }

  return { status: 'recording', roomName };
}

function closeAllStreams(session) {
  for (const [, entry] of session.trackAudio) {
    try { entry.writeStream.end(); } catch (_) {}
  }
}

async function stopRecording(roomName) {
  const session = recorderSessions.get(roomName);
  if (!session) return { status: 'not_recording' };
  if (session.stopping) return { status: 'already_stopping' };

  console.log('[RECORDER] Stopping recording for room:', roomName);
  session.stopping = true;

  // Broadcast stop
  try {
    const encoder = new TextEncoder();
    const msg = JSON.stringify({ type: 'recorder_status', recording: false });
    await session.room.localParticipant.publishData(encoder.encode(msg), { reliable: true });
  } catch (e) {}

  // Small delay to let last audio frames arrive
  await new Promise(r => setTimeout(r, 500));

  // Close all write streams
  closeAllStreams(session);

  // Disconnect from room
  try { session.room.disconnect(); } catch (e) {}

  // Process in background
  processAndSave(session).catch(e => console.error('[RECORDER] Process error:', e));

  return { status: 'processing' };
}

function getRecordingStatus(roomName) {
  const session = recorderSessions.get(roomName);
  if (!session) return { recording: false };
  // Collect unique participant identities
  const identities = new Set();
  for (const [, entry] of session.trackAudio) identities.add(entry.identity);
  return {
    recording: !session.stopping,
    participants: Array.from(identities),
    durationSec: Math.floor((Date.now() - session.startTime) / 1000),
  };
}

// ─── Processing Pipeline ──────────────────────────────────

async function processAndSave(session) {
  const { roomName, trackAudio, startTime, tmpDir } = session;
  const durationSec = Math.floor((Date.now() - startTime) / 1000);

  // Group tracks by participant identity
  const byIdentity = new Map(); // identity → [{ name, pcmPath, bytesWritten, ... }]
  for (const [, entry] of trackAudio) {
    if (entry.bytesWritten === 0) continue;
    if (!byIdentity.has(entry.identity)) byIdentity.set(entry.identity, []);
    byIdentity.get(entry.identity).push(entry);
  }

  console.log('[RECORDER] Processing', byIdentity.size, 'participants (' + trackAudio.size + ' tracks),', durationSec, 'seconds');

  if (byIdentity.size === 0) {
    console.log('[RECORDER] No audio recorded — skipping');
    recorderSessions.delete(roomName);
    return;
  }

  // Save a "processing" placeholder so users see the meeting immediately in the app
  let pendingId = null;
  const participants0 = [];
  const participantIds0 = [];
  for (const [identity, tracks] of byIdentity) {
    participants0.push(tracks[0].name);
    participantIds0.push(identity);
  }
  try {
    const r = await fetch(`${BACKEND_URL}/voice/meetings/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        roomName,
        transcript: '',
        summary: '',
        keyPoints: [],
        actionItems: [],
        decisions: [],
        participants: participants0,
        participantIds: participantIds0,
        durationSec,
        status: 'done',
      }),
    });
    const d = await r.json();
    pendingId = d.id;
    console.log('[RECORDER] Saved pending meeting:', pendingId);
  } catch (e) {
    console.warn('[RECORDER] Failed to save pending meeting:', e.message);
  }

  try {
    // 1. For each participant: convert PCM tracks → OGG, mix if multiple tracks
    const audioFiles = []; // { identity, name, oggPath, oggSize }
    for (const [identity, tracks] of byIdentity) {
      const name = tracks[0].name;

      if (tracks.length === 1) {
        // Single track — straightforward convert
        const entry = tracks[0];
        const pcmSizeMB = (entry.bytesWritten / 1024 / 1024).toFixed(1);
        console.log('[RECORDER]', name, ': 1 track,', pcmSizeMB, 'MB PCM');

        const oggPath = path.join(tmpDir, `${identity}.ogg`);
        await ffmpegConvert(entry.pcmPath, oggPath, SAMPLE_RATE, CHANNELS);
        const oggSize = fs.statSync(oggPath).size;
        console.log('[RECORDER]', name, ':', (oggSize / 1024 / 1024).toFixed(1), 'MB OGG');
        audioFiles.push({ identity, name, oggPath, oggSize });

        // Delete PCM
        try { fs.unlinkSync(entry.pcmPath); } catch (_) {}
      } else {
        // Multiple tracks — convert each to OGG, then mix them
        console.log('[RECORDER]', name, ':', tracks.length, 'tracks');
        const trackOggs = [];
        for (let i = 0; i < tracks.length; i++) {
          const entry = tracks[i];
          const pcmSizeMB = (entry.bytesWritten / 1024 / 1024).toFixed(1);
          console.log('[RECORDER]   track', i, ':', pcmSizeMB, 'MB PCM');

          const trackOgg = path.join(tmpDir, `${identity}_t${i}.ogg`);
          await ffmpegConvert(entry.pcmPath, trackOgg, SAMPLE_RATE, CHANNELS);
          trackOggs.push(trackOgg);

          // Delete PCM
          try { fs.unlinkSync(entry.pcmPath); } catch (_) {}
        }

        // Mix all tracks of this participant into one OGG
        const mixedOgg = path.join(tmpDir, `${identity}_mixed.ogg`);
        await ffmpegMixTracks(trackOggs, mixedOgg);
        const oggSize = fs.statSync(mixedOgg).size;
        console.log('[RECORDER]', name, ': mixed', tracks.length, 'tracks →', (oggSize / 1024 / 1024).toFixed(1), 'MB OGG');
        audioFiles.push({ identity, name, oggPath: mixedOgg, oggSize });

        // Cleanup individual track OGGs
        for (const t of trackOggs) {
          try { fs.unlinkSync(t); } catch (_) {}
        }
      }
    }

    // 2. Mix all participant audio into a single MP3, upload to S3 via backend
    // NOTE: Transcription and summarization are done post-hoc via the app's "Протокол" button
    let recordingUrl = null;
    if (audioFiles.length > 0) {
      try {
        const recId = uuidv4();
        const outMp3 = path.join(tmpDir, recId + '.mp3');
        if (audioFiles.length === 1) {
          await new Promise((resolve, reject) => {
            execFile('ffmpeg', [
              '-y', '-i', audioFiles[0].oggPath,
              '-c:a', 'libmp3lame', '-q:a', '4',
              outMp3,
            ], { timeout: 120000 }, (err, _stdout, stderr) => {
              if (err) reject(new Error('ffmpeg single mix failed: ' + stderr));
              else resolve();
            });
          });
        } else {
          const inputs = audioFiles.flatMap(f => ['-i', f.oggPath]);
          const filterAr = audioFiles.map((_, i) => `[${i}:a]`).join('');
          const filterComplex = `${filterAr}amix=inputs=${audioFiles.length}:duration=longest[aout]`;
          await new Promise((resolve, reject) => {
            execFile('ffmpeg', [
              '-y', ...inputs,
              '-filter_complex', filterComplex,
              '-map', '[aout]',
              '-c:a', 'libmp3lame', '-q:a', '4',
              outMp3,
            ], { timeout: 180000 }, (err, _stdout, stderr) => {
              if (err) reject(new Error('ffmpeg multi mix failed: ' + stderr));
              else resolve();
            });
          });
        }

        // Upload to S3 via backend
        const fileBuffer = fs.readFileSync(outMp3);
        const formData = new FormData();
        const blob = new Blob([fileBuffer], { type: 'audio/mpeg' });
        formData.append('file', blob, `${recId}.mp3`);

        const uploadRes = await fetch(`${BACKEND_URL}/voice/recordings/upload`, {
          method: 'POST',
          body: formData,
        });

        if (uploadRes.ok) {
          const uploadData = await uploadRes.json();
          recordingUrl = uploadData.url;
          console.log('[RECORDER] Recording uploaded to S3:', recordingUrl);
        } else {
          console.error('[RECORDER] S3 upload failed:', uploadRes.status, await uploadRes.text());
          // Fallback: save locally
          const fallbackDir = process.env.RECORDINGS_DIR || '/var/www/recordings';
          const fallbackPath = path.join(fallbackDir, recId + '.mp3');
          fs.copyFileSync(outMp3, fallbackPath);
          recordingUrl = `${BACKEND_URL}/recordings/${recId}.mp3`;
          console.log('[RECORDER] Fallback saved locally:', fallbackPath);
        }
      } catch (e) {
        console.error('[RECORDER] Audio mix/upload failed:', e.message);
      }
    }

    // 3. Save to backend (recording only, no transcript/summary)
    const payload = {
      roomName,
      transcript: '',
      summary: '',
      keyPoints: [],
      actionItems: [],
      decisions: [],
      participants: participants0,
      participantIds: participantIds0,
      durationSec,
      recordingUrl,
    };

    if (pendingId) payload.id = pendingId;
    payload.status = 'done';
    console.log('[RECORDER] Saving to backend...');
    try {
      const res = await fetch(`${BACKEND_URL}/voice/meetings/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      console.log('[RECORDER] Saved meeting summary:', data.id || 'ok');
    } catch (e) {
      console.error('[RECORDER] Failed to save to backend:', e.message);
      const fallbackPath = path.join(os.homedir(), `meeting-${roomName}-${Date.now()}.json`);
      fs.writeFileSync(fallbackPath, JSON.stringify(payload, null, 2));
      console.log('[RECORDER] Saved fallback to:', fallbackPath);
    }
  } finally {
    // Cleanup temp files
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (e) {}
    recorderSessions.delete(roomName);
    console.log('[RECORDER] Done processing room:', roomName);
  }
}

// ─── Helpers ──────────────────────────────────────────────

function ffmpegConvert(pcmPath, oggPath, sampleRate, channels) {
  return new Promise((resolve, reject) => {
    execFile('ffmpeg', [
      '-y', '-f', 's16le', '-ar', String(sampleRate), '-ac', String(channels),
      '-i', pcmPath,
      '-c:a', 'libopus', '-b:a', '48k',
      oggPath,
    ], { timeout: 120000 }, (err, stdout, stderr) => {
      if (err) reject(new Error(`ffmpeg failed: ${err.message}\n${stderr}`));
      else resolve();
    });
  });
}

/**
 * Mix multiple OGG tracks into one OGG file.
 * Uses amix filter to overlay them (all tracks play simultaneously).
 */
function ffmpegMixTracks(inputOggs, outputOgg) {
  return new Promise((resolve, reject) => {
    if (inputOggs.length === 1) {
      // Just copy
      fs.copyFileSync(inputOggs[0], outputOgg);
      return resolve();
    }
    const inputs = inputOggs.flatMap(f => ['-i', f]);
    const filterAr = inputOggs.map((_, i) => `[${i}:a]`).join('');
    const filterComplex = `${filterAr}amix=inputs=${inputOggs.length}:duration=longest:normalize=0[aout]`;
    execFile('ffmpeg', [
      '-y', ...inputs,
      '-filter_complex', filterComplex,
      '-map', '[aout]',
      '-c:a', 'libopus', '-b:a', '48k',
      outputOgg,
    ], { timeout: 120000 }, (err, _stdout, stderr) => {
      if (err) reject(new Error(`ffmpeg mix failed: ${err.message}\n${stderr}`));
      else resolve();
    });
  });
}

function splitOggFile(oggPath, tmpDir, identity) {
  return new Promise((resolve, reject) => {
    const chunkPaths = [];
    const chunkDuration = 8 * 60;
    execFile('ffprobe', [
      '-v', 'error', '-show_entries', 'format=duration',
      '-of', 'default=noprint_wrappers=1:nokey=1', oggPath,
    ], (err, stdout) => {
      if (err) return reject(err);
      const duration = parseFloat(stdout.trim());
      const numChunks = Math.ceil(duration / chunkDuration);
      let completed = 0;

      for (let i = 0; i < numChunks; i++) {
        const chunkPath = path.join(tmpDir, `${identity}_chunk${i}.ogg`);
        chunkPaths.push(chunkPath);
        execFile('ffmpeg', [
          '-y', '-i', oggPath,
          '-ss', String(i * chunkDuration),
          '-t', String(chunkDuration),
          '-c:a', 'libopus',
          chunkPath,
        ], { timeout: 60000 }, (err2) => {
          if (err2) return reject(err2);
          completed++;
          if (completed === numChunks) resolve(chunkPaths);
        });
      }
    });
  });
}

async function transcribeWithWhisper(audioPath) {
  const formData = new FormData();
  const fileBuffer = fs.readFileSync(audioPath);
  const blob = new Blob([fileBuffer], { type: 'audio/ogg' });
  formData.append('file', blob, path.basename(audioPath));
  formData.append('model', 'whisper-1');
  formData.append('response_format', 'verbose_json');
  formData.append('timestamp_granularities[]', 'segment');

  const res = await fetch('https://api.openai.com/v1/audio/transcriptions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${OPENAI_KEY}` },
    body: formData,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Whisper API error ${res.status}: ${text}`);
  }

  const data = await res.json();
  if (data.segments && data.segments.length > 0) {
    return data.segments.map(s => ({
      start: s.start,
      end: s.end,
      text: s.text.trim(),
    }));
  }
  if (data.text) {
    return [{ start: 0, end: 0, text: data.text.trim() }];
  }
  return [];
}

async function summarizeWithGpt(transcript, participantNames) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${OPENAI_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'gpt-4o',
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content: `Ты — ассистент для анализа встреч. Проанализируй транскрипт и верни JSON с полями:
- "summary": краткое резюме встречи (2-3 абзаца, на языке встречи)
- "keyPoints": массив ключевых моментов (строки)
- "actionItems": массив задач, каждая: { "task": "описание", "assignee": "имя или null", "deadline": "срок или null" }
- "decisions": массив принятых решений (строки)

Участники: ${participantNames.join(', ')}
Пиши резюме на том же языке, на котором проходила встреча.`,
        },
        {
          role: 'user',
          content: transcript,
        },
      ],
      max_tokens: 4096,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    console.error('[RECORDER] GPT-4o error:', res.status, text);
    return { summary: 'Ошибка при создании резюме', keyPoints: [], actionItems: [], decisions: [] };
  }

  const data = await res.json();
  try {
    return JSON.parse(data.choices[0].message.content);
  } catch (e) {
    console.error('[RECORDER] Failed to parse GPT response:', e.message);
    return { summary: data.choices[0].message.content, keyPoints: [], actionItems: [], decisions: [] };
  }
}

module.exports = { startRecording, stopRecording, getRecordingStatus };
