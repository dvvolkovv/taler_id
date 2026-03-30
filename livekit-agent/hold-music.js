/**
 * Hold Music Module for Taler ID
 *
 * Joins a LiveKit room as 'hold-music' identity and streams an MP3 file
 * as a looping audio track. Remote participants hear hold music while
 * the caller has them on hold.
 */

const { AccessToken } = require('livekit-server-sdk');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const LK_URL = process.env.LIVEKIT_WS_URL || 'ws://localhost:7880';
const LK_API_KEY = process.env.LIVEKIT_API_KEY || 'lkdevkey';
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || 'lkSecret2024TalerID';

const SAMPLE_RATE = 48000;
const CHANNELS = 1;
const BYTES_PER_SAMPLE = 2; // Int16
const FRAME_DURATION_MS = 20;
const SAMPLES_PER_FRAME = (SAMPLE_RATE * FRAME_DURATION_MS) / 1000;
const BYTES_PER_FRAME = SAMPLES_PER_FRAME * CHANNELS * BYTES_PER_SAMPLE;

const HOLD_MUSIC_FILE = path.join(__dirname, 'hold_music.mp3');

// Active hold music sessions
const holdSessions = new Map();

let livekitRtc = null;
try {
  livekitRtc = require('@livekit/rtc-node');
} catch (e) {
  console.warn('[HOLD-MUSIC] LiveKit RTC not available:', e.message);
}

/**
 * Decode MP3 to raw PCM16 mono 48kHz using ffmpeg
 */
function decodeMp3ToPcm(mp3Path) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const proc = spawn('ffmpeg', [
      '-i', mp3Path,
      '-f', 's16le',
      '-acodec', 'pcm_s16le',
      '-ar', String(SAMPLE_RATE),
      '-ac', String(CHANNELS),
      '-loglevel', 'error',
      'pipe:1',
    ]);
    proc.stdout.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    proc.on('close', (code) => {
      if (code === 0) resolve(Buffer.concat(chunks));
      else reject(new Error('ffmpeg exit code ' + code));
    });
    proc.on('error', reject);
  });
}

async function startHoldMusic(roomName) {
  if (!livekitRtc) throw new Error('LiveKit RTC not available');
  if (holdSessions.has(roomName)) return { status: 'already_playing' };
  if (!fs.existsSync(HOLD_MUSIC_FILE)) throw new Error('hold_music.mp3 not found');

  console.log('[HOLD-MUSIC] Starting for room:', roomName);

  const { Room, LocalAudioTrack, AudioSource, TrackPublishOptions, TrackSource } = livekitRtc;

  // Decode MP3 to PCM buffer
  const pcmBuffer = await decodeMp3ToPcm(HOLD_MUSIC_FILE);
  console.log('[HOLD-MUSIC] Decoded PCM:', pcmBuffer.length, 'bytes');

  // Generate token
  const at = new AccessToken(LK_API_KEY, LK_API_SECRET, {
    identity: 'hold-music',
    name: 'Hold Music',
  });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: false });
  const token = await at.toJwt();

  // Connect to room
  const room = new Room();
  await room.connect(LK_URL, token);
  console.log('[HOLD-MUSIC] Connected to room:', roomName);

  // Create audio source and track
  const audioSource = new AudioSource(SAMPLE_RATE, CHANNELS);
  const track = LocalAudioTrack.createAudioTrack('hold-music', audioSource);
  const opts = new TrackPublishOptions();
  opts.source = TrackSource.SOURCE_MICROPHONE;
  await room.localParticipant.publishTrack(track, opts);
  console.log('[HOLD-MUSIC] Audio track published');

  // Stream PCM in a loop
  let offset = 0;
  let running = true;

  const session = { room, running: true, interval: null };
  holdSessions.set(roomName, session);

  // Send frames at real-time pace
  session.interval = setInterval(async () => {
    if (!session.running) return;
    try {
      // Extract one frame
      const end = offset + BYTES_PER_FRAME;
      let frame;
      if (end <= pcmBuffer.length) {
        frame = pcmBuffer.subarray(offset, end);
        offset = end;
      } else {
        // Loop: wrap around
        const remaining = pcmBuffer.length - offset;
        const tail = pcmBuffer.subarray(offset);
        const head = pcmBuffer.subarray(0, BYTES_PER_FRAME - remaining);
        frame = Buffer.concat([tail, head]);
        offset = BYTES_PER_FRAME - remaining;
      }

      // Convert to Int16Array
      const samples = new Int16Array(frame.buffer, frame.byteOffset, frame.length / 2);
      await audioSource.captureFrame({
        data: samples,
        sampleRate: SAMPLE_RATE,
        channels: CHANNELS,
        samplesPerChannel: SAMPLES_PER_FRAME,
      });
    } catch (e) {
      console.error('[HOLD-MUSIC] Frame error:', e.message);
    }
  }, FRAME_DURATION_MS);

  return { status: 'started' };
}

async function stopHoldMusic(roomName) {
  const session = holdSessions.get(roomName);
  if (!session) return { status: 'not_playing' };

  console.log('[HOLD-MUSIC] Stopping for room:', roomName);
  session.running = false;
  if (session.interval) clearInterval(session.interval);
  try { await session.room.disconnect(); } catch (_) {}
  holdSessions.delete(roomName);
  return { status: 'stopped' };
}

function getHoldMusicStatus(roomName) {
  return { playing: holdSessions.has(roomName) };
}

module.exports = { startHoldMusic, stopHoldMusic, getHoldMusicStatus };
