#!/usr/bin/env node
'use strict';
/**
 * Probe for gpt-realtime-translate: streams a fixture at real-time pace into
 * one translation session per --target and prints every event type with its
 * shape (keys, long strings cut), when the first translated audio arrived,
 * how much of it there was, and both transcripts.
 *
 *   node bench/probe-translate.js --env ~/taler-id/livekit-agent/.env \
 *     --wav bench/fixtures/ru-1.wav --target de --target ru
 */
const fs = require('fs');
const path = require('path');

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}
function args(name) {
  const out = [];
  process.argv.forEach((a, i) => { if (a === `--${name}`) out.push(process.argv[i + 1]); });
  return out;
}

require('dotenv').config({ path: arg('env', path.join(__dirname, '..', '.env')) });
const WebSocket = require('ws');
const { readWav } = require('../wav');

const model = arg('model', 'gpt-realtime-translate');
const { sampleRate, samples } = readWav(fs.readFileSync(arg('wav')));
if (sampleRate !== 24000) throw new Error(`need a 24 kHz fixture, got ${sampleRate}`);
const PIECE = 2400; // 100 ms
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function shape(value, depth = 0) {
  if (Array.isArray(value)) return value.slice(0, 2).map((v) => shape(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = depth > 3 ? typeof v : shape(v, depth + 1);
    return out;
  }
  if (typeof value === 'string' && value.length > 60) return `<string ${value.length}>`;
  return value;
}

async function probe(target) {
  const ws = new WebSocket(`wss://api.openai.com/v1/realtime/translations?model=${model}`, {
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      'OpenAI-Safety-Identifier': 'interpreter-probe',
    },
  });
  const shapes = new Map();
  let audioBytes = 0;
  let firstAudioMs = null;
  let inText = '';
  let outText = '';
  const t0 = Date.now();

  const closed = new Promise((resolve, reject) => {
    ws.on('close', (code) => resolve(code));
    ws.on('error', reject);
  });
  ws.on('message', (raw) => {
    const ev = JSON.parse(raw.toString());
    if (!shapes.has(ev.type)) shapes.set(ev.type, shape(ev));
    if (ev.type === 'session.output_audio.delta') {
      const bytes = Buffer.from(ev.delta || '', 'base64').length;
      if (bytes && firstAudioMs === null) firstAudioMs = Date.now() - t0;
      audioBytes += bytes;
    }
    if (ev.type === 'session.output_transcript.delta') outText += ev.delta || '';
    if (ev.type === 'session.input_transcript.delta') inText += ev.delta || '';
    if (ev.type === 'error') console.log('ERROR', JSON.stringify(ev));
  });
  await new Promise((resolve) => ws.once('open', resolve));
  ws.send(JSON.stringify({ type: 'session.update', session: { audio: { output: { language: target } } } }));
  for (let i = 0; i < samples.length; i += PIECE) {
    const piece = samples.subarray(i, i + PIECE);
    ws.send(JSON.stringify({
      type: 'session.input_audio_buffer.append',
      audio: Buffer.from(piece.buffer, piece.byteOffset, piece.byteLength).toString('base64'),
    }));
    await sleep(100);
  }
  const silence = Buffer.alloc(PIECE * 2).toString('base64');
  for (let i = 0; i < 40; i++) {
    ws.send(JSON.stringify({ type: 'session.input_audio_buffer.append', audio: silence }));
    await sleep(100);
  }
  ws.send(JSON.stringify({ type: 'session.close' }));
  const timer = setTimeout(() => ws.close(), 5000);
  const code = await closed;
  clearTimeout(timer);

  console.log(`\n=== ${path.basename(arg('wav'))} → ${target} (close code ${code})`);
  for (const [type, s] of shapes) console.log(type, JSON.stringify(s));
  console.log(`audio: ${(audioBytes / 48000).toFixed(1)} s, first at ${firstAudioMs} ms after connect`);
  console.log(`input transcript:  ${inText}`);
  console.log(`output transcript: ${outText}`);
}

(async () => {
  for (const target of args('target')) await probe(target);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
