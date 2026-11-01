#!/usr/bin/env node
'use strict';
/**
 * Bench for the face-to-face interpreter (step 0 of the spec).
 *
 * Runs on a host with the agent's .env (LiveKit + OpenAI keys) and the voice
 * embed service — DEV. Two bots join a fresh room and talk by a fixed script
 * of synthetic voices; the interpreter runs in this process; the bots measure
 * what reaches them. Writes a markdown report and the raw gate decisions.
 *
 *   node bench/interpreter-bench.js --env ~/taler-id/livekit-agent/.env --pair all --out bench/reports
 *
 * Script, ms from the start:
 *   2000  A: phrase 1            → B hears it translated
 *   10000 B: phrase 1            → A hears it translated
 *   18000 A: one-word reply      21000 B: one-word reply
 *   25000 A: phrase 2, 25300 B: phrase 2 — both at once
 *   35000 B: phrase 3; the same at 0.15 into A's mic (the partner heard by A's phone)
 *   44000 A's mic plays what A heard in 10000–18000 at 0.15 (the earpiece heard by A's phone)
 */
const fs = require('fs');
const path = require('path');

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}
require('dotenv').config({ path: arg('env', path.join(__dirname, '..', '.env')) });

const rtc = require('@livekit/rtc-node');
const { AccessToken } = require('livekit-server-sdk');
const { readWav, rms } = require('../wav');
const { createVoiceEmbedClient } = require('../voice-embed-client');
const { createTranslateSession } = require('../translate-session');
const { chooseEngine, SIMULTANEOUS_TARGETS } = require('../interpreter-langs');
const interpreter = require('../interpreter');
const report = require('./bench-report');

const SR = 24000;
const FRAME = 240; // 10 ms
const FIXTURES = path.join(__dirname, 'fixtures');
const PAIRS = {
  'ru-de': { a: { id: 'bench-a', lang: 'ru', voice: 'ru' }, b: { id: 'bench-b', lang: 'de', voice: 'de' } },
  'ru-sk': { a: { id: 'bench-a', lang: 'ru', voice: 'ru' }, b: { id: 'bench-c', lang: 'sk', voice: 'sk' } },
};
const LEAK_GAIN = 0.15;
const sleep = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms)));

function clip(name) {
  const { sampleRate, samples } = readWav(fs.readFileSync(path.join(FIXTURES, `${name}.wav`)));
  if (sampleRate !== SR) throw new Error(`${name}.wav must be 24 kHz`);
  return samples;
}

async function tokenFor(identity, roomName) {
  const at = new AccessToken(process.env.LIVEKIT_API_KEY, process.env.LIVEKIT_API_SECRET, { identity });
  at.addGrant({ roomJoin: true, room: roomName, canPublish: true, canSubscribe: true });
  return at.toJwt();
}

/** A phone stand-in: plays scheduled clips as its mic and records its own interpretation track. */
async function createBot({ identity, roomName, listenTo }) {
  const room = new rtc.Room();
  const heard = []; // { t, rms, ms } per frame
  const heardPcm = []; // { t, samples }
  const captions = []; // { t, msg }
  room.on(rtc.RoomEvent.TrackSubscribed, (track, publication, participant) => {
    if (participant.identity !== interpreter.AGENT_IDENTITY || publication.name !== listenTo) return;
    (async () => {
      for await (const frame of new rtc.AudioStream(track, SR, 1)) {
        const samples = new Int16Array(frame.data);
        const t = Date.now();
        heard.push({ t, rms: rms(samples), ms: (samples.length / SR) * 1000 });
        heardPcm.push({ t, samples });
      }
    })().catch(() => {});
  });
  room.on(rtc.RoomEvent.DataReceived, (payload, participant, kind, topic) => {
    if (topic !== 'interp') return;
    try {
      captions.push({ t: Date.now(), msg: JSON.parse(Buffer.from(payload).toString()) });
    } catch (_) { /* not ours */ }
  });
  let source;
  try {
    await room.connect(process.env.LIVEKIT_WS_URL || 'ws://localhost:7880', await tokenFor(identity, roomName), {
      autoSubscribe: true,
      dynacast: false,
    });
    source = new rtc.AudioSource(SR, 1);
    const track = rtc.LocalAudioTrack.createAudioTrack('mic', source);
    await room.localParticipant.publishTrack(track, new rtc.TrackPublishOptions({ source: rtc.TrackSource.SOURCE_MICROPHONE }));
  } catch (e) {
    // Joined but not publishing: leave rather than stay in a room on a shared server.
    await room.disconnect().catch(() => {});
    throw e;
  }

  const clips = []; // { at, samples, gain }
  let running = true;
  const pump = (async () => {
    const t0 = Date.now();
    for (let n = 0; running; n++) {
      const now = t0 + n * 10;
      const frame = new Int16Array(FRAME);
      for (const c of clips) {
        const offset = Math.round(((now - c.at) * SR) / 1000);
        if (offset + FRAME <= 0 || offset >= c.samples.length) continue;
        for (let i = 0; i < FRAME; i++) {
          const j = offset + i;
          if (j < 0 || j >= c.samples.length) continue;
          const v = frame[i] + c.samples[j] * c.gain;
          frame[i] = v > 32767 ? 32767 : v < -32768 ? -32768 : v;
        }
      }
      await source.captureFrame(new rtc.AudioFrame(frame, SR, 1, FRAME));
      await sleep(t0 + (n + 1) * 10 - Date.now());
    }
  })();
  // Handled at once: a captureFrame failure would otherwise be an unhandled
  // rejection that kills the process before any cleanup. close() still awaits it.
  pump.catch(() => {});

  return {
    heard,
    captions,
    schedule(at, samples, gain = 1) {
      clips.push({ at, samples, gain });
    },
    recorded(from, to) {
      const parts = heardPcm.filter((p) => p.t >= from && p.t < to).map((p) => p.samples);
      const out = new Int16Array(parts.reduce((n, p) => n + p.length, 0));
      let o = 0;
      for (const p of parts) {
        out.set(p, o);
        o += p.length;
      }
      return out;
    },
    async close() {
      running = false;
      await pump.catch(() => {});
      await room.disconnect();
    },
  };
}

/**
 * Whether gpt-realtime-translate says anything when the speech is already in
 * the target language. Counted in voiced 10 ms frames, not bytes: the session
 * streams audio continuously, silence included (bench/PROBE.md).
 */
async function sameLanguage(input, target) {
  const samples = clip(input);
  let voicedFrames = 0;
  let transcript = '';
  const session = createTranslateSession({
    apiKey: process.env.OPENAI_API_KEY,
    targetLang: target,
    safetyId: 'interpreter-bench',
    onAudio: (pcm) => {
      for (let i = 0; i + 240 <= pcm.length; i += 240) if (rms(pcm.subarray(i, i + 240)) >= 300) voicedFrames += 1;
    },
    onTranslationText: (text) => { transcript += text; },
  });
  try {
    await sleep(1500);
    for (let i = 0; i < samples.length; i += 2400) {
      session.sendAudio(samples.subarray(i, i + 2400));
      await sleep(100);
    }
    for (let i = 0; i < 40; i++) {
      session.sendAudio(new Int16Array(2400));
      await sleep(100);
    }
  } finally {
    // A failed send must not leave the probe's OpenAI session open.
    session.close();
  }
  return { input, target, voicedSeconds: voicedFrames / 100, transcript: transcript.trim() };
}

/**
 * Captions as the phone shows them, one entry per line: a line ends with a
 * final phrase or after a pause of more than 1.2 s between deltas (the
 * client's rule), and is labelled with its second of the script, so each
 * phrase can be checked for its caption and for invented text.
 */
function captionLines(name, bot, T0) {
  const lines = [];
  const open = {}; // role → the line still being written
  for (const c of bot.captions) {
    if (c.msg.type !== 'caption') continue;
    const { role, text, final } = c.msg;
    let line = open[role];
    if (!line || c.t - line.last > 1200) {
      line = { listener: name, role: `${role}, ${((c.t - T0) / 1000).toFixed(1)} с`, text: '', last: c.t };
      lines.push(line);
      open[role] = line;
    }
    line.text += text;
    line.last = c.t;
    if (final) open[role] = null;
  }
  return lines.map(({ listener, role, text }) => ({ listener, role, text: text.trim() }));
}

async function runPair(pairName) {
  const pair = PAIRS[pairName];
  const cfg = { ...interpreter.readConfig(), backendUrl: null, presenceGraceMs: 600_000 };
  const embed = createVoiceEmbedClient({ baseUrl: cfg.embedUrl, timeoutMs: 20_000 });
  const enroll = (voice) => embed.embedWav(fs.readFileSync(path.join(FIXTURES, `${voice}-enroll.wav`)), { windowSec: 3 });
  const printA = await enroll(pair.a.voice);
  const printB = await enroll(pair.b.voice);

  const roomName = `interp-bench-${pairName}-${Date.now()}`;
  const decisions = [];
  await interpreter.startInterpreter(
    {
      sessionId: `bench-${Date.now()}`,
      roomName,
      participants: [
        { userId: pair.a.id, lang: pair.a.lang, embedding: printA },
        { userId: pair.b.id, lang: pair.b.lang, embedding: printB },
      ],
    },
    { config: cfg, onDecision: (speaker, record) => decisions.push({ speaker, ...record }) },
  );
  let a = null;
  let b = null;
  let startedAt;
  let T0;
  const at = (ms) => T0 + ms;
  try {
    a = await createBot({ identity: `${pair.a.id}#bench`, roomName, listenTo: `interp-for-${pair.a.id}` });
    b = await createBot({ identity: `${pair.b.id}#bench`, roomName, listenTo: `interp-for-${pair.b.id}` });
    await sleep(3000); // let subscriptions settle

    startedAt = new Date().toISOString();
    T0 = Date.now();
    const A = (n) => clip(`${pair.a.voice}-${n}`);
    const B = (n) => clip(`${pair.b.voice}-${n}`);

    a.schedule(at(2000), A('1'));
    b.schedule(at(10000), B('1'));
    a.schedule(at(18000), A('short'));
    b.schedule(at(21000), B('short'));
    a.schedule(at(25000), A('2'));
    b.schedule(at(25300), B('2'));
    b.schedule(at(35000), B('3'));
    a.schedule(at(35030), B('3'), LEAK_GAIN);
    await sleep(at(19000) - Date.now());
    a.schedule(at(44000), a.recorded(at(10000), at(18000)), LEAK_GAIN);
    await sleep(at(62000) - Date.now());
  } finally {
    // Each step on its own: a run that dies part-way must not leave the bots
    // or the agent's lanes on the shared DEV server.
    if (a) await a.close().catch((e) => console.warn(`[BENCH] ${pairName}: closing bot a failed: ${e && e.message}`));
    if (b) await b.close().catch((e) => console.warn(`[BENCH] ${pairName}: closing bot b failed: ${e && e.message}`));
    await interpreter.stopInterpreter(roomName).catch((e) => console.warn(`[BENCH] ${pairName}: stopInterpreter failed: ${e && e.message}`));
  }

  const eAB = chooseEngine(pair.a.lang, pair.b.lang);
  const eBA = chooseEngine(pair.b.lang, pair.a.lang);
  const ab = `${pair.a.lang}→${pair.b.lang}`;
  const ba = `${pair.b.lang}→${pair.a.lang}`;
  const latencies = [
    { phrase: `${pair.a.voice}-1`, direction: ab, engine: eAB, ms: report.firstVoicedAfter(b.heard, at(2000), at(10000)) },
    { phrase: `${pair.b.voice}-1`, direction: ba, engine: eBA, ms: report.firstVoicedAfter(a.heard, at(10000), at(18000)) },
    { phrase: `${pair.a.voice}-short`, direction: ab, engine: eAB, ms: report.firstVoicedAfter(b.heard, at(18000), at(21000)) },
    { phrase: `${pair.b.voice}-short`, direction: ba, engine: eBA, ms: report.firstVoicedAfter(a.heard, at(21000), at(25000)) },
    { phrase: `${pair.a.voice}-2 (одновременно)`, direction: ab, engine: eAB, ms: report.firstVoicedAfter(b.heard, at(25000), at(35000)) },
    { phrase: `${pair.b.voice}-2 (одновременно)`, direction: ba, engine: eBA, ms: report.firstVoicedAfter(a.heard, at(25300), at(35000)) },
  ];
  const silentChecks = [
    { situation: `голос собеседника в микрофоне A (×${LEAK_GAIN})`, voicedMs: report.voicedMs(b.heard, at(37000), at(44000)) },
    { situation: `перевод из трубки A в его микрофоне (×${LEAK_GAIN})`, voicedMs: report.voicedMs(b.heard, at(45000), at(58000)) },
  ];

  const scored = (speaker, windows) => decisions.filter((d) => d.speaker === speaker && d.own !== null
    && windows.some(([from, to]) => d.startedAt >= at(from) && d.startedAt < at(to)));
  const ownA = scored(pair.a.id, [[2000, 10000], [18000, 21000], [25000, 35000]]);
  const ownB = scored(pair.b.id, [[10000, 18000], [21000, 25000], [25000, 35000]]);
  const leakA = scored(pair.a.id, [[35000, 44000]]);
  const echoA = scored(pair.a.id, [[44000, 58000]]);

  const sameLanguageChecks = [];
  if (SIMULTANEOUS_TARGETS.has(pair.b.lang)) sameLanguageChecks.push(await sameLanguage(`${pair.b.voice}-1`, pair.b.lang));
  if (SIMULTANEOUS_TARGETS.has(pair.a.lang)) sameLanguageChecks.push(await sameLanguage(`${pair.a.voice}-1`, pair.a.lang));

  return {
    pair: pairName,
    startedAt,
    config: cfg,
    latencies,
    silentChecks,
    scoreGroups: [
      { group: `свой голос ${pair.a.id}`, scores: ownA },
      { group: `свой голос ${pair.b.id}`, scores: ownB },
      { group: `собеседник в микрофоне ${pair.a.id}`, scores: leakA },
      { group: `перевод из трубки в микрофоне ${pair.a.id}`, scores: echoA },
    ],
    suggestion: report.suggestThresholds([...ownA, ...ownB], [...leakA, ...echoA]),
    captions: [...captionLines(pair.a.id, a, T0), ...captionLines(pair.b.id, b, T0)],
    sameLanguage: sameLanguageChecks,
    embedLatency: report.summarize(decisions.filter((d) => !d.failOpen).map((d) => d.latencyMs)),
    failOpen: decisions.filter((d) => d.failOpen).length,
    decisions,
  };
}

(async () => {
  const which = arg('pair', 'all');
  const pairs = which === 'all' ? Object.keys(PAIRS) : [which];
  const outDir = arg('out', path.join(__dirname, 'reports'));
  fs.mkdirSync(outDir, { recursive: true });
  for (const p of pairs) {
    const result = await runPair(p);
    const md = report.renderReport(result);
    const base = path.join(outDir, `${result.startedAt.slice(0, 16).replace(/[:T]/g, '-')}-${p}`);
    fs.writeFileSync(`${base}.md`, md);
    fs.writeFileSync(`${base}-decisions.csv`, [
      'speaker,index,startedAt,own,other,pass,failOpen,latencyMs',
      ...result.decisions.map((d) => [d.speaker, d.index, d.startedAt, d.own, d.other, d.pass, d.failOpen, d.latencyMs].join(',')),
    ].join('\n'));
    console.log(md);
  }
  process.exit(0); // rtc-node keeps native handles open
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
