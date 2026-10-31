# Разговор с переводом — план 1: агент и стенд

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Агент `livekit-ai-agent` ведёт разговор с переводом для двоих. В нём:
- фильтр голоса по двум образцам;
- синхронный (`gpt-realtime-translate`) и фразовый движки;
- отдельная дорожка перевода на каждого слушателя;
- субтитры по data-каналу.

Стенд на DEV замеряет задержку, утечки и качество и подбирает пороги сверки.

**Architecture:** Новый `livekit-agent/interpreter.js` работает в том же процессе, что и переводчик звонков. Он собран из небольших модулей с узкими интерфейсами — фильтр, движки, маршрутизация, присутствие, сообщения, колбэк, HTTP-ручки — и у каждого свои тесты на `node:test`. `createRealtimeSession` вместе с помощниками переезжает из `translator.js` в отдельные модули, поведение не меняется. Стенд — скрипт в `livekit-agent/bench/`: на DEV он заводит двух ботов в комнату и запускает агента в своём процессе.

**Tech Stack:**
- Node 20 на серверах, Node 26 локально; тесты на `node:test`.
- `@livekit/rtc-node` 0.13.24, `livekit-server-sdk` 2.15, `ws` 8, `express` 5.
- Глобальные `fetch` / `FormData` / `Blob`.
- OpenAI Realtime: `gpt-realtime-translate` и `gpt-realtime-2025-08-28`.
- `voice-embed-service` (ECAPA) на `:18082`.
- macOS `say` и `afconvert` для фикстур.

**Спека:** `docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md`

**Это план 1 из 3.** План 2 — бэкенд `src/interpreter/`, биллинг и сквозной набор. План 3 — мобилка. Оба пишутся после отчёта стенда (задача 21): стенд может сдвинуть пороги сверки или выбор движка.

**Правила для исполнителя:**
- Работа идёт в worktree `/Users/dmitry/taler-id/.worktrees/interpreter`, ветка `feat/interpreter`. Все команды выполняются из `livekit-agent/` этого worktree, если не сказано иное.
- Тесты запускаются `npm test` (= `node --test`) из `livekit-agent/`.
  - Итог локально (Node 26) печатается как `ℹ pass N`, на серверах (Node 20) — как `# pass N`.
  - База до начала работы — 48 тестов, все зелёные.
- Нельзя запускать `node --test` из корня репозитория и нельзя делать `require('./index')` или `require('./translator')` в тестах. Оба файла при загрузке читают ключи LiveKit и без них бросают исключение.
- Код агента — CommonJS. Комментарии в коде на английском, как в соседних файлах, и объясняют «почему», а не «что».
- Каждый коммит — с двумя `-m`: сообщение и `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.
- Ветку не пушить без явного «да» пользователя.
- На DEV код попадает tar-конвейером через бот-сервер (задачи 3 и 20).
  - Чекаут `~/taler-id` на DEV не трогать: из него работает живой агент.
  - Агент на DEV читает `~/taler-id/livekit-agent/.env`. Им же пользуются проба и стенд.
- Ключи OpenAI и LiveKit на экран не печатать.

## Уточнения спеки, внесённые вместе с этим планом

Спека уже синхронизирована в том же коммите, что и план.
1. **Задержка фильтра.** Её задаёт длина куска (`INTERPRETER_GATE_CHUNK_MS`, 500), а не отдельная настройка. Кусок выпускается, когда пришёл следующий, поэтому задержка ≈ два куска.
2. **Ресемплинг.** До 16 кГц сервис сверки приводит звук сам. Агент шлёт WAV на родных 24 кГц, как это делает realtime-прокси.
3. **Тишина.** Куски ниже порога речи уходят нулями: тихий голос соседа не должен попасть в перевод.
4. **Строки субтитров** синхронного движка разбивает клиент, по паузе в дельтах.
5. **Фразовый движок.** `createRealtimeSession` переезжает в `realtime-phrase-session.js`; рядом появляются `lang-names.js` и `audio-out.js`.
6. **`.env` агента.** На DEV это `~/taler-id/livekit-agent/.env`, а не `~/taler-id/.env`.
7. **Таймер присутствия** настраивается: `INTERPRETER_PRESENCE_GRACE_MS` (60 000).

## Карта файлов

Все пути — внутри `livekit-agent/`.

| Файл | Что делает |
|---|---|
| `lang-names.js` (новый, перенос) | `LANG_NAMES`, `SUPPORTED_LANGS`, `LANG_VOICES` |
| `audio-out.js` (новый, перенос) | `applyGain`, `createFrameQueue` |
| `realtime-phrase-session.js` (новый, перенос + опции) | фразовый движок OpenAI Realtime |
| `translator.js` (правка) | импортирует перенесённое, поведение прежнее |
| `wav.js` | WAV туда-обратно, RMS |
| `interpreter-langs.js` | какой движок для пары языков |
| `voice-embed-client.js` | клиент сервиса сверки и `cosine` |
| `voiceprint-gate.js` | фильтр голоса |
| `translate-session.js` | синхронный движок и его самопроверка |
| `phrase-session.js` | фразовый движок в общем интерфейсе движков |
| `reconnecting-engine.js` | переподключения движка |
| `interpreter-routing.js` | два направления из двух участников |
| `presence-watch.js` | кто в комнате, таймер отсутствия |
| `interpreter-messages.js` | сообщения data-канала `interp` |
| `backend-callback.js` | `agent-ended` на бэкенд |
| `interpreter.js` | сессия разговора в комнате LiveKit |
| `interpreter-routes.js` | HTTP-ручки под секретом |
| `index.js` (правка) | подключает ручки |
| `testing/fake-ws.js` | фейковый сокет для тестов (не тест: имя не подходит под шаблоны `node --test`) |
| `bench/make-fixtures.sh`, `bench/fixtures/*.wav` | синтезированные голоса ru / de / sk |
| `bench/probe-translate.js`, `bench/PROBE.md` | проба событий `gpt-realtime-translate` |
| `bench/bench-report.js` (+ тест) | статистика и страница отчёта |
| `bench/interpreter-bench.js` | стенд |
| `bench/reports/*` | отчёты стенда |

**Общий интерфейс движков** (`translate-session.js`, `phrase-session.js`):

```
create…({ apiKey, model, sourceLang, targetLang, safetyId, wsFactory,
          onAudio(int16), onTranslationText(text, final), onSourceText(text, final),
          onReady(), onClose({ unexpected, code }) })
  → { sendAudio(int16 /* PCM16 mono 24 kHz */), close() }
```

---

### Task 0: База

**Files:** нет изменений.

- [ ] **Step 1: Проверить ветку и зависимости**

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter && git branch --show-current
cd livekit-agent && npm ci --loglevel=error && npm test 2>&1 | tail -8
```

Ожидается: ветка `feat/interpreter`, `ℹ tests 48`, `ℹ pass 48`, `ℹ fail 0`.

---

### Task 1: `wav.js` — WAV и RMS

**Files:**
- Create: `livekit-agent/wav.js`
- Test: `livekit-agent/wav.test.js`

- [ ] **Step 1: Написать падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { wrapWavMono, readWav, rms } = require('./wav');

test('a wrapped buffer reads back as the same samples and rate', () => {
  const samples = Int16Array.from([0, 1000, -1000, 32767, -32768]);
  const wav = wrapWavMono(samples, 24000);
  assert.strictEqual(wav.toString('ascii', 0, 4), 'RIFF');
  const back = readWav(wav);
  assert.strictEqual(back.sampleRate, 24000);
  assert.deepStrictEqual(Array.from(back.samples), Array.from(samples));
});

test('the header carries the real sample rate', () => {
  const wav = wrapWavMono(new Int16Array(10), 16000);
  assert.strictEqual(wav.readUInt32LE(24), 16000);
  assert.strictEqual(wav.readUInt32LE(28), 32000);
});

test('a subarray is wrapped from its own offset, not from the start of its buffer', () => {
  const big = Int16Array.from([1, 2, 3, 4, 5, 6]);
  const back = readWav(wrapWavMono(big.subarray(2, 4), 8000));
  assert.deepStrictEqual(Array.from(back.samples), [3, 4]);
});

test('extra chunks before data are skipped and stereo is averaged', () => {
  const fmt = Buffer.alloc(24);
  fmt.write('fmt ', 0, 'ascii');
  fmt.writeUInt32LE(16, 4);
  fmt.writeUInt16LE(1, 8); // PCM
  fmt.writeUInt16LE(2, 10); // stereo
  fmt.writeUInt32LE(24000, 12);
  fmt.writeUInt32LE(96000, 16);
  fmt.writeUInt16LE(4, 20);
  fmt.writeUInt16LE(16, 22);
  const fllr = Buffer.alloc(12);
  fllr.write('FLLR', 0, 'ascii');
  fllr.writeUInt32LE(4, 4);
  const pcm = Buffer.alloc(8);
  pcm.writeInt16LE(100, 0);
  pcm.writeInt16LE(300, 2);
  pcm.writeInt16LE(-50, 4);
  pcm.writeInt16LE(-150, 6);
  const dataHeader = Buffer.alloc(8);
  dataHeader.write('data', 0, 'ascii');
  dataHeader.writeUInt32LE(8, 4);
  const body = Buffer.concat([Buffer.from('WAVE', 'ascii'), fmt, fllr, dataHeader, pcm]);
  const riff = Buffer.concat([Buffer.from('RIFF', 'ascii'), Buffer.alloc(4), body]);
  riff.writeUInt32LE(body.length, 4);

  const { sampleRate, samples } = readWav(riff);
  assert.strictEqual(sampleRate, 24000);
  assert.deepStrictEqual(Array.from(samples), [200, -100]);
});

test('WAVE_FORMAT_EXTENSIBLE with PCM inside reads like plain PCM', () => {
  const plain = wrapWavMono(Int16Array.from([7, -7]), 24000);
  const fmt = Buffer.alloc(8 + 40);
  fmt.write('fmt ', 0, 'ascii');
  fmt.writeUInt32LE(40, 4);
  fmt.writeUInt16LE(0xfffe, 8); // WAVE_FORMAT_EXTENSIBLE
  fmt.writeUInt16LE(1, 10);
  fmt.writeUInt32LE(24000, 12);
  fmt.writeUInt32LE(48000, 16);
  fmt.writeUInt16LE(2, 20);
  fmt.writeUInt16LE(16, 22);
  fmt.writeUInt16LE(22, 24); // cbSize
  fmt.writeUInt16LE(16, 26); // valid bits
  fmt.writeUInt32LE(4, 28); // channel mask
  fmt.writeUInt16LE(1, 32); // SubFormat GUID starts with the PCM code
  const body = Buffer.concat([Buffer.from('WAVE', 'ascii'), fmt, plain.subarray(36)]);
  const riff = Buffer.concat([Buffer.from('RIFF', 'ascii'), Buffer.alloc(4), body]);
  riff.writeUInt32LE(body.length, 4);
  assert.deepStrictEqual(Array.from(readWav(riff).samples), [7, -7]);
});

test('anything but PCM16 is refused', () => {
  const wav = wrapWavMono(new Int16Array(4), 24000);
  wav.writeUInt16LE(3, 20); // IEEE float
  assert.throws(() => readWav(wav), /need PCM16/);
});

test('rms is 0 for silence and the magnitude for a constant', () => {
  assert.strictEqual(rms(new Int16Array(100)), 0);
  assert.strictEqual(rms(new Int16Array(100).fill(-2000)), 2000);
  assert.strictEqual(rms(new Int16Array(0)), 0);
});
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `node --test wav.test.js`
Expected: FAIL — `Cannot find module './wav'`.

- [ ] **Step 3: Реализовать**

```js
'use strict';
/**
 * Just enough WAV for the interpreter: wrap PCM16 mono for the voice-embed
 * service, read the bench's fixtures, and the RMS level used as the cheap
 * "is anyone talking" test.
 *
 * The sample rate in the header must be the real one. torchaudio trusts it:
 * a 24 kHz stream labelled 16 kHz plays 1.5x slow and its embedding matches
 * nobody (the voice gate learned this the hard way, see
 * src/voice-gate/pcm-window.ts).
 */

function wrapWavMono(int16, sampleRate) {
  const pcm = Buffer.from(int16.buffer, int16.byteOffset, int16.byteLength);
  const header = Buffer.alloc(44);
  header.write('RIFF', 0, 'ascii');
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write('WAVE', 8, 'ascii');
  header.write('fmt ', 12, 'ascii');
  header.writeUInt32LE(16, 16); // fmt chunk size
  header.writeUInt16LE(1, 20); // PCM
  header.writeUInt16LE(1, 22); // mono
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(sampleRate * 2, 28); // byte rate
  header.writeUInt16LE(2, 32); // block align
  header.writeUInt16LE(16, 34); // bits per sample
  header.write('data', 36, 'ascii');
  header.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([header, pcm]);
}

/** PCM16 WAV → mono samples. Stereo is averaged; other formats are refused. */
function readWav(buffer) {
  if (buffer.toString('ascii', 0, 4) !== 'RIFF' || buffer.toString('ascii', 8, 12) !== 'WAVE') {
    throw new Error('not a RIFF/WAVE file');
  }
  let fmt = null;
  let data = null;
  let offset = 12;
  // afconvert writes extra chunks (FLLR padding and the like): walk them all.
  while (offset + 8 <= buffer.length) {
    const id = buffer.toString('ascii', offset, offset + 4);
    const size = buffer.readUInt32LE(offset + 4);
    const body = offset + 8;
    if (id === 'fmt ') {
      let format = buffer.readUInt16LE(body);
      // WAVE_FORMAT_EXTENSIBLE keeps the real format code at the start of
      // its SubFormat GUID; afconvert writes it for some layouts.
      if (format === 0xfffe && size >= 26) format = buffer.readUInt16LE(body + 24);
      fmt = {
        format,
        channels: buffer.readUInt16LE(body + 2),
        sampleRate: buffer.readUInt32LE(body + 4),
        bitsPerSample: buffer.readUInt16LE(body + 14),
      };
    } else if (id === 'data') {
      data = buffer.subarray(body, Math.min(body + size, buffer.length));
    }
    offset = body + size + (size % 2);
  }
  if (!fmt || !data) throw new Error('WAV without a fmt or data chunk');
  if (fmt.format !== 1 || fmt.bitsPerSample !== 16) {
    throw new Error(`unsupported WAV (format ${fmt.format}, ${fmt.bitsPerSample} bit): need PCM16`);
  }
  const frames = Math.floor(data.length / (2 * fmt.channels));
  const samples = new Int16Array(frames);
  for (let i = 0; i < frames; i++) {
    let sum = 0;
    for (let c = 0; c < fmt.channels; c++) sum += data.readInt16LE((i * fmt.channels + c) * 2);
    samples[i] = Math.round(sum / fmt.channels);
  }
  return { sampleRate: fmt.sampleRate, samples };
}

/** Root-mean-square level of PCM16 samples, 0–32768. */
function rms(int16) {
  if (int16.length === 0) return 0;
  let sumSq = 0;
  for (let i = 0; i < int16.length; i++) sumSq += int16[i] * int16[i];
  return Math.sqrt(sumSq / int16.length);
}

module.exports = { wrapWavMono, readWav, rms };
```

- [ ] **Step 4: Тест проходит**

Run: `node --test wav.test.js`
Expected: 7 тестов, `ℹ pass 7`.

- [ ] **Step 5: Коммит**

```bash
git add wav.js wav.test.js
git commit -m "feat(interpreter): wav.js — WAV для сервиса сверки и фикстур, RMS" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Фикстуры голосов

Синтезированные голоса для пробы и стенда. Генерируются один раз на маке и коммитятся.

**Files:**
- Create: `livekit-agent/bench/make-fixtures.sh`
- Create: `livekit-agent/bench/fixtures/{ru,de,sk}-{1,2,3,short,enroll}.wav` (15 файлов, их создаёт скрипт)

- [ ] **Step 1: Написать скрипт**

```bash
#!/usr/bin/env bash
# Synthetic voices for bench/probe-translate.js and bench/interpreter-bench.js.
# macOS only (say, afconvert). The WAVs are committed; rerun only to change a
# text. Every voice gets the same set: three phrases, a one-word reply, and
# ~25 s of speech for its voice print.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p fixtures
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

render() { # <voice> <file-stem> <text>
  say -v "$1" -o "$tmp/$2.aiff" "$3"
  afconvert -f WAVE -d LEI16@24000 -c 1 "$tmp/$2.aiff" "fixtures/$2.wav"
}

render Milena ru-1 "Добрый день. Я хотел бы обсудить условия поставки на следующий месяц."
render Milena ru-2 "Цена нас устраивает, но сроки нужно сократить до двух недель."
render Milena ru-3 "Пожалуйста, пришлите нам заказ по электронной почте."
render Milena ru-short "Да."
render Milena ru-enroll "Меня зовут Милена. Я работаю в отделе закупок и каждый день разговариваю с поставщиками из разных стран. Обычно мы обсуждаем цены, сроки доставки, качество товара и условия оплаты. Иногда разговор затягивается, потому что нужно уточнить много деталей, но в итоге мы всегда находим решение, которое устраивает обе стороны. Вечером я люблю гулять в парке и читать книги о путешествиях."

render Anna de-1 "Guten Tag. Wir können die Ware bis Ende des Monats liefern."
render Anna de-2 "Der Preis ist fest, aber über die Lieferzeit können wir sprechen."
render Anna de-3 "Bitte schicken Sie uns die Bestellung per E-Mail."
render Anna de-short "Ja."
render Anna de-enroll "Mein Name ist Anna. Ich arbeite im Vertrieb und spreche jeden Tag mit Kunden aus verschiedenen Ländern. Meistens geht es um Preise, Lieferzeiten, die Qualität der Ware und die Zahlungsbedingungen. Manchmal dauert ein Gespräch länger, weil viele Details zu klären sind, aber am Ende finden wir immer eine Lösung, die für beide Seiten passt. Am Abend gehe ich gern im Park spazieren und lese Bücher über Reisen."

render Laura sk-1 "Dobrý deň. Tovar môžeme dodať do konca mesiaca."
render Laura sk-2 "Cena je pevná, ale o termíne dodania sa môžeme porozprávať."
render Laura sk-3 "Prosím, pošlite nám objednávku e-mailom."
render Laura sk-short "Áno."
render Laura sk-enroll "Volám sa Laura. Pracujem v obchodnom oddelení a každý deň hovorím so zákazníkmi z rôznych krajín. Väčšinou sa rozprávame o cenách, termínoch dodania, kvalite tovaru a platobných podmienkach. Niekedy rozhovor trvá dlhšie, pretože treba vyjasniť veľa detailov, ale nakoniec vždy nájdeme riešenie, ktoré vyhovuje obom stranám. Večer sa rada prechádzam v parku a čítam knihy o cestovaní."
```

- [ ] **Step 2: Сгенерировать фикстуры**

```bash
chmod +x bench/make-fixtures.sh && bench/make-fixtures.sh && ls bench/fixtures | wc -l
```

Ожидается: `15`.

- [ ] **Step 3: Проверить формат и длительность через `wav.js`**

```bash
node -e "
const fs = require('fs'); const { readWav } = require('./wav');
for (const f of fs.readdirSync('bench/fixtures').sort()) {
  const { sampleRate, samples } = readWav(fs.readFileSync('bench/fixtures/' + f));
  const sec = samples.length / sampleRate;
  console.log(f.padEnd(16), sampleRate, sec.toFixed(1) + ' s');
  if (sampleRate !== 24000) throw new Error(f + ': not 24 kHz');
  if (f.includes('enroll') && sec < 15) throw new Error(f + ': shorter than 15 s');
}"
```

Ожидается: 15 строк, у всех `24000`. У `*-enroll.wav` — 15 с и больше, у `*-short.wav` — меньше секунды.
- Если `*-enroll.wav` короче 15 с, дописать в его текст ещё одно предложение.

- [ ] **Step 4: Коммит**

```bash
git add bench/make-fixtures.sh bench/fixtures
git commit -m "test(interpreter): синтезированные голоса ru/de/sk для пробы и стенда" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Проба `gpt-realtime-translate` на DEV

Документация OpenAI называет события, но не их поля. Проба фиксирует четыре вещи:
- точные имена полей;
- шлёт ли сервер `session.updated`;
- задержку первого звука;
- что модель делает с речью, которая уже на языке перевода.

От результата зависят задачи 10 и 20.

**Files:**
- Create: `livekit-agent/bench/probe-translate.js`
- Create: `livekit-agent/bench/PROBE.md`

- [ ] **Step 1: Написать пробу**

```js
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
```

- [ ] **Step 2: Доставить каталог агента на DEV**

Из корня worktree, на маке:

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter
COPYFILE_DISABLE=1 tar --no-mac-metadata -czf - --exclude node_modules --exclude bench/reports -C livekit-agent . \
  | ssh dvolkov@77.73.131.137 'ssh dev-backend "rm -rf ~/interp-bench && mkdir -p ~/interp-bench && tar xzf - -C ~/interp-bench && cd ~/interp-bench && npm ci --loglevel=error >/dev/null && echo delivered"'
```

Ожидается: `delivered`.

- [ ] **Step 3: Запустить пробу**

```bash
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/interp-bench && node bench/probe-translate.js --env ~/taler-id/livekit-agent/.env --wav bench/fixtures/ru-1.wav --target de --target ru && node bench/probe-translate.js --env ~/taler-id/livekit-agent/.env --wav bench/fixtures/de-1.wav --target de"' 2>&1 | tee livekit-agent/bench/probe-output.txt
```

Ожидается три блока `=== … → …`.
- Для `ru-1 → de` должен быть немецкий выходной транскрипт и ненулевой звук.
- Если сессия не открылась (401, 403 или 404 на модель), **остановиться и сообщить пользователю**: без доступа к модели выбор движка из спеки не работает.

- [ ] **Step 4: Записать выводы в `bench/PROBE.md`**

Перенести вывод из `probe-output.txt` в `bench/PROBE.md` внутри блока кода, а под ним ответить на пять вопросов:

```markdown
# Проба gpt-realtime-translate, 2026-10-31, DEV

<вывод пробы>

## Выводы
1. Поле с base64-звуком в `session.output_audio.delta`: `delta` / другое: …
2. Поле с текстом в `session.output_transcript.delta` и `session.input_transcript.delta`: …
3. Шлёт ли сервер `session.updated` после `session.update`: да / нет.
4. Первый звук перевода ru→de: … мс после подключения.
5. Речь уже на языке перевода (ru→ru, de→de): … с звука на выходе (0 — модель молчит).
```

Затем `rm livekit-agent/bench/probe-output.txt`.

Если в п. 1–2 поле называется не `delta`, это учитывается в задаче 10, шаг 4.

- [ ] **Step 5: Коммит**

```bash
git add bench/probe-translate.js bench/PROBE.md
git commit -m "test(interpreter): проба событий gpt-realtime-translate на DEV" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Перенос фразового движка из `translator.js`

Чистый перенос без смены поведения. Новое только одно: `createRealtimeSession` принимает пятым аргументом `opts` с `model` / `apiKey` / `wsFactory`, чтобы его можно было тестировать. Сначала пишутся характеризующие тесты: они фиксируют то, что переводчик в звонках шлёт в OpenAI сегодня.

**Files:**
- Create: `livekit-agent/testing/fake-ws.js`
- Create: `livekit-agent/lang-names.js`, `livekit-agent/audio-out.js`, `livekit-agent/realtime-phrase-session.js`
- Modify: `livekit-agent/translator.js` (строки 10–316, верх файла до `// ─── Helpers ───`)
- Test: `livekit-agent/realtime-phrase-session.test.js`, `livekit-agent/audio-out.test.js`

- [ ] **Step 1: Фейковый сокет для тестов**

`testing/fake-ws.js`:

```js
'use strict';
// Stand-in for a `ws` WebSocket in unit tests. It records what the code under
// test sends (parsed back from JSON) and lets the test play the server.
// readyState follows the `ws` constants: 0 CONNECTING, 1 OPEN, 3 CLOSED.
const { EventEmitter } = require('events');

class FakeWs extends EventEmitter {
  constructor(url, options) {
    super();
    this.url = url;
    this.options = options;
    this.sent = [];
    this.readyState = 0;
  }

  send(data) {
    this.sent.push(JSON.parse(data));
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.emit('close', 1000, Buffer.alloc(0));
  }

  // ── the test's side ──

  open() {
    this.readyState = 1;
    this.emit('open');
  }

  serverSends(event) {
    this.emit('message', Buffer.from(JSON.stringify(event)));
  }

  serverCloses(code = 1006) {
    this.readyState = 3;
    this.emit('close', code, Buffer.alloc(0));
  }

  sentOfType(type) {
    return this.sent.filter((m) => m.type === type);
  }
}

/** A wsFactory that keeps every socket it made, newest last. */
function fakeWsFactory() {
  const sockets = [];
  const factory = (url, options) => {
    const ws = new FakeWs(url, options);
    sockets.push(ws);
    return ws;
  };
  return { factory, sockets, last: () => sockets[sockets.length - 1] };
}

module.exports = { FakeWs, fakeWsFactory };
```

- [ ] **Step 2: Характеризующие тесты (падают — модулей ещё нет)**

`realtime-phrase-session.test.js`:

```js
// Run with: node --test  (from livekit-agent/)
//
// createRealtimeSession moved out of translator.js. These pin what the
// in-call translator has always sent to OpenAI, so neither the move nor the
// options the interpreter adds can change it unnoticed.
const test = require('node:test');
const assert = require('node:assert');
const { fakeWsFactory } = require('./testing/fake-ws');
const { createRealtimeSession } = require('./realtime-phrase-session');

function open(source, target, opts = {}) {
  const { factory, last } = fakeWsFactory();
  const audio = [];
  const ws = createRealtimeSession(source, target, (pcm) => audio.push(pcm), () => {}, {
    wsFactory: factory,
    apiKey: 'test-key',
    ...opts,
  });
  const fake = last();
  fake.open();
  return { ws, fake, audio };
}

test('called the old way it opens gpt-realtime-mini with the key from the environment', () => {
  const saved = process.env.OPENAI_API_KEY;
  process.env.OPENAI_API_KEY = 'env-key';
  try {
    const { factory, last } = fakeWsFactory();
    createRealtimeSession('auto', 'en', () => {}, () => {}, { wsFactory: factory });
    assert.strictEqual(last().url, 'wss://api.openai.com/v1/realtime?model=gpt-realtime-mini');
    assert.deepStrictEqual(last().options, { headers: { Authorization: 'Bearer env-key' } });
  } finally {
    if (saved === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = saved;
  }
});

test('the session.update the in-call translator sends is unchanged', () => {
  const { fake } = open('auto', 'en');
  const [update] = fake.sentOfType('session.update');
  assert.strictEqual(update.session.type, 'realtime');
  assert.deepStrictEqual(update.session.output_modalities, ['audio']);
  assert.deepStrictEqual(update.session.audio, {
    input: {
      format: { type: 'audio/pcm', rate: 24000 },
      transcription: { model: 'whisper-1' },
      turn_detection: null,
    },
    output: { format: { type: 'audio/pcm', rate: 24000 }, voice: 'echo' },
  });
  const lines = update.session.instructions.split('\n');
  assert.strictEqual(lines[0], 'TRANSLATE ONLY. OUTPUT NOTHING EXCEPT THE TRANSLATION.');
  assert.ok(lines.includes(
    'You are a machine that converts spoken audio into spoken English. You are NOT an assistant. You do NOT think. You do NOT respond. You ONLY translate.',
  ));
  assert.ok(lines.includes('- Speech already in English → output NOTHING'));
});

test('a known source language goes into the instructions', () => {
  const { fake } = open('ru', 'sk');
  const { instructions } = fake.sentOfType('session.update')[0].session;
  assert.ok(instructions.includes('converts spoken Russian audio into spoken Slovak'));
  assert.ok(instructions.includes('- Speech NOT in Russian → output NOTHING'));
});

test('another model can be asked for', () => {
  const { fake } = open('ru', 'sk', { model: 'gpt-realtime-2025-08-28' });
  assert.strictEqual(fake.url, 'wss://api.openai.com/v1/realtime?model=gpt-realtime-2025-08-28');
});

test('audio sent before the session is configured waits for session.updated', () => {
  const { factory, last } = fakeWsFactory();
  const ws = createRealtimeSession('ru', 'de', () => {}, () => {}, { wsFactory: factory, apiKey: 'k' });
  const fake = last();
  ws.sendAudio(Buffer.alloc(960).toString('base64')); // still CONNECTING
  fake.open();
  assert.strictEqual(fake.sentOfType('input_audio_buffer.append').length, 0);
  fake.serverSends({ type: 'session.updated' });
  assert.strictEqual(fake.sentOfType('input_audio_buffer.append').length, 1);
});

test('translated audio deltas reach the callback as bytes', () => {
  const { fake, audio } = open('ru', 'de');
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'response.output_audio.delta', delta: Buffer.from([1, 0, 2, 0]).toString('base64') });
  assert.strictEqual(audio.length, 1);
  assert.deepStrictEqual(Array.from(audio[0]), [1, 0, 2, 0]);
});
```

`audio-out.test.js`:

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { applyGain, createFrameQueue } = require('./audio-out');

test('gain 1 leaves the samples alone', () => {
  const s = Int16Array.from([1, -2, 3]);
  assert.strictEqual(applyGain(s, 1), s);
  assert.deepStrictEqual(Array.from(s), [1, -2, 3]);
});

test('gain scales in place and clamps at full scale', () => {
  const s = Int16Array.from([1000, -1000, 30000, -30000]);
  applyGain(s, 2);
  assert.deepStrictEqual(Array.from(s), [2000, -2000, 32767, -32768]);
});

test('frames reach captureFrame one at a time, in order', async () => {
  const started = [];
  let active = 0;
  let maxActive = 0;
  const source = {
    async captureFrame(frame) {
      active += 1;
      maxActive = Math.max(maxActive, active);
      started.push(frame);
      await new Promise((r) => setImmediate(r));
      active -= 1;
    },
  };
  const queue = createFrameQueue(source, 'en');
  queue.push('a');
  queue.push('b');
  queue.push('c');
  await new Promise((r) => setTimeout(r, 20));
  assert.deepStrictEqual(started, ['a', 'b', 'c']);
  assert.strictEqual(maxActive, 1);
});
```

Run: `node --test realtime-phrase-session.test.js audio-out.test.js`
Expected: FAIL — `Cannot find module './realtime-phrase-session'` / `'./audio-out'`.

- [ ] **Step 3: `lang-names.js` — перенос без изменений**

```js
// Languages the agent's translators know, by ISO 639-1 code. Moved out of
// translator.js unchanged so the face-to-face interpreter shares them.

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
const LANG_VOICES = { ru: 'alloy', en: 'echo', de: 'ash', it: 'coral', es: 'sage', zh: 'alloy', ar: 'shimmer', ja: 'ballad' };

module.exports = { LANG_NAMES, SUPPORTED_LANGS, LANG_VOICES };
```

- [ ] **Step 4: `audio-out.js` — перенос без изменений**

```js
// Getting translated PCM onto a LiveKit track. Moved out of translator.js
// unchanged: the face-to-face interpreter publishes through the same path.

// In-place linear gain with int16 clamping (soft-limit at full scale).
function applyGain(int16, gain) {
  if (gain === 1) return int16;
  for (let i = 0; i < int16.length; i++) {
    const v = int16[i] * gain;
    int16[i] = v > 32767 ? 32767 : v < -32768 ? -32768 : v | 0;
  }
  return int16;
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

module.exports = { applyGain, createFrameQueue };
```

- [ ] **Step 5: `realtime-phrase-session.js` — перенос с `opts` для модели, ключа и сокета**

```js
/**
 * One OpenAI Realtime session that renders one person's speech, phrase by
 * phrase, into one target language.
 *
 * Moved out of translator.js so the face-to-face interpreter can run the same
 * engine for the pairs gpt-realtime-translate cannot speak. Called the old way
 * — createRealtimeSession(source, target, onAudio, onError) — it does exactly
 * what it did inside the in-call translator. `opts` adds:
 *   model      Realtime model (default gpt-realtime-mini, as before)
 *   apiKey     default process.env.OPENAI_API_KEY
 *   wsFactory  (url, options) => socket; tests pass a fake
 */
const WebSocket = require('ws');
const { createTurnTaker } = require('./translator-turns');
const { LANG_NAMES, LANG_VOICES } = require('./lang-names');

const DEFAULT_MODEL = 'gpt-realtime-mini';

// Common Whisper hallucination patterns (repeated phrases, YouTube-like text)
const HALLUCINATION_RE = /^((.{2,20})\s*){3,}$|구독과\s*좋아요|ご視聴|チャンネル登録|请订阅|thank you for watching/i;

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
  console.log(`[TRANSLATOR] Opening WS for ${tag}`);

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

  ws.on('open', () => {
    console.log(`[TRANSLATOR] WS opened for ${tag}`);
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
        console.log(`[TRANSLATOR] [${tag}] event: ${event.type}`);
      }

      if (event.type === 'session.updated') {
        ready = true;
        console.log(`[TRANSLATOR] Session configured for ${tag}`);
        for (const msg of pendingMessages) ws.send(msg);
        pendingMessages.length = 0;
      }

      if (event.type === 'response.created') {
        ws._turns.responseCreated();
      }

      if (event.type === 'response.output_audio.delta' && event.delta) {
        if (!ws._audioStartLogged) {
          ws._audioStartLogged = true;
          console.log(`[TRANSLATOR] [${tag}] >>> AUDIO OUTPUT STARTED`);
        }
        onAudioDelta(Buffer.from(event.delta, 'base64'));
      }

      if (event.type === 'response.output_audio.done') {
        ws._audioStartLogged = false;
      }

      if (event.type === 'response.done') {
        const status = event.response?.status;
        console.log(`[TRANSLATOR] [${tag}] response.done status=${status}`);
        // Turns cut while this one was speaking are already committed; this
        // hands the next of them over.
        ws._turns.responseDone();
      }

      if (event.type === 'conversation.item.input_audio_transcription.completed' && event.transcript) {
        const heard = event.transcript.trim();
        console.log(`[TRANSLATOR] [${tag}] heard: "${heard}"`);
        if (isHallucination(heard)) console.log(`[TRANSLATOR] [${tag}] FILTERED: hallucination`);
      }

      if (event.type === 'response.output_audio_transcript.done' && event.transcript) {
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
    ws._turns.reset();
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
      console.log(`[TRANSLATOR] [${tag}] Committing (${reason})`);
      ws.send(JSON.stringify({ type: 'input_audio_buffer.commit' }));
    },
    onRespond: () => {
      if (ws.readyState !== WebSocket.OPEN) return;
      ws.send(JSON.stringify({ type: 'response.create' }));
    },
    onDrop: (reason) => {
      console.warn(
        `[TRANSLATOR] [${tag}] Dropped a turn (${reason}) — translation is more than ` +
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
```

- [ ] **Step 6: `translator.js` берёт перенесённое из новых модулей**

Заменить в `translator.js` всё от строки `const { AccessToken } = require('livekit-server-sdk');` (строка 10) до конца функции `createFrameQueue` включительно (строка 316, последняя строка перед `// ─── Helpers ───`) на блок ниже. Шапку-комментарий (строки 1–8) и всё начиная с `// ─── Helpers ───` не трогать.

```js
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

```

- [ ] **Step 7: Проверить**

```bash
node --check translator.js && echo syntax-ok
grep -cE "^function (createRealtimeSession|createFrameQueue|applyGain|getFrameRMS|isHallucination)" translator.js
npm test 2>&1 | tail -8
```

Ожидается:
- `syntax-ok`;
- `0` — ни одна из перенесённых функций больше не объявлена в `translator.js`;
- `ℹ pass 64`: 48 прежних, 7 из `wav.test.js` и 6 + 3 новых; `ℹ fail 0`.

- [ ] **Step 8: Коммит**

```bash
git add testing/fake-ws.js lang-names.js audio-out.js realtime-phrase-session.js realtime-phrase-session.test.js audio-out.test.js translator.js
git commit -m "refactor(translator): фразовый движок, таблицы языков и вывод звука — в отдельные модули" -m "Поведение переводчика в звонках не меняется; характеризующие тесты фиксируют, что уходит в OpenAI. Нужно разговору с переводом, который использует тот же движок." -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Фразовый движок — `onReady`, `onClose`, `onTranscript`, `pruneHistory`

**Files:**
- Modify: `livekit-agent/realtime-phrase-session.js`
- Test: `livekit-agent/realtime-phrase-session.test.js` (дописать)

- [ ] **Step 1: Дописать падающие тесты в конец `realtime-phrase-session.test.js`**

```js
const { isHallucination } = require('./realtime-phrase-session');

test('only real hallucinations are filtered, ordinary phrases are not', () => {
  assert.strictEqual(isHallucination('Добрый день'), false);
  assert.strictEqual(isHallucination('Guten Tag, wie geht es Ihnen?'), false);
  assert.strictEqual(isHallucination('thank you for watching'), true);
  assert.strictEqual(isHallucination('да да да'), true);
  assert.strictEqual(isHallucination('ok ok ok ok'), true);
  assert.strictEqual(isHallucination(' '), true);
});

test('onReady fires once the session is configured', () => {
  let ready = 0;
  const { fake } = open('ru', 'sk', { onReady: () => { ready += 1; } });
  assert.strictEqual(ready, 0);
  fake.serverSends({ type: 'session.updated' });
  assert.strictEqual(ready, 1);
});

test('recognised speech and its translation are reported, hallucinations are not', () => {
  const seen = [];
  const { fake } = open('ru', 'sk', { onTranscript: (t) => seen.push(t) });
  fake.serverSends({ type: 'conversation.item.input_audio_transcription.completed', transcript: ' Добрый день ' });
  fake.serverSends({ type: 'conversation.item.input_audio_transcription.completed', transcript: 'thank you for watching' });
  fake.serverSends({ type: 'response.output_audio_transcript.done', transcript: ' Dobrý deň ' });
  assert.deepStrictEqual(seen, [
    { role: 'source', text: 'Добрый день' },
    { role: 'translation', text: 'Dobrý deň' },
  ]);
});

test('onClose reports the close code', () => {
  const closes = [];
  const { fake } = open('ru', 'sk', { onClose: (c) => closes.push(c) });
  fake.serverCloses(1011);
  assert.deepStrictEqual(closes, [{ code: 1011 }]);
});

test('with pruneHistory a spoken phrase is deleted and a queued one is kept', () => {
  const { fake } = open('ru', 'sk', { pruneHistory: true });
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'input_audio_buffer.committed', item_id: 'in1' });
  fake.serverSends({ type: 'response.created', response: { id: 'r1' } });
  fake.serverSends({ type: 'input_audio_buffer.committed', item_id: 'in2' }); // cut while r1 speaks
  fake.serverSends({ type: 'response.done', response: { id: 'r1', status: 'completed', output: [{ id: 'out1' }] } });
  assert.deepStrictEqual(fake.sentOfType('conversation.item.delete').map((m) => m.item_id), ['in1', 'out1']);

  fake.serverSends({ type: 'response.created', response: { id: 'r2' } });
  fake.serverSends({ type: 'response.done', response: { id: 'r2', status: 'completed', output: [{ id: 'out2' }] } });
  assert.deepStrictEqual(
    fake.sentOfType('conversation.item.delete').map((m) => m.item_id),
    ['in1', 'out1', 'in2', 'out2'],
  );
});

test('without pruneHistory nothing is deleted', () => {
  const { fake } = open('ru', 'sk');
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'input_audio_buffer.committed', item_id: 'in1' });
  fake.serverSends({ type: 'response.created', response: { id: 'r1' } });
  fake.serverSends({ type: 'response.done', response: { id: 'r1', status: 'completed', output: [{ id: 'out1' }] } });
  assert.strictEqual(fake.sentOfType('conversation.item.delete').length, 0);
});
```

Run: `node --test realtime-phrase-session.test.js`
Expected: новые тесты падают — `ready` = 0, `seen` без исходной речи, и `isHallucination('Добрый день')` возвращает `true`. 6 старых проходят.

- [ ] **Step 2: Починить регулярку галлюцинаций**

Без обратной ссылки повтор `((.{2,20})\s*){3,}` совпадает с любой фразой от шести символов. В переводчике звонков результат только пишется в лог, поэтому вреда не было, но субтитры исходной речи она съела бы целиком. Строку

```js
// Common Whisper hallucination patterns (repeated phrases, YouTube-like text)
const HALLUCINATION_RE = /^((.{2,20})\s*){3,}$|구독과\s*좋아요|ご視聴|チャンネル登録|请订阅|thank you for watching/i;
```

заменить на:

```js
// Common Whisper hallucination patterns: the same 2–20 characters said three
// or more times over, and YouTube-like sign-offs. The repeat used to be
// ((.{2,20})\s*){3,}, which any phrase of six characters satisfies — harmless
// while the result was only logged, but it would swallow every subtitle.
const HALLUCINATION_RE = /^(.{2,20}?)(?:\s*\1){2,}$|구독과\s*좋아요|ご視聴|チャンネル登録|请订阅|thank you for watching/i;
```

- [ ] **Step 2a: Шапка-комментарий — дописать новые опции**

В комментарии над `const WebSocket` заменить строки

```
 *   model      Realtime model (default gpt-realtime-mini, as before)
 *   apiKey     default process.env.OPENAI_API_KEY
 *   wsFactory  (url, options) => socket; tests pass a fake
 */
```

на

```
 *   model         Realtime model (default gpt-realtime-mini, as before)
 *   apiKey        default process.env.OPENAI_API_KEY
 *   wsFactory     (url, options) => socket; tests pass a fake
 *   onReady()     the session accepted its configuration
 *   onClose({ code })
 *   onTranscript({ role: 'source' | 'translation', text })
 *   pruneHistory  delete each phrase from the conversation once spoken
 */
```

- [ ] **Step 3: Учёт реплик для `pruneHistory`**

После строки `const pendingMessages = [];` добавить:

```js
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
```

- [ ] **Step 4: Обработчик сообщений**

Внутри `ws.on('message', …)` сделать пять правок.

а) После `pendingMessages.length = 0;` (в ветке `session.updated`) добавить:

```js
        if (opts.onReady) opts.onReady();
```

б) Ветку `response.created` заменить на:

```js
      if (opts.pruneHistory && event.type === 'input_audio_buffer.committed' && event.item_id) {
        uncoveredInputs.push(event.item_id);
      }

      if (event.type === 'response.created') {
        if (opts.pruneHistory && event.response && event.response.id) {
          inputsByResponse.set(event.response.id, uncoveredInputs.splice(0));
        }
        ws._turns.responseCreated();
      }
```

в) В ветке `response.done` перед `ws._turns.responseDone();` добавить строку. Удаление уходит раньше, чем следующий `response.create` из очереди.

```js
        if (opts.pruneHistory) pruneSpoken(event.response);
```

г) Строку

```js
        if (isHallucination(heard)) console.log(`[TRANSLATOR] [${tag}] FILTERED: hallucination`);
```

заменить на:

```js
        if (isHallucination(heard)) console.log(`[TRANSLATOR] [${tag}] FILTERED: hallucination`);
        else if (opts.onTranscript) opts.onTranscript({ role: 'source', text: heard });
```

д) Ветку `response.output_audio_transcript.done` заменить на:

```js
      if (event.type === 'response.output_audio_transcript.done' && event.transcript) {
        const translated = event.transcript.trim();
        console.log(`[TRANSLATOR] [${tag}] translated: "${translated}"`);
        if (opts.onTranscript && translated) opts.onTranscript({ role: 'translation', text: translated });
      }
```

- [ ] **Step 5: `onClose`**

В `ws.on('close', …)` после `ws._turns.reset();` добавить:

```js
    if (opts.onClose) opts.onClose({ code });
```

- [ ] **Step 6: Тесты проходят**

```bash
node --test realtime-phrase-session.test.js && npm test 2>&1 | tail -8
```

Ожидается: 12 тестов в файле зелёные, всего `ℹ pass 70`.

- [ ] **Step 7: Коммит**

```bash
git add realtime-phrase-session.js realtime-phrase-session.test.js
git commit -m "feat(interpreter): фразовый движок — onReady/onClose/субтитры и удаление озвученных реплик" -m "Попутно: регулярка галлюцинаций Whisper без обратной ссылки помечала любую фразу от шести символов; в переводчике звонков она только писала в лог, но субтитры съела бы целиком." -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `interpreter-langs.js` — какой движок для пары

**Files:**
- Create: `livekit-agent/interpreter-langs.js`
- Test: `livekit-agent/interpreter-langs.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { chooseEngine, isSupported, SIMULTANEOUS_TARGETS } = require('./interpreter-langs');
const { SUPPORTED_LANGS } = require('./lang-names');

test('Russian and German both ways are simultaneous', () => {
  assert.strictEqual(chooseEngine('ru', 'de'), 'simultaneous');
  assert.strictEqual(chooseEngine('de', 'ru'), 'simultaneous');
});

test('a listener the model cannot speak to goes phrase by phrase', () => {
  assert.strictEqual(chooseEngine('ru', 'sk'), 'phrase'); // Slovak is input-only
  assert.strictEqual(chooseEngine('sk', 'ru'), 'simultaneous');
});

test('a speaker the model cannot hear goes phrase by phrase', () => {
  assert.strictEqual(chooseEngine('am', 'en'), 'phrase'); // Amharic is not an input
});

test('every simultaneous target is a language the agent knows', () => {
  for (const lang of SIMULTANEOUS_TARGETS) assert.ok(SUPPORTED_LANGS.includes(lang), lang);
  assert.strictEqual(SIMULTANEOUS_TARGETS.size, 13);
});

test('only the agent languages are supported', () => {
  assert.strictEqual(isSupported('ru'), true);
  assert.strictEqual(isSupported('xx'), false);
  assert.strictEqual(isSupported(undefined), false);
});
```

Run: `node --test interpreter-langs.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * Which engine renders a language pair.
 *
 * gpt-realtime-translate interprets simultaneously — it speaks while the
 * person is still talking — but only INTO 13 languages and only FROM the ones
 * it can hear. Every other pair runs on the phrase engine
 * (realtime-phrase-session.js), which waits for a pause.
 *
 * Both lists are copied from OpenAI's realtime translation guide on
 * 2026-10-31. A stale list only costs a pair that runs phrase by phrase when
 * it did not have to; re-check when OpenAI adds languages.
 */
const { SUPPORTED_LANGS } = require('./lang-names');

const SIMULTANEOUS_TARGETS = new Set([
  'en', 'es', 'pt', 'fr', 'ja', 'ru', 'zh', 'de', 'ko', 'hi', 'id', 'vi', 'it',
]);

const SIMULTANEOUS_SOURCES = new Set([
  'af', 'ar', 'az', 'be', 'bg', 'bn', 'bs', 'ca', 'cs', 'cy', 'da', 'de', 'dz',
  'el', 'en', 'eo', 'es', 'et', 'eu', 'fa', 'fi', 'fr', 'gl', 'gu', 'he', 'hi',
  'hr', 'ht', 'hu', 'hy', 'id', 'it', 'ja', 'jv', 'ka', 'kk', 'ko', 'ku', 'la',
  'lt', 'lv', 'mi', 'mk', 'ml', 'mn', 'ms', 'my', 'ne', 'nl', 'nn', 'no', 'pa',
  'pl', 'pt', 'ro', 'ru', 'sk', 'sl', 'sn', 'sq', 'sr', 'sv', 'sw', 'te', 'th',
  'tl', 'tr', 'uk', 'uz', 'vi', 'yo', 'zh',
]);

function isSupported(lang) {
  return SUPPORTED_LANGS.includes(lang);
}

/** 'simultaneous' or 'phrase' for speech in sourceLang heard in targetLang. */
function chooseEngine(sourceLang, targetLang) {
  return SIMULTANEOUS_TARGETS.has(targetLang) && SIMULTANEOUS_SOURCES.has(sourceLang)
    ? 'simultaneous'
    : 'phrase';
}

module.exports = { SIMULTANEOUS_TARGETS, SIMULTANEOUS_SOURCES, isSupported, chooseEngine };
```

- [ ] **Step 3: Тест проходит** — `node --test interpreter-langs.test.js` → `ℹ pass 5`.

- [ ] **Step 4: Коммит**

```bash
git add interpreter-langs.js interpreter-langs.test.js
git commit -m "feat(interpreter): выбор движка по паре языков" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: `voice-embed-client.js` — сервис сверки и cosine

**Files:**
- Create: `livekit-agent/voice-embed-client.js`
- Test: `livekit-agent/voice-embed-client.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { createVoiceEmbedClient, cosine } = require('./voice-embed-client');

function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}
function body(req) {
  return new Promise((resolve) => {
    const parts = [];
    req.on('data', (c) => parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts)));
  });
}
function stop(server) {
  server.closeAllConnections();
  return new Promise((r) => server.close(r));
}

test('a PCM window goes out as a WAV file and the vector comes back', async () => {
  let got;
  const { server, url } = await serve(async (req, res) => {
    got = { path: req.url, type: req.headers['content-type'], body: await body(req) };
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ vector: [0.1, 0.2], dim: 2 }));
  });
  try {
    const client = createVoiceEmbedClient({ baseUrl: `${url}/`, timeoutMs: 1000 });
    assert.deepStrictEqual(await client.embedPcm(new Int16Array(2400), 24000), [0.1, 0.2]);
    assert.strictEqual(got.path, '/embed');
    assert.match(got.type, /^multipart\/form-data/);
    const text = got.body.toString('latin1');
    assert.match(text, /name="audio"; filename="audio.wav"/);
    assert.ok(text.includes('RIFF'));
    assert.ok(!text.includes('window_sec'));
  } finally {
    await stop(server);
  }
});

test('windowSec is passed for enrollment-style averaging', async () => {
  let text;
  const { server, url } = await serve(async (req, res) => {
    text = (await body(req)).toString('latin1');
    res.end(JSON.stringify({ vector: [1] }));
  });
  try {
    await createVoiceEmbedClient({ baseUrl: url }).embedWav(Buffer.from('RIFFxxxx'), { windowSec: 3, timeout: 1000 });
    assert.match(text, /name="window_sec"\r\n\r\n3\r\n/);
  } finally {
    await stop(server);
  }
});

test('an HTTP error is an error', async () => {
  const { server, url } = await serve((req, res) => { res.statusCode = 422; res.end('{"detail":"audio_too_short"}'); });
  try {
    await assert.rejects(createVoiceEmbedClient({ baseUrl: url, timeoutMs: 1000 }).embedPcm(new Int16Array(10), 24000), /HTTP 422/);
  } finally {
    await stop(server);
  }
});

test('an empty vector is an error', async () => {
  const { server, url } = await serve((req, res) => res.end('{"vector":[]}'));
  try {
    await assert.rejects(createVoiceEmbedClient({ baseUrl: url, timeoutMs: 1000 }).embedPcm(new Int16Array(10), 24000), /no vector/);
  } finally {
    await stop(server);
  }
});

test('a slow service is cut off at the timeout', async () => {
  const { server, url } = await serve((req, res) => setTimeout(() => res.end('{"vector":[1]}'), 300));
  try {
    await assert.rejects(
      createVoiceEmbedClient({ baseUrl: url, timeoutMs: 50 }).embedPcm(new Int16Array(10), 24000),
      (e) => e.name === 'AbortError',
    );
  } finally {
    await stop(server);
  }
});

test('cosine: same direction 1, orthogonal 0, zero vector 0, mismatch throws', () => {
  assert.ok(Math.abs(cosine([1, 2], [2, 4]) - 1) < 1e-12);
  assert.strictEqual(cosine([1, 0], [0, 1]), 0);
  assert.strictEqual(cosine([0, 0], [1, 1]), 0);
  assert.throws(() => cosine([1], [1, 2]), /length mismatch/);
});
```

Run: `node --test voice-embed-client.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * Client for voice-embed-service (ECAPA speaker embeddings on :18082) and the
 * cosine similarity the gate compares embeddings with.
 *
 * The service accepts a WAV at any sample rate and resamples to 16 kHz itself,
 * so the gate sends its 24 kHz audio as it is — the same way the assistant's
 * realtime proxy does. Anything but a non-empty vector is an error; what an
 * error means is the caller's business (the gate lets the audio through).
 */
const { wrapWavMono } = require('./wav');

function createVoiceEmbedClient({ baseUrl, timeoutMs = 300, fetchFn = fetch }) {
  const url = `${String(baseUrl).replace(/\/+$/, '')}/embed`;

  async function embedWav(wav, { windowSec, timeout = timeoutMs } = {}) {
    const form = new FormData();
    form.append('audio', new Blob([wav], { type: 'audio/wav' }), 'audio.wav');
    if (windowSec) form.append('window_sec', String(windowSec));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetchFn(url, { method: 'POST', body: form, signal: controller.signal });
      if (!res.ok) throw new Error(`voice-embed HTTP ${res.status}`);
      const body = await res.json();
      if (!Array.isArray(body.vector) || body.vector.length === 0) throw new Error('voice-embed returned no vector');
      return body.vector;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    embedWav,
    embedPcm: (int16, sampleRate, options) => embedWav(wrapWavMono(int16, sampleRate), options),
  };
}

function cosine(a, b) {
  if (a.length !== b.length) throw new Error(`cosine: vector length mismatch (${a.length} vs ${b.length})`);
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  return denom === 0 ? 0 : dot / denom;
}

module.exports = { createVoiceEmbedClient, cosine };
```

- [ ] **Step 3: Тест проходит** — `node --test voice-embed-client.test.js` → `ℹ pass 6`.

- [ ] **Step 4: Коммит**

```bash
git add voice-embed-client.js voice-embed-client.test.js
git commit -m "feat(interpreter): клиент сервиса сверки голоса" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: `voiceprint-gate.js` — фильтр голоса

**Files:**
- Create: `livekit-agent/voiceprint-gate.js`
- Test: `livekit-agent/voiceprint-gate.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
//
// A 1 kHz "sample rate" keeps chunks tiny: chunkMs 100 → 100 samples. Speech
// is a constant 2000 (RMS 2000), quiet is 200 (below the 400 speech level).
const test = require('node:test');
const assert = require('node:assert');
const { createVoiceprintGate } = require('./voiceprint-gate');

const CHUNK = 100;
const speech = () => new Int16Array(CHUNK).fill(2000);
const silence = () => new Int16Array(CHUNK);
const quiet = () => new Int16Array(CHUNK).fill(200);
const tick = () => new Promise((r) => setImmediate(r));
const isSpeech = (c) => c.length === CHUNK && c.every((x) => x === 2000);
const isZero = (c) => c.length === CHUNK && c.every((x) => x === 0);

const OWN = { own: 0.8, other: 0.1 };
const LEAK = { own: 0.1, other: 0.7 };

function gate(scores, extra = {}) {
  const out = [];
  const speaking = [];
  const decisions = [];
  const windows = [];
  let i = 0;
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    speechRms: 400,
    threshold: 0.25,
    margin: 0.05,
    hysteresis: 2,
    score: async (w) => {
      windows.push(w.length);
      const s = scores[i++];
      if (s instanceof Error) throw s;
      return s;
    },
    onOutput: (c) => out.push(c),
    onSpeaking: (on) => speaking.push(on),
    onDecision: (d) => decisions.push(d),
    ...extra,
  });
  return { g, out, speaking, decisions, windows };
}

async function feed(g, chunks) {
  for (const c of chunks) g.push(c);
  await tick();
}

test('silence goes out one chunk late and never asks the embed service', async () => {
  const { g, out, windows } = gate([]);
  g.push(silence());
  await tick();
  assert.strictEqual(out.length, 0, 'waits for its look-ahead');
  await feed(g, [silence(), silence()]);
  assert.strictEqual(out.length, 2);
  assert.ok(out.every(isZero));
  assert.strictEqual(windows.length, 0);
});

test('audio below the speech level goes out as true silence', async () => {
  const { g, out } = gate([]);
  await feed(g, [quiet(), quiet()]);
  assert.ok(isZero(out[0]));
});

test("the owner's speech passes unchanged; speaking turns on, then off after two quiet chunks", async () => {
  const { g, out, speaking } = gate([OWN, OWN]);
  await feed(g, [speech(), speech(), silence(), silence(), silence()]);
  assert.strictEqual(out.length, 4);
  assert.ok(isSpeech(out[0]) && isSpeech(out[1]));
  assert.ok(isZero(out[2]) && isZero(out[3]));
  assert.deepStrictEqual(speaking, [true, false]);
});

test("the partner's voice on this phone is replaced with silence", async () => {
  const { g, out, speaking } = gate([LEAK, LEAK, LEAK]);
  await feed(g, [speech(), speech(), speech(), silence()]);
  assert.strictEqual(out.length, 3);
  assert.ok(out.every(isZero));
  assert.deepStrictEqual(speaking, []);
});

test('sounding like the owner is not enough without the margin over the partner', async () => {
  const { g, out } = gate([{ own: 0.5, other: 0.48 }]);
  await feed(g, [speech(), silence()]);
  assert.ok(isZero(out[0]));
});

test('one doubtful chunk inside speech is let through, the second in a row is not', async () => {
  const { g, out } = gate([OWN, LEAK, LEAK, OWN]);
  await feed(g, [speech(), speech(), speech(), speech(), silence()]);
  assert.strictEqual(out.length, 4);
  assert.ok(isSpeech(out[0]));
  assert.ok(isSpeech(out[1]), 'first failure tolerated');
  assert.ok(isZero(out[2]), 'second failure in a row cuts');
  assert.ok(isSpeech(out[3]), 'a passing chunk reopens');
});

test('the first chunk of new speech must pass on its own', async () => {
  const { g, out } = gate([LEAK, OWN]);
  await feed(g, [silence(), speech(), speech(), silence()]);
  assert.ok(isZero(out[0]));
  assert.ok(isZero(out[1]), 'no benefit of the doubt at the start');
  assert.ok(isSpeech(out[2]));
});

test('when the embed service fails the chunk is let through and the failure is reported', async () => {
  const { g, out, decisions } = gate([new Error('connection refused')]);
  await feed(g, [speech(), silence()]);
  assert.ok(isSpeech(out[0]));
  assert.strictEqual(decisions[0].failOpen, true);
  assert.strictEqual(decisions[0].error, 'connection refused');
});

test('chunks go out in order even when their answers come back out of order', async () => {
  const pending = [];
  const out = [];
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    score: () => new Promise((resolve) => pending.push(resolve)),
    onOutput: (c) => out.push(c),
  });
  await feed(g, [speech(), speech(), silence()]);
  assert.strictEqual(pending.length, 2);
  pending[1](OWN);
  await tick();
  assert.strictEqual(out.length, 0, 'chunk 1 is ready but chunk 0 is not');
  pending[0](OWN);
  await tick();
  assert.strictEqual(out.length, 2);
});

test('each judged window holds the chunk with its neighbours', async () => {
  const { g, windows } = gate([OWN, OWN]);
  await feed(g, [speech(), speech(), speech()]);
  assert.deepStrictEqual(windows, [200, 300]); // first chunk has no "before"
});

test('frames of any size are re-cut into whole chunks', async () => {
  const { g, out } = gate([OWN, OWN, OWN]);
  g.push(new Int16Array(250).fill(2000));
  g.push(new Int16Array(150).fill(2000));
  await tick();
  assert.strictEqual(out.length, 3);
  assert.ok(out.every((c) => c.length === CHUNK));
});

test('after close nothing more comes out', async () => {
  const pending = [];
  const out = [];
  const g = createVoiceprintGate({
    sampleRate: 1000,
    chunkMs: 100,
    score: () => new Promise((resolve) => pending.push(resolve)),
    onOutput: (c) => out.push(c),
  });
  await feed(g, [speech(), speech()]);
  g.close();
  pending[0](OWN);
  await tick();
  g.push(speech());
  await tick();
  assert.strictEqual(out.length, 0);
});

test('a decision record carries the chunk, when it started, both scores and the embed time', async () => {
  // now(): 1010 chunk 0 starts, 1020 chunk 1 starts, 1030 chunk 0 is sent to
  // the embed service, 1040 its answer is in.
  let t = 1000;
  const { g, decisions } = gate([OWN], { now: () => (t += 10) });
  await feed(g, [speech(), silence()]);
  assert.deepStrictEqual(decisions[0], {
    index: 0, startedAt: 1010, own: 0.8, other: 0.1, pass: true, failOpen: false, error: null, latencyMs: 10,
  });
});
```

Run: `node --test voiceprint-gate.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * Lets through only the phone owner's own speech, judged a chunk at a time
 * against two voice prints: the owner's and the partner's.
 *
 * Two people sit at one table, each with their own phone, so each microphone
 * hears both of them. Only the owner's speech may reach the interpreter: the
 * partner's voice on this phone would be "translated" back at them, and so
 * would the translation playing in this phone's own earpiece. The assistant's
 * gate asks one question, "does this sound like the owner?". With both prints
 * at hand this gate also asks "more like the owner than the partner?", which
 * is the question that actually separates two people at one table.
 *
 * A chunk is judged on a window that includes its neighbours — the embedding
 * model needs about a second of audio to say anything — so a chunk goes out
 * only after the next one has arrived. That, plus the embed call, is the
 * gate's whole delay (~1 s with 500 ms chunks).
 *
 * Out comes either the original chunk or the same length of zeros, in order,
 * so the engine downstream gets a steady stream. Chunks too quiet to count as
 * speech go out as zeros too: a neighbour below the speech threshold is still
 * intelligible to a translation model.
 *
 * If the embed service fails, the chunk is let through (fail-open). A dead
 * conversation is worse than an occasional leak, and a leak is mostly already
 * in the listener's own language, which the model is not expected to repeat.
 */
const { rms } = require('./wav');

function concat(parts) {
  let length = 0;
  for (const p of parts) length += p.length;
  const out = new Int16Array(length);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * @param opts.score      async (windowInt16) => ({ own, other }) cosine similarities; may throw
 * @param opts.onOutput   (chunkInt16) => void — the original chunk or silence, in order
 * @param opts.onSpeaking (on) => void — the owner started / stopped being let through
 * @param opts.onDecision (record) => void — one per judged chunk, for logs and the bench
 */
function createVoiceprintGate(opts) {
  const sampleRate = opts.sampleRate ?? 24000;
  const chunkSamples = Math.round((sampleRate * (opts.chunkMs ?? 500)) / 1000);
  const speechRms = opts.speechRms ?? 400;
  const threshold = opts.threshold ?? 0.25;
  const margin = opts.margin ?? 0.05;
  const hysteresis = Math.max(1, opts.hysteresis ?? 2);
  const { score, onOutput } = opts;
  const onSpeaking = opts.onSpeaking ?? (() => {});
  const onDecision = opts.onDecision ?? (() => {});
  const now = opts.now ?? Date.now;
  if (typeof score !== 'function' || typeof onOutput !== 'function') {
    throw new TypeError('createVoiceprintGate needs score and onOutput');
  }

  let filling = new Int16Array(chunkSamples);
  let filled = 0;
  let fillStartedAt = 0;
  let nextIndex = 0;
  let previous = null;
  const queue = [];
  let closed = false;

  // Release-side state; advanced strictly in stream order.
  let inSpeech = false;
  let open = false;
  let failStreak = 0;
  let speaking = false;
  let quietRun = 0;

  function push(samples) {
    if (closed) return;
    let offset = 0;
    while (offset < samples.length) {
      if (filled === 0) fillStartedAt = now();
      const take = Math.min(chunkSamples - filled, samples.length - offset);
      filling.set(samples.subarray(offset, offset + take), filled);
      filled += take;
      offset += take;
      if (filled === chunkSamples) {
        complete(filling, fillStartedAt);
        filling = new Int16Array(chunkSamples);
        filled = 0;
      }
    }
  }

  function complete(samples, startedAt) {
    const chunk = {
      index: nextIndex++,
      samples,
      startedAt,
      before: previous,
      speech: rms(samples) >= speechRms,
      decided: false,
      pass: false,
    };
    previous = samples;
    queue.push(chunk);
    // The chunk before this one now has its look-ahead and can be judged.
    if (queue.length >= 2) judge(queue[queue.length - 2], samples);
  }

  function judge(chunk, after) {
    if (!chunk.speech) {
      chunk.decided = true;
      release();
      return;
    }
    const window = concat(chunk.before ? [chunk.before, chunk.samples, after] : [chunk.samples, after]);
    const askedAt = now();
    Promise.resolve()
      .then(() => score(window))
      .then(
        (s) => settle(chunk, s.own >= threshold && s.own - s.other >= margin, s, null, askedAt),
        (err) => settle(chunk, true, null, err, askedAt),
      );
  }

  function settle(chunk, pass, s, err, askedAt) {
    if (closed) return;
    chunk.pass = pass;
    chunk.decided = true;
    onDecision({
      index: chunk.index,
      startedAt: chunk.startedAt,
      own: s ? s.own : null,
      other: s ? s.other : null,
      pass,
      failOpen: Boolean(err),
      error: err ? String(err.message || err) : null,
      latencyMs: now() - askedAt,
    });
    release();
  }

  function release() {
    while (!closed && queue.length > 0 && queue[0].decided) {
      const chunk = queue.shift();
      let letThrough = false;
      if (!chunk.speech) {
        inSpeech = false;
        failStreak = 0;
      } else {
        if (!inSpeech) {
          // New speech gets no benefit of the doubt.
          inSpeech = true;
          open = chunk.pass;
          failStreak = chunk.pass ? 0 : 1;
        } else if (chunk.pass) {
          open = true;
          failStreak = 0;
        } else {
          failStreak += 1;
          if (failStreak >= hysteresis) open = false;
        }
        letThrough = open;
      }
      if (letThrough) {
        quietRun = 0;
        if (!speaking) {
          speaking = true;
          onSpeaking(true);
        }
      } else {
        quietRun += 1;
        if (speaking && quietRun >= 2) {
          speaking = false;
          onSpeaking(false);
        }
      }
      onOutput(letThrough ? chunk.samples : new Int16Array(chunk.samples.length));
    }
  }

  return {
    push,
    close() {
      closed = true;
      queue.length = 0;
    },
  };
}

module.exports = { createVoiceprintGate };
```

- [ ] **Step 3: Тест проходит** — `node --test voiceprint-gate.test.js` → `ℹ pass 13`.

- [ ] **Step 4: Коммит**

```bash
git add voiceprint-gate.js voiceprint-gate.test.js
git commit -m "feat(interpreter): фильтр голоса по двум образцам" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: `reconnecting-engine.js` — переподключения

**Files:**
- Create: `livekit-agent/reconnecting-engine.js`
- Test: `livekit-agent/reconnecting-engine.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { createReconnectingEngine } = require('./reconnecting-engine');

function fakeTimers() {
  const timers = [];
  return {
    setTimer: (fn, ms) => {
      const t = { fn, ms, cleared: false, fired: false };
      timers.push(t);
      return t;
    },
    clearTimer: (t) => { t.cleared = true; },
    fireNext() {
      const t = timers.find((x) => !x.cleared && !x.fired);
      if (!t) return null;
      t.fired = true;
      t.fn();
      return t.ms;
    },
    active: () => timers.filter((x) => !x.cleared && !x.fired).length,
  };
}

function fakeFactory() {
  const made = [];
  const factory = (handlers) => {
    const engine = {
      handlers,
      sent: [],
      closed: false,
      sendAudio(x) { this.sent.push(x); },
      close() { this.closed = true; },
    };
    made.push(engine);
    return engine;
  };
  return { made, factory };
}

function setup() {
  const timers = fakeTimers();
  const { made, factory } = fakeFactory();
  const statuses = [];
  const engine = createReconnectingEngine({
    factory,
    onStatus: (s) => statuses.push(s),
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
  });
  return { timers, made, statuses, engine };
}

test('audio goes to the current engine', () => {
  const { made, engine } = setup();
  engine.sendAudio('x');
  assert.deepStrictEqual(made[0].sent, ['x']);
});

test('an unexpected close reconnects after a second and reports it', () => {
  const { timers, made, statuses, engine } = setup();
  made[0].handlers.onClose({ unexpected: true });
  engine.sendAudio('lost'); // no socket: dropped
  assert.deepStrictEqual(statuses, ['reconnecting']);
  assert.strictEqual(timers.fireNext(), 1000);
  made[1].handlers.onReady();
  assert.deepStrictEqual(statuses, ['reconnecting', 'ok']);
  engine.sendAudio('y');
  assert.deepStrictEqual(made[1].sent, ['y']);
});

test('three failures in a row back off 1, 2, 4 s and then give up', () => {
  const { timers, made, statuses } = setup();
  const delays = [];
  for (let i = 0; i < 3; i++) {
    made[i].handlers.onClose({ unexpected: true });
    delays.push(timers.fireNext());
  }
  made[3].handlers.onClose({ unexpected: true });
  assert.deepStrictEqual(delays, [1000, 2000, 4000]);
  assert.deepStrictEqual(statuses, ['reconnecting', 'failed']);
  assert.strictEqual(timers.active(), 0);
});

test('a successful reconnect resets the back-off', () => {
  const { timers, made } = setup();
  made[0].handlers.onClose({ unexpected: true });
  timers.fireNext();
  made[1].handlers.onReady();
  made[1].handlers.onClose({ unexpected: true });
  assert.strictEqual(timers.fireNext(), 1000);
});

test('an expected close does not reconnect', () => {
  const { timers, made, statuses } = setup();
  made[0].handlers.onClose({ unexpected: false });
  assert.strictEqual(timers.active(), 0);
  assert.deepStrictEqual(statuses, []);
});

test('closing cancels a pending reconnect and closes the engine', () => {
  const { timers, made, engine } = setup();
  made[0].handlers.onClose({ unexpected: true });
  engine.close();
  assert.strictEqual(timers.active(), 0);
  assert.strictEqual(made.length, 1);

  const second = setup();
  second.engine.close();
  assert.strictEqual(second.made[0].closed, true);
});
```

Run: `node --test reconnecting-engine.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * Keeps one translation engine alive for a whole conversation. If OpenAI
 * drops the socket, it reconnects after 1, 2 and 4 seconds and gives up after
 * the third failure in a row; a successful reconnect starts the count over.
 * Audio that arrives while there is no socket is dropped: a translation of the
 * gap arriving later would be worse than none.
 *
 * factory({ onReady, onClose }) → { sendAudio, close }; onClose({ unexpected })
 * tells a dropped socket from one we closed. Statuses: 'reconnecting', 'ok'
 * (back after reconnecting), 'failed' (gave up — the caller ends the session).
 */
function createReconnectingEngine({
  factory,
  delaysMs = [1000, 2000, 4000],
  onStatus = () => {},
  setTimer = setTimeout,
  clearTimer = clearTimeout,
}) {
  let engine = null;
  let closed = false;
  let failures = 0;
  let timer = null;
  let reconnecting = false;

  function connect() {
    let self = null;
    self = factory({
      onReady: () => {
        failures = 0;
        if (reconnecting) {
          reconnecting = false;
          onStatus('ok');
        }
      },
      onClose: ({ unexpected }) => {
        if (engine === self) engine = null;
        if (closed || !unexpected) return;
        retry();
      },
    });
    engine = self;
  }

  function retry() {
    if (failures >= delaysMs.length) {
      onStatus('failed');
      return;
    }
    const delay = delaysMs[failures];
    failures += 1;
    if (!reconnecting) {
      reconnecting = true;
      onStatus('reconnecting');
    }
    timer = setTimer(() => {
      timer = null;
      if (!closed) connect();
    }, delay);
  }

  connect();

  return {
    sendAudio(int16) {
      if (engine) engine.sendAudio(int16);
    },
    close() {
      closed = true;
      if (timer) clearTimer(timer);
      timer = null;
      const current = engine;
      engine = null;
      if (current) current.close();
    },
  };
}

module.exports = { createReconnectingEngine };
```

- [ ] **Step 3: Тест проходит** — `node --test reconnecting-engine.test.js` → `ℹ pass 6`.

- [ ] **Step 4: Коммит**

```bash
git add reconnecting-engine.js reconnecting-engine.test.js
git commit -m "feat(interpreter): переподключение движка перевода 1/2/4 с" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: `translate-session.js` — синхронный движок и самопроверка

**Files:**
- Create: `livekit-agent/translate-session.js`
- Test: `livekit-agent/translate-session.test.js`
- Read: `livekit-agent/bench/PROBE.md` (выводы задачи 3)

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { fakeWsFactory } = require('./testing/fake-ws');
const { createTranslateSession, selftestTranslate } = require('./translate-session');

const quietLog = { error() {}, warn() {} };

function session(extra = {}) {
  const { factory, last } = fakeWsFactory();
  const seen = { audio: [], translation: [], source: [], ready: 0, closes: [] };
  const s = createTranslateSession({
    apiKey: 'k',
    targetLang: 'de',
    safetyId: 'abc',
    wsFactory: factory,
    onAudio: (a) => seen.audio.push(a),
    onTranslationText: (t, f) => seen.translation.push([t, f]),
    onSourceText: (t, f) => seen.source.push([t, f]),
    onReady: () => { seen.ready += 1; },
    onClose: (c) => seen.closes.push(c),
    log: quietLog,
    ...extra,
  });
  return { s, fake: last(), seen };
}

const appends = (fake) => fake.sentOfType('session.input_audio_buffer.append');

test('connects to the translations endpoint with the key and a safety identifier', () => {
  const { fake } = session();
  assert.strictEqual(fake.url, 'wss://api.openai.com/v1/realtime/translations?model=gpt-realtime-translate');
  assert.deepStrictEqual(fake.options, { headers: { Authorization: 'Bearer k', 'OpenAI-Safety-Identifier': 'abc' } });
});

test('asks for the listener language as soon as the socket opens', () => {
  const { fake } = session();
  fake.open();
  assert.deepStrictEqual(fake.sent[0], { type: 'session.update', session: { audio: { output: { language: 'de' } } } });
});

test('audio waits for the session and then goes out in 100 ms pieces', () => {
  const { s, fake, seen } = session();
  fake.open();
  s.sendAudio(new Int16Array(6000).fill(7));
  assert.strictEqual(appends(fake).length, 0);
  fake.serverSends({ type: 'session.created' });
  assert.deepStrictEqual(appends(fake).map((a) => Buffer.from(a.audio, 'base64').length), [4800, 4800, 2400]);
  assert.strictEqual(seen.ready, 1);
  s.sendAudio(new Int16Array(2400));
  assert.strictEqual(appends(fake).length, 4);
});

test('at most 4 s waits for the session; older audio is dropped', () => {
  const { s, fake } = session();
  fake.open();
  for (let i = 0; i < 50; i++) s.sendAudio(new Int16Array(2400).fill(i));
  fake.serverSends({ type: 'session.created' });
  assert.strictEqual(appends(fake).length, 40);
  assert.strictEqual(Buffer.from(appends(fake)[0].audio, 'base64').readInt16LE(0), 10);
});

test('translated audio and both transcripts reach their callbacks', () => {
  const { fake, seen } = session();
  fake.open();
  fake.serverSends({ type: 'session.created' });
  const pcm = Int16Array.from([5, -5, 300]);
  fake.serverSends({ type: 'session.output_audio.delta', delta: Buffer.from(pcm.buffer).toString('base64') });
  fake.serverSends({ type: 'session.output_transcript.delta', delta: 'Guten ' });
  fake.serverSends({ type: 'session.input_transcript.delta', delta: 'Добрый ' });
  assert.deepStrictEqual(Array.from(seen.audio[0]), [5, -5, 300]);
  assert.deepStrictEqual(seen.translation, [['Guten ', false]]);
  assert.deepStrictEqual(seen.source, [['Добрый ', false]]);
});

test('closing it ourselves says goodbye and is not unexpected', () => {
  const { s, fake, seen } = session();
  fake.open();
  s.close();
  assert.strictEqual(fake.sentOfType('session.close').length, 1);
  assert.deepStrictEqual(seen.closes, [{ unexpected: false, code: 1000 }]);
});

test('the server dropping the socket is unexpected', () => {
  const { fake, seen } = session();
  fake.open();
  fake.serverCloses(1011);
  assert.deepStrictEqual(seen.closes, [{ unexpected: true, code: 1011 }]);
});

test('selftest passes on session.updated', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, quietMs: 1000 });
  last().open();
  last().serverSends({ type: 'session.updated' });
  assert.deepStrictEqual(await result, { ok: true, reason: 'session.updated received' });
});

test('selftest passes when session.created is followed by quiet', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, quietMs: 20 });
  last().open();
  last().serverSends({ type: 'session.created' });
  const r = await result;
  assert.strictEqual(r.ok, true);
  assert.match(r.reason, /no error within 20 ms/);
});

test('selftest sends a session.update and a little silence', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000, quietMs: 1000 });
  last().open();
  assert.deepStrictEqual(last().sent.map((m) => m.type), ['session.update', 'session.input_audio_buffer.append']);
  last().serverSends({ type: 'session.updated' });
  await result;
});

test('selftest fails on an error event', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000 });
  last().open();
  last().serverSends({ type: 'error', error: { message: 'model not found' } });
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /model not found/);
});

test('selftest fails if the socket closes first', async () => {
  const { factory, last } = fakeWsFactory();
  const result = selftestTranslate({ apiKey: 'k', wsFactory: factory, timeoutMs: 1000 });
  last().serverCloses(1006);
  const r = await result;
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /closed code=1006/);
});

test('selftest without a key fails at once', async () => {
  assert.deepStrictEqual(await selftestTranslate({ apiKey: '' }), { ok: false, reason: 'OPENAI_API_KEY not set' });
});
```

Run: `node --test translate-session.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * One direction of simultaneous interpretation through OpenAI's
 * gpt-realtime-translate: one person's (already gated) speech in, the other
 * person's language out while the speaker is still talking.
 *
 * Unlike the phrase engine there are no turns: no commits, no response.create,
 * no conversation to prune. The session takes a continuous 24 kHz PCM16 stream
 * — silence included — and answers with translated audio and running
 * transcripts of both sides. Its voice follows the speaker's tone and pitch,
 * which is how the listener can still tell the two voices apart.
 *
 * The guide names the server events but not their fields. The accessors below
 * match what bench/probe-translate.js printed on DEV (bench/PROBE.md).
 */
const WebSocket = require('ws');

const ENDPOINT = 'wss://api.openai.com/v1/realtime/translations';
const DEFAULT_MODEL = 'gpt-realtime-translate';
const PIECE_SAMPLES = 2400; // 100 ms at 24 kHz, the size OpenAI's guide appends
const MAX_QUEUED_PIECES = 40; // 4 s may wait for the socket; older audio is dropped

const audioOf = (event) => event.delta;
const textOf = (event) => event.delta;

function defaultWsFactory(url, options) {
  return new WebSocket(url, options);
}

function toBase64(int16) {
  return Buffer.from(int16.buffer, int16.byteOffset, int16.byteLength).toString('base64');
}

function fromBase64(b64) {
  const buf = Buffer.from(b64, 'base64');
  const even = buf.byteLength - (buf.byteLength % 2);
  // Copy: a base64-decoded Buffer may sit at an odd offset in the pool.
  return new Int16Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + even));
}

function connect({ apiKey, model, safetyId, wsFactory }) {
  const headers = { Authorization: `Bearer ${apiKey}` };
  if (safetyId) headers['OpenAI-Safety-Identifier'] = safetyId;
  return wsFactory(`${ENDPOINT}?model=${encodeURIComponent(model)}`, { headers });
}

function createTranslateSession(opts) {
  const {
    targetLang,
    onAudio = () => {},
    onTranslationText = () => {},
    onSourceText = () => {},
    onReady = () => {},
    onClose = () => {},
    log = console,
  } = opts;
  const ws = connect({
    apiKey: opts.apiKey,
    model: opts.model || DEFAULT_MODEL,
    safetyId: opts.safetyId,
    wsFactory: opts.wsFactory || defaultWsFactory,
  });
  let ready = false;
  let closedByUs = false;
  const queue = [];

  const append = (b64) => ws.send(JSON.stringify({ type: 'session.input_audio_buffer.append', audio: b64 }));

  ws.on('open', () => {
    ws.send(JSON.stringify({ type: 'session.update', session: { audio: { output: { language: targetLang } } } }));
  });

  ws.on('message', (raw) => {
    let event;
    try {
      event = JSON.parse(raw.toString());
    } catch (_) {
      return;
    }
    switch (event.type) {
      case 'session.created':
      case 'session.updated':
        // session.update went out on 'open', before any audio, so the
        // language is set by the time the queued audio is read.
        if (!ready) {
          ready = true;
          while (queue.length) append(queue.shift());
          onReady();
        }
        break;
      case 'session.output_audio.delta': {
        const b64 = audioOf(event);
        if (b64) onAudio(fromBase64(b64));
        break;
      }
      case 'session.output_transcript.delta': {
        const text = textOf(event);
        if (text) onTranslationText(text, false);
        break;
      }
      case 'session.input_transcript.delta': {
        const text = textOf(event);
        if (text) onSourceText(text, false);
        break;
      }
      case 'error':
        log.error(`[INTERPRETER] translate →${targetLang} error: ${JSON.stringify(event.error || event)}`);
        break;
      default:
        break;
    }
  });

  ws.on('error', (err) => log.warn(`[INTERPRETER] translate →${targetLang} socket error: ${err.message}`));
  ws.on('close', (code) => onClose({ unexpected: !closedByUs, code }));

  return {
    sendAudio(int16) {
      for (let i = 0; i < int16.length; i += PIECE_SAMPLES) {
        const b64 = toBase64(int16.subarray(i, i + PIECE_SAMPLES));
        if (ready && ws.readyState === WebSocket.OPEN) {
          append(b64);
        } else {
          queue.push(b64);
          if (queue.length > MAX_QUEUED_PIECES) queue.shift();
        }
      }
    },
    close() {
      closedByUs = true;
      try {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'session.close' }));
      } catch (_) { /* closing anyway */ }
      try {
        ws.close();
      } catch (_) { /* already closed */ }
    },
  };
}

/**
 * Post-deploy smoke: opens a session the way the interpreter does and waits
 * for it to be accepted. Catches the model being renamed or withdrawn and the
 * session shape being refused — what broke the in-call translator in 1.0.78.
 * Passes on session.updated, or on session.created followed by quietMs with
 * no error (the guide does not promise a session.updated).
 */
function selftestTranslate({
  apiKey,
  model = DEFAULT_MODEL,
  wsFactory = defaultWsFactory,
  timeoutMs = 10000,
  quietMs = 1500,
} = {}) {
  if (!apiKey) return Promise.resolve({ ok: false, reason: 'OPENAI_API_KEY not set' });
  return new Promise((resolve) => {
    let done = false;
    let quietTimer = null;
    const ws = connect({ apiKey, model, safetyId: 'interpreter-selftest', wsFactory });
    const timer = setTimeout(() => finish({ ok: false, reason: `timeout: no session event within ${timeoutMs} ms` }), timeoutMs);
    function finish(result) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(quietTimer);
      try {
        ws.close();
      } catch (_) { /* already closed */ }
      resolve(result);
    }
    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'session.update', session: { audio: { output: { language: 'en' } } } }));
      ws.send(JSON.stringify({
        type: 'session.input_audio_buffer.append',
        audio: Buffer.alloc(PIECE_SAMPLES * 2 * 5).toString('base64'),
      }));
    });
    ws.on('message', (raw) => {
      let event;
      try {
        event = JSON.parse(raw.toString());
      } catch (_) {
        return;
      }
      if (event.type === 'error') {
        finish({ ok: false, reason: `OpenAI error: ${JSON.stringify(event.error || event)}` });
      } else if (event.type === 'session.updated') {
        finish({ ok: true, reason: 'session.updated received' });
      } else if (event.type === 'session.created' && !quietTimer) {
        quietTimer = setTimeout(() => finish({ ok: true, reason: `session.created, no error within ${quietMs} ms` }), quietMs);
      }
    });
    ws.on('error', (err) => finish({ ok: false, reason: `ws error: ${err.message}` }));
    ws.on('close', (code) => finish({ ok: false, reason: `ws closed code=${code} before confirmation` }));
  });
}

module.exports = { createTranslateSession, selftestTranslate, PIECE_SAMPLES };
```

- [ ] **Step 3: Тест проходит** — `node --test translate-session.test.js` → `ℹ pass 13`.

- [ ] **Step 4: Сверить с `bench/PROBE.md`**

Открыть выводы пробы и проверить два пункта.
- **П. 1–2: поле не `delta`.** Если base64-звук или текст в событиях лежит в другом поле, поменять `audioOf` / `textOf` и в тестах «translated audio and both transcripts…» имя поля в `serverSends`. Например: `const audioOf = (event) => event.audio;` и `{ type: 'session.output_audio.delta', audio: … }`.
- **П. 3: сервер шлёт `session.updated`.** Ничего не менять: готовность наступает по первому из `session.created` / `session.updated`.

После правок — `node --test translate-session.test.js` → `ℹ pass 13`.

- [ ] **Step 5: Коммит**

```bash
git add translate-session.js translate-session.test.js
git commit -m "feat(interpreter): синхронный движок gpt-realtime-translate и его самопроверка" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: `phrase-session.js` — фразовый движок в общем интерфейсе

**Files:**
- Create: `livekit-agent/phrase-session.js`
- Test: `livekit-agent/phrase-session.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { fakeWsFactory } = require('./testing/fake-ws');
const { createPhraseSession } = require('./phrase-session');

function session() {
  const { factory, last } = fakeWsFactory();
  const seen = { audio: [], translation: [], source: [], ready: 0, closes: [] };
  const s = createPhraseSession({
    apiKey: 'k',
    model: 'gpt-realtime-2025-08-28',
    sourceLang: 'ru',
    targetLang: 'sk',
    wsFactory: factory,
    onAudio: (a) => seen.audio.push(a),
    onTranslationText: (t, f) => seen.translation.push([t, f]),
    onSourceText: (t, f) => seen.source.push([t, f]),
    onReady: () => { seen.ready += 1; },
    onClose: (c) => seen.closes.push(c),
  });
  const fake = last();
  fake.open();
  return { s, fake, seen };
}

test('it runs the given model with the known source language', () => {
  const { fake } = session();
  assert.strictEqual(fake.url, 'wss://api.openai.com/v1/realtime?model=gpt-realtime-2025-08-28');
  assert.ok(fake.sentOfType('session.update')[0].session.instructions.includes('spoken Russian audio into spoken Slovak'));
});

test('audio goes in as base64 PCM16 once the session is ready', () => {
  const { s, fake, seen } = session();
  fake.serverSends({ type: 'session.updated' });
  assert.strictEqual(seen.ready, 1);
  s.sendAudio(Int16Array.from([1, -1, 2]));
  const back = Buffer.from(fake.sentOfType('input_audio_buffer.append')[0].audio, 'base64');
  assert.deepStrictEqual([back.readInt16LE(0), back.readInt16LE(2), back.readInt16LE(4)], [1, -1, 2]);
});

test('translated audio comes back as samples and transcripts as whole phrases', () => {
  const { fake, seen } = session();
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'response.output_audio.delta', delta: Buffer.from(Int16Array.from([9, -9]).buffer).toString('base64') });
  fake.serverSends({ type: 'conversation.item.input_audio_transcription.completed', transcript: 'Добрый день' });
  fake.serverSends({ type: 'response.output_audio_transcript.done', transcript: 'Dobrý deň' });
  assert.deepStrictEqual(Array.from(seen.audio[0]), [9, -9]);
  assert.deepStrictEqual(seen.source, [['Добрый день', true]]);
  assert.deepStrictEqual(seen.translation, [['Dobrý deň', true]]);
});

test('spoken phrases are pruned from the conversation', () => {
  const { fake } = session();
  fake.serverSends({ type: 'session.updated' });
  fake.serverSends({ type: 'input_audio_buffer.committed', item_id: 'in1' });
  fake.serverSends({ type: 'response.created', response: { id: 'r1' } });
  fake.serverSends({ type: 'response.done', response: { id: 'r1', status: 'completed', output: [{ id: 'out1' }] } });
  assert.deepStrictEqual(fake.sentOfType('conversation.item.delete').map((m) => m.item_id), ['in1', 'out1']);
});

test('closing it ourselves is not unexpected; the server closing is', () => {
  const a = session();
  a.s.close();
  assert.deepStrictEqual(a.seen.closes, [{ unexpected: false, code: 1000 }]);
  const b = session();
  b.fake.serverCloses(1006);
  assert.deepStrictEqual(b.seen.closes, [{ unexpected: true, code: 1006 }]);
});
```

Run: `node --test phrase-session.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * The phrase engine (realtime-phrase-session.js) behind the same interface as
 * translate-session.js, for the pairs gpt-realtime-translate cannot speak.
 * It waits for a pause and speaks whole phrases, so its transcripts arrive
 * whole as well (final = true). Spoken phrases are pruned from the
 * conversation: an interpreted talk can last an hour.
 */
const { createRealtimeSession } = require('./realtime-phrase-session');

function toInt16(buf) {
  const even = buf.byteLength - (buf.byteLength % 2);
  return new Int16Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + even));
}

function createPhraseSession({
  apiKey,
  model,
  sourceLang,
  targetLang,
  wsFactory,
  onAudio = () => {},
  onTranslationText = () => {},
  onSourceText = () => {},
  onReady = () => {},
  onClose = () => {},
}) {
  let closedByUs = false;
  const ws = createRealtimeSession(
    sourceLang,
    targetLang,
    (pcm) => onAudio(toInt16(pcm)),
    () => {}, // errors are followed by 'close', which is what the caller acts on
    {
      apiKey,
      model,
      wsFactory,
      pruneHistory: true,
      onReady,
      onTranscript: ({ role, text }) => (role === 'source' ? onSourceText(text, true) : onTranslationText(text, true)),
      onClose: ({ code }) => onClose({ unexpected: !closedByUs, code }),
    },
  );
  return {
    sendAudio(int16) {
      ws.sendAudio(Buffer.from(int16.buffer, int16.byteOffset, int16.byteLength).toString('base64'));
    },
    close() {
      closedByUs = true;
      try {
        ws.close();
      } catch (_) { /* already closed */ }
    },
  };
}

module.exports = { createPhraseSession };
```

- [ ] **Step 3: Тест проходит** — `node --test phrase-session.test.js` → `ℹ pass 5`.

- [ ] **Step 4: Коммит**

```bash
git add phrase-session.js phrase-session.test.js
git commit -m "feat(interpreter): фразовый движок в общем интерфейсе движков" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: `interpreter-routing.js` — два направления

**Files:**
- Create: `livekit-agent/interpreter-routing.js`
- Test: `livekit-agent/interpreter-routing.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { planDirections, trackNameFor } = require('./interpreter-routing');

const print = (k) => Array.from({ length: 192 }, (_, i) => (i === k ? 1 : 0));
const anna = { userId: 'u-anna', lang: 'de', embedding: print(1) };
const ivan = { userId: 'u-ivan', lang: 'ru', embedding: print(0) };

test('two people make two directions, each onto the listener track', () => {
  const [toAnna, toIvan] = planDirections([ivan, anna]);
  assert.deepStrictEqual(
    { ...toAnna, ownEmbedding: undefined, otherEmbedding: undefined },
    {
      speaker: 'u-ivan', listener: 'u-anna', sourceLang: 'ru', targetLang: 'de',
      engine: 'simultaneous', trackName: 'interp-for-u-anna', ownEmbedding: undefined, otherEmbedding: undefined,
    },
  );
  assert.strictEqual(toAnna.ownEmbedding, ivan.embedding);
  assert.strictEqual(toAnna.otherEmbedding, anna.embedding);
  assert.strictEqual(toIvan.speaker, 'u-anna');
  assert.strictEqual(toIvan.trackName, trackNameFor('u-ivan'));
  assert.strictEqual(toIvan.ownEmbedding, anna.embedding);
});

test('the engine is chosen per direction', () => {
  const laura = { userId: 'u-laura', lang: 'sk', embedding: print(2) };
  const [toLaura, toIvan] = planDirections([ivan, laura]);
  assert.strictEqual(toLaura.engine, 'phrase');
  assert.strictEqual(toIvan.engine, 'simultaneous');
});

test('anything but two different people with different known languages is refused', () => {
  assert.throws(() => planDirections([ivan]), /exactly two/);
  assert.throws(() => planDirections('x'), /exactly two/);
  assert.throws(() => planDirections([ivan, { ...ivan }]), /two different people/);
  assert.throws(() => planDirections([ivan, { ...anna, lang: 'ru' }]), /same language/);
  assert.throws(() => planDirections([ivan, { ...anna, lang: 'xx' }]), /unsupported language/);
  assert.throws(() => planDirections([ivan, { ...anna, userId: 'u-anna#dev' }]), /bare user id/);
});

test('a missing or malformed voice print is refused', () => {
  assert.throws(() => planDirections([ivan, { ...anna, embedding: undefined }]), /192 finite numbers/);
  assert.throws(() => planDirections([ivan, { ...anna, embedding: print(1).slice(1) }]), /192 finite numbers/);
  assert.throws(() => planDirections([ivan, { ...anna, embedding: [...print(1).slice(1), NaN] }]), /192 finite numbers/);
});
```

Run: `node --test interpreter-routing.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * Turns the two participants the backend sends into the two directions the
 * interpreter runs: who speaks, who listens, in which languages, by which
 * engine, onto which track.
 *
 * Exactly two different people with different languages the agent knows and a
 * 192-number voice print each — the gate cannot tell them apart without both
 * prints, and a same-language pair needs no interpreter. User ids arrive bare
 * (no "#device"): the track and the gate belong to the person, not the phone.
 */
const { isSupported, chooseEngine } = require('./interpreter-langs');

const EMBEDDING_DIM = 192;

function trackNameFor(listenerUserId) {
  return `interp-for-${listenerUserId}`;
}

function checkPerson(p) {
  if (!p || typeof p.userId !== 'string' || p.userId === '' || p.userId.includes('#')) {
    throw new Error('participant userId must be a bare user id');
  }
  if (!isSupported(p.lang)) throw new Error(`participant ${p.userId}: unsupported language ${p.lang}`);
  const e = p.embedding;
  if (!Array.isArray(e) || e.length !== EMBEDDING_DIM || !e.every(Number.isFinite)) {
    throw new Error(`participant ${p.userId}: embedding must be ${EMBEDDING_DIM} finite numbers`);
  }
}

function planDirections(participants) {
  if (!Array.isArray(participants) || participants.length !== 2) {
    throw new Error('exactly two participants required');
  }
  const [a, b] = participants;
  checkPerson(a);
  checkPerson(b);
  if (a.userId === b.userId) throw new Error('participants must be two different people');
  if (a.lang === b.lang) throw new Error('participants speak the same language');

  const direction = (speaker, listener) => ({
    speaker: speaker.userId,
    listener: listener.userId,
    sourceLang: speaker.lang,
    targetLang: listener.lang,
    engine: chooseEngine(speaker.lang, listener.lang),
    trackName: trackNameFor(listener.userId),
    ownEmbedding: speaker.embedding,
    otherEmbedding: listener.embedding,
  });
  return [direction(a, b), direction(b, a)];
}

module.exports = { planDirections, trackNameFor, EMBEDDING_DIM };
```

- [ ] **Step 3: Тест проходит** — `node --test interpreter-routing.test.js` → `ℹ pass 4`.

- [ ] **Step 4: Коммит**

```bash
git add interpreter-routing.js interpreter-routing.test.js
git commit -m "feat(interpreter): направления перевода из двух участников" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: `presence-watch.js` — кто в комнате

**Files:**
- Create: `livekit-agent/presence-watch.js`
- Test: `livekit-agent/presence-watch.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const { createPresenceWatch } = require('./presence-watch');

function setup() {
  const timers = [];
  const gone = [];
  const watch = createPresenceWatch({
    people: ['a', 'b'],
    graceMs: 60000,
    onGone: (p) => gone.push(p),
    setTimer: (fn, ms) => {
      const t = { fn, ms, cleared: false };
      timers.push(t);
      return t;
    },
    clearTimer: (t) => { t.cleared = true; },
  });
  const live = () => timers.filter((t) => !t.cleared && !t.fired);
  const fire = (t) => { t.fired = true; t.fn(); };
  return { watch, timers, gone, live, fire };
}

test('both people get the grace period to show up at all', () => {
  const { watch, live, fire, gone } = setup();
  assert.strictEqual(live().length, 2);
  watch.arrive('a#phone');
  assert.strictEqual(live().length, 1);
  fire(live()[0]);
  assert.deepStrictEqual(gone, ['b']);
});

test('leaving starts the clock and coming back stops it', () => {
  const { watch, live, gone } = setup();
  watch.arrive('a#phone');
  watch.arrive('b#phone');
  watch.leave('b#phone');
  assert.strictEqual(live().length, 1);
  assert.strictEqual(live()[0].ms, 60000);
  watch.arrive('b#phone');
  assert.strictEqual(live().length, 0);
  assert.deepStrictEqual(gone, []);
});

test('a person on two devices is present until the last one leaves', () => {
  const { watch, live } = setup();
  watch.arrive('a#phone');
  watch.arrive('a#tablet');
  watch.arrive('b#phone');
  watch.leave('a#phone');
  assert.strictEqual(live().length, 0);
  assert.deepStrictEqual(watch.identitiesOf('a'), ['a#tablet']);
  watch.leave('a#tablet');
  assert.strictEqual(live().length, 1);
  assert.deepStrictEqual(watch.presentPeople(), ['b']);
});

test('strangers are ignored', () => {
  const { watch } = setup();
  watch.arrive('voice-interpreter');
  watch.arrive('c#phone');
  assert.deepStrictEqual(watch.presentPeople(), []);
  assert.deepStrictEqual(watch.identitiesOf('c'), []);
});

test('after close nobody is reported gone', () => {
  const { watch, timers, gone } = setup();
  watch.close();
  assert.ok(timers.every((t) => t.cleared));
  timers[0].fn();
  assert.deepStrictEqual(gone, []);
});
```

Run: `node --test presence-watch.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * Who of the two is in the room, by person rather than device, and when one
 * of them has been away too long. Each person gets the grace period from the
 * start too — someone who scanned the code but never connected ends the
 * conversation the same way as someone whose phone lost the network.
 *
 * Also the address book for data messages: a person's current identities
 * (userId#device) are where their captions go.
 */
const { baseIdentity } = require('./translator-targets');

function createPresenceWatch({ people, graceMs, onGone, setTimer = setTimeout, clearTimer = clearTimeout }) {
  const present = new Map(people.map((p) => [p, new Set()]));
  const timers = new Map();
  let closed = false;

  function startClock(person) {
    if (closed || timers.has(person)) return;
    timers.set(person, setTimer(() => {
      timers.delete(person);
      if (!closed) onGone(person);
    }, graceMs));
  }

  for (const p of people) startClock(p);

  return {
    arrive(identity) {
      const person = baseIdentity(identity);
      const devices = present.get(person);
      if (closed || !devices) return;
      devices.add(identity);
      const t = timers.get(person);
      if (t) {
        clearTimer(t);
        timers.delete(person);
      }
    },
    leave(identity) {
      const person = baseIdentity(identity);
      const devices = present.get(person);
      if (closed || !devices) return;
      devices.delete(identity);
      if (devices.size === 0) startClock(person);
    },
    identitiesOf(person) {
      return [...(present.get(person) || [])];
    },
    presentPeople() {
      return people.filter((p) => present.get(p).size > 0);
    },
    close() {
      closed = true;
      for (const t of timers.values()) clearTimer(t);
      timers.clear();
    },
  };
}

module.exports = { createPresenceWatch };
```

- [ ] **Step 3: Тест проходит** — `node --test presence-watch.test.js` → `ℹ pass 5`.

- [ ] **Step 4: Коммит**

```bash
git add presence-watch.js presence-watch.test.js
git commit -m "feat(interpreter): присутствие участников и таймер отсутствия" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: `interpreter-messages.js` — data-канал

**Files:**
- Create: `livekit-agent/interpreter-messages.js`
- Test: `livekit-agent/interpreter-messages.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const messages = require('./interpreter-messages');

test('message shapes', () => {
  assert.deepStrictEqual(messages.caption('translation', 'u1', 'Hallo', 0), {
    type: 'caption', role: 'translation', speaker: 'u1', text: 'Hallo', final: false,
  });
  assert.deepStrictEqual(messages.speaking('u1', 1), { type: 'speaking', speaker: 'u1', on: true });
  assert.deepStrictEqual(messages.status('reconnecting'), { type: 'status', state: 'reconnecting' });
});

test('send publishes reliable JSON on the interp topic to exactly the given identities', async () => {
  const calls = [];
  const participant = { publishData: async (payload, opts) => calls.push({ payload, opts }) };
  assert.strictEqual(await messages.send(participant, ['u1#phone'], messages.status('ok')), true);
  assert.deepStrictEqual(JSON.parse(Buffer.from(calls[0].payload).toString()), { type: 'status', state: 'ok' });
  assert.deepStrictEqual(calls[0].opts, { reliable: true, topic: 'interp', destination_identities: ['u1#phone'] });
});

test('nobody to send to means nothing is published', async () => {
  const participant = { publishData: async () => { throw new Error('must not be called'); } };
  assert.strictEqual(await messages.send(participant, [], messages.status('ok')), false);
  assert.strictEqual(await messages.send(undefined, ['u1#phone'], messages.status('ok')), false);
});
```

Run: `node --test interpreter-messages.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * What the interpreter tells the two phones over the LiveKit data channel,
 * topic `interp`, always addressed — a caption is for its listener (or, for
 * the speaker's own recognised text, for the speaker), never broadcast.
 *
 *   caption  { role: 'translation' | 'source', speaker, text, final }
 *            simultaneous engine: deltas, final=false (the phone breaks lines
 *            on a pause); phrase engine: whole phrases, final=true
 *   speaking { speaker, on }  — the gate started / stopped letting them through
 *   status   { state: 'reconnecting' | 'ok' | 'failed' }
 */
const TOPIC = 'interp';

const caption = (role, speaker, text, final) => ({ type: 'caption', role, speaker, text, final: Boolean(final) });
const speaking = (speaker, on) => ({ type: 'speaking', speaker, on: Boolean(on) });
const status = (state) => ({ type: 'status', state });

async function send(localParticipant, identities, msg) {
  if (!localParticipant || identities.length === 0) return false;
  await localParticipant.publishData(Buffer.from(JSON.stringify(msg)), {
    reliable: true,
    topic: TOPIC,
    destination_identities: identities,
  });
  return true;
}

module.exports = { TOPIC, caption, speaking, status, send };
```

- [ ] **Step 3: Тест проходит** — `node --test interpreter-messages.test.js` → `ℹ pass 3`.

- [ ] **Step 4: Коммит**

```bash
git add interpreter-messages.js interpreter-messages.test.js
git commit -m "feat(interpreter): сообщения data-канала interp" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 15: `backend-callback.js` — `agent-ended`

**Files:**
- Create: `livekit-agent/backend-callback.js`
- Test: `livekit-agent/backend-callback.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { notifyAgentEnded } = require('./backend-callback');

const quietLog = { warn() {} };

function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

test('posts the reason to the session endpoint with the shared secret', async () => {
  let got;
  const { server, url } = await serve((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      got = { method: req.method, path: req.url, secret: req.headers['x-interpreter-secret'], body: JSON.parse(raw) };
      res.end('{}');
    });
  });
  try {
    const r = await notifyAgentEnded({ backendUrl: `${url}/`, secret: 's3', sessionId: 'abc 1', reason: 'partner_left', log: quietLog });
    assert.deepStrictEqual(r, { ok: true, status: 200 });
    assert.deepStrictEqual(got, {
      method: 'POST',
      path: '/interpreter/internal/sessions/abc%201/agent-ended',
      secret: 's3',
      body: { reason: 'partner_left' },
    });
  } finally {
    server.close();
  }
});

test('an HTTP error is reported, not thrown', async () => {
  const { server, url } = await serve((req, res) => { res.statusCode = 500; res.end(); });
  try {
    assert.deepStrictEqual(
      await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', log: quietLog }),
      { ok: false, status: 500 },
    );
  } finally {
    server.close();
  }
});

test('an unreachable backend is reported, not thrown', async () => {
  const { server, url } = await serve(() => {});
  await new Promise((r) => server.close(r));
  assert.deepStrictEqual(
    await notifyAgentEnded({ backendUrl: url, secret: 's', sessionId: 'x', reason: 'r', log: quietLog }),
    { ok: false, status: 0 },
  );
});
```

Run: `node --test backend-callback.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * Tells the backend that an interpreter session ended on the agent's side
 * (someone stayed away, the translation could not be restored, the agent lost
 * LiveKit), so it can close billing and the room. Never throws: the backend
 * also reconciles on its own, and the agent must finish stopping either way.
 */
async function notifyAgentEnded({ backendUrl, secret, sessionId, reason, fetchFn = fetch, timeoutMs = 5000, log = console }) {
  const url = `${String(backendUrl).replace(/\/+$/, '')}/interpreter/internal/sessions/${encodeURIComponent(sessionId)}/agent-ended`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-interpreter-secret': secret },
      body: JSON.stringify({ reason }),
      signal: controller.signal,
    });
    if (!res.ok) log.warn(`[INTERPRETER] agent-ended for ${sessionId}: HTTP ${res.status}`);
    return { ok: res.ok, status: res.status };
  } catch (e) {
    log.warn(`[INTERPRETER] agent-ended for ${sessionId} failed: ${e.message}`);
    return { ok: false, status: 0 };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { notifyAgentEnded };
```

- [ ] **Step 3: Тест проходит** — `node --test backend-callback.test.js` → `ℹ pass 3`.

- [ ] **Step 4: Коммит**

```bash
git add backend-callback.js backend-callback.test.js
git commit -m "feat(interpreter): колбэк agent-ended на бэкенд" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: `interpreter.js` — сессия разговора в комнате

**Files:**
- Create: `livekit-agent/interpreter.js`
- Test: `livekit-agent/interpreter.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
//
// LiveKit, OpenAI and the embed service are all faked: these check the wiring
// — which track goes to which gate and engine, what gets published, who gets
// which message. The real thing runs in bench/interpreter-bench.js.
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const interpreter = require('./interpreter');

const print = (k) => Array.from({ length: 192 }, (_, i) => (i === k ? 1 : 0));
const people = (langB = 'de') => [
  { userId: 'a', lang: 'ru', embedding: print(0) },
  { userId: 'b', lang: langB, embedding: print(1) },
];

function fakeRtc() {
  const rtc = {
    rooms: [],
    duringConnect: null,
    RoomEvent: {
      ParticipantConnected: 'participantConnected',
      ParticipantDisconnected: 'participantDisconnected',
      TrackSubscribed: 'trackSubscribed',
      Disconnected: 'disconnected',
    },
    TrackKind: { KIND_AUDIO: 1 },
    TrackSource: { SOURCE_MICROPHONE: 2 },
    AudioSource: class { async captureFrame() {} },
    AudioFrame: class {
      constructor(data, sampleRate, channels, samplesPerChannel) {
        Object.assign(this, { data, sampleRate, channels, samplesPerChannel });
      }
    },
    LocalAudioTrack: { createAudioTrack: (name, source) => ({ name, source }) },
    TrackPublishOptions: class { constructor(init) { Object.assign(this, init); } },
    AudioStream: class {
      constructor(track) { this.track = track; }
      async *[Symbol.asyncIterator]() { for (const data of this.track.frames) yield { data }; }
    },
  };
  rtc.Room = class extends EventEmitter {
    constructor() {
      super();
      rtc.rooms.push(this);
      this.remoteParticipants = new Map();
      this.published = [];
      this.data = [];
      this.localParticipant = {
        publishTrack: async (track, options) => { this.published.push({ name: track.name, options }); },
        publishData: async (payload, options) => {
          this.data.push({ msg: JSON.parse(Buffer.from(payload).toString()), options });
        },
      };
    }
    async connect(url, token, opts) {
      this.connectArgs = { url, token, opts };
      if (rtc.duringConnect) rtc.duringConnect(this);
    }
    async disconnect() { this.disconnected = true; }
  };
  return rtc;
}

function setup() {
  const rtc = fakeRtc();
  const made = [];
  const engine = (kind) => (opts) => {
    const e = { kind, opts, sent: [], closed: false, sendAudio(x) { this.sent.push(x); }, close() { this.closed = true; } };
    made.push(e);
    return e;
  };
  const deps = {
    rtc,
    engines: { simultaneous: engine('simultaneous'), phrase: engine('phrase') },
    credentials: { apiKey: 'devkey', apiSecret: 'x'.repeat(32) },
    embed: { embedPcm: async () => print(0) }, // every window sounds like a
    config: { chunkMs: 100, backendUrl: null },
  };
  return { rtc, made, deps };
}

// 400 ms of loud speech in 10 ms frames at 24 kHz: four 100 ms chunks.
const speechFrames = () => Array.from({ length: 40 }, () => new Int16Array(240).fill(3000));
const settle = () => new Promise((r) => setTimeout(r, 30));

test('configuration falls back to the documented defaults', () => {
  const c = interpreter.readConfig({});
  assert.deepStrictEqual(
    [c.model, c.fallbackModel, c.embedUrl, c.threshold, c.margin, c.chunkMs, c.gateTimeoutMs, c.hysteresis, c.speechRms, c.gain, c.presenceGraceMs],
    ['gpt-realtime-translate', 'gpt-realtime-2025-08-28', 'http://127.0.0.1:18082', 0.25, 0.05, 500, 300, 2, 400, 1.4, 60000],
  );
});

test('configuration reads the environment and keeps values in range', () => {
  const c = interpreter.readConfig({ INTERPRETER_VOICE_THRESHOLD: '0.4', INTERPRETER_GAIN: '9', INTERPRETER_GATE_HYSTERESIS: '0' });
  assert.strictEqual(c.threshold, 0.4);
  assert.strictEqual(c.gain, 4);
  assert.strictEqual(c.hysteresis, 1);
});

test('a bad request is a 400 and opens no room', async () => {
  const { rtc, deps } = setup();
  await assert.rejects(interpreter.startInterpreter({ roomName: 'r0' }, deps), (e) => e.statusCode === 400);
  await assert.rejects(
    interpreter.startInterpreter({ sessionId: 's', roomName: 'r0', participants: [people()[0]] }, deps),
    (e) => e.statusCode === 400 && /exactly two/.test(e.message),
  );
  assert.strictEqual(rtc.rooms.length, 0);
});

test('it publishes a track per listener and reports itself without voice prints', async () => {
  const { rtc, made, deps } = setup();
  assert.deepStrictEqual(
    await interpreter.startInterpreter({ sessionId: 's1', roomName: 'r-tracks', participants: people() }, deps),
    { status: 'started' },
  );
  try {
    const room = rtc.rooms[0];
    assert.strictEqual(room.connectArgs.opts.autoSubscribe, true);
    assert.deepStrictEqual(room.published.map((p) => p.name).sort(), ['interp-for-a', 'interp-for-b']);
    assert.deepStrictEqual(made.map((e) => [e.kind, e.opts.targetLang]).sort(), [['simultaneous', 'de'], ['simultaneous', 'ru']]);
    assert.match(made[0].opts.safetyId, /^[0-9a-f]{32}$/);
    const status = interpreter.getInterpreterStatus('r-tracks');
    assert.strictEqual(status.running, true);
    assert.strictEqual(status.directions.length, 2);
    assert.ok(!JSON.stringify(status).includes('mbedding'));
    assert.deepStrictEqual(
      await interpreter.startInterpreter({ sessionId: 's1', roomName: 'r-tracks', participants: people() }, deps),
      { status: 'already_running' },
    );
  } finally {
    assert.deepStrictEqual(await interpreter.stopInterpreter('r-tracks'), { status: 'stopped' });
  }
  assert.strictEqual(rtc.rooms[0].disconnected, true);
  assert.ok(made.every((e) => e.closed));
  assert.deepStrictEqual(await interpreter.stopInterpreter('r-tracks'), { status: 'not_running' });
});

test('a pair the model cannot speak runs that direction on the phrase engine', async () => {
  const { made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's2', roomName: 'r-sk', participants: people('sk') }, deps);
  try {
    const toSk = made.find((e) => e.opts.targetLang === 'sk');
    assert.strictEqual(toSk.kind, 'phrase');
    assert.strictEqual(toSk.opts.model, 'gpt-realtime-2025-08-28');
    assert.strictEqual(toSk.opts.sourceLang, 'ru');
  } finally {
    await interpreter.stopInterpreter('r-sk');
  }
});

test("the owner's speech reaches only the engine that translates them", async () => {
  const { rtc, made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's3', roomName: 'r-flow', participants: people() }, deps);
  try {
    rtc.rooms[0].emit('trackSubscribed', { kind: 1, frames: speechFrames() }, { name: 'mic' }, { identity: 'a#dev1' });
    await settle();
    const toB = made.find((e) => e.opts.targetLang === 'de');
    const toA = made.find((e) => e.opts.targetLang === 'ru');
    assert.ok(toB.sent.length >= 3, `a→b got ${toB.sent.length} chunks`);
    assert.ok(toB.sent.every((c) => c.some((x) => x !== 0)), 'speech, not silence');
    assert.strictEqual(toA.sent.length, 0);
  } finally {
    await interpreter.stopInterpreter('r-flow');
  }
});

test('a track that arrives while the room is still connecting is not lost', async () => {
  const { rtc, made, deps } = setup();
  rtc.duringConnect = (room) => room.emit('trackSubscribed', { kind: 1, frames: speechFrames() }, { name: 'mic' }, { identity: 'a#dev1' });
  await interpreter.startInterpreter({ sessionId: 's4', roomName: 'r-early', participants: people() }, deps);
  try {
    await settle();
    assert.ok(made.find((e) => e.opts.targetLang === 'de').sent.length >= 3);
  } finally {
    await interpreter.stopInterpreter('r-early');
  }
});

test('captions go to their listener, recognised speech back to its speaker', async () => {
  const { rtc, made, deps } = setup();
  await interpreter.startInterpreter({ sessionId: 's5', roomName: 'r-captions', participants: people() }, deps);
  try {
    const room = rtc.rooms[0];
    room.emit('participantConnected', { identity: 'a#dev1' });
    room.emit('participantConnected', { identity: 'b#dev1' });
    const toB = made.find((e) => e.opts.targetLang === 'de');
    toB.opts.onTranslationText('Guten Tag', false);
    toB.opts.onSourceText('Добрый день', false);
    await settle();
    assert.deepStrictEqual(room.data.map((d) => [d.msg.role, d.msg.speaker, d.msg.text, d.options.destination_identities]), [
      ['translation', 'a', 'Guten Tag', ['b#dev1']],
      ['source', 'a', 'Добрый день', ['a#dev1']],
    ]);
    assert.ok(room.data.every((d) => d.options.topic === 'interp' && d.options.reliable === true));
  } finally {
    await interpreter.stopInterpreter('r-captions');
  }
});
```

Run: `node --test interpreter.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
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
// The embed service failing is survivable chunk by chunk (the gate fails
// open); failing for this long means nobody's voice is being checked.
const FATAL_FAIL_OPEN_MS = 60_000;

const sessions = new Map(); // roomName → session

function num(value, fallback) {
  const n = parseFloat(value);
  return Number.isFinite(n) ? n : fallback;
}

function readConfig(env = process.env) {
  return {
    lkUrl: env.LIVEKIT_WS_URL || 'ws://localhost:7880',
    openaiKey: env.OPENAI_API_KEY,
    model: env.INTERPRETER_MODEL || 'gpt-realtime-translate',
    fallbackModel: env.INTERPRETER_FALLBACK_MODEL || 'gpt-realtime-2025-08-28',
    embedUrl: env.VOICE_EMBED_URL || 'http://127.0.0.1:18082',
    threshold: num(env.INTERPRETER_VOICE_THRESHOLD, 0.25),
    margin: num(env.INTERPRETER_VOICE_MARGIN, 0.05),
    chunkMs: num(env.INTERPRETER_GATE_CHUNK_MS, 500),
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
      onAudio: (int16) => {
        if (session.stopping) return;
        applyGain(int16, cfg.gain);
        out.push(new rtc.AudioFrame(int16, SAMPLE_RATE, 1, int16.length));
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
    for await (const frame of new session.rtc.AudioStream(track, SAMPLE_RATE, 1)) {
      if (session.stopping || lane.listening !== token) break;
      lane.gate.push(new Int16Array(frame.data));
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
  return selftestTranslate({ apiKey: cfg.openaiKey, model: cfg.model, wsFactory: deps.wsFactory });
}

module.exports = { startInterpreter, stopInterpreter, getInterpreterStatus, selftest, readConfig, AGENT_IDENTITY };
```

- [ ] **Step 3: Тест проходит**

```bash
node --test interpreter.test.js && npm test 2>&1 | tail -8
```

Ожидается: `ℹ pass 8` в файле, всего `ℹ pass 141`, `ℹ fail 0`.

- [ ] **Step 4: Коммит**

```bash
git add interpreter.js interpreter.test.js
git commit -m "feat(interpreter): сессия разговора с переводом в комнате LiveKit" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 17: HTTP-ручки агента под секретом

**Files:**
- Create: `livekit-agent/interpreter-routes.js`
- Test: `livekit-agent/interpreter-routes.test.js`
- Modify: `livekit-agent/index.js` (require рядом с `require('./hold-music')`; блок ручек перед `// ── AI VOICE ASSISTANT LOGIC ──`)

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const express = require('express');
const { registerInterpreterRoutes } = require('./interpreter-routes');

async function app(handlers, secret = 's3cret') {
  const a = express();
  a.use(express.json());
  registerInterpreterRoutes(a, { secret, ...handlers });
  return new Promise((resolve) => {
    const server = a.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

const json = (body) => ({
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-interpreter-secret': 's3cret' },
  body: JSON.stringify(body),
});

test('without the right secret nothing runs', async () => {
  let called = false;
  const { server, url } = await app({ start: async () => { called = true; } });
  try {
    const none = await fetch(`${url}/interpreter/start`, { method: 'POST' });
    const wrong = await fetch(`${url}/interpreter/start`, { method: 'POST', headers: { 'x-interpreter-secret': 'nope' } });
    assert.deepStrictEqual([none.status, wrong.status], [401, 401]);
    assert.strictEqual(called, false);
  } finally {
    server.close();
  }
});

test('with no secret configured the routes refuse to work', async () => {
  const { server, url } = await app({}, '');
  try {
    assert.strictEqual((await fetch(`${url}/interpreter/selftest`)).status, 503);
  } finally {
    server.close();
  }
});

test('start passes the body through and maps a 400 from the interpreter', async () => {
  const seen = [];
  const { server, url } = await app({
    start: async (body) => {
      seen.push(body);
      if (body.bad) {
        const e = new Error('exactly two participants required');
        e.statusCode = 400;
        throw e;
      }
      return { status: 'started' };
    },
  });
  try {
    const ok = await fetch(`${url}/interpreter/start`, json({ roomName: 'r' }));
    assert.deepStrictEqual([ok.status, await ok.json()], [200, { status: 'started' }]);
    const bad = await fetch(`${url}/interpreter/start`, json({ bad: true }));
    assert.deepStrictEqual([bad.status, await bad.json()], [400, { error: 'exactly two participants required' }]);
    assert.deepStrictEqual(seen, [{ roomName: 'r' }, { bad: true }]);
  } finally {
    server.close();
  }
});

test('stop needs a room name', async () => {
  const { server, url } = await app({ stop: async (roomName) => ({ status: 'stopped', roomName }) });
  try {
    assert.strictEqual((await fetch(`${url}/interpreter/stop`, json({}))).status, 400);
    const ok = await fetch(`${url}/interpreter/stop`, json({ roomName: 'r1' }));
    assert.deepStrictEqual(await ok.json(), { status: 'stopped', roomName: 'r1' });
  } finally {
    server.close();
  }
});

test('status answers for the room in the path', async () => {
  const { server, url } = await app({ status: (roomName) => ({ running: false, roomName }) });
  try {
    const res = await fetch(`${url}/interpreter/status/interp-1`, { headers: { 'x-interpreter-secret': 's3cret' } });
    assert.deepStrictEqual(await res.json(), { running: false, roomName: 'interp-1' });
  } finally {
    server.close();
  }
});

test('selftest reports how long it took', async () => {
  const { server, url } = await app({ selftest: async () => ({ ok: true, reason: 'fine' }) });
  try {
    const body = await (await fetch(`${url}/interpreter/selftest`, { headers: { 'x-interpreter-secret': 's3cret' } })).json();
    assert.strictEqual(body.ok, true);
    assert.strictEqual(typeof body.latencyMs, 'number');
  } finally {
    server.close();
  }
});
```

Run: `node --test interpreter-routes.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать `interpreter-routes.js`**

```js
'use strict';
/**
 * The interpreter's HTTP surface on the agent port (:3100). Only the backend
 * calls it, with INTERPRETER_SHARED_SECRET in x-interpreter-secret: start
 * carries both people's voice prints, and on some hosts the port is reachable
 * from more than localhost.
 */
const crypto = require('crypto');

function sameSecret(given, expected) {
  const a = Buffer.from(String(given));
  const b = Buffer.from(String(expected));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function registerInterpreterRoutes(app, { secret, start, stop, status, selftest }) {
  const guard = (req, res, next) => {
    if (!secret) return res.status(503).json({ error: 'INTERPRETER_SHARED_SECRET is not set on the agent' });
    if (!sameSecret(req.get('x-interpreter-secret') || '', secret)) return res.status(401).json({ error: 'unauthorized' });
    return next();
  };

  app.post('/interpreter/start', guard, async (req, res) => {
    try {
      res.json(await start(req.body || {}));
    } catch (e) {
      console.error('[INTERPRETER] start failed:', e.message);
      res.status(e.statusCode || 500).json({ error: e.message });
    }
  });

  app.post('/interpreter/stop', guard, async (req, res) => {
    const { roomName } = req.body || {};
    if (!roomName) return res.status(400).json({ error: 'roomName required' });
    try {
      return res.json(await stop(roomName));
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  });

  app.get('/interpreter/status/:roomName', guard, (req, res) => res.json(status(req.params.roomName)));

  app.get('/interpreter/selftest', guard, async (req, res) => {
    const t0 = Date.now();
    try {
      const result = await selftest();
      res.json({ ...result, latencyMs: Date.now() - t0 });
    } catch (e) {
      res.status(500).json({ ok: false, reason: e.message, latencyMs: Date.now() - t0 });
    }
  });
}

module.exports = { registerInterpreterRoutes };
```

- [ ] **Step 3: Подключить в `index.js`**

После строки `const { startHoldMusic, stopHoldMusic, getHoldMusicStatus } = require('./hold-music');` добавить:

```js
const interpreter = require('./interpreter');
const { registerInterpreterRoutes } = require('./interpreter-routes');
```

Перед блоком

```js
// ═══════════════════════════════════════════
// ── AI VOICE ASSISTANT LOGIC ──
// ═══════════════════════════════════════════
```

вставить:

```js
// ═══════════════════════════════════════════
// ── FACE-TO-FACE INTERPRETER ──
// ═══════════════════════════════════════════

registerInterpreterRoutes(app, {
  secret: process.env.INTERPRETER_SHARED_SECRET,
  start: (body) => interpreter.startInterpreter(body),
  stop: (roomName) => interpreter.stopInterpreter(roomName),
  status: (roomName) => interpreter.getInterpreterStatus(roomName),
  selftest: () => interpreter.selftest(),
});

```

- [ ] **Step 4: Проверить**

```bash
node --test interpreter-routes.test.js && node --check index.js && echo index-ok && npm test 2>&1 | tail -8
```

Ожидается: `ℹ pass 6`, `index-ok`, весь набор `ℹ pass 147`, `ℹ fail 0`.

- [ ] **Step 5: Коммит**

```bash
git add interpreter-routes.js interpreter-routes.test.js index.js
git commit -m "feat(interpreter): ручки агента /interpreter/* под общим секретом" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 18: `bench/bench-report.js` — числа и страница отчёта

**Files:**
- Create: `livekit-agent/bench/bench-report.js`
- Test: `livekit-agent/bench/bench-report.test.js`

- [ ] **Step 1: Падающий тест**

```js
// Run with: node --test  (from livekit-agent/)
const test = require('node:test');
const assert = require('node:assert');
const r = require('./bench-report');

test('percentile and summary', () => {
  assert.strictEqual(r.percentile([], 50), null);
  assert.strictEqual(r.percentile([5, 1, 3], 0), 1);
  assert.strictEqual(r.percentile([5, 1, 3], 100), 5);
  assert.deepStrictEqual(r.summarize([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), { n: 10, min: 1, p10: 1, median: 5, p90: 9, max: 10 });
  assert.deepStrictEqual(r.summarize([]), { n: 0 });
});

test('first voiced frame and voiced time inside a window', () => {
  const frames = [
    { t: 100, rms: 10 }, { t: 110, rms: 900 }, { t: 120, rms: 800 }, { t: 300, rms: 1000 },
  ];
  assert.strictEqual(r.firstVoicedAfter(frames, 100, 200), 10);
  assert.strictEqual(r.firstVoicedAfter(frames, 130, 200), null);
  assert.strictEqual(r.voicedMs(frames, 100, 200), 20);
  assert.strictEqual(r.voicedMs(frames, 0, 1000), 30);
});

test('thresholds sit between the owner and the intruders', () => {
  const own = Array.from({ length: 10 }, (_, i) => ({ own: 0.6 + i * 0.02, other: 0.1 }));
  const intruder = Array.from({ length: 10 }, (_, i) => ({ own: 0.04 + i * 0.01, other: 0.5 }));
  // owner: s_own p10 0.60, gap p10 0.50; intruders: s_own p90 0.12, gap p90 -0.38
  assert.deepStrictEqual(r.suggestThresholds(own, intruder), {
    threshold: 0.36, margin: 0.06, thresholdSeparates: true, marginSeparates: true,
  });
});

test('overlapping scores are reported as not separating', () => {
  const own = [{ own: 0.3, other: 0.25 }];
  const intruder = [{ own: 0.35, other: 0.2 }];
  const s = r.suggestThresholds(own, intruder);
  assert.strictEqual(s.thresholdSeparates, false);
  assert.strictEqual(s.marginSeparates, false);
  assert.strictEqual(r.suggestThresholds([], intruder), null);
});

test('the report page carries every section', () => {
  const md = r.renderReport({
    pair: 'ru-de',
    startedAt: '2026-11-01T10:00:00.000Z',
    config: { model: 'gpt-realtime-translate', fallbackModel: 'gpt-realtime-2025-08-28', threshold: 0.25, margin: 0.05, chunkMs: 500, hysteresis: 2 },
    latencies: [{ phrase: 'ru-1', direction: 'ru→de', engine: 'simultaneous', ms: 1840 }],
    silentChecks: [{ situation: 'leak', voicedMs: 0 }],
    scoreGroups: [{ group: 'own A', scores: [{ own: 0.7, other: 0.1, pass: true }] }],
    suggestion: { threshold: 0.36, margin: 0.21, thresholdSeparates: true, marginSeparates: true },
    captions: [{ listener: 'bench-b', role: 'translation', text: 'Guten Tag' }],
    sameLanguage: [{ input: 'de-1', target: 'de', outputSeconds: 0 }],
    embedLatency: { n: 3, min: 20, p10: 20, median: 31, p90: 55, max: 55 },
    failOpen: 0,
  });
  for (const part of ['ru-de', '1840', 'leak', 'own A', '0.36', 'Guten Tag', 'de-1', '20 / 20 / 31 / 55 / 55', 'fail-open']) {
    assert.ok(md.includes(part), part);
  }
});
```

Run: `node --test bench/bench-report.test.js` → FAIL (`Cannot find module`).

- [ ] **Step 2: Реализовать**

```js
'use strict';
/**
 * Numbers and the markdown page for bench/interpreter-bench.js. Pure, so the
 * arithmetic is tested; the bench itself needs LiveKit, OpenAI and the embed
 * service.
 */

function percentile(values, p) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

function summarize(values) {
  if (values.length === 0) return { n: 0 };
  return {
    n: values.length,
    min: percentile(values, 0),
    p10: percentile(values, 10),
    median: percentile(values, 50),
    p90: percentile(values, 90),
    max: percentile(values, 100),
  };
}

/** ms from `from` to the first 10 ms frame at or above `threshold` RMS, before `until`; null if none. */
function firstVoicedAfter(frames, from, until, threshold = 300) {
  for (const f of frames) if (f.t >= from && f.t < until && f.rms >= threshold) return f.t - from;
  return null;
}

/** Milliseconds of 10 ms frames at or above `threshold` RMS inside [from, to). */
function voicedMs(frames, from, to, threshold = 300) {
  let n = 0;
  for (const f of frames) if (f.t >= from && f.t < to && f.rms >= threshold) n += 1;
  return n * 10;
}

/**
 * Thresholds that would separate the owner's own speech from sound intruding
 * on the owner's phone (the partner's voice, the earpiece's translation):
 * midpoints between the owner's 10th percentile and the intruders' 90th.
 */
function suggestThresholds(own, intruder) {
  const round = (x) => Math.round(x * 100) / 100;
  const ownSim = percentile(own.map((s) => s.own), 10);
  const intSim = percentile(intruder.map((s) => s.own), 90);
  const ownGap = percentile(own.map((s) => s.own - s.other), 10);
  const intGap = percentile(intruder.map((s) => s.own - s.other), 90);
  if (ownSim === null || intSim === null) return null;
  return {
    threshold: round((ownSim + intSim) / 2),
    margin: round((ownGap + intGap) / 2),
    thresholdSeparates: ownSim > intSim,
    marginSeparates: ownGap > intGap,
  };
}

const fmt = (x) => (x === null || x === undefined ? '—' : typeof x === 'number' && !Number.isInteger(x) ? x.toFixed(2) : String(x));
const five = (s) => (s.n === 0 ? '—' : [s.min, s.p10, s.median, s.p90, s.max].map(fmt).join(' / '));

function renderReport(r) {
  const c = r.config;
  const lines = [
    `# Стенд переводчика — ${r.pair} — ${r.startedAt}`,
    '',
    `Синхронная модель \`${c.model}\`, фразовая \`${c.fallbackModel}\`; τ=${c.threshold}, δ=${c.margin}, кусок ${c.chunkMs} мс, гистерезис ${c.hysteresis}.`,
    '',
    '## Задержка: от начала фразы до первого звука перевода',
    '',
    '| Фраза | Направление | Движок | мс |',
    '|---|---|---|---|',
    ...r.latencies.map((l) => `| ${l.phrase} | ${l.direction} | ${l.engine} | ${fmt(l.ms)} |`),
    '',
    '## Должно быть тихо',
    '',
    '| Ситуация | Слышно у слушателя, мс |',
    '|---|---|',
    ...r.silentChecks.map((s) => `| ${s.situation} | ${s.voicedMs} |`),
    '',
    '## Сверка голоса',
    '',
    '| Группа | n | s_own: min / p10 / медиана / p90 / max | s_own − s_other: min / p10 / медиана / p90 / max | пропущено |',
    '|---|---|---|---|---|',
    ...r.scoreGroups.map((g) => {
      const own = summarize(g.scores.map((s) => s.own));
      const gap = summarize(g.scores.map((s) => s.own - s.other));
      return `| ${g.group} | ${g.scores.length} | ${five(own)} | ${five(gap)} | ${g.scores.filter((s) => s.pass).length} |`;
    }),
    '',
    '## Предлагаемые пороги',
    '',
    r.suggestion
      ? `τ = ${r.suggestion.threshold} (разделяет: ${r.suggestion.thresholdSeparates ? 'да' : 'нет'}), δ = ${r.suggestion.margin} (разделяет: ${r.suggestion.marginSeparates ? 'да' : 'нет'})`
      : 'Недостаточно данных.',
    '',
    '## Субтитры',
    '',
    ...r.captions.map((cap) => `- ${cap.listener} / ${cap.role}: «${cap.text}»`),
    '',
    '## Речь, уже на языке перевода',
    '',
    '| Вход | Цель | Секунд перевода на выходе |',
    '|---|---|---|',
    ...r.sameLanguage.map((s) => `| ${s.input} | ${s.target} | ${fmt(s.outputSeconds)} |`),
    '',
    '## Сервис сверки',
    '',
    `Время ответа, мс (min / p10 / медиана / p90 / max): ${five(r.embedLatency)}`,
    '',
    '## Пропуски без проверки (fail-open)',
    '',
    String(r.failOpen),
    '',
  ];
  return lines.join('\n');
}

module.exports = { percentile, summarize, firstVoicedAfter, voicedMs, suggestThresholds, renderReport };
```

- [ ] **Step 3: Тест проходит** — `node --test bench/bench-report.test.js` → `ℹ pass 5`; весь `npm test` — `ℹ pass 152`, `ℹ fail 0`.

- [ ] **Step 4: Коммит**

```bash
git add bench/bench-report.js bench/bench-report.test.js
git commit -m "test(interpreter): статистика и страница отчёта стенда" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 19: `bench/interpreter-bench.js` — стенд

**Files:**
- Create: `livekit-agent/bench/interpreter-bench.js`

- [ ] **Step 1: Написать стенд**

```js
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
  const heard = []; // { t, rms } per 10 ms
  const heardPcm = []; // { t, samples }
  const captions = []; // { t, msg }
  room.on(rtc.RoomEvent.TrackSubscribed, (track, publication, participant) => {
    if (participant.identity !== interpreter.AGENT_IDENTITY || publication.name !== listenTo) return;
    (async () => {
      for await (const frame of new rtc.AudioStream(track, SR, 1)) {
        const samples = new Int16Array(frame.data);
        const t = Date.now();
        heard.push({ t, rms: rms(samples) });
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
  await room.connect(process.env.LIVEKIT_WS_URL || 'ws://localhost:7880', await tokenFor(identity, roomName), {
    autoSubscribe: true,
    dynacast: false,
  });
  const source = new rtc.AudioSource(SR, 1);
  const track = rtc.LocalAudioTrack.createAudioTrack('mic', source);
  await room.localParticipant.publishTrack(track, new rtc.TrackPublishOptions({ source: rtc.TrackSource.SOURCE_MICROPHONE }));

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

/** What gpt-realtime-translate says when the speech is already in the target language. */
async function sameLanguage(input, target) {
  const samples = clip(input);
  let bytes = 0;
  const session = createTranslateSession({
    apiKey: process.env.OPENAI_API_KEY,
    targetLang: target,
    safetyId: 'interpreter-bench',
    onAudio: (pcm) => { bytes += pcm.byteLength; },
  });
  await sleep(1500);
  for (let i = 0; i < samples.length; i += 2400) {
    session.sendAudio(samples.subarray(i, i + 2400));
    await sleep(100);
  }
  for (let i = 0; i < 40; i++) {
    session.sendAudio(new Int16Array(2400));
    await sleep(100);
  }
  session.close();
  return { input, target, outputSeconds: bytes / (SR * 2) };
}

function captionTexts(name, bot) {
  const byRole = {};
  for (const c of bot.captions) {
    if (c.msg.type !== 'caption') continue;
    byRole[c.msg.role] = (byRole[c.msg.role] || '') + c.msg.text + (c.msg.final ? ' | ' : '');
  }
  return Object.entries(byRole).map(([role, text]) => ({ listener: name, role, text: text.trim() }));
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
  const a = await createBot({ identity: `${pair.a.id}#bench`, roomName, listenTo: `interp-for-${pair.a.id}` });
  const b = await createBot({ identity: `${pair.b.id}#bench`, roomName, listenTo: `interp-for-${pair.b.id}` });
  await sleep(3000); // let subscriptions settle

  const startedAt = new Date().toISOString();
  const T0 = Date.now();
  const at = (ms) => T0 + ms;
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
  await a.close();
  await b.close();
  await interpreter.stopInterpreter(roomName);

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
    captions: [...captionTexts(pair.a.id, a), ...captionTexts(pair.b.id, b)],
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
```

- [ ] **Step 2: Проверить синтаксис и что `npm test` его не подхватывает**

```bash
node --check bench/interpreter-bench.js && echo bench-ok && npm test 2>&1 | grep -c interpreter-bench
```

Ожидается: `bench-ok` и `0`.

- [ ] **Step 3: Коммит**

```bash
git add bench/interpreter-bench.js
git commit -m "test(interpreter): стенд — два бота, сценарий из синтезированных голосов, отчёт" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 20: Прогон стенда на DEV

- [ ] **Step 1: Доставить свежий код**

Тот же конвейер, что в задаче 3, шаг 2, из корня worktree:

```bash
cd /Users/dmitry/taler-id/.worktrees/interpreter
COPYFILE_DISABLE=1 tar --no-mac-metadata -czf - --exclude node_modules --exclude bench/reports -C livekit-agent . \
  | ssh dvolkov@77.73.131.137 'ssh dev-backend "rm -rf ~/interp-bench && mkdir -p ~/interp-bench && tar xzf - -C ~/interp-bench && cd ~/interp-bench && npm ci --loglevel=error >/dev/null && npm test 2>&1 | grep -E \"^# (pass|fail)\""'
```

Ожидается: `# pass N` и `# fail 0`. Это тот же набор тестов, но на Node 20 DEV.

- [ ] **Step 2: Запустить стенд (~3 минуты)**

```bash
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/interp-bench && node bench/interpreter-bench.js --env ~/taler-id/livekit-agent/.env --pair all --out bench/reports"' 2>&1 | tail -120
```

Ожидается: две страницы отчёта (`ru-de`, `ru-sk`), без исключений.
- Если стенд упал на подключении к LiveKit или к сервису сверки, разобраться по тексту ошибки. Повторять, не меняя сценарий.

- [ ] **Step 3: Забрать отчёты**

```bash
mkdir -p livekit-agent/bench/reports
ssh dvolkov@77.73.131.137 'ssh dev-backend "cd ~/interp-bench/bench/reports && tar czf - ."' | tar xzf - -C livekit-agent/bench/reports
ls livekit-agent/bench/reports
```

Ожидается: два `.md` и два `-decisions.csv`.

- [ ] **Step 4: Проверить, что прогон не задел бэкенд DEV**

```bash
ssh dvolkov@77.73.131.137 'ssh dev-backend "pm2 logs taler-id-dev --lines 300 --nostream 2>&1 | grep -i interp-bench | tail -5"'
```

Ожидается: пусто или только безобидные строки про вебхук LiveKit по незнакомой комнате. Ошибки (`Error`, стек) про `interp-bench` — сообщить пользователю.

- [ ] **Step 5: Коммит отчётов**

```bash
git add bench/reports
git commit -m "test(interpreter): отчёт стенда на DEV — ru↔de и ru↔sk" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 21: Пороги по стенду и контрольная точка

- [ ] **Step 1: Прочитать отчёты и принять решение по порогам**

В обоих `bench/reports/*.md` посмотреть раздел «Предлагаемые пороги».
- **Если хотя бы одно из «разделяет» — «да»**, взять τ и δ из отчёта `ru-de`; при расхождении между парами — меньшее τ и большее δ. В `interpreter.js` заменить значения по умолчанию, например:

```js
    threshold: num(env.INTERPRETER_VOICE_THRESHOLD, 0.25),
    margin: num(env.INTERPRETER_VOICE_MARGIN, 0.05),
```

на

```js
    threshold: num(env.INTERPRETER_VOICE_THRESHOLD, <τ из отчёта>),
    margin: num(env.INTERPRETER_VOICE_MARGIN, <δ из отчёта>),
```

  Затем:
  - поправить ожидания в тесте `configuration falls back to the documented defaults` (`interpreter.test.js`);
  - в спеке поправить строки `INTERPRETER_VOICE_THRESHOLD` / `INTERPRETER_VOICE_MARGIN` таблицы «Конфигурация» и правило пропуска в разделе фильтра.
- **Если «нет» в обоих случаях**, ничего не менять и вынести на контрольную точку: отпечаток голоса на синтезированных голосах не разделяет владельца и соседа.

- [ ] **Step 2: Тесты и коммит (если пороги менялись)**

```bash
npm test 2>&1 | tail -4
git add interpreter.js interpreter.test.js ../docs/superpowers/specs/2026-10-31-interpreter-face-to-face-design.md
git commit -m "chore(interpreter): пороги сверки голоса по отчёту стенда" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 3: Убрать временный каталог на DEV**

```bash
ssh dvolkov@77.73.131.137 'ssh dev-backend "rm -rf ~/interp-bench && echo cleaned"'
```

- [ ] **Step 4: Контрольная точка с пользователем**

Дать короткую сводку по-русски:
- задержка синхронного и фразового движка (медиана по фразам);
- «должно быть тихо»: сколько миллисекунд утечки и эха дошло до слушателя;
- разделение голосов и выбранные пороги, либо их отсутствие;
- что модель делает с речью на языке перевода (`PROBE.md`, п. 5, и раздел отчёта);
- качество перевода по субтитрам — 2–3 примера;
- сколько стоил прогон.

Затем спросить: идём в план 2 (бэкенд, биллинг, сквозной набор) с этими настройками или что-то меняем. План 2 не начинать без ответа.
