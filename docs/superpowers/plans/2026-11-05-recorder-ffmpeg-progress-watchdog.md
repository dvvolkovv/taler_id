# Recorder Progress Watchdog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Устранить обрыв длинных записей по общему ffmpeg-таймауту и честно сохранять/показывать `partial`, если часть дорожек всё же не обработана.

**Architecture:** Новый изолированный Node-раннер запускает ffmpeg через `spawn`, не имеет общего deadline и останавливает процесс только после пяти минут без продвижения `time=...`. Recorder использует его на всех живых этапах конвертации; чистая функция вычисляет `done`/`partial`/`failed` от наличия записи и ошибок. Backend сохраняет `partial` после транскрибации, а Flutter показывает локализованное предупреждение и передаёт флаг ассистенту.

**Tech Stack:** Node.js 20 (`node:test`, `child_process.spawn`), NestJS/TypeScript/Jest, Flutter/Dart (`flutter_test`, ARB), ffmpeg/ffprobe, существующие `taler_id_tests`.

---

## Карта файлов

### Backend + agent, репозиторий `/Users/dmitry/taler-id`, ветка `fix/recorder-progress-watchdog`

- Create `livekit-agent/ffmpeg-process.js` — запуск ffmpeg, прогресс-watchdog, ограниченные stdout/stderr, завершение зависшего процесса.
- Create `livekit-agent/ffmpeg-process.test.js` — unit-тесты успешной работы, ошибок, отсутствия общего deadline, stall/SIGTERM/SIGKILL и cleanup.
- Create `livekit-agent/recording-result.js` — чистое вычисление итогового статуса.
- Create `livekit-agent/recording-result.test.js` — статусы `done`/`partial`/`failed`.
- Create `livekit-agent/recorder-processing.test.js` — структурная регрессия: recorder действительно использует раннер и не возвращает старые deadline.
- Modify `livekit-agent/recorder.js` — замена живых `execFile`-вызовов ffmpeg и итогового статуса; PCM сохраняются и при mix/upload ошибке.
- Modify `src/voice/voice.service.ts` — успешная транскрибация сохраняет `partial`.
- Modify `src/voice/voice.service.summary-participants.spec.ts` — регрессионный тест сохранения `partial`.

### Mobile, репозиторий `/Users/dmitry/Downloads/taler_id_mobile`, ветка `fix/recorder-progress-watchdog`

- Create `lib/features/call_history/presentation/widgets/partial_recording_banner.dart` — компактная метка и полное предупреждение.
- Create `test/features/call_history/partial_recording_banner_test.dart` — RU/EN widget-тесты.
- Modify `lib/features/call_history/presentation/screens/call_history_screen.dart` — классификация и отображение `partial`.
- Modify `test/features/call_history/meeting_card_state_test.dart` — классификация `partial`.
- Modify `lib/features/assistant/tools/assistant_tools_executor.dart` — `partialRecording` в tool result.
- Modify `test/features/assistant/meeting_tools_test.dart` — проверка флага.
- Modify `lib/l10n/app_ru.arb`, `lib/l10n/app_en.arb` и generated localization files — RU/EN строки.

---

### Task 1: Чистое вычисление статуса результата

**Files:**
- Create: `livekit-agent/recording-result.js`
- Test: `livekit-agent/recording-result.test.js`

- [ ] **Step 1: Написать падающий тест трёх итоговых статусов**

```js
// livekit-agent/recording-result.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { recordingStatus } = require('./recording-result');

test('done means a recording exists and no processing failed', () => {
  assert.equal(recordingStatus('https://x/recording.mp3', false), 'done');
});

test('partial means a recording exists but some processing failed', () => {
  assert.equal(recordingStatus('https://x/recording.mp3', true), 'partial');
});

test('failed means there is no usable recording, regardless of earlier errors', () => {
  assert.equal(recordingStatus(null, false), 'failed');
  assert.equal(recordingStatus(null, true), 'failed');
  assert.equal(recordingStatus('', true), 'failed');
});
```

- [ ] **Step 2: Запустить тест и убедиться, что он красный**

Run:

```bash
cd /Users/dmitry/taler-id/livekit-agent
node --test recording-result.test.js
```

Expected: FAIL, `Cannot find module './recording-result'`.

- [ ] **Step 3: Реализовать минимальную функцию**

```js
// livekit-agent/recording-result.js
'use strict';

/**
 * A usable file decides whether the result is partial or failed; hadErrors
 * decides whether a usable file is allowed to be called complete.
 */
function recordingStatus(recordingUrl, hadErrors) {
  if (!recordingUrl) return 'failed';
  return hadErrors ? 'partial' : 'done';
}

module.exports = { recordingStatus };
```

- [ ] **Step 4: Запустить тест повторно**

Run:

```bash
cd /Users/dmitry/taler-id/livekit-agent
node --test recording-result.test.js
```

Expected: 3 tests PASS, 0 FAIL.

- [ ] **Step 5: Commit**

```bash
cd /Users/dmitry/taler-id
git add livekit-agent/recording-result.js livekit-agent/recording-result.test.js
git commit -m "test(recorder): статус результата по аудио и ошибкам" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 2: Базовый ffmpeg-раннер с диагностикой и ограниченным выводом

**Files:**
- Create: `livekit-agent/ffmpeg-process.js`
- Test: `livekit-agent/ffmpeg-process.test.js`

- [ ] **Step 1: Написать падающие тесты success, spawn error, nonzero exit и log tail**

```js
// livekit-agent/ffmpeg-process.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { runFfmpegProcess } = require('./ffmpeg-process');

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.stdout = new EventEmitter();
    this.stderr = new EventEmitter();
    this.kills = [];
  }

  kill(signal) {
    this.kills.push(signal);
    return true;
  }
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('condition did not become true');
    await delay(5);
  }
}

test('resolves stdout and bounded stderr after a zero exit', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess(['-version'], {
    spawnImpl: (command, args, options) => {
      assert.equal(command, 'ffmpeg');
      assert.deepEqual(args, ['-version']);
      assert.deepEqual(options, { stdio: ['ignore', 'pipe', 'pipe'] });
      return child;
    },
  });
  child.stdout.emit('data', 'out');
  child.stderr.emit('data', 'err');
  child.emit('close', 0, null);

  assert.deepEqual(await promise, { stdout: 'out', stderr: 'err' });
});

test('rejects a spawn error', async () => {
  const child = new FakeChild();
  const expected = new Error('spawn failed');
  const promise = runFfmpegProcess([], { spawnImpl: () => child });
  const rejection = assert.rejects(promise, (error) => error === expected);
  child.emit('error', expected);
  await rejection;
});

test('rejects a nonzero exit with stderr and the exit code', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], { spawnImpl: () => child });
  const rejection = assert.rejects(promise, (error) => {
    assert.equal(error.code, 'FFMPEG_EXIT');
    assert.equal(error.exitCode, 2);
    assert.match(error.stderr, /bad input/);
    return true;
  });
  child.stderr.emit('data', 'bad input');
  child.emit('close', 2, null);
  await rejection;
});

test('keeps only the configured tail of stdout and stderr', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    maxLogTailChars: 8,
  });
  child.stdout.emit('data', 'abcdefghij');
  child.stderr.emit('data', '1234567890');
  child.emit('close', 0, null);

  assert.deepEqual(await promise, { stdout: 'cdefghij', stderr: '34567890' });
});
```

- [ ] **Step 2: Запустить тесты и убедиться, что они красные**

Run:

```bash
cd /Users/dmitry/taler-id/livekit-agent
node --test ffmpeg-process.test.js
```

Expected: FAIL, `Cannot find module './ffmpeg-process'`.

- [ ] **Step 3: Реализовать базовый раннер**

```js
// livekit-agent/ffmpeg-process.js
'use strict';

const { spawn } = require('node:child_process');

const DEFAULT_MAX_LOG_TAIL_CHARS = 64 * 1024;

function appendTail(previous, chunk, limit) {
  const next = previous + chunk.toString();
  return next.length > limit ? next.slice(-limit) : next;
}

function runFfmpegProcess(args, options = {}) {
  const {
    command = 'ffmpeg',
    spawnImpl = spawn,
    maxLogTailChars = DEFAULT_MAX_LOG_TAIL_CHARS,
  } = options;

  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImpl(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      reject(error);
      return;
    }

    let stdout = '';
    let stderr = '';
    let settled = false;

    const onStdout = (chunk) => {
      stdout = appendTail(stdout, chunk, maxLogTailChars);
    };
    const onStderr = (chunk) => {
      stderr = appendTail(stderr, chunk, maxLogTailChars);
    };
    const onError = (error) => finish(error);
    const onClose = (code, signal) => {
      if (code === 0) {
        finish(null, { stdout, stderr });
        return;
      }
      const error = new Error(
        `ffmpeg exited with code ${code}${signal ? ` (${signal})` : ''}`,
      );
      error.code = 'FFMPEG_EXIT';
      error.exitCode = code;
      error.signal = signal;
      error.stderr = stderr;
      finish(error);
    };

    function finish(error, value) {
      if (settled) return;
      settled = true;
      child.stdout.removeListener('data', onStdout);
      child.stderr.removeListener('data', onStderr);
      child.removeListener('error', onError);
      child.removeListener('close', onClose);
      if (error) reject(error);
      else resolve(value);
    }

    child.stdout.on('data', onStdout);
    child.stderr.on('data', onStderr);
    child.on('error', onError);
    child.on('close', onClose);
  });
}

module.exports = { runFfmpegProcess };
```

- [ ] **Step 4: Запустить тесты**

Run:

```bash
cd /Users/dmitry/taler-id/livekit-agent
node --test ffmpeg-process.test.js
```

Expected: 4 tests PASS, 0 FAIL.

- [ ] **Step 5: Commit**

```bash
cd /Users/dmitry/taler-id
git add livekit-agent/ffmpeg-process.js livekit-agent/ffmpeg-process.test.js
git commit -m "feat(recorder): изолированный запуск ffmpeg с диагностикой" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 3: Watchdog по прогрессу вместо общего deadline

**Files:**
- Modify: `livekit-agent/ffmpeg-process.js`
- Modify: `livekit-agent/ffmpeg-process.test.js`

- [ ] **Step 1: Добавить падающие тесты отсутствия общего deadline, stall, SIGKILL и cleanup**

Добавить в `livekit-agent/ffmpeg-process.test.js`:

```js
test('total runtime may exceed the idle limit while progress continues', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 200,
  });
  for (const time of ['00:00:01.00', '00:00:02.00', '00:00:03.00', '00:00:04.00']) {
    child.stderr.emit('data', `frame=10 time=${time} bitrate=48kbits/s`);
    await delay(75);
    assert.deepEqual(child.kills, []);
  }
  child.emit('close', 0, null);
  await promise;
});

test('a stalled process gets SIGTERM and rejects FFMPEG_STALLED', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 50,
    killTimeoutMs: 1000,
  });
  const rejection = assert.rejects(promise, (error) => {
    assert.equal(error.code, 'FFMPEG_STALLED');
    assert.equal(error.signal, 'SIGTERM');
    return true;
  });

  await waitFor(() => child.kills.includes('SIGTERM'));
  child.emit('close', null, 'SIGTERM');
  await rejection;
});

test('SIGKILL is sent and the promise rejects if SIGTERM is ignored', async () => {
  const child = new FakeChild();
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    idleTimeoutMs: 50,
    killTimeoutMs: 50,
  });
  const rejection = assert.rejects(promise, (error) => {
    assert.equal(error.code, 'FFMPEG_STALLED');
    assert.equal(error.signal, 'SIGKILL');
    return true;
  });

  await waitFor(() => child.kills.includes('SIGKILL'));
  await rejection;
  assert.deepEqual(child.kills, ['SIGTERM', 'SIGKILL']);
});

test('completion clears the watchdog and listeners', async () => {
  const child = new FakeChild();
  let cleared = false;
  const promise = runFfmpegProcess([], {
    spawnImpl: () => child,
    setIntervalImpl: () => ({ unref() {} }),
    clearIntervalImpl: () => {
      cleared = true;
    },
  });
  child.emit('close', 0, null);
  await promise;

  assert.equal(cleared, true);
  assert.equal(child.listenerCount('close'), 0);
  assert.equal(child.listenerCount('error'), 0);
  assert.equal(child.stdout.listenerCount('data'), 0);
  assert.equal(child.stderr.listenerCount('data'), 0);
});
```

- [ ] **Step 2: Запустить новые тесты и убедиться, что они красные**

Run:

```bash
cd /Users/dmitry/taler-id/livekit-agent
node --test ffmpeg-process.test.js
```

Expected: базовые 4 PASS; новые 4 FAIL — процессы не получают SIGTERM/SIGKILL, watchdog options пока не реализованы.

- [ ] **Step 3: Заменить раннер на версию с прогресс-watchdog**

Полный итоговый `livekit-agent/ffmpeg-process.js`:

```js
'use strict';

const { spawn } = require('node:child_process');

const DEFAULT_IDLE_TIMEOUT_MS = 300000;
const DEFAULT_KILL_TIMEOUT_MS = 10000;
const DEFAULT_MAX_LOG_TAIL_CHARS = 64 * 1024;

function appendTail(previous, chunk, limit) {
  const next = previous + chunk.toString();
  return next.length > limit ? next.slice(-limit) : next;
}

function mediaSeconds(match) {
  return Number(match[1]) * 3600 + Number(match[2]) * 60 + Number(match[3]);
}

function runFfmpegProcess(args, options = {}) {
  const {
    command = 'ffmpeg',
    spawnImpl = spawn,
    idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
    killTimeoutMs = DEFAULT_KILL_TIMEOUT_MS,
    maxLogTailChars = DEFAULT_MAX_LOG_TAIL_CHARS,
    now = Date.now,
    setIntervalImpl = setInterval,
    clearIntervalImpl = clearInterval,
    setTimeoutImpl = setTimeout,
    clearTimeoutImpl = clearTimeout,
  } = options;

  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImpl(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      reject(error);
      return;
    }

    let stdout = '';
    let stderr = '';
    let settled = false;
    let stalling = false;
    let killTimer = null;
    let killSignal = null;
    let lastProgressAt = now();
    let lastMediaSeconds = null;

    const stallError = () => {
      const error = new Error(
        `ffmpeg made no progress for ${idleTimeoutMs} ms` +
          (lastMediaSeconds === null ? '' : ` (last time=${lastMediaSeconds}s)`),
      );
      error.code = 'FFMPEG_STALLED';
      error.signal = killSignal;
      error.stderr = stderr;
      return error;
    };

    const onStdout = (chunk) => {
      stdout = appendTail(stdout, chunk, maxLogTailChars);
    };
    const onStderr = (chunk) => {
      stderr = appendTail(stderr, chunk, maxLogTailChars);
      for (const match of stderr.matchAll(/time=(\d+):(\d+):(\d+(?:\.\d+)?)/g)) {
        const seconds = mediaSeconds(match);
        if (lastMediaSeconds === null || seconds > lastMediaSeconds) {
          lastMediaSeconds = seconds;
          lastProgressAt = now();
        }
      }
    };
    const onError = (error) => finish(stalling ? stallError() : error);
    const onClose = (code, signal) => {
      if (stalling) {
        killSignal = killSignal || signal;
        finish(stallError());
        return;
      }
      if (code === 0) {
        finish(null, { stdout, stderr });
        return;
      }
      const error = new Error(
        `ffmpeg exited with code ${code}${signal ? ` (${signal})` : ''}`,
      );
      error.code = 'FFMPEG_EXIT';
      error.exitCode = code;
      error.signal = signal;
      error.stderr = stderr;
      finish(error);
    };

    const watchdog = setIntervalImpl(() => {
      if (settled || stalling || now() - lastProgressAt < idleTimeoutMs) return;
      stalling = true;
      killSignal = 'SIGTERM';
      child.kill('SIGTERM');
      killTimer = setTimeoutImpl(() => {
        killSignal = 'SIGKILL';
        child.kill('SIGKILL');
        finish(stallError());
      }, killTimeoutMs);
      killTimer?.unref?.();
    }, Math.max(10, Math.min(1000, idleTimeoutMs)));
    watchdog?.unref?.();

    function finish(error, value) {
      if (settled) return;
      settled = true;
      clearIntervalImpl(watchdog);
      if (killTimer !== null) clearTimeoutImpl(killTimer);
      child.stdout.removeListener('data', onStdout);
      child.stderr.removeListener('data', onStderr);
      child.removeListener('error', onError);
      child.removeListener('close', onClose);
      if (error) reject(error);
      else resolve(value);
    }

    child.stdout.on('data', onStdout);
    child.stderr.on('data', onStderr);
    child.on('error', onError);
    child.on('close', onClose);
  });
}

module.exports = {
  runFfmpegProcess,
  DEFAULT_IDLE_TIMEOUT_MS,
  DEFAULT_KILL_TIMEOUT_MS,
};
```

- [ ] **Step 4: Запустить весь файл тестов**

Run:

```bash
cd /Users/dmitry/taler-id/livekit-agent
node --test ffmpeg-process.test.js
```

Expected: 8 tests PASS, 0 FAIL, процесс `node --test` завершается без висящих handles.

- [ ] **Step 5: Commit**

```bash
cd /Users/dmitry/taler-id
git add livekit-agent/ffmpeg-process.js livekit-agent/ffmpeg-process.test.js
git commit -m "fix(recorder): останавливать ffmpeg только без прогресса" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 4: Перевести recorder на watchdog и фактический статус

**Files:**
- Create: `livekit-agent/recorder-processing.test.js`
- Modify: `livekit-agent/recorder.js`

- [ ] **Step 1: Написать падающую структурную регрессию**

```js
// livekit-agent/recorder-processing.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, 'recorder.js'), 'utf8');

test('all live ffmpeg stages use the progress runner, not total deadlines', () => {
  assert.match(source, /require\('\.\/ffmpeg-process'\)/);
  assert.doesNotMatch(source, /calcFfmpegTimeout|calcMixTimeout/);
  const calls = source.match(/runFfmpegProcess\(\[/g) || [];
  assert.ok(calls.length >= 4, `expected PCM, participant mix and final mix calls; got ${calls.length}`);
});

test('the saved status comes from the actual recording and processing errors', () => {
  assert.match(source, /payload\.status = recordingStatus\(recordingUrl, hadErrors\)/);
  assert.match(
    source,
    /catch \(e\) \{\s*hadErrors = true;\s*console\.error\('\[RECORDER\] Audio mix\/upload failed:'/,
  );
});
```

- [ ] **Step 2: Запустить тест и убедиться, что он красный**

Run:

```bash
cd /Users/dmitry/taler-id/livekit-agent
node --test recorder-processing.test.js
```

Expected: FAIL — нет `require('./ffmpeg-process')`, присутствуют старые timeout helpers.

- [ ] **Step 3: Подключить новые модули и удалить старые timeout helpers**

В начале `recorder.js` оставить существующий `execFile` для ffprobe/legacy helper и добавить:

```js
const { runFfmpegProcess } = require('./ffmpeg-process');
const { recordingStatus } = require('./recording-result');
```

Удалить полностью блок `// ─── Timeout helpers ───` вместе с `calcFfmpegTimeout` и `calcMixTimeout`.

- [ ] **Step 4: Заменить PCM→OGG конвертацию**

Для одной дорожки участника заменить timeout/log/вызов на:

```js
const pcmSizeMB = (entry.bytesWritten / 1024 / 1024).toFixed(1);
console.log('[RECORDER]', name, ': 1 track,', pcmSizeMB, 'MB PCM (progress watchdog)');

const oggPath = path.join(tmpDir, `${identity}.ogg`);
await ffmpegConvert(entry.pcmPath, oggPath, SAMPLE_RATE, CHANNELS, entry.offsetMs);
```

Для дорожки внутри `tracks.length > 1` заменить аналогично:

```js
const pcmSizeMB = (entry.bytesWritten / 1024 / 1024).toFixed(1);
console.log('[RECORDER]   track', i, ':', pcmSizeMB, 'MB PCM (progress watchdog)');

const trackOgg = path.join(tmpDir, `${identity}_t${i}.ogg`);
await ffmpegConvert(entry.pcmPath, trackOgg, SAMPLE_RATE, CHANNELS, entry.offsetMs);
```

Заменить `ffmpegConvert` целиком:

```js
// A participant's PCM starts when THEY started publishing, so converting it
// as-is and amix-ing puts a latecomer's first word at second zero of the
// recording. Padding by the join offset keeps the mixdown on the meeting's
// own clock — the same clock the speech timeline and Whisper timestamps use.
function ffmpegConvert(pcmPath, oggPath, sampleRate, channels, delayMs) {
  const delay = Math.round(delayMs || 0);
  const pad = delay > 0 ? ['-af', `adelay=${delay}:all=1`] : [];
  return runFfmpegProcess([
    '-y', '-f', 's16le', '-ar', String(sampleRate), '-ac', String(channels),
    '-i', pcmPath,
    ...pad,
    '-c:a', 'libopus', '-b:a', '48k',
    oggPath,
  ]);
}
```

- [ ] **Step 5: Заменить объединение дорожек участника**

Заменить `ffmpegMixTracks` целиком:

```js
/**
 * Mix multiple OGG tracks into one OGG file.
 * Uses amix filter to overlay them (all tracks play simultaneously).
 */
async function ffmpegMixTracks(inputOggs, outputOgg) {
  if (inputOggs.length === 1) {
    fs.copyFileSync(inputOggs[0], outputOgg);
    return;
  }
  const inputs = inputOggs.flatMap((f) => ['-i', f]);
  const filterAr = inputOggs.map((_, i) => `[${i}:a]`).join('');
  const filterComplex = `${filterAr}amix=inputs=${inputOggs.length}:duration=longest:normalize=0[aout]`;
  await runFfmpegProcess([
    '-y', ...inputs,
    '-filter_complex', filterComplex,
    '-map', '[aout]',
    '-c:a', 'libopus', '-b:a', '48k',
    outputOgg,
  ]);
}
```

- [ ] **Step 6: Заменить финальный MP3 mix и статус ошибок**

Ветка одного OGG:

```js
console.log('[RECORDER] Converting single OGG to MP3 (progress watchdog)');
await runFfmpegProcess([
  '-y', '-i', audioFiles[0].oggPath,
  '-c:a', 'libmp3lame', '-q:a', '4',
  outMp3,
]);
```

Ветка нескольких OGG:

```js
console.log('[RECORDER] Mixing', audioFiles.length, 'OGG files to MP3 (progress watchdog)');
const inputs = audioFiles.flatMap((f) => ['-i', f.oggPath]);
const filterAr = audioFiles.map((_, i) => `[${i}:a]`).join('');
const filterComplex = `${filterAr}amix=inputs=${audioFiles.length}:duration=longest[aout]`;
await runFfmpegProcess([
  '-y', ...inputs,
  '-filter_complex', filterComplex,
  '-map', '[aout]',
  '-c:a', 'libmp3lame', '-q:a', '4',
  outMp3,
]);
```

Удалить ставшие ненужными `totalOggBytes` и `timeout`. Catch финальной стадии заменить на:

```js
} catch (e) {
  hadErrors = true;
  console.error('[RECORDER] Audio mix/upload failed:', e.message);
}
```

После `payload` вместо `payload.status = 'done'` установить:

```js
payload.status = recordingStatus(recordingUrl, hadErrors);
```

- [ ] **Step 7: Запустить регрессионные и существующие recorder-тесты**

Run:

```bash
cd /Users/dmitry/taler-id/livekit-agent
node --test recorder-processing.test.js recorder-endpoints.test.js recording-result.test.js ffmpeg-process.test.js
```

Expected: все PASS, 0 FAIL.

- [ ] **Step 8: Commit**

```bash
cd /Users/dmitry/taler-id
git add livekit-agent/recorder.js livekit-agent/recorder-processing.test.js
git commit -m "fix(recorder): не обрывать длинные дорожки и не скрывать partial" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 5: Сохранять `partial` после успешной транскрибации

**Files:**
- Modify: `src/voice/voice.service.summary-participants.spec.ts`
- Modify: `src/voice/voice.service.ts`

- [ ] **Step 1: Расширить test helper ожиданием `partial` и добавить падающий тест**

В `runToCompletion` заменить predicate на:

```ts
await settled(() =>
  mockPrisma.meetingSummary.update.mock.calls.some(
    ([arg]: any) =>
      arg.data.status === 'done' ||
      arg.data.status === 'partial' ||
      arg.data.status === 'failed',
  ),
);
```

Добавить в `describe`:

```ts
it('keeps a partial recording partial after a successful transcription', async () => {
  mockPrisma.meetingSummary.findUnique.mockResolvedValue(
    meeting({ status: 'partial' }),
  );

  await runToCompletion(service, OWNER_ID, 'm-1');

  const finalUpdate = mockPrisma.meetingSummary.update.mock.calls
    .map(([arg]: any) => arg)
    .find((arg: any) => arg.data.transcript !== undefined);
  expect(finalUpdate).toBeDefined();
  expect(finalUpdate.data.status).toBe('partial');
});
```

- [ ] **Step 2: Запустить тест и убедиться, что он красный**

Run:

```bash
cd /Users/dmitry/taler-id
npx jest src/voice/voice.service.summary-participants.spec.ts --runInBand
```

Expected: новый тест FAIL — `finalUpdate.data.status` равен `done`; остальные тесты PASS.

- [ ] **Step 3: Сохранять исходный partial в VoiceService**

В конце `runTranscription`, перед `meetingSummary.update`, добавить:

```ts
const finalStatus = meeting.status === 'partial' ? 'partial' : 'done';
```

В `data` заменить `status: 'done'` на `status: finalStatus`, а return заменить на:

```ts
return { id: updated.id, status: finalStatus };
```

- [ ] **Step 4: Запустить spec повторно**

Run:

```bash
cd /Users/dmitry/taler-id
npx jest src/voice/voice.service.summary-participants.spec.ts --runInBand
```

Expected: все тесты spec PASS, 0 FAIL.

- [ ] **Step 5: Commit**

```bash
cd /Users/dmitry/taler-id
git add src/voice/voice.service.ts src/voice/voice.service.summary-participants.spec.ts
git commit -m "fix(voice): сохранять partial после транскрибации" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 6: Мобильная классификация и RU/EN предупреждение `partial`

**Files:**
- Modify: `test/features/call_history/meeting_card_state_test.dart`
- Create: `test/features/call_history/partial_recording_banner_test.dart`
- Create: `lib/features/call_history/presentation/widgets/partial_recording_banner.dart`
- Modify: `lib/features/call_history/presentation/screens/call_history_screen.dart`
- Modify: `lib/l10n/app_ru.arb`
- Modify: `lib/l10n/app_en.arb`

- [ ] **Step 1: Создать mobile feature branch от актуального DEV**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git switch -c fix/recorder-progress-watchdog origin/dev
```

Expected: новая ветка создана от `origin/dev`, рабочее дерево чистое.

- [ ] **Step 2: Добавить падающий тест классификации**

В `meeting_card_state_test.dart` внутрь `group('meetingCardState')` добавить:

```dart
test('a usable but incomplete recording is partial, not ready or failed', () {
  expect(meetingCardState('partial'), MeetingCardState.partial);
});
```

Run:

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
flutter test test/features/call_history/meeting_card_state_test.dart
```

Expected: compilation FAIL — `MeetingCardState.partial` ещё не существует.

- [ ] **Step 3: Добавить падающие RU/EN widget-тесты**

```dart
// test/features/call_history/partial_recording_banner_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:taler_id_mobile/features/call_history/presentation/widgets/partial_recording_banner.dart';
import 'package:taler_id_mobile/l10n/app_localizations.dart';

Future<void> pumpBanner(WidgetTester tester, Widget child, Locale locale) async {
  await tester.pumpWidget(MaterialApp(
    locale: locale,
    localizationsDelegates: AppLocalizations.localizationsDelegates,
    supportedLocales: AppLocalizations.supportedLocales,
    home: Scaffold(body: child),
  ));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('compact label is localized in English', (tester) async {
    await pumpBanner(
      tester,
      const PartialRecordingBanner(compact: true),
      const Locale('en'),
    );

    expect(find.text('Partial recording'), findsOneWidget);
    expect(find.textContaining('Some audio tracks'), findsNothing);
  });

  testWidgets('full warning is localized in Russian', (tester) async {
    await pumpBanner(
      tester,
      const PartialRecordingBanner(),
      const Locale('ru'),
    );

    expect(find.text('Запись частичная'), findsOneWidget);
    expect(
      find.text('Часть аудиодорожек не обработана. Доступные запись и протокол могут быть неполными.'),
      findsOneWidget,
    );
  });
}
```

Run:

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
flutter test test/features/call_history/partial_recording_banner_test.dart
```

Expected: compilation FAIL — widget-файл отсутствует.

- [ ] **Step 4: Добавить ARB-строки и виджет**

После `callHistoryRecordingFailed` добавить в оба ARB с соответствующим переводом:

```json
"callHistoryPartialRecording": "Partial recording",
"callHistoryPartialRecordingDetails": "Some audio tracks could not be processed. The available recording and transcript may be incomplete.",
```

Русские значения:

```json
"callHistoryPartialRecording": "Запись частичная",
"callHistoryPartialRecordingDetails": "Часть аудиодорожек не обработана. Доступные запись и протокол могут быть неполными.",
```

Создать виджет:

```dart
// lib/features/call_history/presentation/widgets/partial_recording_banner.dart
import 'package:flutter/material.dart';
import '../../../../l10n/app_localizations.dart';

class PartialRecordingBanner extends StatelessWidget {
  final bool compact;

  const PartialRecordingBanner({super.key, this.compact = false});

  @override
  Widget build(BuildContext context) {
    const amber = Color(0xFFF59E0B);
    final l10n = AppLocalizations.of(context)!;

    if (compact) {
      return Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.warning_amber_rounded, size: 14, color: amber),
          const SizedBox(width: 6),
          Text(
            l10n.callHistoryPartialRecording,
            style: const TextStyle(color: amber, fontSize: 12),
          ),
        ],
      );
    }

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: amber.withOpacity(0.12),
        border: Border.all(color: amber.withOpacity(0.45)),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.warning_amber_rounded, size: 20, color: amber),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  l10n.callHistoryPartialRecording,
                  style: const TextStyle(color: amber, fontSize: 13, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 4),
                Text(
                  l10n.callHistoryPartialRecordingDetails,
                  style: const TextStyle(color: amber, fontSize: 13, height: 1.4),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
```

Запустить генерацию:

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
flutter gen-l10n
```

- [ ] **Step 5: Подключить `partial` в экране встречи**

Добавить import:

```dart
import '../widgets/partial_recording_banner.dart';
```

Изменить enum и классификатор:

```dart
enum MeetingCardState { processing, failed, partial, ready }

MeetingCardState meetingCardState(String? status) {
  if (status == 'processing') return MeetingCardState.processing;
  if (status == 'failed' || status == 'failed_no_audio') {
    return MeetingCardState.failed;
  }
  if (status == 'partial') return MeetingCardState.partial;
  return MeetingCardState.ready;
}
```

В `_buildSummaryCard` добавить:

```dart
final isPartial = cardState == MeetingCardState.partial;
```

В цвете иконки использовать `hasFailed || isPartial` вместо `hasFailed`; внутри иконки использовать:

```dart
hasFailed
    ? Icons.mic_off_rounded
    : isPartial
        ? Icons.warning_amber_rounded
        : Icons.smart_toy_rounded,
```

В trailing Row между `isProcessing` и `hasFailed` добавить ветку:

```dart
} else if (isPartial) ...[
  const SizedBox(width: 8),
  const PartialRecordingBanner(compact: true),
]
```

В detail `ListView(children: [...])` перед участниками добавить:

```dart
if (data['status'] == 'partial') ...[
  const PartialRecordingBanner(),
  const SizedBox(height: 20),
],
```

В `_buildRecordingCard` после блока `participants` и перед основным `SizedBox(height: 12)` добавить:

```dart
if (status == 'partial') ...[
  const SizedBox(height: 6),
  const PartialRecordingBanner(compact: true),
],
```

- [ ] **Step 6: Запустить мобильные targeted tests**

Run:

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
flutter test test/features/call_history/meeting_card_state_test.dart test/features/call_history/partial_recording_banner_test.dart
```

Expected: все тесты PASS, 0 FAIL.

- [ ] **Step 7: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/features/call_history lib/l10n test/features/call_history
git commit -m "feat(call-history): показывать частичную запись" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 7: Сообщать ассистенту `partialRecording`

**Files:**
- Modify: `test/features/assistant/meeting_tools_test.dart`
- Modify: `lib/features/assistant/tools/assistant_tools_executor.dart`

- [ ] **Step 1: Добавить падающий тест**

В `group('get_meeting_summary')` добавить:

```dart
test('flags a partial recording so the recap is not presented as complete', () async {
  stubMeeting({'status': 'partial'});

  final out = jsonDecode(await executor()
      .execute('get_meeting_summary', {'meetingId': 'm-1'})) as Map;

  expect(out['status'], 'partial');
  expect(out['partialRecording'], isTrue);
  expect(out.containsKey('recordingFailed'), isFalse);
  expect(out.containsKey('recapPending'), isFalse);
});
```

Run:

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
flutter test test/features/assistant/meeting_tools_test.dart
```

Expected: новый тест FAIL — `out['partialRecording']` равен null; остальные тесты PASS.

- [ ] **Step 2: Добавить флаг в tool result**

В JSON map рядом с `recapPending` и `recordingFailed` добавить:

```dart
if (status == 'partial') 'partialRecording': true,
```

- [ ] **Step 3: Запустить spec повторно**

Run:

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
flutter test test/features/assistant/meeting_tools_test.dart
```

Expected: все тесты PASS, 0 FAIL.

- [ ] **Step 4: Commit**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git add lib/features/assistant/tools/assistant_tools_executor.dart test/features/assistant/meeting_tools_test.dart
git commit -m "feat(assistant): сообщать о частичной записи" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

### Task 8: Полная локальная проверка перед тестовым контуром

**Files:** только изменения предыдущих задач; новых файлов нет.

- [ ] **Step 1: Проверить backend diff и запустить все agent tests**

```bash
cd /Users/dmitry/taler-id
git diff --check origin/dev...HEAD
node --test livekit-agent/*.test.js livekit-agent/bench/*.test.js
```

Expected: `git diff --check` без вывода; все Node tests PASS, 0 FAIL.

- [ ] **Step 2: Запустить backend unit tests и build**

```bash
cd /Users/dmitry/taler-id
npm test -- --runInBand
npm run build
```

Expected: Jest — 0 failed suites; Nest build завершается exit 0.

- [ ] **Step 3: Запустить все Flutter unit tests**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
flutter test
```

Expected: все тесты PASS, 0 FAIL. По CLAUDE.md это обязательный преддеплойный гейт.

- [ ] **Step 4: Проверить новые замечания анализатора и diffs**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
flutter analyze lib/features/call_history lib/features/assistant/tools/assistant_tools_executor.dart test/features/call_history test/features/assistant/meeting_tools_test.dart
git diff --check origin/dev...HEAD
```

Expected: нет новых ошибок в изменённых файлах; `git diff --check` без вывода. Старый общий lint debt репозитория не выдавать за результат этого изменения.

---

### Task 9: Обязательная преддеплойная батарея из CLAUDE.md

**Files:** исходники не меняются. Любой FAIL останавливает деплой; сначала исправить причину и повторить затронутый набор.

- [ ] **Step 1: Emulator UI integration test**

```bash
flutter emulators --launch Pixel_XL_API_33
~/Library/Android/sdk/platform-tools/adb devices
cd /Users/dmitry/Downloads/taler_id_mobile
flutter test integration_test/app_test.dart --flavor dev --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol -d emulator-5554
```

Expected: onboarding/login/5 вкладок/подэкраны/profile edit PASS, нет крашей. Если `HandshakeException` Google Fonts воспроизводится — выполнить на реальных устройствах, а не пропустить гейт.

- [ ] **Step 2: Двухэмуляторный тест звонка**

```bash
~/Library/Android/sdk/emulator/emulator -avd Pixel_XL_2_API_33 -port 5556 -read-only &
~/Library/Android/sdk/platform-tools/adb devices
~/Library/Android/sdk/platform-tools/adb -s emulator-5554 shell pm grant tirol.taler.taler_id_mobile.dev android.permission.RECORD_AUDIO
~/Library/Android/sdk/platform-tools/adb -s emulator-5556 shell pm grant tirol.taler.taler_id_mobile.dev android.permission.RECORD_AUDIO
cd /Users/dmitry/Downloads/taler_id_mobile
bash integration_test/run_call_test.sh
```

Expected: `emulator-5554` caller и `emulator-5556` receiver проходят VoiceCallScreen, 0 FAIL.

- [ ] **Step 3: API, voice, assistant, files, channels, billing**

Команды выполнять последовательно, не параллельно; между наборами выдержать не менее 20 секунд из-за nginx login rate limit.

```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm test
npm run test:voice
npm run test:assistant
npm run test:files
npm run test:channels
npm run test:billing
```

Expected: API 29/29, voice 10/10, assistant 8/8, files 12/12, channels 23/23, billing 7/7. Первый flaky `/voice/session` перезапустить один раз; 503 на `/auth/login` после кластера логинов развести паузой и повторить, не считая зелёным результат с FAIL.

- [ ] **Step 4: Recording и speakers**

```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm run test:recording
npm run test:speakers
```

Expected: recording 10/10; speakers 13/13. Длинные отрезки speakers не сокращать.

- [ ] **Step 5: MCP, system channel, device approval, pins, room-chat**

Выполнять последовательно с паузами; `device-approval` не запускать вплотную к другим логинам. `room-chat` запускать с этого Mac, не с bot-сервера.

```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm run test:mcp
npm run test:system-channel
npm run test:device-approval
npm run test:pins
npm run test:room-chat
```

Expected: MCP полный scope/CRUD/delivery/negatives PASS; system-channel PASS; device-approval 27/27; pins 84/84 без `ADMIN_EMAIL`; room-chat 88/88.

- [ ] **Step 6: Long transcription**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && BASE_URL=https://staging.id.taler.tirol npx ts-node -r dotenv/config scripts/verify-long-transcription.ts --email integration_test@taler-test.com --password "IntegrationTest123!"'
```

Expected: запись и таймкоды доходят до конца, transcript/summary непустые, `status=done` в БД. HTTP 504 сам по себе не является результатом; проверять итог в БД. Ожидаемая стоимость около $0.4 Whisper.

- [ ] **Step 7: Partner и interpreter**

```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm run test:partner
npm run test:interpreter
```

Expected: partner 64/64; interpreter около 60 проверок PASS, комната/образцы очищены самим набором.

---

### Task 10: DEV deploy, реальная длинная PCM и post-deploy smoke

**Files:** только уже закоммиченные изменения. TEST и PROD в этой задаче не трогаются.

- [ ] **Step 1: Слить backend/agent ветку в DEV и опубликовать её**

```bash
cd /Users/dmitry/taler-id
git switch dev
git pull --ff-only origin dev
git merge --no-ff fix/recorder-progress-watchdog -m "fix(recorder): watchdog длинной конвертации и partial" -m "Co-Authored-By: Claude Code <noreply@anthropic.com>"
git push origin dev
```

Expected: merge содержит только изменения Tasks 1–5 и одобренные docs; push успешен.

- [ ] **Step 2: Задеплоить backend и recorder на DEV**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev livekit-ai-agent'
curl -fsS https://staging.id.taler.tirol/health
```

Expected: оба PM2 процесса online, `/health` HTTP 200. Новых миграций в этом изменении нет; если `git pull` покажет чужую новую миграцию — остановиться и выполнить обязательные `prisma migrate deploy/generate` по CLAUDE.md, не игнорировать.

- [ ] **Step 3: Сгенерировать синтетическую двухчасовую PCM на DEV**

```bash
ssh dvolkov@89.169.55.217 'ffmpeg -y -f lavfi -i "anoisesrc=d=7200:c=pink:r=48000:a=0.2" -ac 1 -ar 48000 -f s16le /tmp/recorder-watchdog-2h.pcm && stat -c "bytes=%s" /tmp/recorder-watchdog-2h.pcm'
```

Expected: `bytes=691200000` (больше 621 МБ исходного инцидента). Это синтетический шум, не пользовательское аудио.

- [ ] **Step 4: Прогнать новый раннер на реальной PCM**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id/livekit-agent && /usr/bin/time -f "elapsed=%e" node -'" <<'NODE'
const { runFfmpegProcess } = require('./ffmpeg-process');
(async () => {
  await runFfmpegProcess([
    '-y', '-f', 's16le', '-ar', '48000', '-ac', '1',
    '-i', '/tmp/recorder-watchdog-2h.pcm',
    '-c:a', 'libopus', '-b:a', '48k',
    '/tmp/recorder-watchdog-2h.ogg',
  ]);
  console.log('CONVERSION_OK');
})().catch((error) => {
  console.error(error.code, error.message, error.stderr || '');
  process.exitCode = 1;
});
NODE
```

Expected: `CONVERSION_OK`, отсутствует `FFMPEG_STALLED`, elapsed превышает прежние 270 секунд на этом хосте. Если хост завершил быстрее 270 секунд, выполнить следующий трёхчасовой вариант; быстрый прогон не считается проверкой прежнего предела:

```bash
ssh dvolkov@89.169.55.217 'ffmpeg -y -f lavfi -i "anoisesrc=d=10800:c=pink:r=48000:a=0.2" -ac 1 -ar 48000 -f s16le /tmp/recorder-watchdog-3h.pcm'
ssh dvolkov@89.169.55.217 'cd ~/taler-id/livekit-agent && /usr/bin/time -f "elapsed=%e" node -' <<'NODE'
const { runFfmpegProcess } = require('./ffmpeg-process');
(async () => {
  await runFfmpegProcess([
    '-y', '-f', 's16le', '-ar', '48000', '-ac', '1',
    '-i', '/tmp/recorder-watchdog-3h.pcm',
    '-c:a', 'libopus', '-b:a', '48k',
    '/tmp/recorder-watchdog-3h.ogg',
  ]);
  console.log('CONVERSION_OK');
})().catch((error) => {
  console.error(error.code, error.message, error.stderr || '');
  process.exitCode = 1;
});
NODE
```

- [ ] **Step 5: Проверить длительность OGG и удалить только синтетические файлы**

```bash
ssh dvolkov@89.169.55.217 'for f in /tmp/recorder-watchdog-2h.ogg /tmp/recorder-watchdog-3h.ogg; do if [ -f "$f" ]; then printf "%s " "$f"; ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 "$f"; fi; done; rm -f /tmp/recorder-watchdog-2h.pcm /tmp/recorder-watchdog-2h.ogg /tmp/recorder-watchdog-3h.pcm /tmp/recorder-watchdog-3h.ogg'
```

Expected: длительность 7200 секунд ±2 секунды (или 10800 ±2 для трёхчасового варианта). Пользовательские PCM и `/root/taler-recovery-4870181f-20261105` не удалять.

- [ ] **Step 6: Обязательные post-deploy smoke для realtime/agent**

```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm run test:voice-session
npm run test:translator
npm run test:interpreter-selftest
```

Expected: voice realtime audio+transcript delta PASS, translator `session.updated` PASS, обе interpreter OpenAI sessions PASS.

- [ ] **Step 7: Проверить новый код на DEV recording/speakers/long transcription**

```bash
cd /Users/dmitry/Downloads/taler_id_tests
npm run test:recording
npm run test:speakers
ssh dvolkov@89.169.55.217 'cd ~/taler-id && BASE_URL=https://staging.id.taler.tirol npx ts-node -r dotenv/config scripts/verify-long-transcription.ts --email integration_test@taler-test.com --password "IntegrationTest123!"'
```

Expected: recording 10/10, speakers 13/13, длинная расшифровка в БД `status=done` с полными таймкодами. При FAIL остановить rollout и вернуться к root cause; не катить дальше.

- [ ] **Step 8: Опубликовать mobile branch для review и остановиться перед следующим контуром**

```bash
cd /Users/dmitry/Downloads/taler_id_mobile
git push -u origin fix/recorder-progress-watchdog
```

Expected: branch опубликован. Далее отдельно запросить у пользователя разрешение на TEST; PROD и мобильные публичные релизы не выполнять без отдельных явных команд. Итоговый отчёт должен содержать commit SHAs, результаты каждого теста, длительность synthetic PCM и любые невыполненные проверки.

---

## Plan self-review

- **Spec coverage:** watchdog и все живые ffmpeg-этапы — Tasks 2–4; `done`/`partial`/`failed` и PCM при mix/upload — Tasks 1 и 4; сохранение `partial` backend — Task 5; мобильная метка/detail/recording card и RU/EN — Task 6; ассистент — Task 7; длинная PCM и существующие e2e — Tasks 9–10; DEV→отдельный TEST/PROD gate — Task 10.
- **Type consistency:** `runFfmpegProcess(args, options)` возвращает `{ stdout, stderr }`; ошибки используют `code = FFMPEG_EXIT | FFMPEG_STALLED`; `recordingStatus(recordingUrl, hadErrors)` возвращает строку; Flutter виджет называется `PartialRecordingBanner`, assistant flag — `partialRecording`.
- **Placeholder scan:** все кодовые шаги содержат конкретный код/замену, все проверки — точные команды и ожидаемые результаты. Значения `d=10800` используются только как явный fallback, если двухчасовой тест не пересёк прежние 270 секунд.
