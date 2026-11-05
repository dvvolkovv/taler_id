const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const Module = require('node:module');

const { describe, it, before, after, beforeEach, afterEach } = test;
const recorderPath = path.join(__dirname, 'recorder.js');
const source = fs.readFileSync(recorderPath, 'utf8');

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

describe('processAndSave recording outcomes', () => {
  const backendUrl = 'https://recorder.test';
  const uploadedUrl = 'https://cdn.test/recording.mp3';
  const originalLoad = Module._load;
  const originalFetch = global.fetch;
  const envKeys = ['BACKEND_URL', 'RECORDER_SHARED_SECRET', 'RECORDINGS_DIR'];
  const originalEnv = Object.fromEntries(envKeys.map((key) => [key, process.env[key]]));

  let processAndSave;
  let ffmpegHandler;
  let uploadHandler;
  let rootDir;
  let tmpDir;
  let fallbackDir;
  let savedPayloads;

  before(() => {
    Module._load = function (request, parent, isMain) {
      if (parent && parent.filename === recorderPath) {
        if (request === 'livekit-server-sdk') return { AccessToken: class AccessToken {} };
        if (request === 'livekit-credentials' || request === './livekit-credentials') {
          return { readLivekitCredentials: () => ({ apiKey: 'test-key', apiSecret: 'test-secret' }) };
        }
        if (request === '@livekit/rtc-node') return {};
        if (request === './ffmpeg-process') {
          return { runFfmpegProcess: (args) => ffmpegHandler(args) };
        }
      }
      return originalLoad.call(this, request, parent, isMain);
    };
    process.env.BACKEND_URL = backendUrl;
    process.env.RECORDER_SHARED_SECRET = 'test-recorder-secret';
    delete require.cache[recorderPath];
    processAndSave = require(recorderPath)._test.processAndSave;
  });

  after(() => {
    Module._load = originalLoad;
    global.fetch = originalFetch;
    for (const key of envKeys) {
      if (originalEnv[key] === undefined) delete process.env[key];
      else process.env[key] = originalEnv[key];
    }
    delete require.cache[recorderPath];
  });

  beforeEach(() => {
    rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 'recorder-processing-'));
    tmpDir = path.join(rootDir, 'tmp');
    fallbackDir = path.join(rootDir, 'fallback');
    fs.mkdirSync(tmpDir);
    fs.mkdirSync(fallbackDir);
    process.env.RECORDINGS_DIR = fallbackDir;
    savedPayloads = [];

    ffmpegHandler = async (args) => {
      fs.writeFileSync(args[args.length - 1], 'fake media');
    };
    uploadHandler = async () => ({
      ok: true,
      status: 200,
      json: async () => ({ url: uploadedUrl }),
      text: async () => '',
    });
    global.fetch = async (url, options = {}) => {
      if (url === `${backendUrl}/voice/meetings/save`) {
        const payload = JSON.parse(options.body);
        savedPayloads.push(payload);
        return { json: async () => ({ id: payload.status === 'processing' ? 'pending-id' : 'meeting-id' }) };
      }
      if (url === `${backendUrl}/voice/recordings/upload`) return uploadHandler(url, options);
      throw new Error(`Unexpected fetch: ${url}`);
    };
  });

  afterEach(() => {
    global.fetch = originalFetch;
    fs.rmSync(rootDir, { recursive: true, force: true });
  });

  function makeSession(participants) {
    const trackAudio = new Map();
    const pcmFiles = [];
    for (const { identity, name = identity, tracks = 1 } of participants) {
      for (let i = 0; i < tracks; i++) {
        const pcmPath = path.join(tmpDir, `${identity}__t${i}.pcm`);
        const contents = Buffer.from([i + 1, 0, identity.length, 0, tracks, 0]);
        fs.writeFileSync(pcmPath, contents);
        pcmFiles.push({ path: pcmPath, contents });
        trackAudio.set(`${identity}__t${i}`, {
          identity,
          name,
          pcmPath,
          bytesWritten: contents.length,
          offsetMs: i * 1000,
          energy: { intervals: () => [[i, i + 0.5]] },
        });
      }
    }
    return {
      session: { roomName: 'room-behavior', trackAudio, startTime: Date.now() - 5000, tmpDir },
      pcmFiles,
    };
  }

  function assertFinalPayload(expectedStatus, expectedUrl) {
    assert.equal(savedPayloads.length, 2, 'expected processing placeholder and final save');
    const payload = savedPayloads[1];
    assert.equal(payload.status, expectedStatus);
    assert.equal(payload.recordingUrl, expectedUrl);
    return payload;
  }

  function assertOnlyOriginalPcm(pcmFiles) {
    assert.ok(fs.existsSync(tmpDir), 'tmpDir must survive failed or partial processing');
    for (const file of pcmFiles) {
      assert.deepEqual(fs.readFileSync(file.path), file.contents, `PCM changed or missing: ${file.path}`);
    }
    assert.deepEqual(
      fs.readdirSync(tmpDir).sort(),
      pcmFiles.map((file) => path.basename(file.path)).sort(),
      'only the complete original PCM set should remain',
    );
  }

  function rejectFinalMix(args) {
    if (args.includes('libmp3lame')) {
      const error = new Error('final mix failed');
      error.stderr = 'ffmpeg diagnostics';
      throw error;
    }
    fs.writeFileSync(args[args.length - 1], 'fake media');
  }

  it('preserves every PCM and reports failed when the final mix fails', async () => {
    const { session, pcmFiles } = makeSession([{ identity: 'alice', tracks: 2 }, { identity: 'boris' }]);
    ffmpegHandler = rejectFinalMix;

    await processAndSave(session);

    assertFinalPayload('failed', null);
    assertOnlyOriginalPcm(pcmFiles);
  });

  it('preserves every PCM and reports failed when S3 and local fallback fail', async () => {
    const { session, pcmFiles } = makeSession([{ identity: 'alice' }]);
    uploadHandler = async () => ({ ok: false, status: 503, text: async () => 'S3 unavailable' });
    process.env.RECORDINGS_DIR = path.join(rootDir, 'missing-fallback');

    await processAndSave(session);

    assertFinalPayload('failed', null);
    assertOnlyOriginalPcm(pcmFiles);
  });

  it('reports partial and preserves every PCM when one participant conversion fails', async () => {
    const { session, pcmFiles } = makeSession([{ identity: 'broken', tracks: 2 }, { identity: 'alice' }]);
    const failedPcm = pcmFiles[1].path;
    ffmpegHandler = async (args) => {
      if (args.includes('s16le') && args[args.indexOf('-i') + 1] === failedPcm) {
        const error = new Error('track conversion failed');
        error.stderr = 'bad PCM';
        throw error;
      }
      fs.writeFileSync(args[args.length - 1], 'fake media');
    };

    await processAndSave(session);

    assertFinalPayload('partial', uploadedUrl);
    assertOnlyOriginalPcm(pcmFiles);
  });

  it('reports done, trims the upload URL and removes tmpDir after full success', async () => {
    const { session } = makeSession([{ identity: 'alice', tracks: 2 }, { identity: 'boris' }]);
    uploadHandler = async () => ({ ok: true, status: 200, json: async () => ({ url: `  ${uploadedUrl}  ` }) });

    await processAndSave(session);

    assertFinalPayload('done', uploadedUrl);
    assert.equal(fs.existsSync(tmpDir), false, 'tmpDir must be removed after a clean usable result');
  });

  it('uses a successful local fallback without marking the recording partial', async () => {
    const { session } = makeSession([{ identity: 'alice' }]);
    uploadHandler = async () => ({ ok: false, status: 503, text: async () => 'S3 unavailable' });

    await processAndSave(session);

    const fallbackFiles = fs.readdirSync(fallbackDir);
    assert.equal(fallbackFiles.length, 1);
    const expectedUrl = `${backendUrl}/recordings/${fallbackFiles[0]}`;
    assertFinalPayload('done', expectedUrl);
    assert.equal(fs.existsSync(tmpDir), false);
    assert.equal(fs.readFileSync(path.join(fallbackDir, fallbackFiles[0]), 'utf8'), 'fake media');
  });

  it('treats HTTP 200 without a URL as upload failure and preserves PCM if fallback fails', async () => {
    const { session, pcmFiles } = makeSession([{ identity: 'alice' }]);
    uploadHandler = async () => ({ ok: true, status: 200, json: async () => ({}) });
    process.env.RECORDINGS_DIR = path.join(rootDir, 'missing-fallback');

    await processAndSave(session);

    assertFinalPayload('failed', null);
    assertOnlyOriginalPcm(pcmFiles);
  });
});
