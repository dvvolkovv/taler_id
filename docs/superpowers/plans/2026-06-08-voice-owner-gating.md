# Voice Owner Gating Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate the audio stream of the TalerID voice assistant so OpenAI Realtime only acts on the owner's voice; non-owner audio is retracted via `input_audio_buffer.clear` + `response.cancel`. Experimental branch only.

**Architecture:** Backend WS proxy in `taler_id/src/main.ts` taps each 1-sec PCM window from the existing client→OpenAI stream, POSTs to Manax SpeechProcessor (DEV `127.0.0.1:8791`) with `mode=enroll`, gets back an ECAPA embedding, computes cosine vs `Profile.ownerEmbedding`. Speculative-forward: audio reaches OpenAI in real time; on non-owner verdict (~1 sec later) we inject retract events. Enrollment happens on first assistant session via a bottom sheet.

**Tech Stack:** NestJS, Prisma (Postgres), axios; Flutter, BLoC, Dio, `record` package; Manax v3.6.1 already running on DEV.

**Spec:** [`../specs/2026-06-08-voice-owner-gating-design.md`](../specs/2026-06-08-voice-owner-gating-design.md)

---

## Phase 0: Pre-implementation verification

### Task 0.1: Confirm Manax `mode=enroll` returns ECAPA embedding

The whole plan rests on this. If it doesn't hold, the plan switches to `mode=all` everywhere (slower per-window verify, ~100-300 ms more latency).

**Files:** none (one-off curl check)

- [ ] **Step 1: Pick a real test recording on DEV**

Run on DEV:
```bash
ssh dvolkov@89.169.55.217 'ls -S /var/www/recordings/*.mp3 | head -3'
```
Pick the smallest with actual speech (avoid the silence-dominated AI-twin junk). The `89d046db-…mp3` is 14 sec with counted speech and is known to work.

- [ ] **Step 2: Submit `mode=enroll` job and capture the response**

```bash
ssh dvolkov@89.169.55.217 '
  API_KEY=$(grep API_KEY ~/manax-speech/.env.local | cut -d= -f2)
  FILE=/var/www/recordings/89d046db-818d-4df0-9fe5-8d5845c6157f.mp3
  JOB=$(curl -sS -X POST -H "X-Api-Key: $API_KEY" \
    -F "audioFile=@$FILE" \
    -F "requestJson={\"mode\":\"enroll\",\"language\":\"ru\"}" \
    http://127.0.0.1:8791/api/v1/jobs/upload-all-in-one \
    | python3 -c "import json,sys;print(json.load(sys.stdin)[\"jobId\"])")
  echo "jobId=$JOB"
  while true; do
    S=$(curl -sS -H "X-Api-Key: $API_KEY" \
      http://127.0.0.1:8791/api/v1/jobs/$JOB/status \
      | python3 -c "import json,sys;print(json.load(sys.stdin).get(\"status\",\"?\"))")
    echo $S
    [ "$S" = "completed" ] || [ "$S" = "failed" ] && break
    sleep 3
  done
  curl -sS -H "X-Api-Key: $API_KEY" \
    http://127.0.0.1:8791/api/v1/jobs/$JOB \
    > /tmp/enroll-probe.json
  python3 -c "
import json
d = json.load(open(\"/tmp/enroll-probe.json\"))
r = d.get(\"result\", {}) or {}
emb = r.get(\"speakerEmbeddings\", [])
print(f\"embeddings={len(emb)}\")
for e in emb:
    v = e.get(\"vector\", [])
    print(f\"  speakerId={e.get(\\\"speakerId\\\")} dim={len(v)} cov={e.get(\\\"coverageFraction\\\")}\")
"
'
```

Expected: `embeddings >= 1` and `dim == 192`. If yes — plan stands as written. If `embeddings == 0` — adjust Task 1.4 and Task 1.5 to use `mode=all` instead, and update the spec accordingly.

- [ ] **Step 3: Record finding in the spec**

Append a one-line confirmation to the spec's section 5.2:
```
**Verified 2026-06-08**: `mode=enroll` returns `speakerEmbeddings[0].vector` with 192 floats.
```

```bash
cd ~/Downloads/taler_id
git add docs/superpowers/specs/2026-06-08-voice-owner-gating-design.md
git commit -m "spec: confirm Manax mode=enroll returns ECAPA embedding"
```

---

## Phase 1: Backend `voice-gate` module

Working tree: `~/Downloads/taler_id` on branch `experiment/voice-owner-gating`.

### Task 1.1: Prisma migration — add owner voice fields to `Profile`

**Files:**
- Modify: `prisma/schema.prisma` (Profile model)
- Create: `prisma/migrations/<timestamp>_add_owner_voice_to_profile/migration.sql`

- [ ] **Step 1: Edit `prisma/schema.prisma` Profile model**

Find the `Profile` model and add two fields above the relations:

```prisma
model Profile {
  // ... existing fields ...
  lastSeenPrivacy      LastSeenPrivacy @default(EVERYONE)

  ownerSpeakerId       String?
  ownerEmbedding       Float[]   @default([])

  documents            Document[]
  user                 User      @relation(fields: [userId], references: [id])
}
```

- [ ] **Step 2: Generate migration**

```bash
cd ~/Downloads/taler_id
npx prisma migrate dev --name add_owner_voice_to_profile --create-only
```

Inspect the generated SQL — should be roughly:
```sql
ALTER TABLE "Profile"
  ADD COLUMN "ownerSpeakerId" TEXT,
  ADD COLUMN "ownerEmbedding" DOUBLE PRECISION[] DEFAULT ARRAY[]::DOUBLE PRECISION[];
```

- [ ] **Step 3: Apply migration locally and regenerate Prisma client**

```bash
npx prisma migrate dev
npx prisma generate
```

Expected: no errors; `Profile` type in generated client now has `ownerSpeakerId?: string | null` and `ownerEmbedding: number[]`.

- [ ] **Step 4: Commit**

```bash
git add prisma/schema.prisma prisma/migrations/
git commit -m "feat(voice-gate): add ownerSpeakerId+ownerEmbedding to Profile"
```

### Task 1.2: Env vars + voice-gate types

**Files:**
- Modify: `.env.example`
- Create: `src/voice-gate/voice-gate.types.ts`

- [ ] **Step 1: Append env vars to `.env.example`**

Add at the end of file:
```
# Voice owner gating (experimental, see docs/superpowers/specs/2026-06-08-voice-owner-gating-design.md)
MANAX_BASE_URL=http://127.0.0.1:8791
MANAX_API_KEY=
OWNER_VOICE_THRESHOLD=0.5
OWNER_VOICE_WINDOW_MS=1000
OWNER_VOICE_ENABLED=true
```

- [ ] **Step 2: Create types file**

`src/voice-gate/voice-gate.types.ts`:
```ts
export interface ManaxSpeakerEmbedding {
  speakerId: string;
  vector: number[];
  coverageFraction?: number;
}

export interface ManaxJobResult {
  durationSec?: number;
  speakerEmbeddings?: ManaxSpeakerEmbedding[];
  quality?: { speechCoverage?: number };
}

export interface ManaxJobResponse {
  jobId: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  attempt?: number;
  error?: string;
  result?: ManaxJobResult;
}

export interface OwnerVerifyResult {
  isOwner: boolean | null;     // null = fail-open (could not decide)
  similarity?: number;
  audioSec?: number;
  manaxLatencyMs?: number;
}

export interface OwnerEnrollResult {
  ok: boolean;
  speakerId?: string;
  embedding?: number[];
  embeddingDim?: number;
  audioSec?: number;
  error?: 'audio_too_short' | 'no_speech_detected' | 'manax_unavailable' | 'feature_disabled';
}
```

- [ ] **Step 3: Commit**

```bash
git add .env.example src/voice-gate/voice-gate.types.ts
git commit -m "feat(voice-gate): env vars and TS types"
```

### Task 1.3: Cosine similarity (TDD)

**Files:**
- Create: `src/voice-gate/cosine.ts`
- Create: `src/voice-gate/cosine.spec.ts`

- [ ] **Step 1: Write the failing test**

`src/voice-gate/cosine.spec.ts`:
```ts
import { cosine } from './cosine';

describe('cosine', () => {
  it('same direction → 1', () => {
    expect(cosine([1, 0, 0], [1, 0, 0])).toBeCloseTo(1.0, 6);
  });

  it('orthogonal → 0', () => {
    expect(cosine([1, 0, 0], [0, 1, 0])).toBeCloseTo(0.0, 6);
  });

  it('opposite → -1', () => {
    expect(cosine([1, 0, 0], [-1, 0, 0])).toBeCloseTo(-1.0, 6);
  });

  it('partial overlap (1,1,0 vs 1,0,0) → 1/sqrt(2)', () => {
    expect(cosine([1, 1, 0], [1, 0, 0])).toBeCloseTo(1 / Math.sqrt(2), 6);
  });

  it('throws on length mismatch', () => {
    expect(() => cosine([1, 2], [1, 2, 3])).toThrow(/length/i);
  });

  it('returns 0 when either vector has zero norm', () => {
    expect(cosine([0, 0, 0], [1, 0, 0])).toBe(0);
    expect(cosine([1, 0, 0], [0, 0, 0])).toBe(0);
  });
});
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
npx jest src/voice-gate/cosine.spec.ts
```
Expected: "Cannot find module './cosine'".

- [ ] **Step 3: Write minimal implementation**

`src/voice-gate/cosine.ts`:
```ts
export function cosine(a: number[], b: number[]): number {
  if (a.length !== b.length) {
    throw new Error(`cosine: vector length mismatch (${a.length} vs ${b.length})`);
  }
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  if (denom === 0) return 0;
  return dot / denom;
}
```

- [ ] **Step 4: Run test, expect PASS**

```bash
npx jest src/voice-gate/cosine.spec.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/cosine.ts src/voice-gate/cosine.spec.ts
git commit -m "feat(voice-gate): cosine similarity"
```

### Task 1.4: VoiceGateService — Manax HTTP client (TDD)

**Files:**
- Create: `src/voice-gate/voice-gate.service.ts`
- Create: `src/voice-gate/voice-gate.service.spec.ts`

- [ ] **Step 1: Write the failing test**

`src/voice-gate/voice-gate.service.spec.ts`:
```ts
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { VoiceGateService } from './voice-gate.service';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

const mockConfig = {
  get: jest.fn((key: string, fallback?: any) => {
    const env: Record<string, any> = {
      MANAX_BASE_URL: 'http://127.0.0.1:8791',
      MANAX_API_KEY: 'test-key',
      OWNER_VOICE_THRESHOLD: '0.5',
      OWNER_VOICE_WINDOW_MS: '1000',
      OWNER_VOICE_ENABLED: 'true',
    };
    return env[key] ?? fallback;
  }),
};

describe('VoiceGateService.embedAudio', () => {
  let service: VoiceGateService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VoiceGateService,
        { provide: ConfigService, useValue: mockConfig },
      ],
    }).compile();
    service = module.get(VoiceGateService);
  });

  it('extracts the highest-coverage embedding from a successful Manax response', async () => {
    mockedAxios.post.mockResolvedValueOnce({
      status: 200,
      data: {
        jobId: 'j1',
        status: 'completed',
        result: {
          durationSec: 1.0,
          speakerEmbeddings: [
            { speakerId: 'spk_a', vector: [0.1, 0.2], coverageFraction: 0.4 },
            { speakerId: 'spk_b', vector: [0.7, 0.8], coverageFraction: 0.9 },
          ],
        },
      },
    });
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toEqual([0.7, 0.8]);
    expect(result.speakerId).toBe('spk_b');
  });

  it('returns null embedding when Manax returns no embeddings', async () => {
    mockedAxios.post.mockResolvedValueOnce({
      status: 200,
      data: { jobId: 'j1', status: 'completed', result: { speakerEmbeddings: [] } },
    });
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
  });

  it('returns null embedding when Manax HTTP fails (fail-open)', async () => {
    mockedAxios.post.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const result = await service.embedAudio(Buffer.from('fake wav'));
    expect(result.embedding).toBeNull();
    expect(result.error).toBe('manax_unavailable');
  });
});
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
npx jest src/voice-gate/voice-gate.service.spec.ts
```

- [ ] **Step 3: Write minimal implementation**

`src/voice-gate/voice-gate.service.ts`:
```ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import FormData from 'form-data';
import { ManaxJobResponse, ManaxSpeakerEmbedding } from './voice-gate.types';

export interface EmbedResult {
  embedding: number[] | null;
  speakerId?: string;
  audioSec?: number;
  manaxLatencyMs?: number;
  error?: 'manax_unavailable' | 'no_speech_detected';
}

@Injectable()
export class VoiceGateService {
  private readonly log = new Logger('VoiceGateService');
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs = 2000;

  constructor(private readonly config: ConfigService) {
    this.baseUrl = config.get<string>('MANAX_BASE_URL', 'http://127.0.0.1:8791');
    this.apiKey = config.get<string>('MANAX_API_KEY', '');
  }

  async embedAudio(audio: Buffer): Promise<EmbedResult> {
    const form = new FormData();
    form.append('audioFile', audio, { filename: 'audio.wav', contentType: 'audio/wav' });
    form.append('requestJson', JSON.stringify({ mode: 'enroll', language: 'ru' }));

    const start = Date.now();
    try {
      const resp = await axios.post<ManaxJobResponse>(
        `${this.baseUrl}/api/v1/audio/upload-all-in-one`,
        form,
        {
          headers: { ...form.getHeaders(), 'X-Api-Key': this.apiKey },
          timeout: this.timeoutMs,
          maxContentLength: 5_000_000,
        },
      );
      const latency = Date.now() - start;
      const embs = resp.data.result?.speakerEmbeddings ?? [];
      if (embs.length === 0) {
        return { embedding: null, error: 'no_speech_detected', manaxLatencyMs: latency };
      }
      const best = this.pickBestEmbedding(embs);
      return {
        embedding: best.vector,
        speakerId: best.speakerId,
        audioSec: resp.data.result?.durationSec,
        manaxLatencyMs: latency,
      };
    } catch (e: any) {
      this.log.warn(`Manax unavailable, fail-open: ${e.message}`);
      return { embedding: null, error: 'manax_unavailable', manaxLatencyMs: Date.now() - start };
    }
  }

  private pickBestEmbedding(embs: ManaxSpeakerEmbedding[]): ManaxSpeakerEmbedding {
    return embs.reduce((best, cur) =>
      (cur.coverageFraction ?? 0) > (best.coverageFraction ?? 0) ? cur : best,
    );
  }
}
```

- [ ] **Step 4: Run test, expect PASS**

```bash
npx jest src/voice-gate/voice-gate.service.spec.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/voice-gate.service.ts src/voice-gate/voice-gate.service.spec.ts
git commit -m "feat(voice-gate): Manax HTTP client with fail-open"
```

### Task 1.5: VoiceGateService — verify method (TDD)

**Files:**
- Modify: `src/voice-gate/voice-gate.service.ts` (add `verify` method)
- Modify: `src/voice-gate/voice-gate.service.spec.ts` (add `verify` describe block)

- [ ] **Step 1: Write the failing test (add to existing spec file)**

Append to `voice-gate.service.spec.ts`:
```ts
describe('VoiceGateService.verify', () => {
  let service: VoiceGateService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VoiceGateService,
        { provide: ConfigService, useValue: mockConfig },
      ],
    }).compile();
    service = module.get(VoiceGateService);
  });

  it('returns isOwner=true when cosine >= threshold', async () => {
    mockedAxios.post.mockResolvedValueOnce({
      status: 200,
      data: { jobId: 'j', status: 'completed', result: { speakerEmbeddings: [{ speakerId: 's', vector: [1, 0, 0], coverageFraction: 1 }] } },
    });
    const r = await service.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBe(true);
    expect(r.similarity).toBeCloseTo(1.0, 6);
  });

  it('returns isOwner=false when cosine < threshold', async () => {
    mockedAxios.post.mockResolvedValueOnce({
      status: 200,
      data: { jobId: 'j', status: 'completed', result: { speakerEmbeddings: [{ speakerId: 's', vector: [0, 1, 0], coverageFraction: 1 }] } },
    });
    const r = await service.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBe(false);
    expect(r.similarity).toBeCloseTo(0.0, 6);
  });

  it('returns isOwner=null (fail-open) when Manax returns no embedding', async () => {
    mockedAxios.post.mockResolvedValueOnce({
      status: 200,
      data: { jobId: 'j', status: 'completed', result: { speakerEmbeddings: [] } },
    });
    const r = await service.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBeNull();
  });

  it('returns isOwner=null when ownerEmbedding is empty', async () => {
    const r = await service.verify(Buffer.alloc(32_000), []);
    expect(r.isOwner).toBeNull();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
npx jest src/voice-gate/voice-gate.service.spec.ts
```
Expected: `service.verify is not a function`.

- [ ] **Step 3: Add `verify` to VoiceGateService**

Add to `voice-gate.service.ts`:
```ts
// at top of imports
import { cosine } from './cosine';
import { OwnerVerifyResult } from './voice-gate.types';
```

Add `threshold` field initialization in constructor:
```ts
private readonly threshold: number;

constructor(private readonly config: ConfigService) {
  this.baseUrl = config.get<string>('MANAX_BASE_URL', 'http://127.0.0.1:8791');
  this.apiKey = config.get<string>('MANAX_API_KEY', '');
  this.threshold = parseFloat(config.get<string>('OWNER_VOICE_THRESHOLD', '0.5'));
}
```

Add method:
```ts
async verify(audio: Buffer, ownerEmbedding: number[]): Promise<OwnerVerifyResult> {
  if (!ownerEmbedding || ownerEmbedding.length === 0) {
    return { isOwner: null };
  }
  const emb = await this.embedAudio(audio);
  if (emb.embedding === null) {
    return { isOwner: null, audioSec: emb.audioSec, manaxLatencyMs: emb.manaxLatencyMs };
  }
  const sim = cosine(emb.embedding, ownerEmbedding);
  return {
    isOwner: sim >= this.threshold,
    similarity: sim,
    audioSec: emb.audioSec,
    manaxLatencyMs: emb.manaxLatencyMs,
  };
}
```

- [ ] **Step 4: Run test, expect PASS**

```bash
npx jest src/voice-gate/voice-gate.service.spec.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/voice-gate.service.ts src/voice-gate/voice-gate.service.spec.ts
git commit -m "feat(voice-gate): verify method with cosine + threshold"
```

### Task 1.6: VoiceGateService — enroll method + feature flag (TDD)

**Files:**
- Modify: `src/voice-gate/voice-gate.service.ts`
- Modify: `src/voice-gate/voice-gate.service.spec.ts`

- [ ] **Step 1: Add tests**

Append to `voice-gate.service.spec.ts`:
```ts
describe('VoiceGateService.enroll', () => {
  let service: VoiceGateService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [VoiceGateService, { provide: ConfigService, useValue: mockConfig }],
    }).compile();
    service = module.get(VoiceGateService);
  });

  it('returns ok=true with embedding from Manax on success', async () => {
    mockedAxios.post.mockResolvedValueOnce({
      status: 200,
      data: { jobId: 'j', status: 'completed', result: { durationSec: 22.4, speakerEmbeddings: [{ speakerId: 'spk_abc', vector: [0.1, 0.2, 0.3], coverageFraction: 0.95 }] } },
    });
    const r = await service.enroll(Buffer.alloc(1000));
    expect(r.ok).toBe(true);
    expect(r.speakerId).toBe('spk_abc');
    expect(r.embedding).toEqual([0.1, 0.2, 0.3]);
    expect(r.embeddingDim).toBe(3);
    expect(r.audioSec).toBeCloseTo(22.4);
  });

  it('returns no_speech_detected when Manax returns 0 embeddings', async () => {
    mockedAxios.post.mockResolvedValueOnce({
      status: 200,
      data: { jobId: 'j', status: 'completed', result: { speakerEmbeddings: [] } },
    });
    const r = await service.enroll(Buffer.alloc(1000));
    expect(r.ok).toBe(false);
    expect(r.error).toBe('no_speech_detected');
  });

  it('returns manax_unavailable on HTTP failure', async () => {
    mockedAxios.post.mockRejectedValueOnce(new Error('boom'));
    const r = await service.enroll(Buffer.alloc(1000));
    expect(r.ok).toBe(false);
    expect(r.error).toBe('manax_unavailable');
  });
});

describe('VoiceGateService feature-disabled', () => {
  function disabledStub() {
    return {
      get: jest.fn((k: string, fallback?: any) =>
        k === 'OWNER_VOICE_ENABLED' ? 'false' : fallback,
      ),
    };
  }

  it('returns feature_disabled from enroll() when OWNER_VOICE_ENABLED=false', async () => {
    const svc = new VoiceGateService(disabledStub() as any);
    const r = await svc.enroll(Buffer.alloc(1000));
    expect(r.ok).toBe(false);
    expect(r.error).toBe('feature_disabled');
  });

  it('returns isOwner=null from verify() when feature is disabled', async () => {
    const svc = new VoiceGateService(disabledStub() as any);
    const r = await svc.verify(Buffer.alloc(32_000), [1, 0, 0]);
    expect(r.isOwner).toBeNull();
  });
});
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
npx jest src/voice-gate/voice-gate.service.spec.ts
```

- [ ] **Step 3: Add `enroll` + `isEnabled` to service**

Add field + constructor read:
```ts
private readonly enabled: boolean;

// in constructor:
this.enabled = config.get<string>('OWNER_VOICE_ENABLED', 'true') !== 'false';
```

Add public getter:
```ts
isEnabled(): boolean {
  return this.enabled;
}
```

Add method:
```ts
async enroll(audio: Buffer): Promise<OwnerEnrollResult> {
  if (!this.enabled) {
    return { ok: false, error: 'feature_disabled' };
  }
  const emb = await this.embedAudio(audio);
  if (emb.error === 'manax_unavailable') {
    return { ok: false, error: 'manax_unavailable' };
  }
  if (emb.embedding === null) {
    return { ok: false, error: 'no_speech_detected' };
  }
  return {
    ok: true,
    speakerId: emb.speakerId,
    embedding: emb.embedding,
    embeddingDim: emb.embedding.length,
    audioSec: emb.audioSec,
  };
}
```

Also gate `verify` on enabled:
```ts
async verify(audio: Buffer, ownerEmbedding: number[]): Promise<OwnerVerifyResult> {
  if (!this.enabled || !ownerEmbedding || ownerEmbedding.length === 0) {
    return { isOwner: null };
  }
  // ... existing body ...
}
```

Add `OwnerEnrollResult` to imports.

- [ ] **Step 4: Run test, expect PASS**

```bash
npx jest src/voice-gate/voice-gate.service.spec.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/voice-gate.service.ts src/voice-gate/voice-gate.service.spec.ts
git commit -m "feat(voice-gate): enroll method + OWNER_VOICE_ENABLED kill switch"
```

### Task 1.7: VoiceGateController — `GET /voice-gate/owner-status` (TDD)

**Files:**
- Create: `src/voice-gate/voice-gate.controller.ts`
- Create: `src/voice-gate/voice-gate.controller.spec.ts`

- [ ] **Step 1: Write the failing test**

`src/voice-gate/voice-gate.controller.spec.ts`:
```ts
import { Test, TestingModule } from '@nestjs/testing';
import { VoiceGateController } from './voice-gate.controller';
import { VoiceGateService } from './voice-gate.service';
import { PrismaService } from '../prisma/prisma.service';

describe('VoiceGateController.ownerStatus', () => {
  let controller: VoiceGateController;
  const mockPrisma = {
    profile: { findUnique: jest.fn(), update: jest.fn() },
  };
  const mockService = { isEnabled: jest.fn(() => true), enroll: jest.fn() };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [VoiceGateController],
      providers: [
        { provide: VoiceGateService, useValue: mockService },
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();
    controller = module.get(VoiceGateController);
  });

  it('returns enrolled=true with speakerId when ownerSpeakerId is set', async () => {
    mockPrisma.profile.findUnique.mockResolvedValueOnce({
      ownerSpeakerId: 'spk_abc',
      ownerEmbedding: [0.1, 0.2],
      updatedAt: new Date('2026-06-08T12:00:00Z'),
    });
    const r = await controller.ownerStatus({ user: { sub: 'u1' } } as any);
    expect(r).toEqual({
      enrolled: true,
      speakerId: 'spk_abc',
      enrolledAt: '2026-06-08T12:00:00.000Z',
    });
  });

  it('returns enrolled=false when ownerSpeakerId is null', async () => {
    mockPrisma.profile.findUnique.mockResolvedValueOnce({
      ownerSpeakerId: null,
      ownerEmbedding: [],
    });
    const r = await controller.ownerStatus({ user: { sub: 'u1' } } as any);
    expect(r).toEqual({ enrolled: false });
  });

  it('returns enrolled=false when profile is missing', async () => {
    mockPrisma.profile.findUnique.mockResolvedValueOnce(null);
    const r = await controller.ownerStatus({ user: { sub: 'u1' } } as any);
    expect(r).toEqual({ enrolled: false });
  });
});
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
npx jest src/voice-gate/voice-gate.controller.spec.ts
```

- [ ] **Step 3: Create controller**

`src/voice-gate/voice-gate.controller.ts`:
```ts
import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { PrismaService } from '../prisma/prisma.service';
import { VoiceGateService } from './voice-gate.service';

@Controller('voice-gate')
@UseGuards(JwtAuthGuard)
export class VoiceGateController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly service: VoiceGateService,
  ) {}

  @Get('owner-status')
  async ownerStatus(@Req() req: any) {
    const userId = req.user.sub;
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    if (!profile || !profile.ownerSpeakerId) {
      return { enrolled: false };
    }
    return {
      enrolled: true,
      speakerId: profile.ownerSpeakerId,
      enrolledAt: profile.updatedAt.toISOString(),
    };
  }
}
```

- [ ] **Step 4: Run test, expect PASS**

```bash
npx jest src/voice-gate/voice-gate.controller.spec.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/voice-gate.controller.ts src/voice-gate/voice-gate.controller.spec.ts
git commit -m "feat(voice-gate): GET /voice-gate/owner-status"
```

### Task 1.8: VoiceGateController — `POST /voice-gate/enroll` (TDD)

**Files:**
- Modify: `src/voice-gate/voice-gate.controller.ts`
- Modify: `src/voice-gate/voice-gate.controller.spec.ts`

- [ ] **Step 1: Add tests**

Append to spec file:
```ts
describe('VoiceGateController.enroll', () => {
  let controller: VoiceGateController;
  const mockPrisma = {
    profile: { findUnique: jest.fn(), update: jest.fn() },
  };
  const mockService = { isEnabled: jest.fn(() => true), enroll: jest.fn() };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [VoiceGateController],
      providers: [
        { provide: VoiceGateService, useValue: mockService },
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();
    controller = module.get(VoiceGateController);
  });

  function fakeFile(sizeBytes: number, durationSec: number): any {
    // 16kHz mono int16 = 32000 bytes/sec; spoof a WAV body of right size
    const buf = Buffer.alloc(Math.max(44, Math.round(durationSec * 32000)));
    return {
      buffer: buf,
      mimetype: 'audio/wav',
      size: buf.length,
      originalname: 'enroll.wav',
    };
  }

  it('returns 400 audio_too_short for < 15 sec', async () => {
    const file = fakeFile(0, 10);
    await expect(
      controller.enroll({ user: { sub: 'u1' } } as any, file),
    ).rejects.toMatchObject({
      response: { ok: false, error: 'audio_too_short', minSec: 15 },
      status: 400,
    });
  });

  it('saves embedding to Profile and returns 200 on success', async () => {
    const file = fakeFile(0, 22);
    mockService.enroll.mockResolvedValueOnce({
      ok: true,
      speakerId: 'spk_abc',
      embedding: [0.1, 0.2, 0.3],
      embeddingDim: 3,
      audioSec: 22.4,
    });
    const r = await controller.enroll({ user: { sub: 'u1' } } as any, file);
    expect(mockPrisma.profile.update).toHaveBeenCalledWith({
      where: { userId: 'u1' },
      data: { ownerSpeakerId: 'spk_abc', ownerEmbedding: [0.1, 0.2, 0.3] },
    });
    expect(r).toEqual({
      ok: true,
      speakerId: 'spk_abc',
      embeddingDim: 3,
      audioSec: 22.4,
    });
  });

  it('returns 422 no_speech_detected', async () => {
    const file = fakeFile(0, 22);
    mockService.enroll.mockResolvedValueOnce({ ok: false, error: 'no_speech_detected' });
    await expect(
      controller.enroll({ user: { sub: 'u1' } } as any, file),
    ).rejects.toMatchObject({ status: 422 });
  });

  it('returns 503 when feature_disabled', async () => {
    const file = fakeFile(0, 22);
    mockService.enroll.mockResolvedValueOnce({ ok: false, error: 'feature_disabled' });
    await expect(
      controller.enroll({ user: { sub: 'u1' } } as any, file),
    ).rejects.toMatchObject({ status: 503 });
  });
});
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
npx jest src/voice-gate/voice-gate.controller.spec.ts
```

- [ ] **Step 3: Add `enroll` to controller**

Add imports:
```ts
import {
  Body,
  HttpException,
  HttpStatus,
  Post,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
```

Add method:
```ts
@Post('enroll')
@UseInterceptors(FileInterceptor('audio'))
async enroll(@Req() req: any, @UploadedFile() file: Express.Multer.File) {
  if (!file || !file.buffer) {
    throw new HttpException({ ok: false, error: 'audio_too_short', minSec: 15 }, HttpStatus.BAD_REQUEST);
  }
  // 16kHz mono int16: 32000 bytes/sec. Reject < 15 sec at the byte level
  // before paying Manax for it.
  const minBytes = 15 * 32_000;
  if (file.size < minBytes) {
    throw new HttpException(
      { ok: false, error: 'audio_too_short', minSec: 15 },
      HttpStatus.BAD_REQUEST,
    );
  }
  const userId = req.user.sub;
  const result = await this.service.enroll(file.buffer);
  if (result.ok && result.embedding && result.speakerId) {
    await this.prisma.profile.update({
      where: { userId },
      data: {
        ownerSpeakerId: result.speakerId,
        ownerEmbedding: result.embedding,
      },
    });
    return {
      ok: true,
      speakerId: result.speakerId,
      embeddingDim: result.embeddingDim,
      audioSec: result.audioSec,
    };
  }
  const code =
    result.error === 'feature_disabled'
      ? HttpStatus.SERVICE_UNAVAILABLE
      : result.error === 'manax_unavailable'
      ? HttpStatus.SERVICE_UNAVAILABLE
      : result.error === 'no_speech_detected'
      ? HttpStatus.UNPROCESSABLE_ENTITY
      : HttpStatus.BAD_REQUEST;
  throw new HttpException({ ok: false, error: result.error }, code);
}
```

- [ ] **Step 4: Run test, expect PASS**

```bash
npx jest src/voice-gate/voice-gate.controller.spec.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/voice-gate.controller.ts src/voice-gate/voice-gate.controller.spec.ts
git commit -m "feat(voice-gate): POST /voice-gate/enroll with size guard"
```

### Task 1.9: VoiceGateController — `DELETE /voice-gate/owner` (TDD)

**Files:**
- Modify: `src/voice-gate/voice-gate.controller.ts`
- Modify: `src/voice-gate/voice-gate.controller.spec.ts`

- [ ] **Step 1: Add test**

Append to spec file:
```ts
describe('VoiceGateController.deleteOwner', () => {
  let controller: VoiceGateController;
  const mockPrisma = {
    profile: { findUnique: jest.fn(), update: jest.fn() },
  };
  const mockService = { isEnabled: jest.fn(() => true), enroll: jest.fn() };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [VoiceGateController],
      providers: [
        { provide: VoiceGateService, useValue: mockService },
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();
    controller = module.get(VoiceGateController);
  });

  it('clears ownerSpeakerId and ownerEmbedding on the profile', async () => {
    await controller.deleteOwner({ user: { sub: 'u1' } } as any);
    expect(mockPrisma.profile.update).toHaveBeenCalledWith({
      where: { userId: 'u1' },
      data: { ownerSpeakerId: null, ownerEmbedding: [] },
    });
  });
});
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
npx jest src/voice-gate/voice-gate.controller.spec.ts
```

- [ ] **Step 3: Add `deleteOwner` method**

Add imports:
```ts
import { Delete, HttpCode } from '@nestjs/common';
```

Add method to controller:
```ts
@Delete('owner')
@HttpCode(204)
async deleteOwner(@Req() req: any) {
  const userId = req.user.sub;
  await this.prisma.profile.update({
    where: { userId },
    data: { ownerSpeakerId: null, ownerEmbedding: [] },
  });
}
```

- [ ] **Step 4: Run test, expect PASS**

```bash
npx jest src/voice-gate/voice-gate.controller.spec.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/voice-gate.controller.ts src/voice-gate/voice-gate.controller.spec.ts
git commit -m "feat(voice-gate): DELETE /voice-gate/owner"
```

### Task 1.10: Register VoiceGateModule in AppModule

**Files:**
- Create: `src/voice-gate/voice-gate.module.ts`
- Modify: `src/app.module.ts`

- [ ] **Step 1: Create module**

`src/voice-gate/voice-gate.module.ts`:
```ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PrismaModule } from '../prisma/prisma.module';
import { VoiceGateController } from './voice-gate.controller';
import { VoiceGateService } from './voice-gate.service';

@Module({
  imports: [ConfigModule, PrismaModule],
  controllers: [VoiceGateController],
  providers: [VoiceGateService],
  exports: [VoiceGateService],
})
export class VoiceGateModule {}
```

- [ ] **Step 2: Import in AppModule**

Edit `src/app.module.ts`: add to imports list (alphabetical-ish, near other feature modules):

```ts
import { VoiceGateModule } from './voice-gate/voice-gate.module';

// in @Module({ imports: [...] }):
VoiceGateModule,
```

- [ ] **Step 3: Build to verify no DI errors**

```bash
npm run build
```
Expected: no Nest DI errors.

- [ ] **Step 4: Run the full backend test suite**

```bash
npx jest
```
Expected: all previously-passing tests still pass; new voice-gate tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/voice-gate.module.ts src/app.module.ts
git commit -m "feat(voice-gate): register module in AppModule"
```

### Task 1.11: Manual integration test against real Manax on DEV

**Files:** none (manual)

- [ ] **Step 1: Set env vars locally**

Get the Manax API key value from DEV:
```bash
ssh dvolkov@89.169.55.217 'grep API_KEY ~/manax-speech/.env.local'
```
Add the value to `~/Downloads/taler_id/.env` (untracked):
```
MANAX_BASE_URL=http://127.0.0.1:8791
MANAX_API_KEY=<value>
OWNER_VOICE_THRESHOLD=0.5
OWNER_VOICE_WINDOW_MS=1000
OWNER_VOICE_ENABLED=true
```

- [ ] **Step 2: Deploy backend build to DEV**

```bash
ssh dvolkov@89.169.55.217 '
  cd ~/taler-id
  git fetch origin
  git checkout experiment/voice-owner-gating
  git pull
  npm run build
  pm2 restart taler-id-dev
'
```

Add env vars to the DEV box's `~/taler-id/.env` first if not there.

- [ ] **Step 3: Smoke-test enroll endpoint with curl**

From the DEV box:
```bash
TOKEN=<a valid JWT for integration_test@taler-test.com — fetch via login>
curl -X POST https://staging.id.taler.tirol/voice-gate/enroll \
  -H "Authorization: Bearer $TOKEN" \
  -F "audio=@/var/www/recordings/89d046db-818d-4df0-9fe5-8d5845c6157f.mp3"
```

NB: this 14-sec file will return 400 `audio_too_short`. That's the expected sad-path. Then try a >15s file:
```bash
curl -X POST https://staging.id.taler.tirol/voice-gate/enroll \
  -H "Authorization: Bearer $TOKEN" \
  -F "audio=@/var/www/recordings/cac3e344-46f6-4b12-918f-6128b8baa838.mp3"
```
This is 98 sec, should return 200 with `speakerId` + `embeddingDim: 192`.

- [ ] **Step 4: Confirm DB state**

```bash
ssh dvolkov@89.169.55.217 'psql taler_id_dev -c "select \"userId\", \"ownerSpeakerId\", array_length(\"ownerEmbedding\", 1) as dim from \"Profile\" where \"ownerSpeakerId\" is not null limit 5;"'
```

Expected: 1 row with `dim = 192`.

- [ ] **Step 5: Confirm `/voice-gate/owner-status` reflects state**

```bash
curl -H "Authorization: Bearer $TOKEN" https://staging.id.taler.tirol/voice-gate/owner-status
# expected: {"enrolled": true, "speakerId": "spk_…", "enrolledAt": "…"}
```

- [ ] **Step 6: Reset and confirm DELETE works**

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" https://staging.id.taler.tirol/voice-gate/owner
curl -H "Authorization: Bearer $TOKEN" https://staging.id.taler.tirol/voice-gate/owner-status
# expected: {"enrolled": false}
```

If any of the above fails, fix and re-deploy before moving on.

---

## Phase 2: Backend WS proxy modifications

### Task 2.1: PCM windowing helper (TDD)

**Files:**
- Create: `src/voice-gate/pcm-window.ts`
- Create: `src/voice-gate/pcm-window.spec.ts`

A `PcmWindow` accumulates base64-encoded PCM chunks (as sent by mobile in `input_audio_buffer.append`) and yields a Buffer once a target window size is reached. Resets after each emit.

- [ ] **Step 1: Write the failing test**

`src/voice-gate/pcm-window.spec.ts`:
```ts
import { PcmWindow } from './pcm-window';

describe('PcmWindow', () => {
  it('does not emit before window is full', () => {
    const w = new PcmWindow(1000); // 1000 bytes window
    expect(w.appendBase64(Buffer.alloc(500).toString('base64'))).toBeNull();
    expect(w.appendBase64(Buffer.alloc(400).toString('base64'))).toBeNull();
  });

  it('emits exactly the configured window size and keeps the overflow', () => {
    const w = new PcmWindow(1000);
    expect(w.appendBase64(Buffer.alloc(700).toString('base64'))).toBeNull();
    const emitted = w.appendBase64(Buffer.alloc(500).toString('base64'));
    expect(emitted).not.toBeNull();
    expect(emitted!.length).toBe(1000);
    // 200 bytes overflow should be carried into the next window
    expect(w.appendBase64(Buffer.alloc(800).toString('base64'))).toBeNull();
    const second = w.appendBase64(Buffer.alloc(0).toString('base64'));
    expect(second).toBeNull(); // total now 1000, but we need explicit fill
    expect(w.appendBase64(Buffer.alloc(0).toString('base64'))).toBeNull();
  });

  it('handles invalid base64 gracefully (returns null)', () => {
    const w = new PcmWindow(1000);
    expect(w.appendBase64('!!!not base64!!!')).toBeNull();
  });
});
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
npx jest src/voice-gate/pcm-window.spec.ts
```

- [ ] **Step 3: Write minimal implementation**

`src/voice-gate/pcm-window.ts`:
```ts
export class PcmWindow {
  private buffer: Buffer = Buffer.alloc(0);

  constructor(private readonly windowBytes: number) {}

  /**
   * Append base64-encoded PCM bytes. Returns a Buffer of exactly windowBytes
   * once enough audio has been accumulated; otherwise returns null. Overflow
   * (bytes past windowBytes) is carried into the next call.
   */
  appendBase64(b64: string): Buffer | null {
    let chunk: Buffer;
    try {
      chunk = Buffer.from(b64, 'base64');
    } catch {
      return null;
    }
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length < this.windowBytes) {
      return null;
    }
    const emitted = this.buffer.subarray(0, this.windowBytes);
    this.buffer = Buffer.from(this.buffer.subarray(this.windowBytes));
    return emitted;
  }

  reset(): void {
    this.buffer = Buffer.alloc(0);
  }
}
```

- [ ] **Step 4: Run test, expect PASS**

```bash
npx jest src/voice-gate/pcm-window.spec.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/pcm-window.ts src/voice-gate/pcm-window.spec.ts
git commit -m "feat(voice-gate): PcmWindow accumulator"
```

### Task 2.2: PCM windowing helper — wrap as WAV (TDD)

Manax wants WAV (header + PCM). Need a tiny helper to wrap raw 16kHz mono int16 PCM into a valid WAV.

**Files:**
- Modify: `src/voice-gate/pcm-window.ts` (add export)
- Modify: `src/voice-gate/pcm-window.spec.ts`

- [ ] **Step 1: Add test**

Append to `pcm-window.spec.ts`:
```ts
import { wrapWav16kMono } from './pcm-window';

describe('wrapWav16kMono', () => {
  it('produces a 44-byte RIFF header + the original PCM payload', () => {
    const pcm = Buffer.alloc(32_000); // 1 sec of audio
    const wav = wrapWav16kMono(pcm);
    expect(wav.length).toBe(44 + 32_000);
    expect(wav.slice(0, 4).toString()).toBe('RIFF');
    expect(wav.slice(8, 12).toString()).toBe('WAVE');
    // sample rate at bytes 24..28 little-endian → 16000
    expect(wav.readUInt32LE(24)).toBe(16000);
    // bits per sample at bytes 34..36 → 16
    expect(wav.readUInt16LE(34)).toBe(16);
    // num channels at bytes 22..24 → 1
    expect(wav.readUInt16LE(22)).toBe(1);
  });
});
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
npx jest src/voice-gate/pcm-window.spec.ts
```

- [ ] **Step 3: Add helper**

Append to `pcm-window.ts`:
```ts
/**
 * Wrap 16kHz mono int16 PCM in a RIFF/WAV header. Manax accepts this directly.
 */
export function wrapWav16kMono(pcm: Buffer): Buffer {
  const sampleRate = 16_000;
  const numChannels = 1;
  const bitsPerSample = 16;
  const byteRate = sampleRate * numChannels * (bitsPerSample / 8);
  const blockAlign = numChannels * (bitsPerSample / 8);

  const header = Buffer.alloc(44);
  header.write('RIFF', 0);
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write('WAVE', 8);
  header.write('fmt ', 12);
  header.writeUInt32LE(16, 16);              // fmt chunk size
  header.writeUInt16LE(1, 20);               // PCM
  header.writeUInt16LE(numChannels, 22);
  header.writeUInt32LE(sampleRate, 24);
  header.writeUInt32LE(byteRate, 28);
  header.writeUInt16LE(blockAlign, 32);
  header.writeUInt16LE(bitsPerSample, 34);
  header.write('data', 36);
  header.writeUInt32LE(pcm.length, 40);

  return Buffer.concat([header, pcm]);
}
```

- [ ] **Step 4: Run test, expect PASS**

```bash
npx jest src/voice-gate/pcm-window.spec.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/voice-gate/pcm-window.ts src/voice-gate/pcm-window.spec.ts
git commit -m "feat(voice-gate): wrapWav16kMono helper"
```

### Task 2.3: Wire WS-proxy tap into `main.ts`

**Files:**
- Modify: `src/main.ts` (the `handleUpgrade` callback, lines 559–678)

This is the riskiest change in the plan. It modifies a hot path. Test by running the assistant end-to-end after deploy; no unit test for `main.ts` proxy code today.

- [ ] **Step 1: Add imports near other voice-gate work**

At the top of `main.ts`:
```ts
import { VoiceGateService } from './voice-gate/voice-gate.service';
import { PcmWindow, wrapWav16kMono } from './voice-gate/pcm-window';
import { PrismaService } from './prisma/prisma.service';
```

- [ ] **Step 2: Resolve services from the Nest container at proxy setup**

Locate the line that starts `const wss = new WebSocketServer({ noServer: true });` (around 560). Just before it, add:
```ts
const voiceGate = app.get(VoiceGateService);
const prisma = app.get(PrismaService);
const windowBytes =
  Math.round(
    parseFloat(process.env.OWNER_VOICE_WINDOW_MS ?? '1000') * 16, // 16 samples/ms × 2 bytes
  ) * 2; // 1000ms → 32000 bytes; written as multiplication for clarity
```

- [ ] **Step 3: Extract `userId` after JWT verify**

Inside the existing `try { verify(token, jwtPublicKey, ...) } catch { ... }` block (~ line 582), change the verify call to capture the decoded payload:
```ts
let userId: string | null = null;
try {
  const payload = verify(token, jwtPublicKey, { algorithms: ['RS256'] }) as any;
  userId = payload.sub ?? null;
} catch {
  socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
  socket.destroy();
  return;
}
```

- [ ] **Step 4: Load `ownerEmbedding` and initialize per-session state inside the upgrade callback**

Inside the `wss.handleUpgrade(req, socket, head, (clientWs) => {` block, right after the model is parsed:
```ts
// Per-session voice-gate state
let ownerEmbedding: number[] = [];
let responseInFlight = false;
const pcmWindow = new PcmWindow(windowBytes);
let verifyInFlight = false;

if (voiceGate.isEnabled() && userId) {
  prisma.profile
    .findUnique({ where: { userId } })
    .then((p) => {
      ownerEmbedding = p?.ownerEmbedding ?? [];
      if (ownerEmbedding.length === 0) {
        Logger.warn(
          `proxy: owner not enrolled (userId=${userId}), gating skipped`,
          'RealtimeProxy',
        );
      }
    })
    .catch((e) => Logger.warn(`proxy: load ownerEmbedding failed: ${e.message}`, 'RealtimeProxy'));
}
```

- [ ] **Step 5: Tap audio frames from client → OpenAI**

Find the existing `clientWs.on('message', (data: any, isBinary: boolean) => { ... });` handler (~ line 603). Do **not** add a second `on('message')` listener — modify the existing one. Inside the existing handler body, after the existing `if (openaiReady) {…} else {…}` forwarding logic completes, append this voice-gate tap block:

```ts
  // ↑↑↑ existing forward-to-OpenAI logic stays exactly as is ↑↑↑

  // Voice-gate tap: extract base64 PCM from input_audio_buffer.append frames
  if (
    voiceGate.isEnabled() &&
    ownerEmbedding.length > 0 &&
    !isBinary &&
    !verifyInFlight
  ) {
    try {
      const parsed = JSON.parse(data.toString());
      if (parsed.type === 'input_audio_buffer.append' && typeof parsed.audio === 'string') {
        const window = pcmWindow.appendBase64(parsed.audio);
        if (window) {
          verifyInFlight = true;
          const wav = wrapWav16kMono(window);
          voiceGate
            .verify(wav, ownerEmbedding)
            .then((verdict) => {
              verifyInFlight = false;
              Logger.log(
                JSON.stringify({
                  ns: 'voice-gate.verify',
                  userId,
                  cosine: verdict.similarity ?? null,
                  verdict:
                    verdict.isOwner === true
                      ? 'owner'
                      : verdict.isOwner === false
                      ? 'non_owner'
                      : 'fail_open',
                  audioSec: verdict.audioSec ?? null,
                  manaxLatencyMs: verdict.manaxLatencyMs ?? null,
                }),
                'voice-gate.verify',
              );
              if (verdict.isOwner === false && openaiWs.readyState === WebSocket.OPEN) {
                openaiWs.send(JSON.stringify({ type: 'input_audio_buffer.clear' }));
                if (responseInFlight) {
                  openaiWs.send(JSON.stringify({ type: 'response.cancel' }));
                }
              }
            })
            .catch((e) => {
              verifyInFlight = false;
              Logger.warn(`voice-gate verify exception: ${e.message}`, 'RealtimeProxy');
            });
        }
      }
    } catch {
      // ignore parse errors; not all messages are JSON we care about
    }
  }
```

(no trailing `});` — you're still inside the existing handler body, the existing closing `});` already follows below it)

- [ ] **Step 6: Track `responseInFlight` from OpenAI → client events**

Find `openaiWs.on('message', (data: any, isBinary: boolean) => {` (around line 644). At the top of the handler, alongside the existing `session.updated` sniff, add:

```ts
openaiWs.on('message', (data: any, isBinary: boolean) => {
  try {
    const ev = JSON.parse(data.toString());
    if (ev.type === 'session.updated') sessionConfigured = true;
    if (ev.type === 'response.created') responseInFlight = true;
    if (ev.type === 'response.done' || ev.type === 'response.cancelled') {
      responseInFlight = false;
    }
  } catch (_) {}
  if (clientWs.readyState === WebSocket.OPEN)
    clientWs.send(isBinary ? data : data.toString(), {
      binary: isBinary,
    });
});
```

- [ ] **Step 7: Build and run all tests**

```bash
cd ~/Downloads/taler_id
npm run build
npx jest
```
Expected: build green; all tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/main.ts
git commit -m "feat(voice-gate): WS proxy tap + speculative retract"
```

---

## Phase 3: Mobile feature `voice_enrollment`

Working tree: `~/Downloads/taler_id_mobile`.

### Task 3.1: Create mobile branch

**Files:** none

- [ ] **Step 1: Branch off dev**

```bash
cd ~/Downloads/taler_id_mobile
git fetch origin
git checkout dev
git pull --rebase
git checkout -b experiment/voice-owner-gating
```

### Task 3.2: Domain entity + repository abstract

**Files:**
- Create: `lib/features/voice_enrollment/domain/entities/owner_voice_status.dart`
- Create: `lib/features/voice_enrollment/domain/repositories/voice_enrollment_repository.dart`

- [ ] **Step 1: Create entity**

`lib/features/voice_enrollment/domain/entities/owner_voice_status.dart`:
```dart
import 'package:freezed_annotation/freezed_annotation.dart';

part 'owner_voice_status.freezed.dart';
part 'owner_voice_status.g.dart';

@freezed
class OwnerVoiceStatus with _$OwnerVoiceStatus {
  const factory OwnerVoiceStatus({
    required bool enrolled,
    String? speakerId,
    DateTime? enrolledAt,
  }) = _OwnerVoiceStatus;

  factory OwnerVoiceStatus.fromJson(Map<String, dynamic> json) =>
      _$OwnerVoiceStatusFromJson(json);
}
```

- [ ] **Step 2: Create repository abstract**

`lib/features/voice_enrollment/domain/repositories/voice_enrollment_repository.dart`:
```dart
import '../entities/owner_voice_status.dart';

abstract class VoiceEnrollmentRepository {
  Future<OwnerVoiceStatus> getStatus();
  Future<OwnerVoiceStatus> enroll(String wavPath);
  Future<void> deleteOwner();
}
```

- [ ] **Step 3: Generate freezed files**

```bash
cd ~/Downloads/taler_id_mobile
flutter pub run build_runner build --delete-conflicting-outputs
```

- [ ] **Step 4: Commit**

```bash
git add lib/features/voice_enrollment/
git commit -m "feat(voice-enrollment): domain entity + repo abstract"
```

### Task 3.3: Data layer — remote datasource + repo impl

**Files:**
- Create: `lib/features/voice_enrollment/data/datasources/voice_enrollment_remote.dart`
- Create: `lib/features/voice_enrollment/data/repositories/voice_enrollment_repository_impl.dart`

- [ ] **Step 1: Remote datasource**

`lib/features/voice_enrollment/data/datasources/voice_enrollment_remote.dart`:
```dart
import 'package:dio/dio.dart';
import '../../../../core/api/dio_client.dart';
import '../../domain/entities/owner_voice_status.dart';

class VoiceEnrollmentRemote {
  final DioClient _dio;

  VoiceEnrollmentRemote(this._dio);

  Future<OwnerVoiceStatus> getStatus() async {
    final resp = await _dio.dio.get('/voice-gate/owner-status');
    return OwnerVoiceStatus.fromJson(Map<String, dynamic>.from(resp.data));
  }

  Future<OwnerVoiceStatus> enroll(String wavPath) async {
    final form = FormData.fromMap({
      'audio': await MultipartFile.fromFile(wavPath, filename: 'enroll.wav'),
    });
    final resp = await _dio.dio.post('/voice-gate/enroll', data: form);
    // Backend returns { ok, speakerId, embeddingDim, audioSec } on 200; map to Status
    final data = Map<String, dynamic>.from(resp.data);
    return OwnerVoiceStatus(
      enrolled: data['ok'] == true,
      speakerId: data['speakerId'] as String?,
      enrolledAt: DateTime.now().toUtc(),
    );
  }

  Future<void> deleteOwner() async {
    await _dio.dio.delete('/voice-gate/owner');
  }
}
```

- [ ] **Step 2: Repository impl**

`lib/features/voice_enrollment/data/repositories/voice_enrollment_repository_impl.dart`:
```dart
import '../../domain/entities/owner_voice_status.dart';
import '../../domain/repositories/voice_enrollment_repository.dart';
import '../datasources/voice_enrollment_remote.dart';

class VoiceEnrollmentRepositoryImpl implements VoiceEnrollmentRepository {
  final VoiceEnrollmentRemote _remote;
  VoiceEnrollmentRepositoryImpl(this._remote);

  @override
  Future<OwnerVoiceStatus> getStatus() => _remote.getStatus();

  @override
  Future<OwnerVoiceStatus> enroll(String wavPath) => _remote.enroll(wavPath);

  @override
  Future<void> deleteOwner() => _remote.deleteOwner();
}
```

- [ ] **Step 3: Commit**

```bash
git add lib/features/voice_enrollment/data/
git commit -m "feat(voice-enrollment): remote datasource + repo impl"
```

### Task 3.4: BLoC events, states, logic + tests

**Files:**
- Create: `lib/features/voice_enrollment/presentation/bloc/voice_enrollment_event.dart`
- Create: `lib/features/voice_enrollment/presentation/bloc/voice_enrollment_state.dart`
- Create: `lib/features/voice_enrollment/presentation/bloc/voice_enrollment_bloc.dart`
- Create: `test/features/voice_enrollment/voice_enrollment_bloc_test.dart`

- [ ] **Step 1: Write the failing test**

`test/features/voice_enrollment/voice_enrollment_bloc_test.dart`:
```dart
import 'package:bloc_test/bloc_test.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:taler_id_mobile/features/voice_enrollment/domain/entities/owner_voice_status.dart';
import 'package:taler_id_mobile/features/voice_enrollment/domain/repositories/voice_enrollment_repository.dart';
import 'package:taler_id_mobile/features/voice_enrollment/presentation/bloc/voice_enrollment_bloc.dart';
import 'package:taler_id_mobile/features/voice_enrollment/presentation/bloc/voice_enrollment_event.dart';
import 'package:taler_id_mobile/features/voice_enrollment/presentation/bloc/voice_enrollment_state.dart';

class _MockRepo extends Mock implements VoiceEnrollmentRepository {}

void main() {
  late _MockRepo repo;

  setUp(() {
    repo = _MockRepo();
  });

  blocTest<VoiceEnrollmentBloc, VoiceEnrollmentState>(
    'Check → emits Enrolled when status.enrolled=true',
    build: () {
      when(() => repo.getStatus()).thenAnswer(
        (_) async => const OwnerVoiceStatus(enrolled: true, speakerId: 'spk_x'),
      );
      return VoiceEnrollmentBloc(repo: repo);
    },
    act: (b) => b.add(const Check()),
    expect: () => [
      isA<Idle>().having((s) => s.busy, 'busy', true),
      isA<Enrolled>().having((s) => s.speakerId, 'speakerId', 'spk_x'),
    ],
  );

  blocTest<VoiceEnrollmentBloc, VoiceEnrollmentState>(
    'Check → emits NotEnrolled when status.enrolled=false',
    build: () {
      when(() => repo.getStatus()).thenAnswer(
        (_) async => const OwnerVoiceStatus(enrolled: false),
      );
      return VoiceEnrollmentBloc(repo: repo);
    },
    act: (b) => b.add(const Check()),
    expect: () => [
      isA<Idle>().having((s) => s.busy, 'busy', true),
      isA<NotEnrolled>(),
    ],
  );

  blocTest<VoiceEnrollmentBloc, VoiceEnrollmentState>(
    'Submit → emits Enrolled on success',
    build: () {
      when(() => repo.enroll(any())).thenAnswer(
        (_) async => const OwnerVoiceStatus(enrolled: true, speakerId: 'spk_y'),
      );
      return VoiceEnrollmentBloc(repo: repo);
    },
    act: (b) => b.add(const Submit('/tmp/x.wav')),
    expect: () => [
      isA<Submitting>(),
      isA<Enrolled>().having((s) => s.speakerId, 'speakerId', 'spk_y'),
    ],
  );

  blocTest<VoiceEnrollmentBloc, VoiceEnrollmentState>(
    'Submit → emits Failed on error',
    build: () {
      when(() => repo.enroll(any())).thenThrow(Exception('boom'));
      return VoiceEnrollmentBloc(repo: repo);
    },
    act: (b) => b.add(const Submit('/tmp/x.wav')),
    expect: () => [
      isA<Submitting>(),
      isA<Failed>(),
    ],
  );
}
```

- [ ] **Step 2: Run test, expect FAIL**

```bash
cd ~/Downloads/taler_id_mobile
flutter test test/features/voice_enrollment/voice_enrollment_bloc_test.dart
```

- [ ] **Step 3: Write events**

`lib/features/voice_enrollment/presentation/bloc/voice_enrollment_event.dart`:
```dart
import 'package:equatable/equatable.dart';

abstract class VoiceEnrollmentEvent extends Equatable {
  const VoiceEnrollmentEvent();
  @override
  List<Object?> get props => const [];
}

class Check extends VoiceEnrollmentEvent {
  const Check();
}

class StartRecording extends VoiceEnrollmentEvent {
  const StartRecording();
}

class Submit extends VoiceEnrollmentEvent {
  final String wavPath;
  const Submit(this.wavPath);
  @override
  List<Object?> get props => [wavPath];
}

class Reset extends VoiceEnrollmentEvent {
  const Reset();
}
```

- [ ] **Step 4: Write states**

`lib/features/voice_enrollment/presentation/bloc/voice_enrollment_state.dart`:
```dart
import 'package:equatable/equatable.dart';

abstract class VoiceEnrollmentState extends Equatable {
  const VoiceEnrollmentState();
  @override
  List<Object?> get props => const [];
}

class Idle extends VoiceEnrollmentState {
  final bool busy;
  const Idle({this.busy = false});
  @override
  List<Object?> get props => [busy];
}

class NotEnrolled extends VoiceEnrollmentState {
  const NotEnrolled();
}

class Recording extends VoiceEnrollmentState {
  const Recording();
}

class Submitting extends VoiceEnrollmentState {
  const Submitting();
}

class Enrolled extends VoiceEnrollmentState {
  final String? speakerId;
  const Enrolled({this.speakerId});
  @override
  List<Object?> get props => [speakerId];
}

class Failed extends VoiceEnrollmentState {
  final String message;
  const Failed(this.message);
  @override
  List<Object?> get props => [message];
}
```

- [ ] **Step 5: Write BLoC**

`lib/features/voice_enrollment/presentation/bloc/voice_enrollment_bloc.dart`:
```dart
import 'package:flutter_bloc/flutter_bloc.dart';
import '../../domain/repositories/voice_enrollment_repository.dart';
import 'voice_enrollment_event.dart';
import 'voice_enrollment_state.dart';

class VoiceEnrollmentBloc
    extends Bloc<VoiceEnrollmentEvent, VoiceEnrollmentState> {
  final VoiceEnrollmentRepository repo;

  VoiceEnrollmentBloc({required this.repo}) : super(const Idle()) {
    on<Check>(_onCheck);
    on<StartRecording>((_, emit) => emit(const Recording()));
    on<Submit>(_onSubmit);
    on<Reset>((_, emit) => emit(const Idle()));
  }

  Future<void> _onCheck(Check _, Emitter<VoiceEnrollmentState> emit) async {
    emit(const Idle(busy: true));
    try {
      final status = await repo.getStatus();
      if (status.enrolled) {
        emit(Enrolled(speakerId: status.speakerId));
      } else {
        emit(const NotEnrolled());
      }
    } catch (e) {
      emit(Failed(e.toString()));
    }
  }

  Future<void> _onSubmit(Submit event, Emitter<VoiceEnrollmentState> emit) async {
    emit(const Submitting());
    try {
      final status = await repo.enroll(event.wavPath);
      emit(Enrolled(speakerId: status.speakerId));
    } catch (e) {
      emit(Failed(e.toString()));
    }
  }
}
```

- [ ] **Step 6: Run test, expect PASS**

```bash
flutter test test/features/voice_enrollment/voice_enrollment_bloc_test.dart
```

- [ ] **Step 7: Commit**

```bash
git add lib/features/voice_enrollment/presentation/bloc/ test/features/voice_enrollment/
git commit -m "feat(voice-enrollment): BLoC events, states, logic + tests"
```

### Task 3.5: Owner enrollment sheet widget

**Files:**
- Create: `lib/features/voice_enrollment/presentation/widgets/owner_enrollment_sheet.dart`

- [ ] **Step 1: Write the widget**

`lib/features/voice_enrollment/presentation/widgets/owner_enrollment_sheet.dart`:
```dart
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:path_provider/path_provider.dart';
import 'package:record/record.dart';
import '../bloc/voice_enrollment_bloc.dart';
import '../bloc/voice_enrollment_event.dart';
import '../bloc/voice_enrollment_state.dart';

class OwnerEnrollmentSheet extends StatefulWidget {
  const OwnerEnrollmentSheet({super.key});

  @override
  State<OwnerEnrollmentSheet> createState() => _OwnerEnrollmentSheetState();
}

class _OwnerEnrollmentSheetState extends State<OwnerEnrollmentSheet> {
  static const int _targetSec = 20;
  final _recorder = AudioRecorder();
  Timer? _ticker;
  int _elapsedSec = 0;
  String? _wavPath;

  @override
  void dispose() {
    _ticker?.cancel();
    _recorder.dispose();
    super.dispose();
  }

  Future<void> _startRecording() async {
    if (!await _recorder.hasPermission()) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Микрофон не разрешён')),
        );
      }
      return;
    }
    final dir = await getTemporaryDirectory();
    final path = '${dir.path}/owner_enroll_${DateTime.now().millisecondsSinceEpoch}.wav';
    await _recorder.start(
      const RecordConfig(encoder: AudioEncoder.wav, sampleRate: 16000, numChannels: 1),
      path: path,
    );
    setState(() {
      _wavPath = path;
      _elapsedSec = 0;
    });
    context.read<VoiceEnrollmentBloc>().add(const StartRecording());
    _ticker = Timer.periodic(const Duration(seconds: 1), (t) async {
      if (_elapsedSec >= _targetSec) {
        t.cancel();
        await _stopAndSubmit();
        return;
      }
      setState(() => _elapsedSec += 1);
    });
  }

  Future<void> _stopAndSubmit() async {
    final path = _wavPath;
    await _recorder.stop();
    if (path != null && mounted) {
      context.read<VoiceEnrollmentBloc>().add(Submit(path));
    }
  }

  @override
  Widget build(BuildContext context) {
    return BlocConsumer<VoiceEnrollmentBloc, VoiceEnrollmentState>(
      listener: (ctx, state) {
        if (state is Enrolled) Navigator.of(ctx).pop(true);
      },
      builder: (ctx, state) {
        final isRecording = state is Recording;
        final isSubmitting = state is Submitting;
        return Padding(
          padding: EdgeInsets.only(
            bottom: MediaQuery.of(ctx).viewInsets.bottom,
            left: 24,
            right: 24,
            top: 24,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Запиши свой голос',
                style: Theme.of(ctx).textTheme.titleLarge,
              ),
              const SizedBox(height: 12),
              const Text(
                'Это нужно, чтобы ассистент реагировал только на тебя. '
                'Скажи что-то на $_targetSec секунд — например, прочитай '
                'два предложения из новостей или опиши свой день.',
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              if (isRecording)
                Column(children: [
                  const Icon(Icons.mic, size: 48, color: Colors.red),
                  Text('$_elapsedSec / $_targetSec сек'),
                ])
              else if (isSubmitting)
                const Column(children: [
                  CircularProgressIndicator(),
                  SizedBox(height: 8),
                  Text('Отправляю…'),
                ])
              else if (state is Failed)
                Text('Ошибка: ${state.message}', style: const TextStyle(color: Colors.red))
              else
                IconButton(
                  icon: const Icon(Icons.mic, size: 64),
                  onPressed: _startRecording,
                ),
              const SizedBox(height: 24),
              TextButton(
                onPressed: () => Navigator.of(ctx).pop(false),
                child: const Text('Отмена'),
              ),
              const SizedBox(height: 16),
            ],
          ),
        );
      },
    );
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add lib/features/voice_enrollment/presentation/widgets/
git commit -m "feat(voice-enrollment): owner enrollment bottom sheet"
```

### Task 3.6: DI registration

**Files:**
- Modify: `lib/core/di/service_locator.dart`

- [ ] **Step 1: Add imports near other feature imports**

```dart
import '../../features/voice_enrollment/data/datasources/voice_enrollment_remote.dart';
import '../../features/voice_enrollment/data/repositories/voice_enrollment_repository_impl.dart';
import '../../features/voice_enrollment/domain/repositories/voice_enrollment_repository.dart';
import '../../features/voice_enrollment/presentation/bloc/voice_enrollment_bloc.dart';
```

- [ ] **Step 2: Register near the other data-source registrations (~line 558)**

```dart
sl.registerLazySingleton(() => VoiceEnrollmentRemote(sl<DioClient>()));
sl.registerLazySingleton<VoiceEnrollmentRepository>(
  () => VoiceEnrollmentRepositoryImpl(sl<VoiceEnrollmentRemote>()),
);
```

- [ ] **Step 3: Register BLoC factory near other BLoC factories (~line 754)**

```dart
sl.registerFactory(() => VoiceEnrollmentBloc(repo: sl<VoiceEnrollmentRepository>()));
```

- [ ] **Step 4: Commit**

```bash
git add lib/core/di/service_locator.dart
git commit -m "feat(voice-enrollment): DI registration"
```

### Task 3.7: Assistant screen integration

**Files:**
- Modify: `lib/features/assistant/presentation/screens/assistant_screen.dart`

- [ ] **Step 1: Add imports**

Near other imports:
```dart
import '../../../voice_enrollment/presentation/bloc/voice_enrollment_bloc.dart';
import '../../../voice_enrollment/presentation/bloc/voice_enrollment_event.dart';
import '../../../voice_enrollment/presentation/bloc/voice_enrollment_state.dart';
import '../../../voice_enrollment/presentation/widgets/owner_enrollment_sheet.dart';
import '../../../../core/di/service_locator.dart';
```

- [ ] **Step 2: Add a helper that runs before the WebSocket opens**

Find the method that starts the realtime session (the one containing `WebSocket.connect(wsUrl)` around line 328). Before the existing line `_ws = await WebSocket.connect(wsUrl);`, insert:
```dart
// Voice owner gating (experimental). If the owner hasn't enrolled their
// voice yet, show the bottom sheet first. If they cancel, we still let
// the session run — gating is just disabled for them.
final enrolled = await _ensureOwnerEnrolled();
if (!mounted) return;
// continue regardless of enrolled value; backend will fail open if not enrolled
```

- [ ] **Step 3: Implement `_ensureOwnerEnrolled` in the same State class**

```dart
Future<bool> _ensureOwnerEnrolled() async {
  final bloc = sl<VoiceEnrollmentBloc>();
  bloc.add(const Check());
  // Wait for either Enrolled or NotEnrolled
  final settled = await bloc.stream.firstWhere(
    (s) => s is Enrolled || s is NotEnrolled || s is Failed,
  );
  if (settled is Enrolled) return true;
  if (settled is Failed) return false; // be forgiving — let the session run
  // NotEnrolled: show the bottom sheet
  final result = await showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    isDismissible: false,
    enableDrag: false,
    builder: (ctx) => BlocProvider.value(
      value: bloc,
      child: const OwnerEnrollmentSheet(),
    ),
  );
  return result == true;
}
```

- [ ] **Step 4: Build dev APK and side-load**

```bash
cd ~/Downloads/taler_id_mobile
flutter build apk --flavor dev --release -t lib/main_dev.dart \
  --dart-define=FLAVOR=dev --dart-define=BASE_URL=https://staging.id.taler.tirol
```

- [ ] **Step 5: Commit**

```bash
git add lib/features/assistant/presentation/screens/assistant_screen.dart
git commit -m "feat(assistant): show owner enrollment sheet on first session"
```

---

## Phase 4: End-to-end smoke

### Task 4.1: Run the scenario from spec §8

**Files:** none

- [ ] **Step 1: Reset the test user's voice profile to a clean state**

```bash
ssh dvolkov@89.169.55.217 'psql taler_id_dev -c "UPDATE \"Profile\" SET \"ownerSpeakerId\" = NULL, \"ownerEmbedding\" = ARRAY[]::DOUBLE PRECISION[] WHERE \"userId\" = (SELECT id FROM \"User\" WHERE email = \"integration_test@taler-test.com\");"'
```

- [ ] **Step 2: Tail the backend log on DEV in a separate terminal**

```bash
ssh dvolkov@89.169.55.217 'pm2 logs taler-id-dev --raw | grep voice-gate'
```

- [ ] **Step 3: Install dev APK and log in as `integration_test@taler-test.com`**

```bash
# from local Mac
adb install -r ~/Downloads/taler_id_mobile/build/app/outputs/flutter-apk/app-dev-release.apk
```

- [ ] **Step 4: Open the assistant screen → enrollment sheet should appear**

Record ~20 sec of own voice → wait for the sheet to close.

Expected on backend: `voice-gate` log line `verdict: owner` once mic streams start.

- [ ] **Step 5: Play a 5-sec audio clip from a TV/YouTube near the phone while no one is speaking**

Expected: backend log line `verdict: non_owner, cosine: <0.5`. OpenAI should not start a response, or its response should be `response.cancelled` shortly after `response.created`.

- [ ] **Step 6: Speak own voice again**

Expected: `verdict: owner` resumes; assistant replies normally.

- [ ] **Step 7: Document findings**

Append a short "Pilot results" section to the spec with:
- Cosine distribution observed for owner vs non-owner windows
- Any false positives/negatives
- Whether the threshold needs adjustment

```bash
cd ~/Downloads/taler_id
git add docs/superpowers/specs/2026-06-08-voice-owner-gating-design.md
git commit -m "docs(voice-gate): pilot results from first end-to-end run"
```
