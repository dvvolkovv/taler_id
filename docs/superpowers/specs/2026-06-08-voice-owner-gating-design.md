# Voice Owner Gating — Design

**Status**: Experimental (separate branch, not merged to dev)
**Branch**: `experiment/voice-owner-gating` in `taler_id` and `taler_id_mobile`
**Author**: Dmitry Volkov, with Claude
**Date**: 2026-06-08

## 1. Background

The TalerID voice assistant on mobile streams microphone audio via a backend WebSocket proxy (`/voice/realtime-proxy`) to OpenAI Realtime. The assistant is push-to-talk: the user presses a button, says something, gets a response.

Real-world failure: during a push-to-talk session a TV plays in the background or another person speaks nearby. OpenAI Realtime hears that ambient audio, treats it as part of the user's turn, and the assistant either replies to TV content or mixes the other person's words into the user's request. Both feel broken.

We want to gate the audio stream so OpenAI only acts on speech from the **owner** of the account (the user who is logged in on this device). Audio from other voices in the room must be discarded before OpenAI commits to a response.

## 2. Non-goals

- Production deployment of Manax or this feature. This is an experimental branch; only DEV-backend builds from this branch see the feature.
- Replacing OpenAI Realtime, Deepgram, or any existing voice path.
- Always-on / wake-word listening. We only gate during active push-to-talk sessions.
- Voice-profile editing UI. Profile is recorded once at first session; re-record only via manual DB reset for now.
- Multi-tenant speaker bookkeeping. Owner is the single account holder; we don't track guests separately.
- Continuous embedding refinement from successful interactions.

## 3. Architecture

### 3.1 Active session flow

```
mobile (mic 16kHz PCM)
   │
   │ WS /voice/realtime-proxy
   ▼
backend main.ts (WS proxy)
   │
   ├──> forward to OpenAI Realtime   ← unchanged speculative path
   │
   └──> voice-gate.service:
         buffer 1s PCM window
         POST /api/v1/audio/upload-all-in-one mode=enroll
              → Manax returns ECAPA embedding (192-dim)
         cosine(embedding, profile.ownerEmbedding)
         if cosine < threshold (0.5):
             inject input_audio_buffer.clear into OpenAI socket
             inject response.cancel if responseInFlight
             increment non_owner_detected metric
```

Mobile and OpenAI are unchanged. The only mutated path is inside the backend's existing WebSocket upgrade handler in `src/main.ts`.

**Speculative-forward choice rationale**: audio reaches OpenAI in real time and the gate runs in parallel. On a non-owner verdict (~1 sec later) we retract via `input_audio_buffer.clear` + `response.cancel`. Cost of an unretracted turn is a few cents of OpenAI tokens; the win is zero added user-perceivable latency for the dominant case (owner speaking).

### 3.2 Enrollment flow

First time a user opens the assistant screen:

```
mobile opens /assistant
   │
   ▼
GET /voice-gate/owner-status → { enrolled: false }
   │
mobile shows bottom sheet "record your voice for ~20 sec"
   │
mobile records → POST /voice-gate/enroll (multipart audio.wav)
   │
backend → Manax mode=enroll → ECAPA embedding + speakerId
   │
profile.update({ ownerSpeakerId, ownerEmbedding: [192 floats] })
   │
mobile receives 200 → opens regular assistant WS (gating active)
```

Subsequent sessions skip the bottom sheet because `GET /voice-gate/owner-status` returns `enrolled: true`.

### 3.3 Failure-mode posture

If Manax is down, slow, or returns garbage: **fail open**. The proxy stops gating for the affected session and forwards audio to OpenAI as before. Better a working assistant without gating than a broken assistant with gating.

## 4. Components

### 4.1 Backend (`taler_id`)

New module `src/voice-gate/`:

| File | Purpose |
|---|---|
| `voice-gate.module.ts` | Registration in `AppModule`, imports `PrismaModule`, `ConfigModule` |
| `voice-gate.controller.ts` | REST endpoints `GET /voice-gate/owner-status`, `POST /voice-gate/enroll`, `DELETE /voice-gate/owner` |
| `voice-gate.service.ts` | Manax HTTP client (axios), cosine math, threshold logic, fail-open wrapper |
| `voice-gate.types.ts` | `ManaxEnrollResponse`, `OwnerVerifyResult` |

Modify `src/main.ts` realtime-proxy upgrade handler (lines 559–674):

- Extract `userId` (`sub` claim) from the JWT payload after the existing `verify(token, ...)` call.
- Load `profile.ownerEmbedding` once at upgrade time and cache it on the WS context. If the user updates their voice profile mid-session, the change takes effect on the next WS upgrade — acceptable for MVP.
- Maintain a rolling 1-sec PCM buffer (16000 samples × 2 bytes = 32 KB) per WS connection. On each `input_audio_buffer.append` frame, decode the base64 PCM and append. When the buffer fills, snapshot it, reset the buffer, and call `voiceGateService.verify(window, ownerEmbedding)`. Windows are non-overlapping.
- Continue forwarding every chunk to OpenAI unconditionally — verify runs in parallel with forwarding, not in series.
- On `verify` returning `isOwner: false`, send `{"type":"input_audio_buffer.clear"}` and, if `responseInFlight`, `{"type":"response.cancel"}` to the OpenAI socket.
- Track `responseInFlight` by sniffing the OpenAI→client event stream: set `true` on `response.created`, `false` on `response.done` or `response.cancelled`.

### 4.2 Prisma

Migration `prisma/migrations/2026XXXX_add_owner_voice_to_profile/migration.sql`:

```sql
ALTER TABLE "Profile"
  ADD COLUMN "ownerSpeakerId" TEXT,
  ADD COLUMN "ownerEmbedding" DOUBLE PRECISION[];
```

Update `prisma/schema.prisma` `Profile` model with the two new optional fields.

### 4.3 Env vars (DEV backend `.env`)

```
MANAX_BASE_URL=http://127.0.0.1:8791
MANAX_API_KEY=<value from ~/manax-speech/.env.local>
OWNER_VOICE_THRESHOLD=0.5
OWNER_VOICE_WINDOW_MS=1000
OWNER_VOICE_ENABLED=true
```

`OWNER_VOICE_ENABLED=false` is a kill switch without redeploy. When false: the WS proxy skips load-on-upgrade and per-frame gating entirely, and the `/voice-gate/enroll` and `DELETE /voice-gate/owner` endpoints return 503 `feature_disabled`. `GET /voice-gate/owner-status` still returns the stored value (so mobile can read state truthfully).

### 4.4 Mobile (`taler_id_mobile`)

New feature `lib/features/voice_enrollment/`:

| File | Purpose |
|---|---|
| `data/datasources/voice_enrollment_remote.dart` | Dio calls to `/voice-gate/*` |
| `data/repositories/voice_enrollment_repository_impl.dart` | Repo implementation |
| `domain/entities/owner_voice_status.dart` | Freezed `{ enrolled, speakerId? }` |
| `domain/repositories/voice_enrollment_repository.dart` | Abstract interface |
| `presentation/bloc/voice_enrollment_bloc.dart` | Events: `Check`, `StartRecording`, `Submit`, `Reset`. States: `Idle`, `NotEnrolled`, `Recording`, `Submitting`, `Enrolled`, `Failed` |
| `presentation/widgets/owner_enrollment_sheet.dart` | Bottom sheet: mic icon, 20-sec progress ring, submit button |

Modify `lib/features/assistant/presentation/screens/assistant_screen.dart`:

- Before `WebSocket.connect(wsUrl)` (current line 328), dispatch `VoiceEnrollmentBloc.add(Check())`.
- If state is `NotEnrolled`, `showModalBottomSheet(OwnerEnrollmentSheet)` and `await` an `Enrolled` event.
- Proceed with the existing session-start sequence.

Register `VoiceEnrollmentRepository`, `VoiceEnrollmentRemote`, `VoiceEnrollmentBloc` in `lib/core/di/injection.dart`.

Use the existing `record` package (already in `pubspec.yaml` for chat voice messages) with `RecordConfig(encoder: AudioEncoder.wav, sampleRate: 16000, numChannels: 1)`.

## 5. API contracts

### 5.1 Backend → Mobile

**`GET /voice-gate/owner-status`** (JWT-auth)

```json
// 200 — enrolled
{ "enrolled": true, "speakerId": "spk_a8f3c1...", "enrolledAt": "2026-06-08T12:34:56Z" }

// 200 — not enrolled
{ "enrolled": false }
```

**`POST /voice-gate/enroll`** (JWT-auth, multipart)

Request: `audio: file` (WAV 16kHz mono, 15–30 seconds)

```json
// 200
{ "ok": true, "speakerId": "spk_a8f3c1...", "embeddingDim": 192, "audioSec": 22.4 }

// 400 audio_too_short
{ "ok": false, "error": "audio_too_short", "minSec": 15 }

// 422 no_speech_detected
{ "ok": false, "error": "no_speech_detected" }

// 503 manax_unavailable
{ "ok": false, "error": "manax_unavailable" }
```

**`DELETE /voice-gate/owner`** (JWT-auth)

Clears `ownerSpeakerId` and `ownerEmbedding` on the user's profile. Returns 204.

### 5.2 Backend → Manax

**Enrollment and per-window verify (same endpoint and mode)**:

```http
POST /api/v1/audio/upload-all-in-one
X-Api-Key: <MANAX_API_KEY>
Content-Type: multipart/form-data

audioFile: <WAV bytes>
requestJson: {"mode":"enroll","language":"ru"}
```

Manax returns `JobResponse` with `result.speakerEmbeddings[0].vector` (192 floats). If `speakerEmbeddings.length == 0` we treat it as "no speech in window" (silence or noise) and the verdict is fail-open. If `> 1` we pick the entry with the highest `coverageFraction`.

`mode=enroll` is the lightest pipeline that still computes ECAPA. We deliberately avoid `mode=all` for per-window verify because it would run the full pyannote diarization on a 1-sec chunk — wasteful and slower.

**Verified 2026-06-08**: `mode=enroll` against Manax v3.6.1 on DEV (98 sec Russian WAV) returns `result.speakerEmbeddings[0].vector` with `dim=192`, `embeddingBackend=speechbrain-ecapa`, `asrBackend=disabled`. `coverageFraction` field is `null` for enroll mode — the `pickBestEmbedding` `?? 0` fallback is sufficient.

### 5.3 Cosine similarity

```ts
function cosine(a: number[], b: number[]): number {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}
```

`isOwner = cosine >= OWNER_VOICE_THRESHOLD` (default 0.5).

### 5.4 OpenAI frame injection

On `isOwner: false`:

```ts
openaiWs.send(JSON.stringify({ type: 'input_audio_buffer.clear' }));
if (responseInFlight) {
  openaiWs.send(JSON.stringify({ type: 'response.cancel' }));
}
```

`responseInFlight` is tracked by sniffing the OpenAI→client event stream: set to `true` on `response.created`, set to `false` on `response.done` or `response.cancelled`.

## 6. Error handling

| Scenario | Behavior | Logging |
|---|---|---|
| Manax HTTP 5xx or timeout > 2 sec | Fail open: skip `clear`, keep forwarding to OpenAI | `Logger.warn('voice-gate Manax unavailable, fail-open')` |
| Manax returns 0 embeddings | Fail open (likely silence in window, not a competing speaker) | debug log |
| `profile.ownerEmbedding` null on WS upgrade | Gating disabled for this session (mobile should have enrolled, but defensive) | `Logger.warn('proxy: owner not enrolled, gating skipped')` |
| Mobile uploads audio < 15 sec on enroll | 400 `audio_too_short` | — |
| Mobile uploads audio without speech | 422 `no_speech_detected` (Manax returns `speechCoverage < 0.05`) | — |
| WS proxy fails to parse a frame | Continue forwarding; don't block | warn once per session |
| OpenAI rejects `response.cancel` (no active response) | OpenAI ignores it; no action needed | — |
| `OWNER_VOICE_ENABLED=false` env | Proxy skips load-on-upgrade and per-frame verify entirely | one-time info log |

## 7. Telemetry for threshold tuning

Each per-window verify call logs a structured JSON line under a dedicated logger namespace (`voice-gate.verify`):

```json
{
  "ts": "2026-06-08T12:34:56.789Z",
  "userId": "u_...",
  "sessionId": "s_...",
  "cosine": 0.84,
  "verdict": "owner",
  "audioSec": 1.02,
  "manaxLatencyMs": 67
}
```

After several real sessions we'll have a distribution of cosine values for owner-positive and non-owner-positive windows, which lets us pick a calibrated threshold. Starting value 0.5 is a literature default for ECAPA; expect to slide into the 0.45–0.55 range after data.

## 8. Testing strategy

### Backend (`test/voice-gate/`)

- `voice-gate.service.spec.ts` — cosine math (with known fixture vectors), fail-open path on 5xx from Manax, threshold edge cases (cosine == threshold, very high, very low).
- `voice-gate.controller.spec.ts` — enroll happy path with mocked Manax, owner-status returns shape matching schema, DELETE clears fields.
- Integration test (manual until ready): POST a real WAV from `taler_id_tests/fixtures/` against the actual Manax container, verify response.

### Mobile

- `voice_enrollment_bloc_test.dart` — transitions `Idle → NotEnrolled → Recording → Submitting → Enrolled` and failure paths.
- Manual smoke: emulator, record real audio, run an assistant session, verify the bottom sheet does not show on a second session.

### End-to-end smoke (after both sides land)

On DEV with the experimental branch deployed:

1. Fresh test user logs in on mobile dev build.
2. Open assistant → bottom sheet appears.
3. Record 20-sec own voice → returns 200 → assistant session starts.
4. Speak a normal command → assistant responds (gating verdict = owner).
5. Play a 5-sec YouTube TV clip nearby → no assistant response, log shows `verdict: non_owner, cosine: <0.5`.
6. Speak own voice again → assistant resumes responding.

## 9. Rollout plan

1. Branch is `experiment/voice-owner-gating` in `taler_id` and `taler_id_mobile`. No PR open; not merged to `dev`.
2. Backend built locally and deployed to DEV via `pm2 restart taler-id-dev` only after `git checkout experiment/voice-owner-gating && npm run build`.
3. Mobile dev APK built locally and side-loaded.
4. Manax container (`manax-speech:v3.6.1`) is already running on DEV; no changes needed there.
5. Decision after pilot: keep as-is on experimental branch, refactor toward a sidecar service (Approach C from the brainstorm) for a real rollout, or drop in favor of self-hosting ECAPA in `ai-twin-agent` (path B from the original brainstorm).
