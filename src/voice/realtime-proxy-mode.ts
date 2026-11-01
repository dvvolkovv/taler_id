// Decides what one /voice/realtime-proxy connection runs on.
//
// The assistant's translator mode connects with `mode=translator`. Two things
// differ for it:
//  - model: the mini model half-translates between related languages (Slovak
//    speech came back as «Добрый день, lekáreň je hneď za rohom» in 3 of 9
//    checks, the full model got 9 of 9), so translator sessions run on the full
//    model. It is chosen here, on the server, so it can be changed without an
//    app release — the client only says which mode it is in.
//  - voice gate: the gate retracts speech that is not the account owner's.
//    In translator mode the other person's speech is exactly what has to be
//    translated, so the gate is off there.
//  - transcription: the translator holds every reply until its utterance is
//    transcribed (translator-turn-gate.ts), so the transcript has to be fast
//    and must not invent words for noise. whisper-1 took 0.4–1.7 s and heard
//    "you" in a cough; gpt-4o-mini-transcribe answers in ~0.35 s with "" for
//    turns without speech.

export const DEFAULT_REALTIME_MODEL = 'gpt-realtime-mini-2025-12-15';
export const DEFAULT_TRANSLATOR_MODEL = 'gpt-realtime-2025-08-28';
export const DEFAULT_TRANSLATOR_TRANSCRIBE_MODEL = 'gpt-4o-mini-transcribe';

export interface RealtimeProxyMode {
  model: string;
  translator: boolean;
  voiceGate: boolean;
  /** Input transcription model forced on translator sessions. */
  transcribeModel?: string;
  /** Set when the client asked for a model outside the allow-list. */
  refusedModel?: string;
}

export function realtimeProxyMode(
  params: URLSearchParams,
  env: NodeJS.ProcessEnv = process.env,
): RealtimeProxyMode {
  if (params.get('mode') === 'translator') {
    return {
      model: env.REALTIME_TRANSLATOR_MODEL || DEFAULT_TRANSLATOR_MODEL,
      translator: true,
      voiceGate: false,
      transcribeModel:
        env.REALTIME_TRANSLATOR_TRANSCRIBE_MODEL ||
        DEFAULT_TRANSLATOR_TRANSCRIBE_MODEL,
    };
  }
  const allowed = new Set(
    (env.REALTIME_ALLOWED_MODELS ?? DEFAULT_REALTIME_MODEL)
      .split(',')
      .map((m) => m.trim())
      .filter(Boolean),
  );
  const requested = params.get('model');
  if (requested && allowed.has(requested)) {
    return { model: requested, translator: false, voiceGate: true };
  }
  return {
    model: DEFAULT_REALTIME_MODEL,
    translator: false,
    voiceGate: true,
    ...(requested ? { refusedModel: requested } : {}),
  };
}
