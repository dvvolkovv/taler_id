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

export const DEFAULT_REALTIME_MODEL = 'gpt-realtime-mini-2025-12-15';
export const DEFAULT_TRANSLATOR_MODEL = 'gpt-realtime-2025-08-28';

export interface RealtimeProxyMode {
  model: string;
  translator: boolean;
  voiceGate: boolean;
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
