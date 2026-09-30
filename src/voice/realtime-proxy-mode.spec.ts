import {
  DEFAULT_REALTIME_MODEL,
  DEFAULT_TRANSLATOR_MODEL,
  realtimeProxyMode,
} from './realtime-proxy-mode';

const q = (s: string) => new URLSearchParams(s);

describe('realtimeProxyMode', () => {
  it('plain assistant session: default mini model, gate on', () => {
    expect(realtimeProxyMode(q('token=x'), {})).toEqual({
      model: DEFAULT_REALTIME_MODEL,
      translator: false,
      voiceGate: true,
    });
  });

  it('translator session: full model, gate off', () => {
    expect(realtimeProxyMode(q('token=x&mode=translator'), {})).toEqual({
      model: DEFAULT_TRANSLATOR_MODEL,
      translator: true,
      voiceGate: false,
    });
  });

  it('translator model can be overridden by env', () => {
    const m = realtimeProxyMode(q('mode=translator'), {
      REALTIME_TRANSLATOR_MODEL: 'gpt-realtime-x',
    });
    expect(m.model).toBe('gpt-realtime-x');
  });

  it('translator mode ignores a client-supplied model', () => {
    const m = realtimeProxyMode(q('mode=translator&model=gpt-4o-realtime'), {});
    expect(m.model).toBe(DEFAULT_TRANSLATOR_MODEL);
  });

  it('allow-listed model override still works for assistant sessions', () => {
    const m = realtimeProxyMode(q('model=b'), { REALTIME_ALLOWED_MODELS: 'a, b' });
    expect(m).toEqual({ model: 'b', translator: false, voiceGate: true });
  });

  it('model outside the allow-list falls back to default and is reported', () => {
    const m = realtimeProxyMode(q('model=expensive'), {});
    expect(m.model).toBe(DEFAULT_REALTIME_MODEL);
    expect(m.refusedModel).toBe('expensive');
  });

  it('unknown mode value is a normal assistant session', () => {
    expect(realtimeProxyMode(q('mode=other'), {}).translator).toBe(false);
  });
});
