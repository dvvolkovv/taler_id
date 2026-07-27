// The agent scripts live outside jest's rootDir (src), so this reaches into
// livekit-agent/ to cover the credential guard they all call at import time.
describe('livekit-agent credential guard', () => {
  const ORIGINAL = { ...process.env };

  afterEach(() => {
    process.env = { ...ORIGINAL };
    jest.resetModules();
  });

  const load = () => {
    jest.resetModules();
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require('../../livekit-agent/livekit-credentials');
  };

  it('returns the configured pair', () => {
    process.env.LIVEKIT_API_KEY = 'real-key';
    process.env.LIVEKIT_API_SECRET = 'real-secret';

    expect(load().readLivekitCredentials()).toEqual({
      apiKey: 'real-key',
      apiSecret: 'real-secret',
    });
  });

  it('throws when the secret is missing instead of using a fallback', () => {
    process.env.LIVEKIT_API_KEY = 'real-key';
    delete process.env.LIVEKIT_API_SECRET;

    expect(() => load().readLivekitCredentials()).toThrow(
      /LIVEKIT_API_SECRET/,
    );
  });

  it('throws when the key is missing', () => {
    delete process.env.LIVEKIT_API_KEY;
    process.env.LIVEKIT_API_SECRET = 'real-secret';

    expect(() => load().readLivekitCredentials()).toThrow(/LIVEKIT_API_KEY/);
  });

  it('refuses the secret committed to this repository', () => {
    process.env.LIVEKIT_API_KEY = 'lkdevkey';
    process.env.LIVEKIT_API_SECRET = 'lkSecret2024TalerID';

    expect(() => load().readLivekitCredentials()).toThrow(/committed/);
  });
});
