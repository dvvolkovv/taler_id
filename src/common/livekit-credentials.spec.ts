// The credential module binds process.env at import time, so each case has to
// re-import it under the environment it wants to test.
describe('livekit credentials', () => {
  const ORIGINAL = { ...process.env };

  afterEach(() => {
    process.env = { ...ORIGINAL };
    jest.resetModules();
  });

  const load = () => {
    jest.resetModules();
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require('./livekit-credentials');
  };

  it('uses the configured credentials when they are set', () => {
    process.env.NODE_ENV = 'production';
    process.env.LIVEKIT_API_KEY = 'real-key';
    process.env.LIVEKIT_API_SECRET = 'real-secret';

    const mod = load();
    expect(mod.LK_API_KEY).toBe('real-key');
    expect(mod.LK_API_SECRET).toBe('real-secret');
    expect(() => mod.assertLivekitCredentials()).not.toThrow();
  });

  it('does not substitute the committed pair outside tests', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.LIVEKIT_API_KEY;
    delete process.env.LIVEKIT_API_SECRET;

    const mod = load();
    expect(mod.LK_API_SECRET).toBe('');
    expect(mod.LK_API_SECRET).not.toBe('lkSecret2024TalerID');
  });

  it('refuses to start when credentials are missing', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.LIVEKIT_API_KEY;
    delete process.env.LIVEKIT_API_SECRET;

    const mod = load();
    expect(() => mod.assertLivekitCredentials()).toThrow(/LIVEKIT_API_KEY/);
  });

  it('refuses to start on the secret committed to the repository', () => {
    process.env.NODE_ENV = 'production';
    process.env.LIVEKIT_API_KEY = 'lkdevkey';
    process.env.LIVEKIT_API_SECRET = 'lkSecret2024TalerID';

    const mod = load();
    expect(() => mod.assertLivekitCredentials()).toThrow(/committed/);
  });

  it('keeps the dev pair available under jest so specs can sign tokens', () => {
    process.env.NODE_ENV = 'test';
    delete process.env.LIVEKIT_API_KEY;
    delete process.env.LIVEKIT_API_SECRET;

    const mod = load();
    expect(mod.LK_API_KEY).toBe('lkdevkey');
    expect(mod.LK_API_SECRET).toBe('lkSecret2024TalerID');
  });
});
