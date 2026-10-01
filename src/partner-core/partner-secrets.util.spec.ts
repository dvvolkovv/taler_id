import {
  decryptWebhookSecret,
  encryptWebhookSecret,
  generateWebhookSecret,
  hashLinkCode,
  linkCodeMatches,
  partnerSecretsKeyFingerprint,
  reportPartnerSecretsKey,
} from './partner-secrets.util';

const saved = process.env.PARTNER_SECRETS_KEY;
const savedEnabled = process.env.PARTNER_API_ENABLED;

describe('partner secrets', () => {
  beforeEach(() => {
    process.env.PARTNER_SECRETS_KEY = 'a'.repeat(64);
  });
  afterAll(() => {
    if (saved === undefined) delete process.env.PARTNER_SECRETS_KEY;
    else process.env.PARTNER_SECRETS_KEY = saved;
    if (savedEnabled === undefined) delete process.env.PARTNER_API_ENABLED;
    else process.env.PARTNER_API_ENABLED = savedEnabled;
  });

  it('encrypts and decrypts the webhook secret', () => {
    const secret = generateWebhookSecret();
    expect(secret).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    const enc = encryptWebhookSecret(secret);
    expect(enc).not.toContain(secret);
    expect(decryptWebhookSecret(enc)).toBe(secret);
  });

  it('binds the link-code hash to the link', () => {
    const hash = hashLinkCode('link-1', '123456');
    expect(linkCodeMatches('link-1', '123456', hash)).toBe(true);
    expect(linkCodeMatches('link-2', '123456', hash)).toBe(false);
    expect(linkCodeMatches('link-1', '654321', hash)).toBe(false);
    expect(linkCodeMatches('link-1', '123456', '')).toBe(false);
  });

  it('fails closed without a proper master key', () => {
    process.env.PARTNER_SECRETS_KEY = 'short';
    expect(() => hashLinkCode('l', '1')).toThrow('PARTNER_SECRETS_KEY');
  });

  it('fails to decrypt with a different master key', () => {
    const secret = generateWebhookSecret();
    const enc = encryptWebhookSecret(secret);
    process.env.PARTNER_SECRETS_KEY = 'b'.repeat(64);
    expect(() => decryptWebhookSecret(enc)).toThrow();
  });

  it('encrypts the same secret differently each time', () => {
    const secret = generateWebhookSecret();
    expect(encryptWebhookSecret(secret)).not.toBe(encryptWebhookSecret(secret));
  });

  it('fails closed on encrypt/decrypt without a proper master key too', () => {
    process.env.PARTNER_SECRETS_KEY = 'short';
    expect(() => encryptWebhookSecret('whsec_x')).toThrow(
      'PARTNER_SECRETS_KEY',
    );
    expect(() => decryptWebhookSecret('whatever')).toThrow(
      'PARTNER_SECRETS_KEY',
    );
  });

  it('gives a short non-secret fingerprint that changes with the key', () => {
    const first = partnerSecretsKeyFingerprint();
    expect(first).toMatch(/^[0-9a-f]{8}$/);
    process.env.PARTNER_SECRETS_KEY = 'b'.repeat(64);
    expect(partnerSecretsKeyFingerprint()).not.toBe(first);
  });

  it('logs the fingerprint at startup, or shouts when the key is bad, without throwing', () => {
    const logger = { log: jest.fn(), error: jest.fn() };
    process.env.PARTNER_API_ENABLED = 'true';
    reportPartnerSecretsKey(logger);
    expect(logger.log).toHaveBeenCalledWith(
      `partner secrets key fingerprint: ${partnerSecretsKeyFingerprint()}`,
    );
    process.env.PARTNER_SECRETS_KEY = 'short';
    expect(() => reportPartnerSecretsKey(logger)).not.toThrow();
    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('PARTNER_SECRETS_KEY'),
    );
  });

  it('stays silent at startup while the partner API is off', () => {
    const logger = { log: jest.fn(), error: jest.fn() };
    process.env.PARTNER_API_ENABLED = 'false';
    reportPartnerSecretsKey(logger);
    expect(logger.log).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
  });
});
