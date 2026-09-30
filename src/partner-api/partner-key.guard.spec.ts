import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { generatePartnerKey, hashPartnerKey } from '../partner-core/partner-key.util';
import { PartnerKeyGuard } from './partner-key.guard';

function ctx(req: any) {
  return { switchToHttp: () => ({ getRequest: () => req }) } as any;
}

const saved = process.env.PARTNER_API_ENABLED;

describe('PartnerKeyGuard', () => {
  const key = generatePartnerKey('nadi');
  const partner = { id: 'p1', slug: 'nadi', keyHash: hashPartnerKey(key), enabled: true, ipAllowlist: [] as string[] };
  const request = (over: any = {}) => ({ headers: { authorization: `Bearer ${key}` }, ip: '1.2.3.4', ...over });
  let registry: any;
  let guard: PartnerKeyGuard;

  beforeEach(() => {
    process.env.PARTNER_API_ENABLED = 'true';
    registry = { findBySlug: jest.fn().mockResolvedValue(partner) };
    guard = new PartnerKeyGuard(registry);
  });
  afterAll(() => {
    if (saved === undefined) delete process.env.PARTNER_API_ENABLED;
    else process.env.PARTNER_API_ENABLED = saved;
  });

  it('attaches the partner for a valid key', async () => {
    const req: any = request();
    await expect(guard.canActivate(ctx(req))).resolves.toBe(true);
    expect(req.partner).toBe(partner);
    expect(registry.findBySlug).toHaveBeenCalledWith('nadi');
  });

  it('403 while the partner API is switched off, before looking at the key', async () => {
    process.env.PARTNER_API_ENABLED = 'false';
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow(ForbiddenException);
    expect(registry.findBySlug).not.toHaveBeenCalled();
  });

  it.each([undefined, 'Bearer', `Basic ${key}`, `Bearer tidp_nadi_${'x'.repeat(43)}`])(
    '401 for authorization %p',
    async (authorization: string | undefined) => {
      await expect(guard.canActivate(ctx(request({ headers: { authorization } })))).rejects.toThrow(
        UnauthorizedException,
      );
    },
  );

  it('401 for an unknown partner', async () => {
    registry.findBySlug.mockResolvedValue(null);
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow(UnauthorizedException);
  });

  it('403 for a disabled partner with a valid key', async () => {
    registry.findBySlug.mockResolvedValue({ ...partner, enabled: false });
    await expect(guard.canActivate(ctx(request()))).rejects.toThrow(ForbiddenException);
  });

  it('checks the IP allowlist, ignoring the ::ffff: prefix', async () => {
    registry.findBySlug.mockResolvedValue({ ...partner, ipAllowlist: ['165.227.141.149'] });
    await expect(guard.canActivate(ctx(request({ ip: '::ffff:165.227.141.149' })))).resolves.toBe(true);
    await expect(guard.canActivate(ctx(request({ ip: '8.8.8.8' })))).rejects.toThrow(UnauthorizedException);
  });
});
