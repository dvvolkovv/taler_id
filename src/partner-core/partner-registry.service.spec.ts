import { PartnerRegistryService } from './partner-registry.service';

const partner = {
  id: 'p1',
  slug: 'nadi',
  name: 'Nadi',
  keyHash: 'h',
  ipAllowlist: [],
  webhookUrl: null,
  webhookSecretEnc: null,
  oauthClientId: 'nadi-partner',
  enabled: true,
};

describe('PartnerRegistryService', () => {
  let prisma: any;
  let registry: PartnerRegistryService;

  beforeEach(() => {
    jest.useFakeTimers({ now: new Date('2026-10-01T10:00:00Z') });
    prisma = { partner: { findUnique: jest.fn().mockResolvedValue(partner) } };
    registry = new PartnerRegistryService(prisma);
  });
  afterEach(() => jest.useRealTimers());

  it('caches lookups by slug for 30 seconds', async () => {
    await registry.findBySlug('nadi');
    await registry.findBySlug('nadi');
    expect(prisma.partner.findUnique).toHaveBeenCalledTimes(1);
    jest.setSystemTime(new Date('2026-10-01T10:00:31Z'));
    await registry.findBySlug('nadi');
    expect(prisma.partner.findUnique).toHaveBeenCalledTimes(2);
  });

  it('looks partners up by OAuth client id', async () => {
    await expect(registry.findByClientId('nadi-partner')).resolves.toEqual(partner);
    expect(prisma.partner.findUnique).toHaveBeenCalledWith({ where: { oauthClientId: 'nadi-partner' } });
  });

  it('caches misses too', async () => {
    prisma.partner.findUnique.mockResolvedValue(null);
    await registry.findBySlug('ghost');
    await registry.findBySlug('ghost');
    expect(prisma.partner.findUnique).toHaveBeenCalledTimes(1);
  });

  it('reads by id straight from the database', async () => {
    await registry.findById('p1');
    await registry.findById('p1');
    expect(prisma.partner.findUnique).toHaveBeenCalledTimes(2);
  });
});
