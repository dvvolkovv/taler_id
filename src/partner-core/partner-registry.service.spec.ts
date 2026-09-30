import { Logger, ServiceUnavailableException } from '@nestjs/common';
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
const other = { ...partner, id: 'p2', slug: 'acme', oauthClientId: 'acme-partner' };

const T0 = new Date('2026-10-01T10:00:00Z').getTime();
const at = (seconds: number) => new Date(T0 + seconds * 1000);

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('PartnerRegistryService', () => {
  let prisma: any;
  let registry: PartnerRegistryService;
  let warn: jest.SpyInstance;

  beforeEach(() => {
    jest.useFakeTimers({ now: at(0) });
    warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    prisma = {
      partner: {
        findMany: jest.fn().mockResolvedValue([partner, other]),
        findUnique: jest.fn().mockResolvedValue(partner),
      },
    };
    registry = new PartnerRegistryService(prisma);
  });
  afterEach(() => {
    jest.useRealTimers();
    warn.mockRestore();
  });

  it('serves lookups by slug and by client id from one load of the table', async () => {
    await expect(registry.findBySlug('nadi')).resolves.toEqual(partner);
    await expect(registry.findByClientId('acme-partner')).resolves.toEqual(other);
    await expect(registry.findByClientId('nadi-partner')).resolves.toEqual(partner);
    expect(prisma.partner.findMany).toHaveBeenCalledTimes(1);
    expect(prisma.partner.findUnique).not.toHaveBeenCalled();
  });

  it('answers unknown keys from the snapshot: no query and no growth', async () => {
    await registry.findBySlug('nadi');
    for (let i = 0; i < 1000; i++) {
      await expect(registry.findBySlug(`ghost-${i}`)).resolves.toBeNull();
      await expect(registry.findByClientId(`ghost-${i}-partner`)).resolves.toBeNull();
    }
    expect(prisma.partner.findMany).toHaveBeenCalledTimes(1);
    expect(prisma.partner.findUnique).not.toHaveBeenCalled();
  });

  it('reloads the table once after 30 seconds and serves the fresh data', async () => {
    await registry.findBySlug('nadi');
    jest.setSystemTime(at(29));
    await registry.findBySlug('nadi');
    expect(prisma.partner.findMany).toHaveBeenCalledTimes(1);

    prisma.partner.findMany.mockResolvedValueOnce([{ ...partner, enabled: false }]);
    jest.setSystemTime(at(31));
    await expect(registry.findBySlug('nadi')).resolves.toMatchObject({ enabled: false });
    await expect(registry.findByClientId('acme-partner')).resolves.toBeNull();
    await registry.findBySlug('ghost');
    expect(prisma.partner.findMany).toHaveBeenCalledTimes(2);
  });

  it('shares one in-flight load between concurrent callers', async () => {
    const load = deferred<any[]>();
    prisma.partner.findMany.mockReturnValueOnce(load.promise);
    const pending = Promise.all([
      registry.findBySlug('nadi'),
      registry.findByClientId('nadi-partner'),
      registry.findBySlug('ghost'),
    ]);
    load.resolve([partner]);
    await expect(pending).resolves.toEqual([partner, partner, null]);
    expect(prisma.partner.findMany).toHaveBeenCalledTimes(1);

    // и перечитывание по истечении срока — тоже одно на всех
    jest.setSystemTime(at(31));
    const reload = deferred<any[]>();
    prisma.partner.findMany.mockReturnValueOnce(reload.promise);
    const again = Promise.all([registry.findBySlug('nadi'), registry.findByClientId('nadi-partner')]);
    reload.resolve([partner]);
    await again;
    expect(prisma.partner.findMany).toHaveBeenCalledTimes(2);
  });

  it('keeps serving the previous snapshot when a reload fails', async () => {
    await registry.findBySlug('nadi');
    jest.setSystemTime(at(31));
    prisma.partner.findMany.mockRejectedValueOnce(new Error('db down'));
    await expect(registry.findBySlug('nadi')).resolves.toEqual(partner);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('db down'));

    // снимок так и остался старым — следующий запрос снова пробует перечитать
    await expect(registry.findByClientId('nadi-partner')).resolves.toEqual(partner);
    expect(prisma.partner.findMany).toHaveBeenCalledTimes(3);
  });

  it('answers 503 when the first load fails, and recovers on the next call', async () => {
    prisma.partner.findMany.mockRejectedValueOnce(new Error('db down'));
    await expect(registry.findBySlug('nadi')).rejects.toThrow(ServiceUnavailableException);
    await expect(registry.findBySlug('nadi')).resolves.toEqual(partner);
    expect(prisma.partner.findMany).toHaveBeenCalledTimes(2);
  });

  it('reads by id straight from the database', async () => {
    await registry.findById('p1');
    await registry.findById('p1');
    expect(prisma.partner.findUnique).toHaveBeenCalledTimes(2);
    expect(prisma.partner.findUnique).toHaveBeenCalledWith({ where: { id: 'p1' } });
    expect(prisma.partner.findMany).not.toHaveBeenCalled();
  });
});
