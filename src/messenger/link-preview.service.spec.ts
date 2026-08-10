import { LinkPreviewService } from './link-preview.service';

/**
 * Сервис ходит по ссылкам из чужих сообщений, поэтому проверяется прежде всего
 * то, куда он ходить отказывается.
 */
describe('LinkPreviewService', () => {
  let service: LinkPreviewService;
  let prisma: any;
  let fetchMock: jest.Mock;

  const html = (body: string) =>
    ({
      status: 200,
      ok: true,
      headers: new Headers({ 'content-type': 'text/html; charset=utf-8' }),
      body: {
        getReader: () => {
          let done = false;
          return {
            read: async () => {
              if (done) return { done: true, value: undefined };
              done = true;
              return { done: false, value: new TextEncoder().encode(body) };
            },
            cancel: async () => undefined,
          };
        },
      },
    }) as any;

  beforeEach(() => {
    prisma = {
      linkPreview: {
        findUnique: jest.fn().mockResolvedValue(null),
        upsert: jest.fn().mockResolvedValue({}),
      },
    };
    service = new LinkPreviewService(prisma);
    fetchMock = jest.fn();
    (global as any).fetch = fetchMock;
    // По умолчанию имя резолвится в публичный адрес.
    jest.spyOn(require('dns/promises'), 'lookup').mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
    ] as any);
  });

  afterEach(() => jest.restoreAllMocks());

  it('returns a parsed card and caches it', async () => {
    fetchMock.mockResolvedValue(html('<meta property="og:title" content="Заголовок">'));

    const out = await service.getPreview('https://example.com/a');

    expect(out?.title).toBe('Заголовок');
    expect(prisma.linkPreview.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ where: { url: 'https://example.com/a' } }),
    );
  });

  it('never leaves the process for a private address', async () => {
    jest.spyOn(require('dns/promises'), 'lookup').mockResolvedValue([
      { address: '10.130.0.13', family: 4 },
    ] as any);

    const out = await service.getPreview('https://internal.example.com');

    expect(out).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses a host that resolves to several addresses if ANY is private', async () => {
    // Классический обход: имя отдаёт публичный и внутренний адрес разом.
    jest.spyOn(require('dns/promises'), 'lookup').mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ] as any);

    expect(await service.getPreview('https://sneaky.example.com')).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a non-http scheme without any lookup', async () => {
    expect(await service.getPreview('file:///etc/passwd')).toBeNull();
    expect(prisma.linkPreview.findUnique).not.toHaveBeenCalled();
  });

  it('re-checks the address after a redirect', async () => {
    // Публичное имя, редиректящее на метаданные облака — ровно тот случай,
    // ради которого редиректы обрабатываются вручную.
    const lookupMock = jest
      .spyOn(require('dns/promises'), 'lookup')
      .mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }] as any)
      .mockResolvedValueOnce([{ address: '169.254.169.254', family: 4 }] as any);
    fetchMock.mockResolvedValueOnce({
      status: 302,
      ok: false,
      headers: new Headers({ location: 'http://metadata.example.com/latest' }),
    } as any);

    const out = await service.getPreview('https://example.com/redirect');

    expect(out).toBeNull();
    expect(lookupMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenCalledTimes(1); // второй запрос не состоялся
  });

  it('gives up instead of following redirects forever', async () => {
    fetchMock.mockResolvedValue({
      status: 302,
      ok: false,
      headers: new Headers({ location: 'https://example.com/loop' }),
    } as any);

    expect(await service.getPreview('https://example.com/loop')).toBeNull();
    expect(fetchMock.mock.calls.length).toBeLessThanOrEqual(4);
  });

  it('ignores a non-html response', async () => {
    fetchMock.mockResolvedValue({
      status: 200,
      ok: true,
      headers: new Headers({ 'content-type': 'application/pdf' }),
    } as any);

    expect(await service.getPreview('https://example.com/doc.pdf')).toBeNull();
  });

  it('serves a fresh cache entry without going out', async () => {
    prisma.linkPreview.findUnique.mockResolvedValue({
      url: 'https://example.com/a',
      title: 'Из кэша',
      description: null,
      imageUrl: null,
      siteName: null,
      ok: true,
      fetchedAt: new Date(),
    });

    const out = await service.getPreview('https://example.com/a');

    expect(out?.title).toBe('Из кэша');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('remembers a failure so a dead link is not hammered', async () => {
    prisma.linkPreview.findUnique.mockResolvedValue({
      url: 'https://example.com/dead',
      ok: false,
      fetchedAt: new Date(),
      title: null, description: null, imageUrl: null, siteName: null,
    });

    expect(await service.getPreview('https://example.com/dead')).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('records a page with no usable tags as a failure', async () => {
    // Иначе сайт без разметки перезапрашивался бы при каждом открытии чата.
    fetchMock.mockResolvedValue(html('<html><body>ничего</body></html>'));

    const out = await service.getPreview('https://example.com/bare');

    expect(out).toBeNull();
    expect(prisma.linkPreview.upsert).toHaveBeenCalledWith(
      expect.objectContaining({ update: expect.objectContaining({ ok: false }) }),
    );
  });

  it('survives the fetch throwing', async () => {
    fetchMock.mockRejectedValue(new Error('ETIMEDOUT'));

    await expect(service.getPreview('https://example.com/slow')).resolves.toBeNull();
  });
});
