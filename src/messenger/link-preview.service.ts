import { Injectable, Logger } from '@nestjs/common';
import { lookup } from 'dns/promises';
import { PrismaService } from '../prisma/prisma.service';
import { isPrivateAddress, normalizePreviewUrl } from './link-preview.guard';
import { parsePreview, ParsedPreview } from './link-preview.parse';

/** Сколько живёт удачное превью, прежде чем перезапросить. */
const FRESH_MS = 7 * 24 * 3600 * 1000;
/** Неудачу помним меньше: сайт мог лежать временно. */
const FAILED_FRESH_MS = 6 * 3600 * 1000;
/** Дольше ждать нет смысла: карточка — украшение, а не содержимое. */
const TIMEOUT_MS = 5000;
/** Сколько байт готовы прочитать: og-теги живут в самом начале документа. */
const MAX_BYTES = 512 * 1024;
/** Больше трёх прыжков — почти всегда петля или трекер. */
const MAX_REDIRECTS = 3;

export interface LinkPreviewResult extends ParsedPreview {
  url: string;
}

@Injectable()
export class LinkPreviewService {
  private readonly logger = new Logger(LinkPreviewService.name);

  constructor(private prisma: PrismaService) {}

  /**
   * Превью для ссылки: из кэша, иначе сходить и запомнить.
   *
   * Возвращает null, если ссылка запрещена или страница ничего не дала —
   * клиент в этом случае просто не рисует карточку.
   */
  async getPreview(rawUrl: string): Promise<LinkPreviewResult | null> {
    const url = normalizePreviewUrl(rawUrl);
    if (!url) return null;

    const cached = await this.prisma.linkPreview.findUnique({ where: { url } });
    if (cached) {
      const age = Date.now() - cached.fetchedAt.getTime();
      const ttl = cached.ok ? FRESH_MS : FAILED_FRESH_MS;
      if (age < ttl) {
        return cached.ok
          ? {
              url,
              title: cached.title,
              description: cached.description,
              imageUrl: cached.imageUrl,
              siteName: cached.siteName,
            }
          : null;
      }
    }

    let parsed: ParsedPreview | null = null;
    try {
      parsed = await this.fetchPreview(url);
    } catch (e) {
      this.logger.warn(`link preview failed for ${url}: ${(e as Error).message}`);
    }

    // Пустую карточку тоже запоминаем как неудачу: иначе сайт без разметки
    // перезапрашивался бы при каждом открытии чата.
    const ok = !!(parsed && (parsed.title || parsed.description || parsed.imageUrl));
    const data = {
      title: parsed?.title ?? null,
      description: parsed?.description ?? null,
      imageUrl: parsed?.imageUrl ?? null,
      siteName: parsed?.siteName ?? null,
      ok,
      fetchedAt: new Date(),
    };
    await this.prisma.linkPreview.upsert({
      where: { url },
      create: { url, ...data },
      update: data,
    });

    return ok ? { url, ...(parsed as ParsedPreview) } : null;
  }

  /**
   * Сходить по ссылке, проверяя адрес перед каждым прыжком.
   *
   * Редиректы обрабатываются вручную: автоматический переход увёл бы нас на
   * адрес, который никто не проверял, — а именно так и делается обход защиты
   * (публичное имя, редиректящее на 169.254.169.254).
   */
  private async fetchPreview(startUrl: string): Promise<ParsedPreview | null> {
    let current = startUrl;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      await this.assertPublicHost(current);
      const res = await fetch(current, {
        redirect: 'manual',
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: {
          // Часть сайтов без внятного UA отдаёт заглушку вместо разметки.
          'User-Agent': 'TalerIDBot/1.0 (+https://talerid.io)',
          Accept: 'text/html,application/xhtml+xml',
        },
      });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        if (!location) return null;
        const next = normalizePreviewUrl(new URL(location, current).toString());
        if (!next) return null;
        current = next;
        continue;
      }
      if (!res.ok) return null;

      const type = res.headers.get('content-type') ?? '';
      // Не HTML разбирать нечем: картинку или PDF мы всё равно не опишем.
      if (!type.includes('text/html') && !type.includes('application/xhtml')) {
        return null;
      }
      const html = await this.readCapped(res);
      return parsePreview(html, current);
    }
    return null; // кончились прыжки
  }

  /** Резолвит имя и требует, чтобы ВСЕ адреса были публичными. */
  private async assertPublicHost(url: string): Promise<void> {
    const { hostname } = new URL(url);
    const addresses = await lookup(hostname, { all: true });
    if (addresses.length === 0) {
      throw new Error(`no addresses for ${hostname}`);
    }
    for (const a of addresses) {
      if (isPrivateAddress(a.address)) {
        throw new Error(`refusing private address ${a.address} for ${hostname}`);
      }
    }
  }

  /**
   * Читает тело с потолком.
   *
   * Content-Length верить нельзя — его может не быть или он может врать,
   * поэтому режем по факту прочитанного, а не по заголовку.
   */
  private async readCapped(res: Response): Promise<string> {
    const reader = res.body?.getReader();
    if (!reader) return '';
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (total < MAX_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
    }
    await reader.cancel().catch(() => undefined);
    return Buffer.concat(chunks).toString('utf8').slice(0, MAX_BYTES);
  }
}
