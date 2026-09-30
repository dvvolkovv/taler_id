import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export interface PartnerRecord {
  id: string;
  slug: string;
  name: string;
  keyHash: string;
  ipAllowlist: string[];
  webhookUrl: string | null;
  webhookSecretEnc: string | null;
  oauthClientId: string;
  enabled: boolean;
}

const CACHE_TTL_MS = 30_000;

type Cache = Map<string, { at: number; value: PartnerRecord | null }>;

/**
 * Партнёры читаются на каждый запрос партнёрского API и на каждый запрос
 * мессенджера по партнёрскому токену, а меняются раз в месяцы. Поэтому кэш на
 * 30 секунд: выключение партнёра или смена ключа доходят за это время.
 */
@Injectable()
export class PartnerRegistryService {
  private readonly bySlug: Cache = new Map();
  private readonly byClient: Cache = new Map();

  constructor(private readonly prisma: PrismaService) {}

  findBySlug(slug: string): Promise<PartnerRecord | null> {
    return this.cached(this.bySlug, slug, () => this.prisma.partner.findUnique({ where: { slug } }));
  }

  findByClientId(clientId: string): Promise<PartnerRecord | null> {
    return this.cached(this.byClient, clientId, () =>
      this.prisma.partner.findUnique({ where: { oauthClientId: clientId } }),
    );
  }

  /** Без кэша: воркер вебхуков должен видеть свежий адрес и секрет. */
  findById(id: string): Promise<PartnerRecord | null> {
    return this.prisma.partner.findUnique({ where: { id } });
  }

  private async cached(
    cache: Cache,
    key: string,
    load: () => Promise<PartnerRecord | null>,
  ): Promise<PartnerRecord | null> {
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;
    const value = (await load()) ?? null;
    cache.set(key, { at: Date.now(), value });
    return value;
  }
}
