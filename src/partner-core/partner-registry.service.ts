import {
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Partner } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';

export type PartnerRecord = Omit<Partner, 'createdAt' | 'updatedAt'>;

/** Как часто перечитывать таблицу: за это время доходят выключение партнёра и смена ключа. */
const SNAPSHOT_TTL_MS = 30_000;

interface Snapshot {
  at: number;
  bySlug: Map<string, PartnerRecord>;
  byClientId: Map<string, PartnerRecord>;
}

/**
 * Партнёры читаются на каждый запрос партнёрского API и на каждый запрос
 * мессенджера по партнёрскому токену, а меняются раз в месяцы, и их единицы.
 * Поэтому в памяти лежит снимок всей таблицы, и перечитывается он не чаще раза
 * в 30 секунд — одним запросом на всех, кто пришёл в этот момент.
 *
 * Кэш по ключу здесь не годится: slug и clientId приходят от ещё не опознанного
 * клиента, и каждый выдуманный ключ оставался бы в памяти навсегда. Снимок от
 * чужих ключей не растёт, а промах по нему не стоит ни одного запроса в базу.
 */
@Injectable()
export class PartnerRegistryService {
  private readonly logger = new Logger(PartnerRegistryService.name);
  private snapshot: Snapshot | null = null;
  private loading: Promise<Snapshot> | null = null;

  constructor(private readonly prisma: PrismaService) {}

  async findBySlug(slug: string): Promise<PartnerRecord | null> {
    return (await this.current()).bySlug.get(slug) ?? null;
  }

  async findByClientId(clientId: string): Promise<PartnerRecord | null> {
    return (await this.current()).byClientId.get(clientId) ?? null;
  }

  /** Без кэша: воркер вебхуков должен видеть свежий адрес и секрет. */
  findById(id: string): Promise<PartnerRecord | null> {
    return this.prisma.partner.findUnique({ where: { id } });
  }

  private current(): Promise<Snapshot> {
    const snapshot = this.snapshot;
    if (snapshot && Date.now() - snapshot.at < SNAPSHOT_TTL_MS)
      return Promise.resolve(snapshot);
    // Все, кто пришёл во время загрузки, ждут её же — второго запроса в базу нет.
    this.loading ??= this.reload().finally(() => {
      this.loading = null;
    });
    return this.loading;
  }

  /**
   * Сбой перечитывания не должен ронять вход партнёров, пока есть снимок: лучше
   * отвечать по данным минутной давности, чем отказывать всем. Без снимка
   * отвечать нечем — 503.
   */
  private async reload(): Promise<Snapshot> {
    try {
      const rows: PartnerRecord[] = await this.prisma.partner.findMany();
      const snapshot: Snapshot = {
        at: Date.now(),
        bySlug: new Map(rows.map((p) => [p.slug, p])),
        byClientId: new Map(rows.map((p) => [p.oauthClientId, p])),
      };
      this.snapshot = snapshot;
      return snapshot;
    } catch (e) {
      const stale = this.snapshot;
      if (!stale) {
        this.logger.warn(
          `partner registry load failed: ${(e as Error).message}`,
        );
        throw new ServiceUnavailableException('partner registry unavailable');
      }
      this.logger.warn(
        `partner registry reload failed, serving snapshot from ${new Date(stale.at).toISOString()}: ${(e as Error).message}`,
      );
      return stale;
    }
  }
}
