import { Injectable } from '@nestjs/common';
import { RedisService } from '../redis/redis.service';

export interface SinkEntry {
  receivedAt: string;
  event: string | null;
  delivery: string | null;
  signature: string | null;
  body: string;
}

const SINK_MAX = 100;
const SINK_TTL_SECONDS = 3600;
const sinkKey = (slug: string) => `partner:sink:${slug}`;

/** Последние 100 вебхуков партнёра за час — только для e2e на DEV/TEST. */
@Injectable()
export class PartnerWebhookSinkStore {
  constructor(private readonly redis: RedisService) {}

  static enabled(): boolean {
    return process.env.PARTNER_WEBHOOK_SINK === 'true';
  }

  async push(slug: string, entry: SinkEntry): Promise<void> {
    const client = this.redis.getClient();
    await client.lpush(sinkKey(slug), JSON.stringify(entry));
    await client.ltrim(sinkKey(slug), 0, SINK_MAX - 1);
    await client.expire(sinkKey(slug), SINK_TTL_SECONDS);
  }

  async list(slug: string): Promise<SinkEntry[]> {
    const rows = await this.redis
      .getClient()
      .lrange(sinkKey(slug), 0, SINK_MAX - 1);
    return rows.map((row) => JSON.parse(row) as SinkEntry);
  }
}
