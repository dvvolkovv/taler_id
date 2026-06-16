import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private client: Redis;

  constructor(private configService: ConfigService) {
    const redisUrl =
      this.configService.get<string>('redis.url') ?? 'redis://localhost:6379';
    this.client = new Redis(redisUrl);
    this.client.on('error', (err) => console.error('Redis error:', err));
  }

  onModuleInit() {
    // Redis client initialized in constructor so it's available for factory providers
  }

  async onModuleDestroy() {
    await this.client.quit();
  }

  getClient(): Redis {
    return this.client;
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async set(key: string, value: string): Promise<void> {
    await this.client.set(key, value);
  }

  async setEx(key: string, ttlSeconds: number, value: string): Promise<void> {
    await this.client.setex(key, ttlSeconds, value);
  }

  /**
   * Atomic "set if not exists" with TTL. Returns true if the key was set
   * (caller acquired the lock), false if the key already existed. Used by
   * messenger gateway for race-free message dedup — replaces the
   * non-atomic GET-then-SETEX pattern that was losing the race for
   * back-to-back duplicate sends in the same millisecond.
   */
  async setNxEx(
    key: string,
    ttlSeconds: number,
    value: string,
  ): Promise<boolean> {
    const r = await this.client.set(key, value, 'EX', ttlSeconds, 'NX');
    return r === 'OK';
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async incr(key: string): Promise<number> {
    return this.client.incr(key);
  }

  async expire(key: string, ttlSeconds: number): Promise<void> {
    await this.client.expire(key, ttlSeconds);
  }
}
