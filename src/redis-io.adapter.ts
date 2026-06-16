import { INestApplicationContext, Logger } from '@nestjs/common';
import { IoAdapter } from '@nestjs/platform-socket.io';
import { ServerOptions } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import Redis from 'ioredis';

/**
 * Socket.IO adapter backed by Redis pub/sub.
 *
 * Without this, every Node process keeps room membership in its own memory.
 * On a single-process deploy (aeza) that's fine. Behind the DO load balancer
 * there are TWO app nodes: a sender on app-1 emitting to `user:<id>` /
 * `<conversationId>` never reaches a recipient whose socket lives on app-2 —
 * the message persists in Postgres but the live `new_message` event is lost.
 *
 * The Redis adapter relays room joins and emits across every process sharing
 * the same Redis, so `server.to(room).emit(...)` fans out to all nodes.
 *
 * Falls back to the default in-memory adapter if REDIS_URL is absent, so local
 * dev without Redis still boots (single-process only).
 */
export class RedisIoAdapter extends IoAdapter {
  private adapterConstructor?: ReturnType<typeof createAdapter>;

  constructor(app: INestApplicationContext) {
    super(app);
  }

  async connectToRedis(): Promise<void> {
    const url = process.env.REDIS_URL;
    if (!url) {
      Logger.warn(
        'REDIS_URL not set — Socket.IO running with the in-memory adapter (single-node only)',
        'RedisIoAdapter',
      );
      return;
    }

    const pubClient = new Redis(url);
    const subClient = pubClient.duplicate();

    await Promise.all([
      new Promise<void>((resolve, reject) => {
        pubClient.once('ready', resolve);
        pubClient.once('error', reject);
      }),
      new Promise<void>((resolve, reject) => {
        subClient.once('ready', resolve);
        subClient.once('error', reject);
      }),
    ]);

    this.adapterConstructor = createAdapter(pubClient, subClient);
    Logger.log(
      'Socket.IO Redis adapter connected — cross-node broadcast enabled',
      'RedisIoAdapter',
    );
  }

  createIOServer(port: number, options?: ServerOptions): any {
    const server = super.createIOServer(port, options);
    if (this.adapterConstructor) {
      server.adapter(this.adapterConstructor);
    }
    return server;
  }
}
