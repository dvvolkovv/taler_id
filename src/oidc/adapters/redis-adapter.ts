import type Redis from 'ioredis';

const grantable = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
]);

export class RedisOidcAdapter {
  private model: string;
  private client: Redis;

  constructor(model: string, client: Redis) {
    this.model = model;
    this.client = client;
  }

  private key(id: string): string {
    return `oidc:${this.model}:${id}`;
  }

  async upsert(id: string, payload: any, expiresIn: number): Promise<void> {
    const key = this.key(id);
    const multi = this.client.multi();

    if (expiresIn) {
      multi.set(key, JSON.stringify(payload), 'EX', expiresIn);
    } else {
      multi.set(key, JSON.stringify(payload));
    }

    if (this.model === 'Session' && payload.uid) {
      if (expiresIn) {
        multi.set(`oidc:sessionUid:${payload.uid}`, id, 'EX', expiresIn);
      } else {
        multi.set(`oidc:sessionUid:${payload.uid}`, id);
      }
    }

    if (grantable.has(this.model) && payload.grantId) {
      const grantKey = `oidc:grant:${payload.grantId}`;
      multi.rpush(grantKey, key);
      if (expiresIn) {
        multi.expire(grantKey, expiresIn);
      }
    }

    if (payload.userCode) {
      if (expiresIn) {
        multi.set(`oidc:userCode:${payload.userCode}`, id, 'EX', expiresIn);
      } else {
        multi.set(`oidc:userCode:${payload.userCode}`, id);
      }
    }

    await multi.exec();
  }

  async find(id: string): Promise<any | undefined> {
    const data = await this.client.get(this.key(id));
    if (!data) return undefined;
    return JSON.parse(data);
  }

  async findByUid(uid: string): Promise<any | undefined> {
    const id = await this.client.get(`oidc:sessionUid:${uid}`);
    if (!id) return undefined;
    return this.find(id);
  }

  async findByUserCode(userCode: string): Promise<any | undefined> {
    const id = await this.client.get(`oidc:userCode:${userCode}`);
    if (!id) return undefined;
    return this.find(id);
  }

  async destroy(id: string): Promise<void> {
    await this.client.del(this.key(id));
  }

  async consume(id: string): Promise<void> {
    const data = await this.find(id);
    if (data) {
      data.consumed = Math.floor(Date.now() / 1000);
      const ttl = await this.client.ttl(this.key(id));
      if (ttl > 0) {
        await this.client.set(this.key(id), JSON.stringify(data), 'EX', ttl);
      } else {
        await this.client.set(this.key(id), JSON.stringify(data));
      }
    }
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const grantKey = `oidc:grant:${grantId}`;
    const tokens = await this.client.lrange(grantKey, 0, -1);
    const multi = this.client.multi();
    tokens.forEach((token) => multi.del(token));
    multi.del(grantKey);
    await multi.exec();
  }
}
