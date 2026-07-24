import {
  BadRequestException, ConflictException, Injectable, Logger,
  NotFoundException, OnModuleDestroy, OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { MailcowClient } from './mailcow.client';
import { encryptSecret, decryptSecret } from './mail-crypto';
import { normalizeLocalpart, validateLocalpart } from './localpart';

const RETRY_ZSET = 'mail:provision:retry';
const RETRY_ATTEMPTS_HASH = 'mail:provision:attempts';
const RETRY_MAX_ATTEMPTS = 10;
const RETRY_POLL_MS = 30_000;
const RETRY_DELAY_MS = 60_000;

function generatePassword(bytes = 18): string {
  // base64url без паддинга — 24 символа, безопасен для IMAP/SMTP auth
  return randomBytes(bytes).toString('base64url');
}

@Injectable()
export class MailAccountService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(MailAccountService.name);
  private pollTimer?: NodeJS.Timeout;
  private readonly domain: string;
  private readonly masterKey: string;
  private readonly clientHost: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly mailcow: MailcowClient,
    config: ConfigService,
  ) {
    this.domain = config.get<string>('mail.domain')!;
    this.masterKey = config.get<string>('mail.masterKey')!;
    this.clientHost = config.get<string>('mail.clientHost')!;
  }

  onModuleInit() {
    this.pollTimer = setInterval(
      () => this.retryTick().catch((e) => this.logger.error('retry tick error', e)),
      RETRY_POLL_MS,
    );
  }

  onModuleDestroy() {
    if (this.pollTimer) clearInterval(this.pollTimer);
  }

  address(account: { localpart: string; domain: string }): string {
    return `${account.localpart}@${account.domain}`;
  }

  async checkAvailability(raw: string): Promise<{ localpart: string; available: boolean; reason?: string }> {
    const localpart = normalizeLocalpart(raw ?? '');
    const invalid = validateLocalpart(localpart);
    if (invalid) return { localpart, available: false, reason: invalid };
    const taken = await this.prisma.mailAccount.findUnique({ where: { localpart } });
    if (taken) return { localpart, available: false, reason: 'TAKEN' };
    // Домен может быть общим для нескольких окружений (DEV/TEST на mail-dev.*) —
    // локальная БД не видит чужие ящики, поэтому сверяемся с Mailcow.
    if (await this.mailcow.mailboxExists(`${localpart}@${this.domain}`)) {
      return { localpart, available: false, reason: 'TAKEN' };
    }
    return { localpart, available: true };
  }

  async createAccount(userId: string, rawLocalpart: string) {
    const existing = await this.prisma.mailAccount.findUnique({ where: { userId } });
    if (existing) throw new ConflictException('mail_account_already_exists');

    const { localpart, available, reason } = await this.checkAvailability(rawLocalpart);
    if (!available) throw new BadRequestException(`localpart_${(reason ?? 'invalid').toLowerCase()}`);

    const masterPassword = generatePassword();
    // I1: ловим гонку — два параллельных запроса могут пройти findUnique одновременно
    let account: Awaited<ReturnType<typeof this.prisma.mailAccount.create>>;
    try {
      account = await this.prisma.mailAccount.create({
        data: {
          userId,
          localpart,
          domain: this.domain,
          status: 'PROVISIONING',
          masterSecret: encryptSecret(masterPassword, this.masterKey),
        },
      });
    } catch (e: any) {
      if (e?.code === 'P2002') {
        const target: string[] = e?.meta?.target ?? [];
        if (target.includes('userId') || target.includes('user_id')) {
          throw new ConflictException('mail_account_already_exists');
        }
        throw new BadRequestException('localpart_taken');
      }
      throw e;
    }

    await this.provision(account.id, localpart, masterPassword);
    return this.getAccount(userId);
  }

  private async provision(accountId: string, localpart: string, masterPassword: string): Promise<void> {
    try {
      await this.mailcow.createMailbox(localpart, this.domain, masterPassword, 1024, localpart);
      await this.prisma.mailAccount.update({ where: { id: accountId }, data: { status: 'ACTIVE' } });
      // I2: при успехе сбрасываем счётчик попыток
      await this.redis.getClient().hdel(RETRY_ATTEMPTS_HASH, accountId);
      this.logger.log(`provisioned ${localpart}@${this.domain}`);
    } catch (e) {
      this.logger.warn(`provision failed for ${localpart}, scheduling retry: ${(e as Error).message}`);
      await this.redis.getClient().zadd(RETRY_ZSET, Date.now() + RETRY_DELAY_MS, accountId);
    }
  }

  private async retryTick(): Promise<void> {
    const client = this.redis.getClient();
    const due: string[] = await client.zrangebyscore(RETRY_ZSET, '-inf', String(Date.now()));
    for (const accountId of due) {
      // I3: атомарный zrem — только один инстанс обработает задачу
      const removed: number = await client.zrem(RETRY_ZSET, accountId);
      if (!removed) continue;

      // I2: проверяем счётчик попыток
      const attempts = await client.hincrby(RETRY_ATTEMPTS_HASH, accountId, 1);
      if (attempts > RETRY_MAX_ATTEMPTS) {
        this.logger.error(`provision permanently failed for accountId=${accountId} after ${RETRY_MAX_ATTEMPTS} retries — giving up`);
        await client.hdel(RETRY_ATTEMPTS_HASH, accountId);
        continue;
      }

      const account = await this.prisma.mailAccount.findUnique({ where: { id: accountId } });
      if (!account || account.status !== 'PROVISIONING') {
        await client.hdel(RETRY_ATTEMPTS_HASH, accountId);
        continue;
      }
      await this.provision(account.id, account.localpart, decryptSecret(account.masterSecret, this.masterKey));
    }
  }

  async getAccount(userId: string) {
    const account = await this.prisma.mailAccount.findUnique({ where: { userId } });
    if (!account) throw new NotFoundException('mail_account_not_found');
    return {
      address: this.address(account),
      localpart: account.localpart,
      domain: account.domain,
      status: account.status,
      quotaBytes: account.quotaBytes.toString(),
      clientSettings: {
        host: this.clientHost,
        imapPort: 993, imapSecurity: 'SSL/TLS',
        smtpPort: 465, smtpSecurity: 'SSL/TLS',
        login: this.address(account),
      },
    };
  }

  /** Внутренний доступ для моста: entity + расшифровка masterSecret */
  async requireActiveAccount(userId: string) {
    const account = await this.prisma.mailAccount.findUnique({ where: { userId } });
    if (!account) throw new NotFoundException('mail_account_not_found');
    if (account.status !== 'ACTIVE') throw new BadRequestException(`mail_account_${account.status.toLowerCase()}`);
    return account;
  }

  // ── App-passwords ──────────────────────────────────────────────

  async createAppPassword(userId: string, label: string) {
    const account = await this.requireActiveAccount(userId);
    const cleanLabel = (label ?? '').trim().slice(0, 64) || 'Mail client';
    const password = generatePassword();
    const mailcowId = await this.mailcow.createAppPassword(this.address(account), cleanLabel, password);
    const rec = await this.prisma.mailAppPassword.create({
      data: { mailAccountId: account.id, mailcowId, label: cleanLabel },
    });
    return {
      id: rec.id,
      label: rec.label,
      password, // показывается ровно один раз
      clientSettings: (await this.getAccount(userId)).clientSettings,
    };
  }

  async listAppPasswords(userId: string) {
    const account = await this.requireActiveAccount(userId);
    const rows = await this.prisma.mailAppPassword.findMany({
      where: { mailAccountId: account.id, revokedAt: null },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => ({ id: r.id, label: r.label, createdAt: r.createdAt }));
  }

  async revokeAppPassword(userId: string, id: string): Promise<void> {
    const account = await this.requireActiveAccount(userId);
    const rec = await this.prisma.mailAppPassword.findFirst({
      where: { id, mailAccountId: account.id, revokedAt: null },
    });
    if (!rec) throw new NotFoundException('app_password_not_found');
    await this.mailcow.deleteAppPassword(rec.mailcowId);
    await this.prisma.mailAppPassword.update({ where: { id }, data: { revokedAt: new Date() } });
  }
}
