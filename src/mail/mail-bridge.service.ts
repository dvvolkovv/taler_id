import { BadRequestException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ImapFlow } from 'imapflow';
import { simpleParser, ParsedMail } from 'mailparser';
import * as nodemailer from 'nodemailer';
import sanitizeHtml from 'sanitize-html';
import { RedisService } from '../redis/redis.service';
import { MailAccountService } from './mail-account.service';
import { decryptSecret } from './mail-crypto';

export interface MailListItem {
  uid: number;
  from: string;
  fromAddress: string;
  subject: string;
  date: string;
  seen: boolean;
  snippet: string;
  hasAttachments: boolean;
}

@Injectable()
export class MailBridgeService {
  private readonly logger = new Logger(MailBridgeService.name);
  private readonly imapHost: string;
  private readonly masterKey: string;
  private readonly sendDailyLimit: number;

  constructor(
    private readonly accounts: MailAccountService,
    private readonly redis: RedisService,
    config: ConfigService,
  ) {
    // Мост ходит на тот же Mailcow, что и внешние клиенты
    this.imapHost = config.get<string>('mail.clientHost')!;
    this.masterKey = config.get<string>('mail.masterKey')!;
    this.sendDailyLimit = config.get<number>('mail.sendDailyLimit')!;
  }

  private async withImap<T>(userId: string, fn: (client: ImapFlow, address: string) => Promise<T>): Promise<T> {
    const account = await this.accounts.requireActiveAccount(userId);
    const address = this.accounts.address(account);
    const client = new ImapFlow({
      host: this.imapHost,
      port: 993,
      secure: true,
      auth: { user: address, pass: decryptSecret(account.masterSecret, this.masterKey) },
      logger: false,
    });
    await client.connect();
    try {
      return await fn(client, address);
    } finally {
      await client.logout().catch(() => client.close());
    }
  }

  async listMessages(userId: string, folder = 'INBOX', beforeUid?: number, limit = 30): Promise<{ items: MailListItem[]; nextCursor: number | null }> {
    return this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock(folder);
      try {
        const mailbox = client.mailbox;
        if (!mailbox || mailbox.exists === 0) return { items: [], nextCursor: null };
        const range: string = beforeUid ? `1:${beforeUid - 1}` : '1:*';
        const items: MailListItem[] = [];
        for await (const msg of client.fetch(
          range,
          { uid: true, envelope: true, flags: true, bodyStructure: true, bodyParts: ['text'] },
          { uid: true },
        )) {
          const text = msg.bodyParts?.get('text')?.toString('utf8') ?? '';
          items.push({
            uid: msg.uid,
            from: msg.envelope?.from?.[0]?.name || msg.envelope?.from?.[0]?.address || '',
            fromAddress: msg.envelope?.from?.[0]?.address || '',
            subject: msg.envelope?.subject || '',
            date: (msg.envelope?.date ?? new Date()).toISOString(),
            seen: msg.flags?.has('\\Seen') ?? false,
            snippet: text.replace(/\s+/g, ' ').trim().slice(0, 120),
            hasAttachments: hasAttachmentParts(msg.bodyStructure),
          });
        }
        items.sort((a, b) => b.uid - a.uid);
        const page = items.slice(0, limit);
        return { items: page, nextCursor: page.length === limit ? page[page.length - 1].uid : null };
      } finally {
        lock.release();
      }
    });
  }

  async getMessage(userId: string, uid: number) {
    return this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock('INBOX');
      try {
        const dl = await client.download(String(uid), undefined, { uid: true });
        if (!dl?.content) throw new NotFoundException('message_not_found');
        const parsed: ParsedMail = await simpleParser(dl.content);
        await client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true });
        return {
          uid,
          from: parsed.from?.text ?? '',
          to: parsed.to ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]).map((t) => t.text).join(', ') : '',
          subject: parsed.subject ?? '',
          date: (parsed.date ?? new Date()).toISOString(),
          messageId: parsed.messageId ?? null,
          html: parsed.html ? sanitize(parsed.html) : null,
          text: parsed.text ?? '',
          attachments: (parsed.attachments ?? []).map((a, i) => ({
            index: i,
            filename: a.filename ?? `attachment-${i}`,
            contentType: a.contentType,
            size: a.size,
          })),
        };
      } finally {
        lock.release();
      }
    });
  }

  async getAttachment(userId: string, uid: number, index: number) {
    return this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock('INBOX');
      try {
        const dl = await client.download(String(uid), undefined, { uid: true });
        if (!dl?.content) throw new NotFoundException('message_not_found');
        const parsed = await simpleParser(dl.content);
        const att = (parsed.attachments ?? [])[index];
        if (!att) throw new NotFoundException('attachment_not_found');
        return { filename: att.filename ?? `attachment-${index}`, contentType: att.contentType, content: att.content };
      } finally {
        lock.release();
      }
    });
  }

  async setSeen(userId: string, uid: number, seen: boolean): Promise<void> {
    await this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock('INBOX');
      try {
        if (seen) await client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true });
        else await client.messageFlagsRemove(String(uid), ['\\Seen'], { uid: true });
      } finally {
        lock.release();
      }
    });
  }

  async deleteMessage(userId: string, uid: number): Promise<void> {
    await this.withImap(userId, async (client) => {
      const lock = await client.getMailboxLock('INBOX');
      try {
        await client.messageDelete(String(uid), { uid: true });
      } finally {
        lock.release();
      }
    });
  }

  async sendMessage(
    userId: string,
    input: { to: string; subject: string; text: string; inReplyTo?: string; attachments?: { filename: string; contentBase64: string }[] },
  ): Promise<void> {
    const account = await this.accounts.requireActiveAccount(userId);
    await this.enforceSendLimit(userId);

    const totalSize = (input.attachments ?? []).reduce((s, a) => s + a.contentBase64.length * 0.75, 0);
    if (totalSize > 10 * 1024 * 1024) throw new BadRequestException('attachments_too_large');

    const address = this.accounts.address(account);
    const transport = nodemailer.createTransport({
      host: this.imapHost,
      port: 465,
      secure: true,
      auth: { user: address, pass: decryptSecret(account.masterSecret, this.masterKey) },
    });
    await transport.sendMail({
      from: address,
      to: input.to,
      subject: input.subject,
      text: input.text,
      inReplyTo: input.inReplyTo,
      references: input.inReplyTo,
      attachments: (input.attachments ?? []).map((a) => ({
        filename: a.filename,
        content: Buffer.from(a.contentBase64, 'base64'),
      })),
    });
  }

  private async enforceSendLimit(userId: string): Promise<void> {
    const day = new Date().toISOString().slice(0, 10);
    const key = `mail:send:${userId}:${day}`;
    const client = this.redis.getClient();
    const count = await client.incr(key);
    if (count === 1) await client.expire(key, 86_400);
    if (count > this.sendDailyLimit) throw new BadRequestException('mail_send_daily_limit');
  }
}

function sanitize(html: string): string {
  return sanitizeHtml(html, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img', 'h1', 'h2', 'span']),
    allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, '*': ['style'] },
    // remote-картинки блокируются: разрешаем только data:-URI
    allowedSchemesByTag: { img: ['data'] },
  });
}

function hasAttachmentParts(node: any): boolean {
  if (!node) return false;
  if (node.disposition === 'attachment') return true;
  return (node.childNodes ?? []).some((c: any) => hasAttachmentParts(c));
}
