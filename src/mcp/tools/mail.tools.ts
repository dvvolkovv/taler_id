import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { MailBridgeService } from '../../mail/mail-bridge.service';

const json = (data: unknown) => ({
  content: [{ type: 'text' as const, text: JSON.stringify(data) }],
});
const err = (message: string) => ({
  content: [{ type: 'text' as const, text: JSON.stringify({ error: message }) }],
  isError: true,
});

export function registerMailReadTools(
  server: McpServer,
  bridge: MailBridgeService,
  userId: string,
) {
  server.tool(
    'check_mail',
    'Возвращает последние письма из почтового ящика пользователя @talerid.io (uid, from, subject, date, seen, snippet).',
    { limit: z.number().int().min(1).max(20).optional().describe('Сколько писем вернуть (default 5)') },
    async ({ limit }) => {
      try {
        const page = await bridge.listMessages(userId, 'INBOX', undefined, limit ?? 5);
        return json(page.items);
      } catch (e) {
        return err((e as Error).message.includes('mail_account')
          ? 'no_mailbox_yet'
          : 'mail_unavailable');
      }
    },
  );

  server.tool(
    'read_mail',
    'Читает письмо по uid (из check_mail). Возвращает текст письма.',
    { uid: z.number().int().describe('uid письма из check_mail') },
    async ({ uid }) => {
      const msg = await bridge.getMessage(userId, uid);
      return json({
        from: msg.from, to: msg.to, subject: msg.subject, date: msg.date,
        text: msg.text.slice(0, 4000),
        attachments: msg.attachments.map((a: { filename: string }) => a.filename),
      });
    },
  );
}

export function registerMailSendTool(
  server: McpServer,
  bridge: MailBridgeService,
  userId: string,
) {
  server.tool(
    'send_mail',
    'Отправляет письмо от имени пользователя с его адреса @talerid.io. Подтверди у пользователя получателя и текст перед вызовом.',
    {
      to: z.string().email().describe('Email получателя'),
      subject: z.string().max(255).describe('Тема'),
      text: z.string().min(1).describe('Текст письма'),
    },
    async ({ to, subject, text }) => {
      await bridge.sendMessage(userId, { to, subject, text });
      return json({ ok: true, sent_to: to });
    },
  );
}
