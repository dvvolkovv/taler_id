import { z } from 'zod';
import { HttpException } from '@nestjs/common';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { MessengerService } from '../../messenger/messenger.service';
import type { Server } from 'socket.io';

function json(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
}

function err(message: string) {
  return {
    content: [{ type: 'text' as const, text: message }],
    isError: true as const,
  };
}

type MessengerReadSvc = Pick<
  MessengerService,
  'listContacts' | 'getConversations' | 'getMessages' | 'searchMessages'
>;

type MessengerSendSvc = Pick<
  MessengerService,
  | 'hasContactWith'
  | 'getOrCreateDirectConversation'
  | 'createMessage'
  | 'getMessageById'
  | 'getUserDisplayName'
>;

type GatewayLike = { server: Pick<Server, 'to'> };

/**
 * Read-only messenger tools: contacts, conversations, messages, search.
 */
export function registerMessengerReadTools(
  server: McpServer,
  svc: MessengerReadSvc,
  userId: string,
) {
  // list_contacts — контакты юзера
  server.tool(
    'list_contacts',
    'Возвращает список контактов пользователя. ' +
      'Писать сообщения разрешено только контактам из этого списка. ' +
      'Используй для получения contact_id перед вызовом send_message.',
    {},
    async () => {
      const contacts = await svc.listContacts(userId);
      return json(contacts);
    },
  );

  // list_conversations — диалоги
  server.tool(
    'list_conversations',
    'Возвращает список диалогов и групповых чатов пользователя. ' +
      'Содержит последнее сообщение, количество непрочитанных и участников. ' +
      'Используй для получения conversation_id перед вызовом get_messages.',
    {},
    async () => {
      const convs = await svc.getConversations(userId);
      return json(convs);
    },
  );

  // get_messages — история сообщений
  server.tool(
    'get_messages',
    'Возвращает историю сообщений диалога. ' +
      'Поддерживает пагинацию через cursor (nextCursor из предыдущего ответа) и limit (макс. 100, по умолчанию 30). ' +
      'Используй для чтения переписки.',
    {
      conversation_id: z.string().describe('UUID диалога или чата'),
      cursor: z
        .string()
        .optional()
        .describe('Курсор пагинации — значение nextCursor из предыдущего ответа'),
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe('Количество сообщений (1–100, по умолчанию 30)'),
    },
    async ({ conversation_id, cursor, limit }) => {
      try {
        const result = await svc.getMessages(
          conversation_id,
          userId,
          cursor,
          limit ?? 30,
        );
        return json(result);
      } catch (e) {
        if (e instanceof HttpException) {
          return err(
            `Не удалось получить сообщения диалога ${conversation_id}: нет доступа или диалог не найден`,
          );
        }
        throw e;
      }
    },
  );

  // search_messages — поиск сообщений
  server.tool(
    'search_messages',
    'Ищет сообщения по тексту во всех диалогах пользователя. ' +
      'Минимальная длина запроса — 2 символа. ' +
      'Используй для поиска конкретной информации в переписке.',
    {
      query: z
        .string()
        .min(2)
        .describe('Поисковый запрос (не менее 2 символов)'),
    },
    async ({ query }) => {
      const results = await svc.searchMessages(query, userId);
      return json(results);
    },
  );
}

/**
 * Send tool — requires contact relationship (security gate).
 */
export function registerMessengerSendTool(
  server: McpServer,
  svc: MessengerReadSvc & MessengerSendSvc,
  gateway: GatewayLike,
  userId: string,
) {
  // send_message — отправить сообщение контакту
  server.tool(
    'send_message',
    'Отправляет текстовое сообщение контакту пользователя. ' +
      'ВАЖНО: получатель должен быть в контактах — используй list_contacts для получения contact_id. ' +
      'Отправка незнакомым пользователям запрещена.',
    {
      contact_id: z.string().describe('UUID пользователя-получателя (должен быть в контактах)'),
      text: z
        .string()
        .min(1)
        .describe('Текст сообщения (не менее 1 символа)'),
    },
    async ({ contact_id, text }) => {
      // Security gate: only contacts may receive messages
      const isContact = await svc.hasContactWith(userId, contact_id);
      if (!isContact) {
        return err(
          'Пользователь не в контактах — отправка запрещена. Используйте list_contacts.',
        );
      }

      // Get or create direct conversation
      const conv = await svc.getOrCreateDirectConversation(userId, contact_id);

      // Create the message
      const message = await svc.createMessage(conv.id, userId, text) as { id: string; deduped?: boolean };

      // Broadcast only if not a dedup hit
      if (!message.deduped) {
        const full = await svc.getMessageById(message.id);
        if (full) {
          const senderName = await svc.getUserDisplayName(userId);
          (gateway.server.to(conv.id) as any).emit('new_message', {
            ...full,
            senderName,
            reactions: [],
          });
        }
      }

      return json({ message_id: message.id, conversation_id: conv.id });
    },
  );
}
