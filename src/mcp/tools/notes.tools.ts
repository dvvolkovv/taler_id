import { z } from 'zod';
import { HttpException } from '@nestjs/common';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { NotesService } from '../../notes/notes.service';

function json(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
}

function err(message: string) {
  return {
    content: [{ type: 'text' as const, text: message }],
    isError: true as const,
  };
}

export function registerNotesTools(
  server: McpServer,
  notes: Pick<NotesService, 'findAll' | 'create' | 'update' | 'remove'>,
  userId: string,
) {
  // list_notes — список заметок пользователя
  server.tool(
    'list_notes',
    'Возвращает список заметок пользователя. ' +
      'Поддерживает пагинацию через limit (макс. 100, по умолчанию 50) и offset (по умолчанию 0). ' +
      'Используй для отображения всех заметок или постраничного просмотра.',
    {
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe('Количество заметок для получения (1–100, по умолчанию 50)'),
      offset: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe('Сдвиг (для пагинации, по умолчанию 0)'),
    },
    async ({ limit, offset }) => {
      const result = await notes.findAll(userId, limit ?? 50, offset ?? 0);
      return json(result);
    },
  );

  // create_note — создать заметку
  server.tool(
    'create_note',
    'Создаёт новую заметку пользователя. ' +
      'Обязательные поля: title (заголовок) и content (содержимое). ' +
      'Необязательное: source (источник, например ASSISTANT).',
    {
      title: z.string().describe('Заголовок заметки'),
      content: z.string().describe('Содержимое заметки'),
      source: z
        .string()
        .optional()
        .describe('Источник создания заметки (например, MANUAL или ASSISTANT)'),
    },
    async ({ title, content, source }) => {
      const data: { title: string; content: string; source?: string } = {
        title,
        content,
      };
      if (source !== undefined) data.source = source;
      const result = await notes.create(userId, data);
      return json(result);
    },
  );

  // update_note — обновить заметку
  server.tool(
    'update_note',
    'Обновляет существующую заметку. ' +
      'Обязательный параметр: id заметки. ' +
      'Все остальные поля необязательны — передавай только те, которые нужно изменить.',
    {
      id: z.string().describe('UUID заметки для обновления'),
      title: z.string().optional().describe('Новый заголовок'),
      content: z.string().optional().describe('Новое содержимое'),
    },
    async ({ id, title, content }) => {
      try {
        const data: { title?: string; content?: string } = {};
        if (title !== undefined) data.title = title;
        if (content !== undefined) data.content = content;
        const result = await notes.update(userId, id, data);
        return json(result);
      } catch (e) {
        if (e instanceof HttpException) {
          return err(`Заметка ${id} не найдена или нет прав`);
        }
        throw e;
      }
    },
  );

  // delete_note — удалить заметку
  server.tool(
    'delete_note',
    'Удаляет заметку пользователя по её ID. ' +
      'Возвращает удалённую заметку. Действие необратимо.',
    {
      id: z.string().describe('UUID заметки для удаления'),
    },
    async ({ id }) => {
      try {
        const result = await notes.remove(userId, id);
        return json(result);
      } catch (e) {
        if (e instanceof HttpException) {
          return err(`Заметка ${id} не найдена или нет прав`);
        }
        throw e;
      }
    },
  );
}
