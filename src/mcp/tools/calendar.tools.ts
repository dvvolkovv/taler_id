import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CalendarService } from '../../calendar/calendar.service';

function json(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
}

function err(message: string) {
  return {
    content: [{ type: 'text' as const, text: message }],
    isError: true as const,
  };
}

export function registerCalendarTools(
  server: McpServer,
  calendar: Pick<
    CalendarService,
    'findByRange' | 'findOne' | 'create' | 'update' | 'remove'
  >,
  userId: string,
) {
  // list_calendar_events — список событий за диапазон дат
  server.tool(
    'list_calendar_events',
    'Возвращает список событий календаря пользователя за указанный диапазон дат. ' +
      'Если from и to не указаны — возвращает все события. ' +
      'Используй для показа расписания, поиска свободного времени.',
    {
      from: z
        .string()
        .optional()
        .describe('Начало диапазона (ISO 8601 дата или datetime)'),
      to: z
        .string()
        .optional()
        .describe('Конец диапазона (ISO 8601 дата или datetime)'),
    },
    async ({ from, to }) => {
      const events = await calendar.findByRange(userId, from, to);
      return json(events);
    },
  );

  // get_calendar_event — получить одно событие по ID
  server.tool(
    'get_calendar_event',
    'Возвращает детали одного события календаря по его ID. ' +
      'Используй для просмотра подробностей встречи, напоминания, участников.',
    {
      id: z.string().describe('UUID события календаря'),
    },
    async ({ id }) => {
      try {
        const event = await calendar.findOne(userId, id);
        return json(event);
      } catch {
        return err(`Событие ${id} не найдено или нет прав`);
      }
    },
  );

  // create_calendar_event — создать событие
  server.tool(
    'create_calendar_event',
    'Создаёт новое событие в календаре пользователя. ' +
      'Обязательные поля: title (название), type (тип: MEETING/CALL/REMINDER/TASK/OTHER), startAt (начало). ' +
      'Необязательные: endAt (конец), description (описание), reminder_minutes_before (за сколько минут до начала напомнить).',
    {
      title: z.string().describe('Название события'),
      type: z
        .string()
        .describe('Тип события: MEETING, CALL, REMINDER, TASK, OTHER'),
      startAt: z
        .string()
        .describe('Дата и время начала (ISO 8601), например 2026-07-25T10:00:00.000Z'),
      endAt: z
        .string()
        .optional()
        .describe('Дата и время окончания (ISO 8601)'),
      description: z.string().optional().describe('Описание события'),
      reminder_minutes_before: z
        .number()
        .int()
        .positive()
        .optional()
        .describe('За сколько минут до начала выслать напоминание'),
    },
    async ({ title, type, startAt, endAt, description, reminder_minutes_before }) => {
      const createData: Parameters<CalendarService['create']>[1] = {
        title,
        type,
        startAt,
        ...(endAt !== undefined ? { endAt } : {}),
        ...(description !== undefined ? { description } : {}),
        ...(reminder_minutes_before !== undefined
          ? {
              reminderAt: new Date(
                new Date(startAt).getTime() - reminder_minutes_before * 60000,
              ).toISOString(),
            }
          : {}),
      };
      const event = await calendar.create(userId, createData);
      return json(event);
    },
  );

  // update_calendar_event — обновить событие
  server.tool(
    'update_calendar_event',
    'Обновляет существующее событие календаря. ' +
      'Обязательный параметр: id события. ' +
      'Все остальные поля необязательны — передавай только те, которые нужно изменить.',
    {
      id: z.string().describe('UUID события для обновления'),
      title: z.string().optional().describe('Новое название'),
      type: z
        .string()
        .optional()
        .describe('Новый тип: MEETING, CALL, REMINDER, TASK, OTHER'),
      startAt: z
        .string()
        .optional()
        .describe('Новая дата начала (ISO 8601)'),
      endAt: z.string().optional().describe('Новая дата окончания (ISO 8601)'),
      description: z.string().optional().describe('Новое описание'),
      allDay: z
        .boolean()
        .optional()
        .describe('Признак «весь день»'),
      reminder_minutes_before: z
        .number()
        .int()
        .positive()
        .optional()
        .describe('За сколько минут до начала напомнить (вычисляется от startAt)'),
    },
    async ({
      id,
      title,
      type,
      startAt,
      endAt,
      description,
      allDay,
      reminder_minutes_before,
    }) => {
      try {
        const updateData: Record<string, unknown> = {};
        if (title !== undefined) updateData.title = title;
        if (type !== undefined) updateData.type = type;
        if (startAt !== undefined) updateData.startAt = startAt;
        if (endAt !== undefined) updateData.endAt = endAt;
        if (description !== undefined) updateData.description = description;
        if (allDay !== undefined) updateData.allDay = allDay;
        if (reminder_minutes_before !== undefined) {
          // reminderAt is computed from startAt if provided, otherwise the
          // service will use the existing startAt — but the update path in
          // CalendarService accepts reminderAt as an absolute ISO string.
          const base = startAt ?? undefined;
          if (base) {
            updateData.reminderAt = new Date(
              new Date(base).getTime() - reminder_minutes_before * 60000,
            ).toISOString();
          }
        }
        const event = await calendar.update(userId, id, updateData);
        return json(event);
      } catch {
        return err(`Событие ${id} не найдено или нет прав`);
      }
    },
  );

  // delete_calendar_event — удалить событие
  server.tool(
    'delete_calendar_event',
    'Удаляет событие из календаря пользователя. ' +
      'Участники получают push-уведомление об отмене встречи.',
    {
      id: z.string().describe('UUID события для удаления'),
    },
    async ({ id }) => {
      try {
        const result = await calendar.remove(userId, id);
        return json(result);
      } catch {
        return err(`Событие ${id} не найдено или нет прав`);
      }
    },
  );
}
