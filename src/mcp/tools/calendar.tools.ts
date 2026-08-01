import { z } from 'zod';
import { HttpException } from '@nestjs/common';
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

/**
 * Zod schema for a datetime string with timezone offset (ISO 8601 with Z or ±HH:MM).
 * Example: "2026-07-25T10:00:00.000Z"
 */
const isoDatetime = z
  .string()
  .datetime({ offset: true })
  .describe('Дата и время в формате ISO 8601 с указанием таймзоны, например 2026-07-25T10:00:00.000Z');

/**
 * Zod schema for a date-or-datetime range boundary.
 * Accepts ISO date ("2026-07-01") or full datetime ("2026-07-01T00:00:00Z").
 */
const isoDateOrDatetime = (description: string) =>
  z
    .string()
    .refine((s) => !Number.isNaN(Date.parse(s)), 'Invalid date — ожидается ISO 8601 дата или datetime')
    .describe(description);

/**
 * Expand a date-only bound (YYYY-MM-DD) to cover the whole UTC day, so a range
 * like from=2026-09-01&to=2026-09-15 includes events at any time on Sep 15
 * (a bare date would otherwise mean that day's 00:00 and exclude same-day
 * events). Full datetimes and undefined pass through unchanged.
 */
const expandRangeBound = (
  v: string | undefined,
  edge: 'start' | 'end',
): string | undefined => {
  if (!v) return v;
  return /^\d{4}-\d{2}-\d{2}$/.test(v)
    ? `${v}T${edge === 'start' ? '00:00:00.000' : '23:59:59.999'}Z`
    : v;
};

/**
 * Known CalendarEventType values from Prisma enum CalendarEventType.
 * Defined in prisma/schema.prisma: CALL | EVENT | REMINDER
 */
const CALENDAR_EVENT_TYPES = ['CALL', 'EVENT', 'REMINDER'] as const;
const calendarEventType = z
  .enum(CALENDAR_EVENT_TYPES)
  .describe('Тип события: CALL (звонок), EVENT (встреча/событие), REMINDER (напоминание)');

/**
 * Recurrence rule — canonical shape per calendar API spec §3.3.
 * Stored freeform; the server expands recurring events into occurrences.
 */
const RECURRENCE_WEEKDAYS = ['MO', 'TU', 'WE', 'TH', 'FR', 'SA', 'SU'] as const;
const recurrenceSchema = z
  .object({
    freq: z
      .enum(['daily', 'weekly', 'monthly'])
      .describe('Частота повтора: daily | weekly | monthly'),
    interval: z
      .number()
      .int()
      .min(1)
      .optional()
      .describe('Повторять каждые N единиц (по умолчанию 1)'),
    byDay: z
      .array(z.enum(RECURRENCE_WEEKDAYS))
      .optional()
      .describe('Дни недели для weekly, например ["MO","WE","FR"]'),
    count: z
      .number()
      .int()
      .min(1)
      .optional()
      .describe('Ограничение по числу повторов'),
    until: z
      .string()
      .optional()
      .describe('ISO 8601 — повторять до этой даты включительно'),
  })
  .describe('Правило повтора (spec §3.3). Указывай только для повторяющихся событий.');

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
      from: isoDateOrDatetime('Начало диапазона (ISO 8601 дата или datetime), например 2026-07-01 или 2026-07-01T00:00:00Z').optional(),
      to: isoDateOrDatetime('Конец диапазона (ISO 8601 дата или datetime), например 2026-07-31 или 2026-07-31T23:59:59Z').optional(),
    },
    async ({ from, to }) => {
      const events = await calendar.findByRange(
        userId,
        expandRangeBound(from, 'start'),
        expandRangeBound(to, 'end'),
      );
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
      } catch (e) {
        if (e instanceof HttpException) {
          return err(`Событие ${id} не найдено или нет прав`);
        }
        throw e;
      }
    },
  );

  // create_calendar_event — создать событие
  server.tool(
    'create_calendar_event',
    'Создаёт новое событие в календаре пользователя. ' +
      'Обязательные поля: title (название), type (тип: CALL/EVENT/REMINDER), startAt (начало). ' +
      'Необязательные: endAt (конец), description (описание), reminder_minutes_before, ' +
      'recurrence (повтор), idempotency_key (стабильный ключ против дублей).',
    {
      title: z.string().describe('Название события'),
      type: calendarEventType,
      startAt: isoDatetime.describe(
        'Дата и время начала (ISO 8601 с таймзоной), например 2026-07-25T10:00:00.000Z',
      ),
      endAt: isoDatetime
        .describe('Дата и время окончания (ISO 8601 с таймзоной)')
        .optional(),
      description: z.string().optional().describe('Описание события'),
      reminder_minutes_before: z
        .number()
        .int()
        .positive()
        .optional()
        .describe('За сколько минут до начала выслать напоминание'),
      recurrence: recurrenceSchema.optional(),
      idempotency_key: z
        .string()
        .optional()
        .describe(
          'Ключ идемпотентности (стабильный uid). Повторный create с тем же ключом ' +
            'возвращает существующее событие вместо создания дубля.',
        ),
    },
    async ({
      title,
      type,
      startAt,
      endAt,
      description,
      reminder_minutes_before,
      recurrence,
      idempotency_key,
    }) => {
      const createData: Parameters<CalendarService['create']>[1] = {
        title,
        type,
        startAt,
        ...(endAt !== undefined ? { endAt } : {}),
        ...(description !== undefined ? { description } : {}),
        ...(recurrence !== undefined ? { recurrence } : {}),
        ...(idempotency_key !== undefined ? { id: idempotency_key } : {}),
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
      type: calendarEventType.optional(),
      startAt: isoDatetime
        .describe('Новая дата начала (ISO 8601 с таймзоной)')
        .optional(),
      endAt: isoDatetime
        .describe('Новая дата окончания (ISO 8601 с таймзоной)')
        .optional(),
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
        .describe('За сколько минут до начала напомнить (вычисляется от startAt; если startAt не передан в этом же вызове — игнорируется)'),
      recurrence: recurrenceSchema
        .nullable()
        .optional()
        .describe('Новое правило повтора (spec §3.3); null — снять повтор.'),
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
      recurrence,
    }) => {
      try {
        const updateData: Record<string, unknown> = {};
        if (title !== undefined) updateData.title = title;
        if (type !== undefined) updateData.type = type;
        if (startAt !== undefined) updateData.startAt = startAt;
        if (endAt !== undefined) updateData.endAt = endAt;
        if (description !== undefined) updateData.description = description;
        if (allDay !== undefined) updateData.allDay = allDay;
        if (recurrence !== undefined) updateData.recurrence = recurrence;
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
      } catch (e) {
        if (e instanceof HttpException) {
          return err(`Событие ${id} не найдено или нет прав`);
        }
        throw e;
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
      } catch (e) {
        if (e instanceof HttpException) {
          return err(`Событие ${id} не найдено или нет прав`);
        }
        throw e;
      }
    },
  );
}
