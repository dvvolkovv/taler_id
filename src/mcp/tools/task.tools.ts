import { z } from 'zod';
import { HttpException } from '@nestjs/common';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { TasksService } from '../../tasks/tasks.service';
import type { CalendarService } from '../../calendar/calendar.service';
import { recurrenceSchema } from './calendar.tools';

function json(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
}
function err(message: string) {
  return {
    content: [{ type: 'text' as const, text: message }],
    isError: true as const,
  };
}

const iso = z.string().describe('ISO 8601 datetime с таймзоной');

/**
 * Task / routine tools (calendar API spec §4.2). Registered under the
 * mcp:calendar scope alongside the event tools.
 */
export function registerTaskTools(
  server: McpServer,
  tasks: Pick<
    TasksService,
    'list' | 'create' | 'update' | 'setStatus' | 'remove'
  >,
  userId: string,
) {
  // list_tasks — дела и рутины; для рутин — вхождения в окне с поштучным статусом
  server.tool(
    'list_tasks',
    'Возвращает дела и рутины пользователя. Для рутин (у которых есть recurrence) ' +
      'возвращает вхождения (occurrences) за окно [from,to] с поштучным статусом. ' +
      'includeDone=false (по умолчанию) скрывает выполненные/снятые разовые дела.',
    {
      from: iso.optional().describe('Начало окна (для разворота вхождений рутин)'),
      to: iso.optional().describe('Конец окна'),
      includeDone: z
        .boolean()
        .optional()
        .describe('Включать выполненные/снятые разовые дела (по умолчанию false)'),
    },
    async ({ from, to, includeDone }) => {
      const result = await tasks.list(userId, { from, to, includeDone });
      return json(result);
    },
  );

  // create_task
  server.tool(
    'create_task',
    'Создаёт дело или рутину. due — мягкий ориентир по времени; deadline — жёсткий срок ' +
      '(разные поля). recurrence (§3.3) → это рутина (повторяющееся дело). ' +
      'idempotency_key — стабильный uid против дублей.',
    {
      title: z.string().describe('Название дела'),
      due: iso.optional().describe('Мягкий ориентир по времени (ISO 8601)'),
      deadline: iso.optional().describe('Жёсткий срок (ISO 8601), отдельно от due'),
      note: z.string().optional().describe('Заметка'),
      recurrence: recurrenceSchema
        .optional()
        .describe('Правило повтора (§3.3) — задаёт рутину'),
      idempotency_key: z
        .string()
        .optional()
        .describe(
          'Ключ идемпотентности (стабильный uid). Повторный create с тем же ключом ' +
            'возвращает существующее дело, не создаёт дубль.',
        ),
    },
    async ({ title, due, deadline, note, recurrence, idempotency_key }) => {
      const task = await tasks.create(userId, {
        title,
        ...(due !== undefined ? { due } : {}),
        ...(deadline !== undefined ? { deadline } : {}),
        ...(note !== undefined ? { note } : {}),
        ...(recurrence !== undefined ? { recurrence } : {}),
        ...(idempotency_key !== undefined ? { id: idempotency_key } : {}),
      });
      return json(task);
    },
  );

  // update_task
  server.tool(
    'update_task',
    'Обновляет дело/рутину. Передавай только изменяемые поля. ' +
      'recurrence=null снимает повтор (рутина → разовое дело).',
    {
      id: z.string().describe('UID дела'),
      title: z.string().optional().describe('Новое название'),
      due: iso.nullable().optional().describe('Новый due (null — очистить)'),
      deadline: iso.nullable().optional().describe('Новый deadline (null — очистить)'),
      note: z.string().nullable().optional().describe('Новая заметка (null — очистить)'),
      recurrence: recurrenceSchema
        .nullable()
        .optional()
        .describe('Новое правило повтора (§3.3); null — снять повтор'),
    },
    async ({ id, title, due, deadline, note, recurrence }) => {
      try {
        const task = await tasks.update(userId, id, {
          ...(title !== undefined ? { title } : {}),
          ...(due !== undefined ? { due } : {}),
          ...(deadline !== undefined ? { deadline } : {}),
          ...(note !== undefined ? { note } : {}),
          ...(recurrence !== undefined ? { recurrence } : {}),
        });
        return json(task);
      } catch (e) {
        if (e instanceof HttpException) return err(`Дело ${id} не найдено или нет прав`);
        throw e;
      }
    },
  );

  // set_task_status — статус целиком или поштучно (для рутин, §3.4)
  server.tool(
    'set_task_status',
    'Ставит статус дела: done | pending | dropped. Для РУТИНЫ передай occurrenceDate ' +
      '(YYYY-MM-DD), чтобы отметить конкретный день (§3.4), не трогая остальные вхождения ' +
      '(done→выполнено, dropped→пропущено). doneAt проставляет сервер.',
    {
      id: z.string().describe('UID дела/рутины'),
      status: z.enum(['done', 'pending', 'dropped']).describe('Новый статус'),
      occurrenceDate: z
        .string()
        .regex(/^\d{4}-\d{2}-\d{2}$/)
        .optional()
        .describe('YYYY-MM-DD — конкретный день рутины (для поштучной отметки)'),
    },
    async ({ id, status, occurrenceDate }) => {
      try {
        const task = await tasks.setStatus(userId, id, status, occurrenceDate);
        return json(task);
      } catch (e) {
        if (e instanceof HttpException) return err(`Дело ${id} не найдено или нет прав`);
        throw e;
      }
    },
  );

  // delete_task
  server.tool(
    'delete_task',
    'Удаляет дело/рутину по UID (вместе со всеми поштучными вхождениями).',
    { id: z.string().describe('UID дела') },
    async ({ id }) => {
      try {
        await tasks.remove(userId, id);
        return json({ ok: true });
      } catch (e) {
        if (e instanceof HttpException) return err(`Дело ${id} не найдено или нет прав`);
        throw e;
      }
    },
  );
}

/**
 * list_schedule (spec §4.3) — events + tasks за одно окно одним вызовом.
 */
export function registerScheduleTool(
  server: McpServer,
  calendar: Pick<CalendarService, 'findByRange'>,
  tasks: Pick<TasksService, 'list'>,
  userId: string,
) {
  server.tool(
    'list_schedule',
    'Единое чтение расписания за окно [from,to]: возвращает { events, tasks } одним ' +
      'вызовом (события с развёрнутыми повторами + дела/рутины с вхождениями и статусами). ' +
      'Чтобы не делать два отдельных запроса.',
    {
      from: iso.describe('Начало окна (ISO 8601 с таймзоной)'),
      to: iso.describe('Конец окна (ISO 8601 с таймзоной)'),
      includeDone: z
        .boolean()
        .optional()
        .describe('Включать выполненные/снятые разовые дела (по умолчанию false)'),
    },
    async ({ from, to, includeDone }) => {
      const [events, taskList] = await Promise.all([
        calendar.findByRange(userId, from, to),
        tasks.list(userId, { from, to, includeDone }),
      ]);
      // list_schedule is a WINDOWED view ("расписание за окно"), unlike
      // list_tasks which returns the full one-off backlog. Keep only tasks
      // that actually land in [from,to]: routines with ≥1 occurrence in the
      // window, and one-off tasks whose due or deadline falls in the window.
      const fromMs = Date.parse(from);
      const toMs = Date.parse(to);
      const inWindow = (iso?: string | null) => {
        if (!iso) return false;
        const t = Date.parse(iso);
        return !Number.isNaN(t) && t >= fromMs && t <= toMs;
      };
      const scheduledTasks = taskList.filter((t: any) =>
        Array.isArray(t.occurrences)
          ? t.occurrences.length > 0
          : inWindow(t.due) || inWindow(t.deadline),
      );
      return json({ events, tasks: scheduledTasks });
    },
  );
}
