import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { expandOccurrences } from '../calendar/recurrence.util';

// Occurrence dates are UTC calendar dates (prod runs UTC; expandOccurrences
// advances by whole days preserving time-of-day, so the UTC date is stable).
function toDateStr(d: Date): string {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}
const lower = (s: string) => s.toLowerCase();
const isRoutine = (rec: any) => !!(rec && (rec.freq || rec.frequency));

export interface CreateTaskInput {
  id?: string;
  title: string;
  due?: string;
  deadline?: string;
  note?: string;
  recurrence?: Record<string, any> | null;
  createdBy?: string;
}

@Injectable()
export class TasksService {
  constructor(private readonly prisma: PrismaService) {}

  /** Create-or-return-existing (idempotent by client-provided id/uid). */
  async create(userId: string, data: CreateTaskInput) {
    if (data.id) {
      const existing = await this.prisma.task.findUnique({
        where: { id: data.id },
        include: { occurrences: true },
      });
      if (existing) {
        if (existing.userId !== userId) {
          throw new ConflictException('Task id already used by another account');
        }
        return this.toDto(existing);
      }
    }
    const task = await this.prisma.task.create({
      data: {
        ...(data.id ? { id: data.id } : {}),
        userId,
        title: data.title,
        due: data.due ? new Date(data.due) : null,
        deadline: data.deadline ? new Date(data.deadline) : null,
        note: data.note ?? null,
        recurrence: (data.recurrence ?? Prisma.DbNull) as Prisma.InputJsonValue,
        createdBy: data.createdBy ?? 'MANUAL',
      },
      include: { occurrences: true },
    });
    return this.toDto(task);
  }

  async update(
    userId: string,
    id: string,
    patch: {
      title?: string;
      due?: string | null;
      deadline?: string | null;
      note?: string | null;
      recurrence?: Record<string, any> | null;
    },
  ) {
    await this.requireOwned(userId, id);
    const data: Prisma.TaskUpdateInput = {};
    if (patch.title !== undefined) data.title = patch.title;
    if (patch.due !== undefined) data.due = patch.due ? new Date(patch.due) : null;
    if (patch.deadline !== undefined)
      data.deadline = patch.deadline ? new Date(patch.deadline) : null;
    if (patch.note !== undefined) data.note = patch.note;
    if (patch.recurrence !== undefined)
      data.recurrence = (patch.recurrence ?? Prisma.DbNull) as Prisma.InputJsonValue;
    const task = await this.prisma.task.update({
      where: { id },
      data,
      include: { occurrences: true },
    });
    return this.toDto(task);
  }

  async remove(userId: string, id: string) {
    await this.requireOwned(userId, id);
    await this.prisma.task.delete({ where: { id } });
    return { ok: true };
  }

  /**
   * Set status. status ∈ pending|done|dropped.
   * With `occurrenceDate` (routine): marks that single day (§3.4) — done→DONE,
   * dropped→SKIPPED, pending→PENDING — without touching the series. Without it:
   * sets the task's own status. doneAt is server-set on transition to done.
   */
  async setStatus(
    userId: string,
    id: string,
    status: 'pending' | 'done' | 'dropped',
    occurrenceDate?: string,
  ) {
    await this.requireOwned(userId, id);
    if (occurrenceDate) {
      const occStatus =
        status === 'done' ? 'DONE' : status === 'dropped' ? 'SKIPPED' : 'PENDING';
      const doneAt = occStatus === 'DONE' ? new Date() : null;
      await this.prisma.taskOccurrence.upsert({
        where: { taskId_occurrenceDate: { taskId: id, occurrenceDate } },
        create: { taskId: id, occurrenceDate, status: occStatus, doneAt },
        update: { status: occStatus, doneAt },
      });
    } else {
      const taskStatus =
        status === 'done' ? 'DONE' : status === 'dropped' ? 'DROPPED' : 'PENDING';
      await this.prisma.task.update({
        where: { id },
        data: { status: taskStatus, doneAt: taskStatus === 'DONE' ? new Date() : null },
      });
    }
    return this.getOne(userId, id);
  }

  /**
   * List tasks. Routines return their in-window occurrences (per-day status);
   * non-routines are filtered by includeDone (default false hides DONE/DROPPED).
   */
  async list(
    userId: string,
    opts: { from?: string; to?: string; includeDone?: boolean },
  ) {
    const includeDone = opts.includeDone ?? false;
    const from = opts.from ? new Date(opts.from) : null;
    const to = opts.to ? new Date(opts.to) : null;
    const tasks = await this.prisma.task.findMany({
      where: { userId },
      include: { occurrences: true },
      orderBy: { createdAt: 'asc' },
    });
    const out: any[] = [];
    for (const task of tasks) {
      if (isRoutine(task.recurrence)) {
        out.push(this.toDto(task, from, to));
      } else {
        if (!includeDone && (task.status === 'DONE' || task.status === 'DROPPED'))
          continue;
        out.push(this.toDto(task));
      }
    }
    return out;
  }

  async getOne(userId: string, id: string) {
    const task = await this.requireOwned(userId, id);
    return this.toDto(task);
  }

  /**
   * Task/routine occurrences shaped as read-only calendar-event items, so the
   * app's calendar screen (which reads GET /calendar) shows routines like the
   * user's morning/evening washing — which Linkeon moved from events to tasks.
   *
   * Each occurrence is a SEPARATE synthetic event with a unique id
   * `task:{taskId}:{YYYY-MM-DD}` (the app keys Hive by id and matches a tile to
   * a day by startAt, so per-occurrence rows are required). `type:'TASK'` is an
   * already-valid CalendarEventType in the app, so these render on installed
   * apps with no update. Marker fields (kind/taskId/occurrenceDate/status/
   * readOnly) are ignored by the current app and used by a future TASK-aware UI.
   *
   * This is used ONLY by the app-facing REST controller — NOT findByRange,
   * which MCP list_calendar_events / list_schedule rely on returning pure events.
   */
  async occurrencesForCalendar(userId: string, from?: string, to?: string) {
    const startDate = from ? new Date(from) : new Date();
    const endDate = to
      ? new Date(to)
      : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const tasks = await this.prisma.task.findMany({
      where: { userId },
      include: { occurrences: true },
    });
    const items: any[] = [];
    for (const task of tasks) {
      if (isRoutine(task.recurrence)) {
        const anchor = task.due ?? task.createdAt;
        const stored = new Map<string, any>(
          (task.occurrences ?? []).map((o: any) => [o.occurrenceDate, o]),
        );
        for (const d of expandOccurrences(
          new Date(anchor),
          task.recurrence,
          startDate,
          endDate,
        )) {
          const ds = toDateStr(d);
          const occ = stored.get(ds);
          if (occ && occ.status === 'SKIPPED') continue; // hide skipped days
          items.push(this.synthCalendarItem(task, d, ds, occ));
        }
      } else {
        if (task.status === 'DONE' || task.status === 'DROPPED') continue;
        const when = task.due ?? task.deadline;
        if (when && when >= startDate && when <= endDate) {
          const w = new Date(when);
          items.push(this.synthCalendarItem(task, w, toDateStr(w), null));
        }
      }
    }
    return items;
  }

  private synthCalendarItem(task: any, when: Date, ds: string, occ: any) {
    const toIso = (v: any) => (v instanceof Date ? v.toISOString() : v);
    return {
      id: `task:${task.id}:${ds}`,
      title: task.title,
      description: task.note ?? undefined,
      type: 'TASK',
      startAt: when.toISOString(),
      endAt: null,
      allDay: false,
      recurrence: task.recurrence ?? undefined,
      createdBy: task.createdBy ?? 'MANUAL',
      createdAt: toIso(task.createdAt),
      updatedAt: toIso(task.updatedAt),
      // task-specific markers (ignored by current app):
      kind: 'task',
      taskId: task.id,
      occurrenceDate: ds,
      status: occ ? lower(occ.status) : lower(task.status),
      readOnly: true,
    };
  }

  private async requireOwned(userId: string, id: string) {
    const task = await this.prisma.task.findFirst({
      where: { id, userId },
      include: { occurrences: true },
    });
    if (!task) throw new NotFoundException('task_not_found');
    return task;
  }

  private toDto(task: any, from?: Date | null, to?: Date | null) {
    const rec = task.recurrence;
    let occurrences: any[] | undefined;
    if (isRoutine(rec)) {
      const stored = new Map<string, any>(
        (task.occurrences ?? []).map((o: any) => [o.occurrenceDate, o]),
      );
      const mapOcc = (ds: string, o: any) => ({
        occurrenceDate: ds,
        status: o ? lower(o.status) : 'pending',
        doneAt: o?.doneAt ?? undefined,
        dueOverride: o?.dueOverride ?? undefined,
      });
      if (from && to) {
        const anchor = task.due ?? task.createdAt;
        occurrences = expandOccurrences(new Date(anchor), rec, from, to).map((d) => {
          const ds = toDateStr(d);
          return mapOcc(ds, stored.get(ds));
        });
      } else {
        occurrences = (task.occurrences ?? []).map((o: any) =>
          mapOcc(o.occurrenceDate, o),
        );
      }
    }
    return {
      uid: task.id,
      title: task.title,
      due: task.due ?? undefined,
      deadline: task.deadline ?? undefined,
      note: task.note ?? undefined,
      recurrence: rec ?? undefined,
      status: lower(task.status),
      doneAt: task.doneAt ?? undefined,
      ...(occurrences ? { occurrences } : {}),
      updatedAt: task.updatedAt,
    };
  }
}
