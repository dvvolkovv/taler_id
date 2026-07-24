import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerCalendarTools } from './calendar.tools';

describe('calendar tools', () => {
  const calendar: any = {
    findByRange: jest.fn().mockResolvedValue([{ id: 'e1', title: 'Standup' }]),
    findOne: jest.fn().mockResolvedValue({ id: 'e1', title: 'Standup' }),
    create: jest.fn().mockResolvedValue({ id: 'e2' }),
    update: jest.fn().mockResolvedValue({ id: 'e1' }),
    remove: jest.fn().mockResolvedValue({ ok: true }),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  function build() {
    const server = new McpServer({ name: 't', version: '1' });
    registerCalendarTools(server, calendar, 'user-1');
    return server;
  }

  it('registers all five tools', () => {
    const server = build();
    const names = Object.keys((server as any)._registeredTools);
    expect(names.sort()).toEqual([
      'create_calendar_event',
      'delete_calendar_event',
      'get_calendar_event',
      'list_calendar_events',
      'update_calendar_event',
    ]);
  });

  it('list passes userId and range', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['list_calendar_events'];
    const result = await tool.handler({ from: '2026-07-01', to: '2026-07-31' }, {} as any);
    expect(calendar.findByRange).toHaveBeenCalledWith('user-1', '2026-07-01', '2026-07-31');
    expect(JSON.parse(result.content[0].text)).toHaveLength(1);
  });

  it('create maps args to real CalendarService.create signature with reminderAt computed', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['create_calendar_event'];
    const startAt = '2026-07-25T10:00:00.000Z';
    const result = await tool.handler(
      {
        title: 'Team meeting',
        type: 'MEETING',
        startAt,
        endAt: '2026-07-25T11:00:00.000Z',
        description: 'Weekly sync',
        reminder_minutes_before: 15,
      },
      {} as any,
    );

    const expectedReminderAt = new Date(
      new Date(startAt).getTime() - 15 * 60000,
    ).toISOString();

    expect(calendar.create).toHaveBeenCalledWith('user-1', {
      title: 'Team meeting',
      type: 'MEETING',
      startAt,
      endAt: '2026-07-25T11:00:00.000Z',
      description: 'Weekly sync',
      reminderAt: expectedReminderAt,
    });
    expect(JSON.parse(result.content[0].text)).toEqual({ id: 'e2' });
  });

  it('create without reminder_minutes_before omits reminderAt', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['create_calendar_event'];
    await tool.handler(
      { title: 'Quick call', type: 'CALL', startAt: '2026-07-25T09:00:00.000Z' },
      {} as any,
    );

    const callArg = calendar.create.mock.calls[0][1];
    expect(callArg.reminderAt).toBeUndefined();
  });

  it('get_calendar_event returns isError message when findOne throws', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['get_calendar_event'];
    calendar.findOne.mockRejectedValueOnce(new Error('Not found'));
    const result = await tool.handler({ id: 'missing-id' }, {} as any);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/missing-id/);
  });

  it('get_calendar_event returns event JSON on success', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['get_calendar_event'];
    const result = await tool.handler({ id: 'e1' }, {} as any);
    expect(calendar.findOne).toHaveBeenCalledWith('user-1', 'e1');
    expect(JSON.parse(result.content[0].text)).toEqual({ id: 'e1', title: 'Standup' });
  });

  it('update_calendar_event passes partial fields including reminderAt computed', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['update_calendar_event'];
    const startAt = '2026-07-26T14:00:00.000Z';
    await tool.handler(
      { id: 'e1', title: 'Renamed', startAt, reminder_minutes_before: 30 },
      {} as any,
    );
    const expectedReminderAt = new Date(
      new Date(startAt).getTime() - 30 * 60000,
    ).toISOString();
    expect(calendar.update).toHaveBeenCalledWith('user-1', 'e1', {
      title: 'Renamed',
      startAt,
      reminderAt: expectedReminderAt,
    });
  });

  it('update_calendar_event returns isError when update throws', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['update_calendar_event'];
    calendar.update.mockRejectedValueOnce(new Error('Forbidden'));
    const result = await tool.handler({ id: 'bad-id' }, {} as any);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/bad-id/);
  });

  it('delete_calendar_event calls remove and returns success JSON', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['delete_calendar_event'];
    const result = await tool.handler({ id: 'e1' }, {} as any);
    expect(calendar.remove).toHaveBeenCalledWith('user-1', 'e1');
    expect(JSON.parse(result.content[0].text)).toEqual({ ok: true });
  });

  it('delete_calendar_event returns isError when remove throws', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['delete_calendar_event'];
    calendar.remove.mockRejectedValueOnce(new Error('Not found'));
    const result = await tool.handler({ id: 'gone' }, {} as any);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/gone/);
  });
});
