import { NotFoundException, ForbiddenException } from '@nestjs/common';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerNotesTools } from './notes.tools';

describe('notes tools', () => {
  const notes: any = {
    findAll: jest.fn().mockResolvedValue([{ id: 'n1', title: 'My note', content: 'hello' }]),
    create: jest.fn().mockResolvedValue({ id: 'n2', title: 'New note', content: 'body' }),
    update: jest.fn().mockResolvedValue({ id: 'n1', title: 'Updated', content: 'hello' }),
    remove: jest.fn().mockResolvedValue({ id: 'n1' }),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  function build() {
    const server = new McpServer({ name: 't', version: '1' });
    registerNotesTools(server, notes, 'user-1');
    return server;
  }

  it('registers exactly four tools', () => {
    const server = build();
    const names = Object.keys((server as any)._registeredTools);
    expect(names.sort()).toEqual([
      'create_note',
      'delete_note',
      'list_notes',
      'update_note',
    ]);
  });

  // ─── list_notes ───

  it('list_notes passes userId with default limit 50 and offset 0', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['list_notes'];
    const result = await tool.handler({}, {} as any);
    expect(notes.findAll).toHaveBeenCalledWith('user-1', 50, 0);
    expect(JSON.parse(result.content[0].text)).toHaveLength(1);
  });

  it('list_notes passes custom limit and offset', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['list_notes'];
    await tool.handler({ limit: 10, offset: 20 }, {} as any);
    expect(notes.findAll).toHaveBeenCalledWith('user-1', 10, 20);
  });

  it('list_notes clamps limit to 100 via zod schema', () => {
    const server = build();
    const schema = (server as any)._registeredTools['list_notes'].inputSchema;
    const result = schema.safeParse({ limit: 200 });
    expect(result.success).toBe(false);
  });

  it('list_notes rejects negative offset via zod schema', () => {
    const server = build();
    const schema = (server as any)._registeredTools['list_notes'].inputSchema;
    const result = schema.safeParse({ offset: -1 });
    expect(result.success).toBe(false);
  });

  // ─── create_note ───

  it('create_note maps args to real NotesService.create signature', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['create_note'];
    const result = await tool.handler(
      { title: 'New note', content: 'body' },
      {} as any,
    );
    expect(notes.create).toHaveBeenCalledWith('user-1', {
      title: 'New note',
      content: 'body',
    });
    expect(JSON.parse(result.content[0].text)).toEqual({ id: 'n2', title: 'New note', content: 'body' });
  });

  it('create_note passes optional id and source when provided', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['create_note'];
    await tool.handler(
      { title: 'Titled', content: 'body', id: 'custom-id', source: 'ASSISTANT' },
      {} as any,
    );
    expect(notes.create).toHaveBeenCalledWith('user-1', {
      title: 'Titled',
      content: 'body',
      id: 'custom-id',
      source: 'ASSISTANT',
    });
  });

  it('create_note omits optional fields not provided', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['create_note'];
    await tool.handler({ title: 'T', content: 'C' }, {} as any);
    const callArg = notes.create.mock.calls[0][1];
    expect(callArg.id).toBeUndefined();
    expect(callArg.source).toBeUndefined();
  });

  // ─── update_note ───

  it('update_note maps partial fields to NotesService.update signature', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['update_note'];
    const result = await tool.handler(
      { id: 'n1', title: 'Updated' },
      {} as any,
    );
    expect(notes.update).toHaveBeenCalledWith('user-1', 'n1', { title: 'Updated' });
    expect(JSON.parse(result.content[0].text)).toMatchObject({ id: 'n1' });
  });

  it('update_note returns isError for NotFoundException', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['update_note'];
    notes.update.mockRejectedValueOnce(new NotFoundException('Note not found'));
    const result = await tool.handler({ id: 'bad-id' }, {} as any);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/bad-id/);
  });

  it('update_note returns isError for ForbiddenException', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['update_note'];
    notes.update.mockRejectedValueOnce(new ForbiddenException());
    const result = await tool.handler({ id: 'other-note' }, {} as any);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/other-note/);
  });

  it('update_note re-throws plain Error (e.g. DB down)', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['update_note'];
    notes.update.mockRejectedValueOnce(new Error('db down'));
    await expect(tool.handler({ id: 'n1' }, {} as any)).rejects.toThrow('db down');
  });

  // ─── delete_note ───

  it('delete_note calls remove and returns success JSON', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['delete_note'];
    const result = await tool.handler({ id: 'n1' }, {} as any);
    expect(notes.remove).toHaveBeenCalledWith('user-1', 'n1');
    expect(JSON.parse(result.content[0].text)).toEqual({ id: 'n1' });
  });

  it('delete_note returns isError for NotFoundException', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['delete_note'];
    notes.remove.mockRejectedValueOnce(new NotFoundException('Note not found'));
    const result = await tool.handler({ id: 'gone' }, {} as any);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/gone/);
  });

  it('delete_note returns isError for ForbiddenException', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['delete_note'];
    notes.remove.mockRejectedValueOnce(new ForbiddenException());
    const result = await tool.handler({ id: 'forbidden-note' }, {} as any);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/forbidden-note/);
  });

  it('delete_note re-throws plain Error', async () => {
    const server = build();
    const tool = (server as any)._registeredTools['delete_note'];
    notes.remove.mockRejectedValueOnce(new Error('db down'));
    await expect(tool.handler({ id: 'n1' }, {} as any)).rejects.toThrow('db down');
  });
});
