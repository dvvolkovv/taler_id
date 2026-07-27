import { ForbiddenException } from '@nestjs/common';
import { NotesService } from './notes.service';

// Regression cover for the 2026-07-27 audit finding: update() spread the whole
// request body into prisma.note.update(), so a caller could set columns the
// route never meant to expose.
describe('NotesService.update field whitelist', () => {
  let service: NotesService;
  let prisma: any;

  const NOTE = {
    id: 'note-1',
    userId: 'owner',
    title: 'Original',
    content: 'Body',
    updatedAt: new Date('2026-07-27T10:00:00.000Z'),
  };

  beforeEach(() => {
    prisma = {
      note: {
        findUnique: jest.fn().mockResolvedValue(NOTE),
        update: jest.fn().mockResolvedValue(NOTE),
      },
    };
    service = new NotesService(prisma);
  });

  it('writes only title and content', async () => {
    await service.update('owner', 'note-1', {
      title: 'New title',
      content: 'New body',
    });

    expect(prisma.note.update).toHaveBeenCalledWith({
      where: { id: 'note-1' },
      data: { title: 'New title', content: 'New body' },
    });
  });

  it('ignores an attempt to reassign the note to another account', async () => {
    await service.update('owner', 'note-1', {
      title: 'New title',
      // Not part of the DTO, but the MCP tool path reaches the service directly.
      userId: 'attacker',
    } as any);

    expect(prisma.note.update).toHaveBeenCalledWith({
      where: { id: 'note-1' },
      data: { title: 'New title' },
    });
  });

  it('ignores attempts to rewrite id and timestamps', async () => {
    await service.update('owner', 'note-1', {
      content: 'New body',
      id: 'other-id',
      createdAt: new Date(0),
      updatedAt: new Date(0),
    } as any);

    expect(prisma.note.update).toHaveBeenCalledWith({
      where: { id: 'note-1' },
      data: { content: 'New body' },
    });
  });

  it('omits fields the caller did not send', async () => {
    await service.update('owner', 'note-1', { title: 'Only title' });

    expect(prisma.note.update).toHaveBeenCalledWith({
      where: { id: 'note-1' },
      data: { title: 'Only title' },
    });
  });

  it('still refuses to touch someone else note', async () => {
    await expect(
      service.update('intruder', 'note-1', { title: 'x' }),
    ).rejects.toThrow(ForbiddenException);

    expect(prisma.note.update).not.toHaveBeenCalled();
  });
});
