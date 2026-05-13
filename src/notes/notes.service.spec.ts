import { Test } from '@nestjs/testing';
import { NotesService } from './notes.service';
import { PrismaService } from '../prisma/prisma.service';
import { ConflictException } from '@nestjs/common';

describe('NotesService.create', () => {
  let service: NotesService;
  let prisma: { note: { create: jest.Mock; findUnique: jest.Mock } };

  beforeEach(async () => {
    prisma = {
      note: {
        create: jest.fn(),
        findUnique: jest.fn(),
      },
    };
    const mod = await Test.createTestingModule({
      providers: [
        NotesService,
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();
    service = mod.get(NotesService);
  });

  it('without id: generates uuid as before', async () => {
    prisma.note.create.mockResolvedValue({ id: 'generated', userId: 'u1', title: 't', content: 'c' });
    await service.create('u1', { title: 't', content: 'c' });
    expect(prisma.note.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ userId: 'u1', title: 't', content: 'c' }),
    });
    // The data should NOT contain an id (Prisma default kicks in).
    const arg = prisma.note.create.mock.calls[0][0].data;
    expect(arg.id).toBeUndefined();
  });

  it('with id: passes the id through to Prisma', async () => {
    prisma.note.findUnique.mockResolvedValue(null);
    prisma.note.create.mockResolvedValue({ id: 'mine-uuid', userId: 'u1', title: 't', content: 'c' });
    const result = await service.create('u1', { id: 'mine-uuid', title: 't', content: 'c' });
    expect(prisma.note.create).toHaveBeenCalledWith({
      data: expect.objectContaining({ id: 'mine-uuid', userId: 'u1', title: 't', content: 'c' }),
    });
    expect(result.id).toBe('mine-uuid');
  });

  it('with id of an existing note owned by same user: returns existing (idempotent), no double-create', async () => {
    prisma.note.findUnique.mockResolvedValue({ id: 'mine-uuid', userId: 'u1', title: 'orig', content: 'orig' });
    const result = await service.create('u1', { id: 'mine-uuid', title: 'new', content: 'new' });
    expect(prisma.note.create).not.toHaveBeenCalled();
    expect(result).toEqual({ id: 'mine-uuid', userId: 'u1', title: 'orig', content: 'orig' });
  });

  it('with id of a note owned by another user: throws ConflictException', async () => {
    prisma.note.findUnique.mockResolvedValue({ id: 'theirs', userId: 'other', title: 't', content: 'c' });
    await expect(service.create('u1', { id: 'theirs', title: 't', content: 'c' })).rejects.toBeInstanceOf(ConflictException);
    expect(prisma.note.create).not.toHaveBeenCalled();
  });
});

describe('NotesService.update', () => {
  let service: NotesService;
  let prisma: { note: { findUnique: jest.Mock; update: jest.Mock } };

  beforeEach(async () => {
    prisma = {
      note: {
        findUnique: jest.fn(),
        update: jest.fn(),
      },
    };
    const mod = await Test.createTestingModule({
      providers: [
        NotesService,
        { provide: PrismaService, useValue: prisma },
      ],
    }).compile();
    service = mod.get(NotesService);
  });

  it('without expectedUpdatedAt: applies update (LWW, back-compat)', async () => {
    const now = new Date('2026-05-13T10:00:00Z');
    prisma.note.findUnique.mockResolvedValue({ id: 'n1', userId: 'u1', updatedAt: now });
    prisma.note.update.mockResolvedValue({ id: 'n1', userId: 'u1', title: 'new' });
    const out = await service.update('u1', 'n1', { title: 'new' });
    expect(prisma.note.update).toHaveBeenCalledWith({ where: { id: 'n1' }, data: { title: 'new' } });
    expect(out.title).toBe('new');
  });

  it('with matching expectedUpdatedAt: applies update', async () => {
    const now = new Date('2026-05-13T10:00:00Z');
    prisma.note.findUnique.mockResolvedValue({ id: 'n1', userId: 'u1', updatedAt: now });
    prisma.note.update.mockResolvedValue({ id: 'n1', userId: 'u1', title: 'new' });
    const out = await service.update('u1', 'n1', { title: 'new', expectedUpdatedAt: now.toISOString() });
    expect(prisma.note.update).toHaveBeenCalled();
    expect(out.title).toBe('new');
  });

  it('with stale expectedUpdatedAt: throws ConflictException with currentNote in payload', async () => {
    const dbTime = new Date('2026-05-13T10:05:00Z');
    const clientThought = new Date('2026-05-13T10:00:00Z').toISOString();
    const current = { id: 'n1', userId: 'u1', updatedAt: dbTime, title: 'on server' };
    prisma.note.findUnique.mockResolvedValue(current);
    let thrown: any;
    try {
      await service.update('u1', 'n1', { title: 'mine', expectedUpdatedAt: clientThought });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(ConflictException);
    const response = (thrown as ConflictException).getResponse() as any;
    expect(response.currentNote).toEqual(current);
    expect(prisma.note.update).not.toHaveBeenCalled();
  });

  it('with bogus expectedUpdatedAt string: throws ConflictException (treated as stale)', async () => {
    const dbTime = new Date('2026-05-13T10:05:00Z');
    prisma.note.findUnique.mockResolvedValue({ id: 'n1', userId: 'u1', updatedAt: dbTime });
    await expect(
      service.update('u1', 'n1', { title: 'mine', expectedUpdatedAt: 'not-a-date' }),
    ).rejects.toBeInstanceOf(ConflictException);
  });
});
