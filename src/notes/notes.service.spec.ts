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
