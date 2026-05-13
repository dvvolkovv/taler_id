import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class NotesService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(userId: string, limit = 50, offset = 0) {
    return this.prisma.note.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    });
  }

  async findOne(userId: string, id: string) {
    const note = await this.prisma.note.findUnique({ where: { id } });
    if (!note) throw new NotFoundException('Note not found');
    if (note.userId !== userId) throw new ForbiddenException();
    return note;
  }

  async create(
    userId: string,
    data: { id?: string; title: string; content: string; source?: string },
  ) {
    if (data.id) {
      const existing = await this.prisma.note.findUnique({ where: { id: data.id } });
      if (existing) {
        if (existing.userId !== userId) {
          throw new ConflictException('Note id already used by another account');
        }
        return existing;
      }
    }
    return this.prisma.note.create({
      data: {
        ...(data.id ? { id: data.id } : {}),
        userId,
        title: data.title,
        content: data.content,
        source: (data.source as any) || 'MANUAL',
      },
    });
  }

  async update(userId: string, id: string, data: { title?: string; content?: string }) {
    const note = await this.prisma.note.findUnique({ where: { id } });
    if (!note) throw new NotFoundException('Note not found');
    if (note.userId !== userId) throw new ForbiddenException();
    return this.prisma.note.update({ where: { id }, data });
  }

  async remove(userId: string, id: string) {
    const note = await this.prisma.note.findUnique({ where: { id } });
    if (!note) throw new NotFoundException('Note not found');
    if (note.userId !== userId) throw new ForbiddenException();
    return this.prisma.note.delete({ where: { id } });
  }
}
