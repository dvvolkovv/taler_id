import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AssistantService {
  constructor(private prisma: PrismaService) {}

  async saveTranscript(userId: string, messages: { role: string; text: string }[]) {
    return this.prisma.assistantTranscript.create({
      data: { userId, messages },
    });
  }
}
