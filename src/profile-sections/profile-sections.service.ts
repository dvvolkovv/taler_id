import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SectionType, SectionVisibility, UpsertSectionDto } from './dto/upsert-section.dto';

@Injectable()
export class ProfileSectionsService {
  private readonly logger = new Logger(ProfileSectionsService.name);

  constructor(private readonly prisma: PrismaService) {}

  async getMySections(userId: string) {
    return this.prisma.profileSection.findMany({
      where: { userId },
      orderBy: { type: 'asc' },
    });
  }

  async upsertSection(userId: string, dto: UpsertSectionDto) {
    const section = await this.prisma.profileSection.upsert({
      where: { userId_type: { userId, type: dto.type } },
      update: {
        content: dto.content as any,
        ...(dto.visibility ? { visibility: dto.visibility } : {}),
      },
      create: {
        userId,
        type: dto.type,
        content: dto.content as any,
        visibility: dto.visibility || SectionVisibility.PRIVATE,
      },
    });

    // Generate embedding asynchronously
    this.generateEmbedding(section.id, dto.content).catch((e) =>
      this.logger.error('Embedding generation failed:', e),
    );

    return section;
  }

  async deleteSection(userId: string, type: SectionType) {
    await this.prisma.profileSection.deleteMany({
      where: { userId, type },
    });
    return { success: true };
  }

  async updateVisibility(userId: string, type: SectionType, visibility: SectionVisibility) {
    return this.prisma.profileSection.update({
      where: { userId_type: { userId, type } },
      data: { visibility },
    });
  }

  async getUserSections(viewerId: string, targetUserId: string) {
    const sections = await this.prisma.profileSection.findMany({
      where: { userId: targetUserId },
      orderBy: { type: 'asc' },
    });

    // Check if viewer is a contact of the target user
    const isContact = await this.isContact(viewerId, targetUserId);

    return sections.filter((s) => {
      if (s.visibility === 'PUBLIC') return true;
      if (s.visibility === 'CONTACTS' && isContact) return true;
      return false;
    });
  }

  private async isContact(userA: string, userB: string): Promise<boolean> {
    // Two users are contacts if they have a DIRECT conversation together
    const conv = await this.prisma.conversationParticipant.findFirst({
      where: {
        userId: userA,
        conversation: {
          type: 'DIRECT',
          participants: { some: { userId: userB } },
        },
      },
    });
    return !!conv;
  }

  private async generateEmbedding(
    sectionId: string,
    content: { items: string[]; freeText?: string },
  ) {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) return;

    const textParts = [...(content.items || [])];
    if (content.freeText) textParts.push(content.freeText);
    const text = textParts.join('. ');
    if (!text.trim()) return;

    try {
      const response = await fetch('https://api.openai.com/v1/embeddings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: 'text-embedding-3-small',
          input: text,
        }),
      });

      const data = await response.json();
      const embedding = data?.data?.[0]?.embedding;
      if (!embedding) return;

      const vectorStr = `[${embedding.join(',')}]`;
      await this.prisma.$executeRawUnsafe(
        `UPDATE "ProfileSection" SET "embedding" = $1::vector WHERE "id" = $2`,
        vectorStr,
        sectionId,
      );
      this.logger.log(`Embedding saved for section ${sectionId}`);
    } catch (e) {
      this.logger.error('OpenAI embedding error:', e);
    }
  }
}
