import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AssistantService {
  private readonly logger = new Logger(AssistantService.name);
  constructor(private prisma: PrismaService) {}

  async saveTranscript(userId: string, messages: { role: string; text: string }[]) {
    return this.prisma.assistantTranscript.create({
      data: { userId, messages },
    });
  }

  async webSearch(query: string): Promise<{ answer: string; citations?: string[] }> {
    const apiKey = process.env.PERPLEXITY_API_KEY;
    if (!apiKey) {
      this.logger.warn('PERPLEXITY_API_KEY not set');
      return { answer: 'Web search is not configured' };
    }
    try {
      const res = await fetch('https://api.perplexity.ai/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'sonar',
          messages: [
            {
              role: 'system',
              content: 'Be concise. Answer in the language of the query. Provide factual information with sources.',
            },
            { role: 'user', content: query },
          ],
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        this.logger.error(`Perplexity API error ${res.status}: ${errText}`);
        return { answer: `Search error: ${res.status}` };
      }
      const data = await res.json() as any;
      const answer = data.choices?.[0]?.message?.content ?? 'No answer';
      const citations = data.citations as string[] | undefined;
      return { answer, citations };
    } catch (e: any) {
      this.logger.error(`Perplexity search failed: ${e.message}`);
      return { answer: 'Search failed' };
    }
  }
}
