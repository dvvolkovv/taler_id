import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { GatingService } from '../billing/services/gating.service';
import { LedgerService } from '../billing/services/ledger.service';
import { PricingService } from '../billing/services/pricing.service';
import { FEATURE_KEYS } from '../billing/constants/feature-keys';

@Injectable()
export class AssistantService {
  private readonly logger = new Logger(AssistantService.name);
  constructor(
    private prisma: PrismaService,
    private readonly gating: GatingService,
    private readonly ledger: LedgerService,
    private readonly pricing: PricingService,
  ) {}

  async saveTranscript(userId: string, messages: { role: string; text: string }[]) {
    return this.prisma.assistantTranscript.create({
      data: { userId, messages },
    });
  }

  async webSearch(userId: string, query: string): Promise<{ answer: string; citations?: string[] }> {
    // Billing pre-check: feature toggle + minReserve balance. Throws
    // FeatureDisabledException / InsufficientFundsException for the
    // caller (controller) to map to structured tool-call errors.
    const session = await this.gating.startSession(userId, FEATURE_KEYS.WEB_SEARCH);

    // Exact cost for 1 request; debit up-front so the refund path is
    // well-defined on Perplexity failure.
    const cost = await this.pricing.calculatePlanckCost(FEATURE_KEYS.WEB_SEARCH, 1);
    let tx: { id: string };
    try {
      tx = await this.ledger.debit(userId, cost, 'SPEND', {
        featureKey: FEATURE_KEYS.WEB_SEARCH,
        sessionId: session.id,
        metadata: { query: query.slice(0, 200) } as Prisma.JsonObject,
      });
    } catch (err) {
      // InsufficientFunds at the debit point → also end session so cron doesn't dangle.
      await this.gating.endSession(session.id, 'failed').catch(() => {});
      throw err;
    }

    try {
      const apiKey = process.env.PERPLEXITY_API_KEY;
      if (!apiKey) {
        this.logger.warn('PERPLEXITY_API_KEY not set');
        // Treat missing configuration as a service error: refund and rethrow
        // rather than silently charging for a non-call.
        throw new Error('PERPLEXITY_API_KEY not configured');
      }
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
        throw new Error(`Perplexity ${res.status}: ${errText.slice(0, 200)}`);
      }
      const data = await res.json() as any;
      const answer = data.choices?.[0]?.message?.content ?? 'No answer';
      const citations = data.citations as string[] | undefined;
      const result = { answer, citations };
      await this.gating.endSession(session.id, 'completed');
      return result;
    } catch (err) {
      // Network / 5xx / Perplexity error: refund + mark session failed.
      this.logger.error(`Perplexity search failed: ${(err as Error).message}`);
      await this.ledger.refund(tx.id, `web_search error: ${String(err).slice(0, 200)}`).catch(() => {});
      await this.gating.endSession(session.id, 'failed').catch(() => {});
      throw err;
    }
  }
}
