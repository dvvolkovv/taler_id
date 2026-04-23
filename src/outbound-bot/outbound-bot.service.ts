import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { VoximplantService } from './voximplant.service';
import { v4 as uuidv4 } from 'uuid';

const CLAUDE_WORKER_URL = process.env.CLAUDE_WORKER_URL || 'http://5.101.115.184:3033';
const BOT_SENDER_ID = 'ai-outbound-bot';

@Injectable()
export class OutboundBotService {
  private readonly logger = new Logger(OutboundBotService.name);
  private emitToUser: ((target: string, event: string, data: any) => void) | null = null;
  // Track active calls for UI (voice-turn session id)
  private activeCalls = new Map<string, { sessionId: string; businessName: string; campaignId: string }>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly vox: VoximplantService,
  ) {}

  registerEmitter(fn: (target: string, event: string, data: any) => void) {
    this.emitToUser = fn;
  }

  // ── Get or create AI_OUTBOUND conversation ──

  async getOrCreateChat(userId: string): Promise<string> {
    const existing = await this.prisma.conversation.findFirst({
      where: { type: 'AI_OUTBOUND', participants: { some: { userId } } },
    });
    if (existing) return existing.id;
    const conv = await this.prisma.conversation.create({
      data: {
        type: 'AI_OUTBOUND', name: 'AI Обзвон', topicsEnabled: true,
        createdById: userId, participants: { create: { userId, role: 'OWNER' } },
      },
    });
    this.logger.log(`Created AI_OUTBOUND conversation ${conv.id}`);
    return conv.id;
  }

  // ── Create task (step 1: name only → bot asks clarifying questions via Claude) ──

  async createTask(userId: string, title: string) {
    const conversationId = await this.getOrCreateChat(userId);
    const topic = await this.prisma.topic.create({
      data: { conversationId, title, icon: '📞', createdBy: userId },
    });
    const campaign = await this.prisma.outboundCampaign.create({
      data: { userId, conversationId, topicId: topic.id, taskText: title, status: 'gathering' },
    });
    await this.updateTopicIcon(topic.id, 'gathering');

    this.logger.log(`Created task: topic=${topic.id} campaign=${campaign.id}`);

    // Return immediately — Claude will think asynchronously
    // Show typing indicator while Claude generates clarifying questions
    if (this.emitToUser) {
      this.emitToUser(conversationId, 'typing', {
        conversationId, topicId: topic.id,
        userId: BOT_SENDER_ID, userName: 'AI Обзвон',
        isTyping: true, typingText: '🤔 Анализирую задачу...',
      });
    }

    const topicId = topic.id;
    const campaignId = campaign.id;

    // Ask Claude asynchronously — result comes via Socket.IO
    this.generateClarifyingQuestions(campaignId, conversationId, topicId, title).catch(e => {
      this.logger.error(`Clarify questions failed: ${(e as Error).message}`);
    });

    return { conversationId, topicId, campaignId };
  }

  // ── Generate clarifying questions asynchronously ──

  private async generateClarifyingQuestions(campaignId: string, conversationId: string, topicId: string, title: string) {
    const clarifyPrompt = `Пользователь хочет обзвонить компании. Задача: "${title}"

Задай 2-3 уточняющих вопроса, чтобы лучше понять:
- Что конкретно нужно (параметры, характеристики, предпочтения)?
- Город или район поиска?
- Бюджет или ограничения по цене?
- Сроки?
- Какие вопросы задать при звонке (наличие, цена, сроки, гарантия и т.д.)?

Также подумай, какие вопросы могут задать на той стороне (в компаниях), и спроси пользователя заранее, чтобы агент мог ответить. Например: модель, год выпуска, VIN, размеры, объём и т.д.

Формат: дружелюбный, короткий. В конце напиши "Когда будете готовы — нажмите Ищи".`;

    try {
      const questions = await this.askClaude(clarifyPrompt, `outbound-gather-${campaignId}`);
      if (this.emitToUser) {
        this.emitToUser(conversationId, 'typing', { conversationId, topicId, userId: BOT_SENDER_ID, isTyping: false });
      }
      await this.postBotMessage(conversationId, topicId, `${questions}\n\n[ACTION:Ищи]`);
    } catch (e) {
      if (this.emitToUser) {
        this.emitToUser(conversationId, 'typing', { conversationId, topicId, userId: BOT_SENDER_ID, isTyping: false });
      }
      this.logger.warn(`Claude clarify failed: ${(e as Error).message}`);
      await this.postBotMessage(conversationId, topicId,
        `Отлично! Задача: **${title}**\n\n` +
        `Расскажите подробнее:\n` +
        `- Что именно нужно?\n` +
        `- В каком городе/районе?\n` +
        `- Есть ограничения по бюджету или срокам?\n` +
        `- Какие вопросы задать компаниям?\n\n` +
        `Когда будете готовы — нажмите **"Ищи"**.\n\n[ACTION:Ищи]`
      );
    }
  }

  // ── Handle user message in AI_OUTBOUND conversation ──

  async handleUserMessage(input: {
    userId: string; conversationId: string; messageText: string;
    topicId?: string; fileUrls?: { url: string; name: string }[];
  }): Promise<void> {
    const { userId, conversationId, messageText, fileUrls } = input;
    this.logger.log(`handleUserMessage: msg="${messageText.slice(0, 50)}" topicId=${input.topicId || 'none'}`);

    try {
      // Find campaign by topicId first, then any active one
      let campaign = input.topicId
        ? await this.prisma.outboundCampaign.findFirst({ where: { topicId: input.topicId } })
        : null;
      if (!campaign) {
        campaign = await this.prisma.outboundCampaign.findFirst({
          where: { conversationId, status: { in: ['gathering', 'pending_approval', 'calling', 'paused'] } },
          orderBy: { createdAt: 'desc' },
        });
      }

      if (!campaign) {
        this.logger.warn(`No active campaign for conv=${conversationId}`);
        return;
      }

      const topicId = campaign.topicId;

      if (campaign.status === 'gathering') {
        await this.handleGathering(campaign, userId, conversationId, topicId, messageText, fileUrls);
      } else if (campaign.status === 'pending_approval') {
        await this.handlePlanFeedback(campaign, userId, conversationId, topicId, messageText);
      } else if (campaign.status === 'calling' || campaign.status === 'paused') {
        await this.handleCallingFeedback(campaign, userId, conversationId, topicId, messageText);
      }
    } catch (e) {
      this.logger.error(`handleUserMessage crashed: ${(e as Error).message}`);
    }
  }

  // ── Handle messages during calling/paused phase ──

  private async handleCallingFeedback(
    campaign: any, userId: string, conversationId: string, topicId: string, text: string,
  ) {
    const lower = text.toLowerCase().trim();

    if (['достаточно', 'стоп', 'хватит', 'stop', 'enough'].includes(lower)) {
      await this.prisma.outboundCampaign.update({ where: { id: campaign.id }, data: { status: 'paused' } });
      await this.updateTopicIcon(topicId, 'paused');
      await this.postBotMessage(conversationId, topicId,
        '⏸ Обзвон приостановлен.\n\n' +
        'Хотите получить сводку по имеющимся результатам или продолжить?\n\n' +
        '[ACTION:Сводка][ACTION:Продолжить обзвон]'
      );
    } else if (['продолжить обзвон', 'продолжить', 'дальше', 'continue'].includes(lower)) {
      if (campaign.status === 'paused') {
        await this.prisma.outboundCampaign.update({ where: { id: campaign.id }, data: { status: 'calling' } });
        await this.updateTopicIcon(topicId, 'calling');
        await this.postBotMessage(conversationId, topicId, '▶️ Продолжаю обзвон...');
        this.resumeCalls(campaign.id, userId, conversationId, topicId).catch(e => {
          this.logger.error(`Resume calls failed: ${e.message}`);
          this.postStatus(conversationId, topicId, `❌ Ошибка: ${e.message}`).catch(() => {});
        });
      } else {
        // Status is 'calling' — clear waiting flag so executeCalls loop continues
        await this.redis.del(`outbound:waiting:${campaign.id}`);
        await this.postBotMessage(conversationId, topicId, '▶️ Продолжаю...');
      }
    } else if (['сводка', 'итоги', 'результаты', 'summary'].includes(lower)) {
      await this.analyzeResults(campaign.id, userId, conversationId, topicId);
    } else if (lower.includes("слушать") || lower === "listen") {
      // Listen-in is not supported with Voximplant. Show last recording if available.
      const lastCall = await this.prisma.outboundCall.findFirst({
        where: { campaignId: campaign.id, status: 'completed', recordingUrl: { not: null } },
        orderBy: { createdAt: 'desc' },
      });
      if (lastCall?.recordingUrl) {
        await this.postBotMessage(conversationId, topicId,
          `🎧 Запись звонка с **${lastCall.businessName}** уже в чате ⬆️`
        );
      } else {
        await this.postBotMessage(conversationId, topicId, '❌ Запись появится после завершения звонка.');
      }
    }
  }

  // ── Resume calls from where we stopped ──

  private async resumeCalls(campaignId: string, userId: string, conversationId: string, topicId: string) {
    const campaign = await this.prisma.outboundCampaign.findUnique({
      where: { id: campaignId },
      include: { calls: true },
    });
    if (!campaign) return;

    const callPlan = campaign.callPlan as any;
    const calls = callPlan?.callPlan || [];
    const completedPhones = new Set(
      campaign.calls.filter(c => ['completed', 'failed', 'no_answer'].includes(c.status)).map(c => c.phoneNumber),
    );

    const remaining = calls.filter((c: any) => !completedPhones.has(c.phone));
    if (remaining.length === 0) {
      await this.postBotMessage(conversationId, topicId, 'Все звонки из плана завершены.');
      await this.analyzeResults(campaignId, userId, conversationId, topicId);
      return;
    }

    await this.postStatus(conversationId, topicId, `📞 Осталось ${remaining.length} звонков...`);

    for (let i = 0; i < remaining.length; i++) {
      // Check if campaign was paused again
      const check = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId } });
      if (!check || check.status !== 'calling') {
        this.logger.log(`[resume] Campaign ${campaignId} status=${check?.status}, stopping`);
        return;
      }

      try {
        const totalDone = campaign.calls.filter(c => ['completed', 'failed', 'no_answer'].includes(c.status)).length;
        await this.executeCall(campaignId, userId, conversationId, topicId, remaining[i], totalDone + i, calls.length);

        // Check if paused during the call
        const afterCall = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId } });
        if (!afterCall || afterCall.status !== 'calling') {
          this.logger.log(`[resume] Campaign paused after call, stopping`);
          return;
        }

        // After each call, ask to continue (if not last)
        if (i < remaining.length - 1) {
          await this.postBotMessage(conversationId, topicId,
            `✅ Завершено. Продолжить?\n\n[ACTION:Продолжить обзвон][ACTION:Достаточно]`
          );
          const decided = await this.waitForCampaignStatus(campaignId, 120000);
          if (decided === 'paused' || decided === 'done') return;
        }
      } catch (e) {
        if ((e as Error).message === 'CAMPAIGN_PAUSED') {
          this.logger.log(`[resume] Campaign paused during call`);
          return;
        }
        await this.postBotMessage(conversationId, topicId, `❌ ${remaining[i].businessName}: ${(e as Error).message}`);
      }
    }
    await this.analyzeResults(campaignId, userId, conversationId, topicId);
  }

  // ── Wait for campaign status change (polling with timeout) ──

  // Waits for user to press Continue or Enough after a call completes.
  // Before calling, set a Redis flag; handleCallingFeedback clears it on "continue".
  private async waitForCampaignStatus(campaignId: string, timeoutMs: number): Promise<string> {
    const key = `outbound:waiting:${campaignId}`;
    await this.redis.setEx(key, Math.ceil(timeoutMs / 1000), '1');
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const campaign = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId } });
      if (!campaign) return 'done';
      if (campaign.status === 'paused') { await this.redis.del(key); return 'paused'; }
      if (campaign.status === 'done') { await this.redis.del(key); return 'done'; }
      // Check if "continue" was pressed (flag cleared)
      const waiting = await this.redis.get(key);
      if (!waiting) return 'calling';
      await new Promise(r => setTimeout(r, 2000));
    }
    await this.redis.del(key);
    return 'calling'; // timeout — auto-continue
  }

  // ── Get active call for a campaign (for REST endpoint) ──
  // Note: listen-in is no longer supported via LiveKit (calls go through Voximplant).

  async getActiveCall(campaignId: string, _userId: string) {
    const active = this.activeCalls.get(campaignId);
    if (!active) return null;
    return { sessionId: active.sessionId, businessName: active.businessName };
  }

  // ── Gathering phase: collect details with AI clarifying questions ──

  private async handleGathering(
    campaign: any, userId: string, conversationId: string,
    topicId: string, text: string, fileUrls?: { url: string; name: string }[],
  ) {
    const lower = text.toLowerCase().trim();
    const startWords = ['ищи', 'начинай', 'поехали', 'старт', 'start', 'search'];
    const isStartCommand = startWords.includes(lower);

    if (lower.length === 0) return;

    if (isStartCommand) {
      const taskLines = (campaign.taskText || '').split('\n').filter((l: string) => l.trim().length > 0);
      if (taskLines.length <= 1) {
        await this.postBotMessage(conversationId, topicId,
          'Сначала опишите задачу подробнее — что нужно, где, какие ограничения. Потом нажмите **"Ищи"**.\n\n[ACTION:Ищи]');
        return;
      }
      await this.prisma.outboundCampaign.update({ where: { id: campaign.id }, data: { status: 'planning' } });
      await this.updateTopicIcon(topicId, 'planning');

      const phases = ['🔍 Ищу...', '🌐 Ищу варианты...', '📊 Анализирую...', '📋 Составляю план...', '🔍 Проверяю контакты...', '🤔 Формирую вопросы...'];
      let phaseIdx = 0;
      const emitTyping = (text: string) => {
        if (this.emitToUser) {
          this.emitToUser(conversationId, 'typing', {
            conversationId, topicId,
            userId: BOT_SENDER_ID, userName: 'AI Обзвон',
            isTyping: true, typingText: text,
          });
        }
      };
      emitTyping(phases[0]);
      const typingInterval = setInterval(() => {
        phaseIdx = (phaseIdx + 1) % phases.length;
        emitTyping(phases[phaseIdx]);
      }, 3000);
      this.planCampaign(campaign.id, userId, conversationId, topicId, campaign.taskText || text, fileUrls).then(() => {
        clearInterval(typingInterval);
        if (this.emitToUser) this.emitToUser(conversationId, 'typing', { conversationId, topicId, userId: BOT_SENDER_ID, isTyping: false });
      }).catch(e => {
        clearInterval(typingInterval);
        if (this.emitToUser) this.emitToUser(conversationId, 'typing', { conversationId, topicId, userId: BOT_SENDER_ID, isTyping: false });
        this.logger.error(`Campaign ${campaign.id} failed: ${e.message}`);
        this.postStatus(conversationId, topicId, `❌ Ошибка: ${e.message}`).catch(() => {});
      });
    } else {
      const updated = (campaign.taskText || '') + '\n' + text;
      await this.prisma.outboundCampaign.update({ where: { id: campaign.id }, data: { taskText: updated } });

      const followUpPrompt = `Пользователь собирается обзвонить компании. Вот что он уже рассказал:

"${updated}"

Оцени, достаточно ли информации для поиска и обзвона. Если нет — задай 1-2 уточняющих вопроса.

Подумай также, какие вопросы могут задать на стороне компании (марка, модель, год, VIN, размеры, цвет, количество и т.д.), и спроси заранее, чтобы агент мог ответить.

Если информации достаточно — скажи кратко что всё понятно и предложи начать поиск.

Формат: короткий, дружелюбный, по делу.`;

      if (this.emitToUser) {
        this.emitToUser(conversationId, 'typing', {
          conversationId, topicId,
          userId: BOT_SENDER_ID, userName: 'AI Обзвон',
          isTyping: true, typingText: '🤔 Думаю...',
        });
      }

      try {
        const followUp = await this.askClaude(followUpPrompt, `outbound-gather-${campaign.id}`);
        if (this.emitToUser) {
          this.emitToUser(conversationId, 'typing', { conversationId, topicId, userId: BOT_SENDER_ID, isTyping: false });
        }
        await this.postBotMessage(conversationId, topicId, `${followUp}\n\n[ACTION:Ищи]`);
      } catch (e) {
        if (this.emitToUser) {
          this.emitToUser(conversationId, 'typing', { conversationId, topicId, userId: BOT_SENDER_ID, isTyping: false });
        }
        this.logger.warn(`Claude follow-up failed: ${(e as Error).message}`);
        await this.postBotMessage(conversationId, topicId,
          'Принято! Если есть ещё детали — пишите. Когда готовы — нажмите **"Ищи"**.\n\n[ACTION:Ищи]');
      }
    }
  }

  // ── Plan feedback: approve or adjust ──

  private async handlePlanFeedback(
    campaign: any, userId: string, conversationId: string, topicId: string, text: string,
  ) {
    const lower = text.toLowerCase().trim();
    const approveWords = ['начинай', 'начать', 'запускай', 'поехали', 'ок', 'ok', 'да', 'start'];

    if (approveWords.some(w => lower.includes(w))) {
      await this.prisma.outboundCampaign.update({ where: { id: campaign.id }, data: { status: 'calling' } });
      await this.updateTopicIcon(topicId, 'calling');
      await this.postStatus(conversationId, topicId, '🚀 Запускаю обзвон...');
      this.executeCalls(campaign.id, userId, conversationId, topicId, campaign.callPlan).catch(e => {
        this.logger.error(`Calls failed: ${e.message}`);
        this.postStatus(conversationId, topicId, `❌ Ошибка: ${e.message}`).catch(() => {});
      });
    } else if (lower.startsWith('промпт:') || lower.startsWith('prompt:')) {
      const newPrompt = text.replace(/^(промпт|prompt):\s*/i, '').trim();
      const plan = campaign.callPlan as any || {};
      plan.agentPrompt = newPrompt;
      await this.prisma.outboundCampaign.update({ where: { id: campaign.id }, data: { callPlan: plan } });
      await this.postBotMessage(conversationId, topicId, `✅ Промпт обновлён:\n\n"${newPrompt}"\n\nНажмите кнопку или напишите **"Начинай"**.\n\n[ACTION:Начинай]`);
    } else {
      if (text.length > 50) {
        const plan = campaign.callPlan as any || {};
        plan.agentPrompt = text;
        await this.prisma.outboundCampaign.update({ where: { id: campaign.id }, data: { callPlan: plan } });
        await this.postBotMessage(conversationId, topicId, `✅ Промпт обновлён:\n\n"${text}"\n\nНажмите кнопку или напишите **"Начинай"**.\n\n[ACTION:Начинай]`);
      } else {
        await this.postStatus(conversationId, topicId, '🤔 Корректирую план...');
        await this.adjustPlan(campaign, userId, conversationId, topicId, text);
      }
    }
  }

  // ── Plan campaign via Claude ──

  private async planCampaign(
    campaignId: string, userId: string, conversationId: string, topicId: string,
    taskText: string, fileUrls?: { url: string; name: string }[],
  ) {
    const prompt = `Ты — AI-ассистент для обзвона бизнесов. Задача:\n\n"${taskText}"\n\nНайди подходящие компании. Для каждой: name, phone (+7XXXXXXXXXX), address, relevance.

КРИТИЧЕСКИ ВАЖНО при поиске:
- Ищи ТОЛЬКО компании, которые РЕАЛЬНО занимаются нужной деятельностью.
- НЕ включай компании с похожими названиями, но другим профилем (парикмахерские, кафе, магазины одежды и т.д.).
- Проверь, что компания действительно продаёт/предоставляет то, что нужно в задаче.
- Лучше найти 3-4 точно подходящих, чем 10 сомнительных.
- Телефоны должны быть реальными, действующими номерами компании.

Составь план обзвона.\n\nВАЖНО: Ответ ТОЛЬКО JSON:\n{"businesses":[{"name":"...","phone":"+7...","address":"...","relevance":"почему эта компания подходит"}],"callPlan":[{"businessName":"...","phone":"+7...","questionsToAsk":["..."]}],"summary":"..."}`;

    const planResponse = await this.askClaude(prompt, `outbound-${campaignId}`);
    this.logger.log(`Claude response: ${planResponse.length} chars`);

    let callPlan: any;
    try {
      let jsonStr = planResponse;
      const cbm = planResponse.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (cbm) jsonStr = cbm[1].trim();
      const jm = jsonStr.match(/\{[\s\S]*\}/);
      callPlan = jm ? JSON.parse(jm[0]) : JSON.parse(jsonStr);
    } catch (e) {
      this.logger.error(`JSON parse failed: ${planResponse.slice(0, 200)}`);
      throw new Error(`Не удалось разобрать план`);
    }

    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    const ownerName = [profile?.firstName, profile?.lastName].filter(Boolean).join(' ') || 'клиент';
    const defaultPrompt = `Я — личный ассистент ${ownerName}. Звоню от его имени. Представлюсь и вежливо задам вопросы из плана. Буду краток и по-деловому.`;

    callPlan.agentPrompt = defaultPrompt;
    await this.prisma.outboundCampaign.update({
      where: { id: campaignId }, data: { callPlan, status: 'pending_approval' },
    });
    await this.updateTopicIcon(topicId, 'pending_approval');

    const planMsg = `📋 **План обзвона:**\n\n${callPlan.summary || ''}\n\n` +
      (callPlan.callPlan || []).map((c: any, i: number) =>
        `${i + 1}. **${c.businessName}** — ${c.phone}\n   Вопросы: ${(c.questionsToAsk || []).join(', ')}`
      ).join('\n\n');

    await this.postBotMessage(conversationId, topicId, planMsg);

    const promptMsg = `🤖 **Промпт агента:**\n\n"${defaultPrompt}"\n\n---\nЕсли хотите изменить — напишите новый промпт.\nНажмите кнопку или напишите **"Начинай"**.\n\n[ACTION:Начинай]`;
    await this.postBotMessage(conversationId, topicId, promptMsg);
  }

  // ── Adjust plan ──

  private async adjustPlan(campaign: any, userId: string, conversationId: string, topicId: string, feedback: string) {
    const prompt = `Текущий план: ${JSON.stringify(campaign.callPlan)}\n\nКомментарий: "${feedback}"\n\nСкорректируй план. ТОЛЬКО JSON:\n{"businesses":[...],"callPlan":[{"businessName":"...","phone":"+7...","questionsToAsk":["..."]}],"summary":"..."}`;

    const response = await this.askClaude(prompt, `outbound-${campaign.id}`);
    let newPlan: any;
    try {
      let jsonStr = response;
      const cbm = response.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (cbm) jsonStr = cbm[1].trim();
      const jm = jsonStr.match(/\{[\s\S]*\}/);
      newPlan = jm ? JSON.parse(jm[0]) : JSON.parse(jsonStr);
    } catch {
      await this.postBotMessage(conversationId, topicId, 'Не удалось скорректировать. Попробуйте уточнить.');
      return;
    }

    await this.prisma.outboundCampaign.update({ where: { id: campaign.id }, data: { callPlan: newPlan } });

    const msg = `📋 **Обновлённый план:**\n\n${newPlan.summary || ''}\n\n` +
      (newPlan.callPlan || []).map((c: any, i: number) => `${i + 1}. **${c.businessName}** — ${c.phone}`).join('\n') +
      `\n\n---\n✅ **"Начинай"** или ещё комментарий.\n\n[ACTION:Начинай]`;
    await this.postBotMessage(conversationId, topicId, msg);
  }

  // ── Execute calls ──

  private async executeCalls(campaignId: string, userId: string, conversationId: string, topicId: string, callPlan: any) {
    const calls = callPlan?.callPlan || [];
    for (let i = 0; i < calls.length; i++) {
      // Check if campaign was paused/stopped before starting next call
      const check = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId } });
      if (!check || check.status !== 'calling') {
        this.logger.log(`[calls] Campaign ${campaignId} status=${check?.status}, stopping`);
        return;
      }

      try {
        await this.executeCall(campaignId, userId, conversationId, topicId, calls[i], i, calls.length);

        // Check if paused during the call
        const afterCall = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId } });
        if (!afterCall || afterCall.status !== 'calling') {
          this.logger.log(`[calls] Campaign paused/stopped after call, exiting loop`);
          return;
        }

        // After each completed call (except last), ask user
        if (i < calls.length - 1) {
          const completedCalls = await this.prisma.outboundCall.count({
            where: { campaignId, status: 'completed' },
          });
          await this.postBotMessage(conversationId, topicId,
            `✅ Завершено ${completedCalls} из ${calls.length} звонков.\n\n` +
            `Продолжить или достаточно?\n\n[ACTION:Продолжить обзвон][ACTION:Достаточно]`
          );
          const decided = await this.waitForCampaignStatus(campaignId, 120000);
          if (decided === 'paused' || decided === 'done') return;
        }
      } catch (e) {
        if ((e as Error).message === 'CAMPAIGN_PAUSED') {
          this.logger.log(`[calls] Campaign paused during call ${i}`);
          return;
        }
        await this.postBotMessage(conversationId, topicId, `❌ ${calls[i].businessName}: ${(e as Error).message}`);
      }
    }
    await this.analyzeResults(campaignId, userId, conversationId, topicId);
  }

  private async executeCall(
    campaignId: string, userId: string, conversationId: string, topicId: string,
    spec: { businessName: string; phone: string; questionsToAsk: string[] }, idx: number, total: number,
  ) {
    const sessionId = `outbound-${uuidv4()}`;
    const call = await this.prisma.outboundCall.create({
      data: { campaignId, roomName: sessionId, businessName: spec.businessName, phoneNumber: spec.phone, status: 'dialing', startedAt: new Date() },
    });

    const campaign = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId } });
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    const ownerName = [profile?.firstName, profile?.lastName].filter(Boolean).join(' ') || 'клиент';
    const agentPrompt = (campaign?.callPlan as any)?.agentPrompt || '';

    const result = await this.vox.startOutboundCall({
      phone: spec.phone,
      sessionId,
      metadata: {
        businessName: spec.businessName,
        phoneNumber: spec.phone,
        questionsToAsk: spec.questionsToAsk,
        taskContext: campaign?.taskText || '',
        campaignId,
        callId: call.id,
        ownerName,
        agentPrompt,
      },
    });

    await this.prisma.outboundCall.update({
      where: { id: call.id },
      data: {
        status: 'in_progress',
        // Store Voximplant session id in transcript JSON for later recording lookup
        transcript: { voxCallSessionHistoryId: result.callSessionHistoryId } as any,
      },
    });

    this.activeCalls.set(campaignId, { sessionId, businessName: spec.businessName, campaignId });
    await this.postBotMessage(conversationId, topicId,
      `📞 Звоню (${idx + 1}/${total}): **${spec.businessName}**...`
    );

    // Wait for voice-turn callback (max 7 min), check campaign pause
    const start = Date.now();
    while (Date.now() - start < 420000) {
      const u = await this.prisma.outboundCall.findUnique({ where: { id: call.id } });
      if (u && ['completed', 'failed', 'no_answer'].includes(u.status)) break;

      const camp = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId } });
      if (camp && camp.status === 'paused') {
        this.logger.log(`[call] Campaign paused during call ${call.id}`);
        this.activeCalls.delete(campaignId);
        await this.prisma.outboundCall.update({ where: { id: call.id }, data: { status: 'failed', endedAt: new Date() } });
        throw new Error('CAMPAIGN_PAUSED');
      }

      await new Promise(r => setTimeout(r, 3000));
    }

    this.activeCalls.delete(campaignId);

    const final_ = await this.prisma.outboundCall.findUnique({ where: { id: call.id } });
    if (!final_ || !['completed', 'failed', 'no_answer'].includes(final_.status)) {
      await this.postStatus(conversationId, topicId, `⏳ ${spec.businessName}: ${final_?.status || 'timeout'}`);
    }
  }

  // ── Analyze results ──

  private async analyzeResults(campaignId: string, userId: string, conversationId: string, topicId: string) {
    await this.postStatus(conversationId, topicId, '📊 Анализирую результаты...');
    const campaign = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId }, include: { calls: true } });
    if (!campaign) return;

    const completed = campaign.calls.filter(c => c.status === 'completed');
    if (completed.length === 0) {
      await this.postBotMessage(conversationId, topicId, '⚠️ Ни один звонок не завершён успешно.');
      await this.prisma.outboundCampaign.update({ where: { id: campaignId }, data: { status: 'done' } });
      await this.updateTopicIcon(topicId, 'done');
      return;
    }

    const transcripts = completed.map(c => `--- ${c.businessName} (${c.phoneNumber}) ---\n${c.summary || ''}`).join('\n\n');
    const analysis = await this.askClaude(
      `Проанализируй результаты обзвона по задаче: "${campaign.taskText}"\n\n` +
      `Результаты звонков:\n${transcripts}\n\n` +
      `Напиши ЧЕЛОВЕЧЕСКИМ ТЕКСТОМ (НЕ JSON) краткую сводку:\n` +
      `1. Лучший вариант и почему\n` +
      `2. Сравнение цен и сроков\n` +
      `3. Контакты для связи\n` +
      `4. Рекомендация: что делать дальше`,
      `outbound-${campaignId}`,
    );

    await this.prisma.outboundCampaign.update({ where: { id: campaignId }, data: { status: 'done', summary: { text: analysis } } });
    await this.updateTopicIcon(topicId, 'done');
    await this.postBotMessage(conversationId, topicId, `📊 **Сводка:**\n\n${analysis || 'Нет данных.'}`);
  }

  // ── Call callback from voice-turn service ──

  async handleCallCallback(data: {
    callId: string; campaignId: string; transcript: any; summary: string;
    durationSec: number; status: string; recordingUrl?: string;
  }) {
    const existing = await this.prisma.outboundCall.findUnique({ where: { id: data.callId } });
    const voxId = (existing?.transcript as any)?.voxCallSessionHistoryId;

    const call = await this.prisma.outboundCall.update({
      where: { id: data.callId },
      data: {
        transcript: { ...(data.transcript || {}), voxCallSessionHistoryId: voxId },
        summary: data.summary,
        durationSec: data.durationSec,
        status: data.status || 'completed',
        recordingUrl: data.recordingUrl,
        endedAt: new Date(),
      },
    });
    this.logger.log(`Call ${data.callId} completed: ${data.durationSec}s`);

    // Fetch recording from Voximplant (async, don't block)
    if (voxId) {
      this.fetchVoxRecording(call.id, voxId, data.campaignId).catch(e => {
        this.logger.warn(`[recording] Failed to fetch: ${(e as Error).message}`);
      });
    }

    const goalAchieved = data.summary && /GOAL_ACHIEVED:\s*да/i.test(data.summary);
    const cleanSummary = (data.summary || '').replace(/\n?GOAL_ACHIEVED:\s*(да|нет).*/i, '').trim();

    const campaign = await this.prisma.outboundCampaign.findUnique({ where: { id: data.campaignId } });
    if (campaign) {
      if (goalAchieved) {
        await this.postBotMessage(
          campaign.conversationId,
          campaign.topicId,
          `🎉 **${call.businessName}** — цель достигнута! (${data.durationSec}с)\n\n${cleanSummary}`,
        );
        await this.prisma.outboundCampaign.update({ where: { id: data.campaignId }, data: { status: 'paused' } });
        await this.updateTopicIcon(campaign.topicId, 'paused');
        await this.postBotMessage(
          campaign.conversationId,
          campaign.topicId,
          '✅ **Цель достигнута!** Продолжить обзвон или достаточно?\n\n[ACTION:Продолжить обзвон][ACTION:Сводка]',
        );
      } else {
        await this.postBotMessage(
          campaign.conversationId,
          campaign.topicId,
          `✅ **${call.businessName}** (${data.durationSec}с)\n\n${cleanSummary}`,
        );
      }
    }
  }

  // ── Fetch recording URL from Voximplant (polled after call ends) ──

  private async fetchVoxRecording(callId: string, voxCallSessionHistoryId: number, campaignId: string) {
    // Voximplant needs ~10-30s to finalize the recording after call ends
    for (let attempt = 0; attempt < 30; attempt++) {
      await new Promise(r => setTimeout(r, 5000));
      const url = await this.vox.getCallRecording(voxCallSessionHistoryId);
      if (url) {
        await this.prisma.outboundCall.update({ where: { id: callId }, data: { recordingUrl: url } });
        const call = await this.prisma.outboundCall.findUnique({ where: { id: callId }, include: { campaign: true } });
        if (call?.campaign) {
          await this.postBotMessage(
            call.campaign.conversationId,
            call.campaign.topicId,
            `🎧 **Запись: ${call.businessName}**\n[▶ Слушать / Скачать](${url})`,
          );
        }
        this.logger.log(`[recording] Got URL for call ${callId}: ${url}`);
        return;
      }
    }
    this.logger.warn(`[recording] No URL found after 150s for call ${callId}`);
  }

  // ── Topic icon by campaign status ──

  private async updateTopicIcon(topicId: string, status: string) {
    const icons: Record<string, string> = {
      gathering: '📝', planning: '🔍', pending_approval: '📋',
      calling: '📞', paused: '⏸', analyzing: '📊', done: '✅', failed: '❌',
    };
    const icon = icons[status] || '📞';
    try {
      const topic = await this.prisma.topic.update({ where: { id: topicId }, data: { icon } });
      // Notify mobile so topics list refreshes immediately
      if (this.emitToUser && topic.conversationId) {
        this.emitToUser(topic.conversationId, 'topic_updated', { topicId, icon, status });
      }
    } catch {}
  }

  // ── Helpers ──

  private async postBotMessage(conversationId: string, topicId: string, content: string) {
    const msg = await this.prisma.message.create({
      data: { conversationId, topicId, senderId: BOT_SENDER_ID, content, isSystem: false },
    });
    this.emitMsg(conversationId, msg);
  }

  private async postStatus(conversationId: string, topicId: string, content: string) {
    const msg = await this.prisma.message.create({
      data: { conversationId, topicId, senderId: BOT_SENDER_ID, content, isSystem: true },
    });
    this.emitMsg(conversationId, msg);
    return msg;
  }

  private emitMsg(conversationId: string, msg: any) {
    if (this.emitToUser) this.emitToUser(conversationId, 'new_message', { ...msg, senderName: 'AI Обзвон', reactions: [] });
  }

  private emit(userId: string, event: string, data: any) {
    if (this.emitToUser) this.emitToUser(`user:${userId}`, event, data);
  }

  private async askClaude(message: string, sessionId: string): Promise<string> {
    const resp = await fetch(`${CLAUDE_WORKER_URL}/chat`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, sessionId }),
    });
    if (!resp.ok) throw new Error(`Claude Worker returned ${resp.status}`);

    const reader = resp.body?.getReader();
    if (!reader) throw new Error('No response body');
    const decoder = new TextDecoder();
    let result = '', buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop() || '';
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          const ev = JSON.parse(line.slice(6).trim());
          if (ev.type === 'delta' && ev.text) result += ev.text;
          else if (ev.type === 'result' && ev.text && ev.text.length > result.length) result = ev.text;
        } catch {}
      }
    }
    return result;
  }

  async getCampaigns(userId: string, conversationId: string) {
    return this.prisma.outboundCampaign.findMany({
      where: { userId, conversationId }, include: { calls: { orderBy: { createdAt: 'asc' } } }, orderBy: { createdAt: 'desc' },
    });
  }

  async getCampaign(campaignId: string) {
    return this.prisma.outboundCampaign.findUnique({ where: { id: campaignId }, include: { calls: { orderBy: { createdAt: 'asc' } } } });
  }
}
