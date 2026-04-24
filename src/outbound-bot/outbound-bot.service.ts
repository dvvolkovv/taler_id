import { Inject, Injectable, Logger, forwardRef } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { SipService } from './sip.service';
import { AgentDispatchClient, RoomServiceClient, AccessToken } from 'livekit-server-sdk';
import { v4 as uuidv4 } from 'uuid';
import { GatingService } from '../billing/services/gating.service';
import { MeteringService } from '../billing/services/metering.service';
import { FEATURE_KEYS } from '../billing/constants/feature-keys';
import { InsufficientFundsException } from '../billing/exceptions/insufficient-funds.exception';
import { FeatureDisabledException } from '../billing/exceptions/feature-disabled.exception';

const CLAUDE_WORKER_URL = process.env.CLAUDE_WORKER_URL || 'http://5.101.115.184:3033';
const LK_HOST = process.env.LIVEKIT_HOST || 'http://localhost:7880';
const LK_API_KEY = process.env.LIVEKIT_API_KEY || 'lkdevkey';
const LK_API_SECRET = process.env.LIVEKIT_API_SECRET || 'lkSecret2024TalerID';
const LK_WS_URL = process.env.LIVEKIT_WS_URL || 'wss://staging.id.taler.tirol/livekit/';
const OUTBOUND_AGENT_NAME = 'outbound-call-agent';
const BACKEND_URL = process.env.BACKEND_URL || 'https://staging.id.taler.tirol';
const AI_AGENT_URL = process.env.AI_AGENT_URL || 'http://localhost:3100';
const BOT_SENDER_ID = 'ai-outbound-bot';

@Injectable()
export class OutboundBotService {
  private readonly logger = new Logger(OutboundBotService.name);
  private readonly rooms = new RoomServiceClient(LK_HOST, LK_API_KEY, LK_API_SECRET);
  private readonly dispatcher = new AgentDispatchClient(LK_HOST, LK_API_KEY, LK_API_SECRET);
  private emitToUser: ((target: string, event: string, data: any) => void) | null = null;
  // Track active call rooms for listen-in
  private activeCallRooms = new Map<string, { roomName: string; businessName: string; campaignId: string }>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly sip: SipService,
    // forwardRef mirrors the cycle declared in OutboundBotModule — BillingModule
    // imports MessengerModule which imports OutboundBotModule.
    @Inject(forwardRef(() => GatingService))
    private readonly gating: GatingService,
    @Inject(forwardRef(() => MeteringService))
    private readonly metering: MeteringService,
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
      // User wants to listen in — handled via REST endpoint GET /campaigns/:id/listen
      const activeRoom = this.activeCallRooms.get(campaign.id);
      if (activeRoom) {
        await this.postBotMessage(conversationId, topicId,
          `🎧 Подключение к звонку с **${activeRoom.businessName}**...`
        );
        // Emit special event for mobile to connect
        if (this.emitToUser) {
          const token = await this.generateListenToken(userId, activeRoom.roomName);
          this.emitToUser(conversationId, 'outbound_listen', {
            roomName: activeRoom.roomName,
            businessName: activeRoom.businessName,
            token,
            wsUrl: LK_WS_URL,
          });
        }
      } else {
        // No active call — show last recording if available
        const lastCall = await this.prisma.outboundCall.findFirst({
          where: { campaignId: campaign.id, status: 'completed', recordingUrl: { not: null } },
          orderBy: { createdAt: 'desc' },
        });
        if (lastCall?.recordingUrl) {
          // Recording was already auto-posted by stopRecorderAndGetUrl
          await this.postBotMessage(conversationId, topicId,
            `🎧 Запись звонка с **${lastCall.businessName}** уже в чате ⬆️`
          );

        } else {
          await this.postBotMessage(conversationId, topicId, '❌ Сейчас нет активного звонка и записи.');
        }
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
        if ((e as Error).message === 'BILLING_INSUFFICIENT') {
          await this.prisma.outboundCampaign.update({
            where: { id: campaignId }, data: { status: 'paused' },
          });
          await this.updateTopicIcon(topicId, 'paused');
          await this.postBotMessage(conversationId, topicId,
            '⏸ Кампания приостановлена — недостаточно средств на балансе. Пополните баланс и нажмите "Продолжить".\n\n[ACTION:Продолжить обзвон]',
          );
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

  // ── Generate listen-in token for user ──

  async generateListenToken(userId: string, roomName: string): Promise<string> {
    const token = new AccessToken(LK_API_KEY, LK_API_SECRET, {
      identity: `listener-${userId}`,
      name: 'Слушатель',
    });
    token.addGrant({
      room: roomName,
      roomJoin: true,
      canPublish: false,  // listen only
      canSubscribe: true,
    });
    return await token.toJwt();
  }

  // ── Get active call for a campaign (for REST endpoint) ──

  async getActiveCall(campaignId: string, userId: string) {
    const activeRoom = this.activeCallRooms.get(campaignId);
    if (!activeRoom) return null;
    const token = await this.generateListenToken(userId, activeRoom.roomName);
    return { roomName: activeRoom.roomName, businessName: activeRoom.businessName, token, wsUrl: LK_WS_URL };
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
        if ((e as Error).message === 'BILLING_INSUFFICIENT') {
          // Pause the campaign — the owner needs to top up before we can
          // spend any more of their balance. Post a system message so the
          // user sees why things stopped.
          await this.prisma.outboundCampaign.update({
            where: { id: campaignId }, data: { status: 'paused' },
          });
          await this.updateTopicIcon(topicId, 'paused');
          await this.postBotMessage(conversationId, topicId,
            '⏸ Кампания приостановлена — недостаточно средств на балансе. Пополните баланс и нажмите "Продолжить".\n\n[ACTION:Продолжить обзвон]',
          );
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
    const roomName = `outbound-${uuidv4()}`;
    const call = await this.prisma.outboundCall.create({
      data: { campaignId, roomName, businessName: spec.businessName, phoneNumber: spec.phone, status: 'dialing', startedAt: new Date() },
    });

    // Billing gate (Task 15): campaign owner pays per-minute for outbound calls.
    // Check balance BEFORE allocating a LiveKit room or dispatching the agent —
    // if the user can't afford the minReserve, skip cleanly and let the caller
    // (executeCalls / resumeCalls) pause the campaign.
    let billingSessionId: string;
    try {
      const session = await this.gating.startSession(
        userId,
        FEATURE_KEYS.OUTBOUND_CALL,
        call.id,
      );
      billingSessionId = session.id;
    } catch (err) {
      if (
        err instanceof InsufficientFundsException ||
        err instanceof FeatureDisabledException
      ) {
        // Roll back the outbound_call row we just created so we don't leave
        // a phantom "dialing" record hanging around for a call that never left.
        await this.prisma.outboundCall
          .update({ where: { id: call.id }, data: { status: 'failed', endedAt: new Date() } })
          .catch(() => {});
        this.logger.warn(
          `[billing] outbound call skipped for user=${userId} campaign=${campaignId}: ${err.message}`,
        );
        throw new Error('BILLING_INSUFFICIENT');
      }
      throw err;
    }

    await this.rooms.createRoom({ name: roomName, emptyTimeout: 300, maxParticipants: 5 });
    const campaign = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId } });
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    const ownerName = [profile?.firstName, profile?.lastName].filter(Boolean).join(' ') || 'клиент';
    const agentPrompt = (campaign?.callPlan as any)?.agentPrompt || '';
    const metadata = JSON.stringify({
      businessName: spec.businessName, phoneNumber: spec.phone, questionsToAsk: spec.questionsToAsk,
      taskContext: campaign?.taskText || '', campaignId, callId: call.id,
      ownerName, agentPrompt,
      // Agent echoes this back in the callback so MeteringService can book
      // the authoritative debit based on actual duration.
      billingSessionId,
      callbackUrl: `${BACKEND_URL}/outbound-bot/call-callback`,
    });

    try {
      await this.dispatcher.createDispatch(roomName, OUTBOUND_AGENT_NAME, { metadata });
    } catch (e) {
      // Release the billing session we just opened — otherwise the cron would
      // keep draining the owner's wallet for a call that never actually dispatched.
      await this.gating.endSession(billingSessionId, 'failed').catch(() => {});
      throw e;
    }

    if (this.sip.isConfigured()) await this.sip.dialOutbound(roomName, spec.phone);
    else this.logger.warn(`SIP not configured — agent in room ${roomName}`);

    // Track active call for listen-in
    this.activeCallRooms.set(campaignId, { roomName, businessName: spec.businessName, campaignId });

    // Start recorder after SIP connects
    setTimeout(async () => {
      try {
        await fetch(`${AI_AGENT_URL}/record`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ roomName, withAi: false }),
        });
        this.logger.log(`[Recorder] started for room ${roomName}`);
      } catch (e) {
        this.logger.warn(`[Recorder] failed to start: ${(e as Error).message}`);
      }
    }, 5000);

    await this.prisma.outboundCall.update({ where: { id: call.id }, data: { status: 'in_progress' } });
    await this.postBotMessage(conversationId, topicId,
      `📞 Звоню (${idx + 1}/${total}): **${spec.businessName}**...\n\n[ACTION:🎧 Слушать]`
    );

    // Wait for callback (max 7 min), but also check if campaign was paused
    const start = Date.now();
    while (Date.now() - start < 420000) {
      const u = await this.prisma.outboundCall.findUnique({ where: { id: call.id } });
      if (u && ['completed', 'failed', 'no_answer'].includes(u.status)) break;

      // Check if campaign was paused by user
      const camp = await this.prisma.outboundCampaign.findUnique({ where: { id: campaignId } });
      if (camp && camp.status === 'paused') {
        this.logger.log(`[call] Campaign paused during call ${call.id}, stopping call`);
        // Clean up: remove from active rooms
        this.activeCallRooms.delete(campaignId);
        // Mark call as failed
        await this.prisma.outboundCall.update({ where: { id: call.id }, data: { status: 'failed', endedAt: new Date() } });
        // Delete room to end SIP
        try { await this.rooms.deleteRoom(roomName); } catch {}
        throw new Error('CAMPAIGN_PAUSED');
      }

      await new Promise(r => setTimeout(r, 3000));
    }

    // Clean up active room tracking
    this.activeCallRooms.delete(campaignId);

    // Don't post result here — handleCallCallback already posts it
    // (including goal detection and recording link later)
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

  // ── Call callback from Python agent ──

  async handleCallCallback(data: {
    callId: string; campaignId: string; transcript: any; summary: string;
    durationSec: number; status: string; recordingUrl?: string;
  }) {
    const call = await this.prisma.outboundCall.update({
      where: { id: data.callId },
      data: { transcript: data.transcript, summary: data.summary, durationSec: data.durationSec, status: data.status || 'completed', recordingUrl: data.recordingUrl, endedAt: new Date() },
    });
    this.logger.log(`Call ${data.callId} completed: ${data.durationSec}s`);

    // Stop recorder and get recording URL (async, don't block)
    if (call.roomName) {
      this.stopRecorderAndGetUrl(call.id, call.roomName, data.campaignId).catch(e => {
        this.logger.warn(`[recorder] Failed to stop/get URL: ${(e as Error).message}`);
      });
    }

    // Check if goal was achieved (booking confirmed, etc.)
    const goalAchieved = data.summary && /GOAL_ACHIEVED:\s*да/i.test(data.summary);
    // Clean up GOAL_ACHIEVED line from displayed summary
    const cleanSummary = (data.summary || '').replace(/\n?GOAL_ACHIEVED:\s*(да|нет).*/i, '').trim();

    // Post result to chat immediately (recording link will come later)
    const campaign = await this.prisma.outboundCampaign.findUnique({ where: { id: data.campaignId } });
    if (campaign) {
      if (goalAchieved) {
        await this.postBotMessage(
          campaign.conversationId,
          campaign.topicId,
          `🎉 **${call.businessName}** — цель достигнута! (${data.durationSec}с)\n\n${cleanSummary}`,
        );
        // Pause campaign — goal achieved, ask user if they want to continue
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

    // Delete room quickly to hang up SIP call (recorder processes from local PCM files)
    if (call.roomName) {
      const roomName = call.roomName;
      setTimeout(async () => {
        try {
          await this.rooms.deleteRoom(roomName);
          this.logger.log(`[hangup] Room ${roomName} deleted`);
        } catch (e) {
          this.logger.warn(`[hangup] Failed to delete room: ${(e as Error).message}`);
        }
      }, 2000); // 2s — enough for recorder to get stop signal
    }
  }

  // ── Stop recorder and retrieve recording URL ──

  private async stopRecorderAndGetUrl(callId: string, roomName: string, campaignId: string) {
    try {
      // Stop the recorder
      const stopRes = await fetch(`${AI_AGENT_URL}/stop-record`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      this.logger.log(`[recorder] Stop request for ${roomName}: ${stopRes.status}`);

      // Wait for processing — poll MeetingSummary for recordingUrl
      for (let attempt = 0; attempt < 40; attempt++) {
        await new Promise(r => setTimeout(r, 3000));
        const summary = await this.prisma.meetingSummary.findFirst({
          where: { roomName },
        });
        if (summary?.recordingUrl) {
          // Decode %2F → / so flutter_markdown doesn't double-encode it
          const decodedUrl = decodeURIComponent(summary.recordingUrl);
          // Update OutboundCall with recording URL
          await this.prisma.outboundCall.update({
            where: { id: callId },
            data: { recordingUrl: decodedUrl },
          });
          this.logger.log(`[recorder] Got recording URL for call ${callId}: ${decodedUrl}`);

          // Post recording link to chat
          const call = await this.prisma.outboundCall.findUnique({
            where: { id: callId },
            include: { campaign: true },
          });
          if (call?.campaign) {
            await this.postBotMessage(
              call.campaign.conversationId,
              call.campaign.topicId,
              `🎧 **Запись: ${call.businessName}**\n[▶ Слушать / Скачать](${decodedUrl})`,
            );
          }
          return;
        }
      }
      this.logger.warn(`[recorder] No recording URL found after 120s for room ${roomName}`);
    } catch (e) {
      this.logger.warn(`[recorder] Error: ${(e as Error).message}`);
    }
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
