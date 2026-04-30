import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { VoximplantService } from './voximplant.service';
import { SipService } from './sip.service';
import {
  AgentDispatchClient,
  RoomServiceClient,
  AccessToken,
} from 'livekit-server-sdk';
import { v4 as uuidv4 } from 'uuid';

const CLAUDE_WORKER_URL =
  process.env.CLAUDE_WORKER_URL || 'http://5.101.115.184:3033';
const BOT_SENDER_ID = 'ai-outbound-bot';

// OUTBOUND_MODE=voximplant (default, Yandex TTS) or livekit (SIPNET + ElevenLabs streaming)
const OUTBOUND_MODE = process.env.OUTBOUND_MODE || 'voximplant';
const OUTBOUND_AGENT_NAME = 'outbound-call-agent';
const LK_HOST =
  process.env.LIVEKIT_HOST_OUTBOUND || 'https://ru.id.taler.tirol';
const LK_API_KEY =
  process.env.LIVEKIT_API_KEY_OUTBOUND || 'devkey278c50b6c7ef4dab';
const LK_API_SECRET =
  process.env.LIVEKIT_API_SECRET_OUTBOUND ||
  '71658877e5b5f568313c7394c57a566ee6acd66ccf8e3f900237ac88d7e649e7';
const BACKEND_URL = process.env.BACKEND_URL || 'https://staging.id.taler.tirol';
const RECORDER_URL =
  process.env.RECORDER_URL_OUTBOUND || 'http://167.172.181.34:3100';
const LK_WS_URL_OUTBOUND =
  process.env.LIVEKIT_WS_URL_OUTBOUND ||
  'wss://id.taler.tirol/livekit-outbound';

@Injectable()
export class OutboundBotService {
  private readonly logger = new Logger(OutboundBotService.name);
  private readonly rooms = new RoomServiceClient(
    LK_HOST,
    LK_API_KEY,
    LK_API_SECRET,
  );
  private readonly dispatcher = new AgentDispatchClient(
    LK_HOST,
    LK_API_KEY,
    LK_API_SECRET,
  );
  private emitToUser:
    | ((target: string, event: string, data: any) => void)
    | null = null;
  private activeCalls = new Map<
    string,
    { sessionId: string; businessName: string; campaignId: string }
  >();

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly vox: VoximplantService,
    private readonly sip: SipService,
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
        type: 'AI_OUTBOUND',
        name: 'AI Обзвон',
        topicsEnabled: true,
        createdById: userId,
        participants: { create: { userId, role: 'OWNER' } },
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
      data: {
        userId,
        conversationId,
        topicId: topic.id,
        taskText: title,
        status: 'gathering',
      },
    });
    await this.updateTopicIcon(topic.id, 'gathering');

    this.logger.log(`Created task: topic=${topic.id} campaign=${campaign.id}`);

    // Return immediately — Claude will think asynchronously
    // Show typing indicator while Claude generates clarifying questions
    if (this.emitToUser) {
      this.emitToUser(conversationId, 'typing', {
        conversationId,
        topicId: topic.id,
        userId: BOT_SENDER_ID,
        userName: 'AI Обзвон',
        isTyping: true,
        typingText: '🤔 Анализирую задачу...',
      });
    }

    const topicId = topic.id;
    const campaignId = campaign.id;

    // Ask Claude asynchronously — result comes via Socket.IO
    this.generateClarifyingQuestions(
      campaignId,
      conversationId,
      topicId,
      title,
    ).catch((e) => {
      this.logger.error(`Clarify questions failed: ${(e as Error).message}`);
    });

    return { conversationId, topicId, campaignId };
  }

  // ── Generate clarifying questions asynchronously ──

  private async generateClarifyingQuestions(
    campaignId: string,
    conversationId: string,
    topicId: string,
    title: string,
  ) {
    const clarifyPrompt = `Пользователь хочет обзвонить компании. Задача: "${title}"

Задай 2-3 уточняющих вопроса, чтобы лучше понять:
- Что конкретно нужно (параметры, характеристики, предпочтения)?
- Город или район поиска?
- Бюджет или ограничения по цене?
- Сроки?
- Какие вопросы задать при звонке (наличие, цена, сроки, гарантия и т.д.)?

Также подумай, какие вопросы могут задать на той стороне (в компаниях), и спроси пользователя заранее, чтобы агент мог ответить. Например: модель, год выпуска, VIN, размеры, объём и т.д.

Формат: дружелюбный, короткий. В конце напиши "Расскажите, пожалуйста, подробнее про задачу".`;

    try {
      const questions = await this.askClaude(
        clarifyPrompt,
        `outbound-gather-${campaignId}`,
      );
      if (this.emitToUser) {
        this.emitToUser(conversationId, 'typing', {
          conversationId,
          topicId,
          userId: BOT_SENDER_ID,
          isTyping: false,
        });
      }
      await this.postBotMessage(conversationId, topicId, questions);
    } catch (e) {
      if (this.emitToUser) {
        this.emitToUser(conversationId, 'typing', {
          conversationId,
          topicId,
          userId: BOT_SENDER_ID,
          isTyping: false,
        });
      }
      this.logger.warn(`Claude clarify failed: ${(e as Error).message}`);
      await this.postBotMessage(
        conversationId,
        topicId,
        `Отлично! Задача: **${title}**\n\n` +
          `Расскажите про задачу подробнее:\n` +
          `- Что именно нужно?\n` +
          `- В каком городе/районе?\n` +
          `- Есть ограничения по бюджету или срокам?\n` +
          `- Какие вопросы задать компаниям?\n\n` +
          `Когда будете готовы — нажмите **"Далее"**.\n\n[ACTION:Далее]`,
      );
    }
  }

  // ── Handle user message in AI_OUTBOUND conversation ──

  async handleUserMessage(input: {
    userId: string;
    conversationId: string;
    messageText: string;
    topicId?: string;
    fileUrls?: { url: string; name: string }[];
  }): Promise<void> {
    const { userId, conversationId, messageText, fileUrls } = input;
    this.logger.log(
      `handleUserMessage: msg="${messageText.slice(0, 50)}" topicId=${input.topicId || 'none'}`,
    );

    try {
      // Prefer LATEST active campaign; fall back to latest done/failed (living session)
      const activeStatuses = [
        'gathering',
        'pending_approval',
        'calling',
        'paused',
      ];
      let campaign: any = null;
      if (input.topicId) {
        campaign = await this.prisma.outboundCampaign.findFirst({
          where: { topicId: input.topicId, status: { in: activeStatuses } },
          orderBy: { createdAt: 'desc' },
        });
        if (!campaign) {
          campaign = await this.prisma.outboundCampaign.findFirst({
            where: { topicId: input.topicId },
            orderBy: { createdAt: 'desc' },
          });
        }
      }
      if (!campaign) {
        campaign = await this.prisma.outboundCampaign.findFirst({
          where: { conversationId, status: { in: activeStatuses } },
          orderBy: { createdAt: 'desc' },
        });
      }

      if (!campaign) {
        this.logger.warn(`No active campaign for conv=${conversationId}`);
        return;
      }

      const topicId = campaign.topicId;

      if (campaign.status === 'gathering') {
        await this.handleGathering(
          campaign,
          userId,
          conversationId,
          topicId,
          messageText,
          fileUrls,
        );
      } else if (campaign.status === 'pending_approval') {
        await this.handlePlanFeedback(
          campaign,
          userId,
          conversationId,
          topicId,
          messageText,
        );
      } else if (
        campaign.status === 'calling' ||
        campaign.status === 'paused'
      ) {
        await this.handleCallingFeedback(
          campaign,
          userId,
          conversationId,
          topicId,
          messageText,
        );
      } else if (campaign.status === 'done' || campaign.status === 'failed') {
        await this.handleDoneFeedback(
          campaign,
          userId,
          conversationId,
          topicId,
          messageText,
        );
      }
    } catch (e) {
      this.logger.error(`handleUserMessage crashed: ${(e as Error).message}`);
    }
  }

  // ── Handle messages after campaign is done/failed (living session) ──
  // Allows user to: re-call some/all, add new numbers, ask for new summary,
  // or start a new task in the same topic.

  private async handleDoneFeedback(
    campaign: any,
    userId: string,
    conversationId: string,
    topicId: string,
    text: string,
  ) {
    const lower = text.toLowerCase().trim();

    // Quick commands
    if (['сводка', 'итоги', 'результаты', 'summary'].includes(lower)) {
      await this.analyzeResults(campaign.id, userId, conversationId, topicId);
      return;
    }

    if (
      [
        'повтори',
        'повторить',
        'перезвони',
        'retry',
        'ещё раз',
        'еще раз',
      ].includes(lower)
    ) {
      // Retry all failed/no_answer calls in the same campaign
      await this.prisma.outboundCampaign.update({
        where: { id: campaign.id },
        data: { status: 'calling' },
      });
      await this.updateTopicIcon(topicId, 'calling');
      await this.postBotMessage(
        conversationId,
        topicId,
        '🔁 Повторяю необзвоненные номера...',
      );
      this.resumeCalls(campaign.id, userId, conversationId, topicId).catch(
        (e) => {
          this.logger.error(`Resume calls failed: ${e.message}`);
        },
      );
      return;
    }

    // Anything else — treat as new task in the same topic
    const newCampaign = await this.prisma.outboundCampaign.create({
      data: {
        userId,
        conversationId,
        topicId,
        taskText: text,
        status: 'gathering',
      },
    });
    await this.updateTopicIcon(topicId, 'gathering');
    this.logger.log(`Continued topic: new campaign=${newCampaign.id}`);
    if (this.emitToUser) {
      this.emitToUser(conversationId, 'typing', {
        conversationId,
        topicId,
        userId: BOT_SENDER_ID,
        userName: 'AI Обзвон',
        isTyping: true,
        typingText: '🤔 Анализирую задачу...',
      });
    }
    this.generateClarifyingQuestions(
      newCampaign.id,
      conversationId,
      topicId,
      text,
    ).catch((e) => {
      this.logger.error(`Clarify questions failed: ${(e as Error).message}`);
    });
  }

  // ── Handle messages during calling/paused phase ──

  private async handleCallingFeedback(
    campaign: any,
    userId: string,
    conversationId: string,
    topicId: string,
    text: string,
  ) {
    const lower = text.toLowerCase().trim();

    if (['достаточно', 'стоп', 'хватит', 'stop', 'enough'].includes(lower)) {
      await this.prisma.outboundCampaign.update({
        where: { id: campaign.id },
        data: { status: 'paused' },
      });
      await this.updateTopicIcon(topicId, 'paused');
      await this.postBotMessage(
        conversationId,
        topicId,
        '⏸ Обзвон приостановлен.\n\n' +
          'Хотите получить сводку по имеющимся результатам или продолжить?\n\n' +
          '[ACTION:Сводка][ACTION:Продолжить обзвон]',
      );
    } else if (
      [
        'продолжить обзвон',
        'продолжить',
        'дальше',
        'continue',
        'повтори',
        'повторить',
        'перезвони',
        'retry',
      ].includes(lower)
    ) {
      if (campaign.status === 'paused') {
        await this.prisma.outboundCampaign.update({
          where: { id: campaign.id },
          data: { status: 'calling' },
        });
        await this.updateTopicIcon(topicId, 'calling');
        await this.postBotMessage(
          conversationId,
          topicId,
          '▶️ Продолжаю обзвон...',
        );
        this.resumeCalls(campaign.id, userId, conversationId, topicId).catch(
          (e) => {
            this.logger.error(`Resume calls failed: ${e.message}`);
            this.postStatus(
              conversationId,
              topicId,
              `❌ Ошибка: ${e.message}`,
            ).catch(() => {});
          },
        );
      } else {
        // Status is 'calling' — clear waiting flag so executeCalls loop continues
        await this.redis.del(`outbound:waiting:${campaign.id}`);
        await this.postBotMessage(conversationId, topicId, '▶️ Продолжаю...');
      }
    } else if (['сводка', 'итоги', 'результаты', 'summary'].includes(lower)) {
      await this.analyzeResults(campaign.id, userId, conversationId, topicId);
    } else if (lower.includes('слушать') || lower === 'listen') {
      // livekit mode: emit socket event with token+wsUrl so mobile can join as listener
      const active = this.activeCalls.get(campaign.id);
      if (active && OUTBOUND_MODE === 'livekit') {
        const token = await this.generateListenToken(userId, active.sessionId);
        await this.postBotMessage(
          conversationId,
          topicId,
          `🎧 Подключение к звонку с **${active.businessName}**...`,
        );
        if (this.emitToUser) {
          this.emitToUser(conversationId, 'outbound_listen', {
            roomName: active.sessionId,
            businessName: active.businessName,
            token,
            wsUrl: LK_WS_URL_OUTBOUND,
          });
        }
      } else {
        // No active call — show last recording if available
        const lastCall = await this.prisma.outboundCall.findFirst({
          where: {
            campaignId: campaign.id,
            status: 'completed',
            recordingUrl: { not: null },
          },
          orderBy: { createdAt: 'desc' },
        });
        if (lastCall?.recordingUrl) {
          await this.postBotMessage(
            conversationId,
            topicId,
            `🎧 Запись звонка с **${lastCall.businessName}** уже в чате ⬆️`,
          );
        } else {
          await this.postBotMessage(
            conversationId,
            topicId,
            '❌ Сейчас нет активного звонка и записи.',
          );
        }
      }
    }
  }

  // ── Resume calls from where we stopped ──

  private async resumeCalls(
    campaignId: string,
    userId: string,
    conversationId: string,
    topicId: string,
  ) {
    const campaign = await this.prisma.outboundCampaign.findUnique({
      where: { id: campaignId },
      include: { calls: true },
    });
    if (!campaign) return;

    const callPlan = campaign.callPlan as any;
    const calls = callPlan?.callPlan || [];
    const completedPhones = new Set(
      campaign.calls
        .filter((c) => ['completed', 'failed', 'no_answer'].includes(c.status))
        .map((c) => c.phoneNumber),
    );

    const remaining = calls.filter((c: any) => !completedPhones.has(c.phone));
    if (remaining.length === 0) {
      await this.postBotMessage(
        conversationId,
        topicId,
        'Все звонки из плана завершены.',
      );
      await this.analyzeResults(campaignId, userId, conversationId, topicId);
      return;
    }

    await this.postStatus(
      conversationId,
      topicId,
      `📞 Осталось ${remaining.length} звонков...`,
    );

    for (let i = 0; i < remaining.length; i++) {
      // Check if campaign was paused again
      const check = await this.prisma.outboundCampaign.findUnique({
        where: { id: campaignId },
      });
      if (!check || check.status !== 'calling') {
        this.logger.log(
          `[resume] Campaign ${campaignId} status=${check?.status}, stopping`,
        );
        return;
      }

      try {
        const totalDone = campaign.calls.filter((c) =>
          ['completed', 'failed', 'no_answer'].includes(c.status),
        ).length;
        await this.executeCall(
          campaignId,
          userId,
          conversationId,
          topicId,
          remaining[i],
          totalDone + i,
          calls.length,
        );

        // Check if paused during the call
        const afterCall = await this.prisma.outboundCampaign.findUnique({
          where: { id: campaignId },
        });
        if (!afterCall || afterCall.status !== 'calling') {
          this.logger.log(`[resume] Campaign paused after call, stopping`);
          return;
        }

        // After each call, ask to continue (if not last)
        if (i < remaining.length - 1) {
          await this.postBotMessage(
            conversationId,
            topicId,
            `✅ Завершено. Продолжить?\n\n[ACTION:Продолжить обзвон][ACTION:Достаточно]`,
          );
          const decided = await this.waitForCampaignStatus(campaignId, 120000);
          if (decided === 'paused' || decided === 'done') return;
        }
      } catch (e) {
        if ((e as Error).message === 'CAMPAIGN_PAUSED') {
          this.logger.log(`[resume] Campaign paused during call`);
          return;
        }
        await this.postBotMessage(
          conversationId,
          topicId,
          `❌ ${remaining[i].businessName}: ${(e as Error).message}`,
        );
      }
    }
    await this.analyzeResults(campaignId, userId, conversationId, topicId);
  }

  // ── Wait for campaign status change (polling with timeout) ──

  // Waits for user to press Continue or Enough after a call completes.
  // Before calling, set a Redis flag; handleCallingFeedback clears it on "continue".
  private async waitForCampaignStatus(
    campaignId: string,
    timeoutMs: number,
  ): Promise<string> {
    const key = `outbound:waiting:${campaignId}`;
    await this.redis.setEx(key, Math.ceil(timeoutMs / 1000), '1');
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const campaign = await this.prisma.outboundCampaign.findUnique({
        where: { id: campaignId },
      });
      if (!campaign) return 'done';
      if (campaign.status === 'paused') {
        await this.redis.del(key);
        return 'paused';
      }
      if (campaign.status === 'done') {
        await this.redis.del(key);
        return 'done';
      }
      // Check if "continue" was pressed (flag cleared)
      const waiting = await this.redis.get(key);
      if (!waiting) return 'calling';
      await new Promise((r) => setTimeout(r, 2000));
    }
    await this.redis.del(key);
    return 'calling'; // timeout — auto-continue
  }

  // ── Generate listen-only token for a user (livekit mode) ──

  async generateListenToken(userId: string, roomName: string): Promise<string> {
    const token = new AccessToken(LK_API_KEY, LK_API_SECRET, {
      identity: `listener-${userId}`,
      name: 'Слушатель',
    });
    token.addGrant({
      room: roomName,
      roomJoin: true,
      canPublish: false,
      canSubscribe: true,
    });
    return await token.toJwt();
  }

  async getActiveCall(campaignId: string, userId: string) {
    const active = this.activeCalls.get(campaignId);
    if (!active) return null;
    if (OUTBOUND_MODE !== 'livekit') {
      return { sessionId: active.sessionId, businessName: active.businessName };
    }
    const token = await this.generateListenToken(userId, active.sessionId);
    return {
      roomName: active.sessionId,
      businessName: active.businessName,
      token,
      wsUrl: LK_WS_URL_OUTBOUND,
    };
  }

  // ── Gathering phase: collect details with AI clarifying questions ──

  private async handleGathering(
    campaign: any,
    userId: string,
    conversationId: string,
    topicId: string,
    text: string,
    fileUrls?: { url: string; name: string }[],
  ) {
    const lower = text.toLowerCase().trim();
    const startWords = [
      'далее',
      'ищи',
      'начинай',
      'поехали',
      'старт',
      'start',
      'search',
    ];
    const isStartCommand = startWords.includes(lower);

    if (lower.length === 0) return;

    if (isStartCommand) {
      const taskLines = (campaign.taskText || '')
        .split('\n')
        .filter((l: string) => l.trim().length > 0);
      if (taskLines.length <= 1) {
        await this.postBotMessage(
          conversationId,
          topicId,
          'Сначала опишите задачу подробнее — что нужно, где, какие ограничения. Потом нажмите **"Далее"**.\n\n[ACTION:Далее]',
        );
        return;
      }
      await this.prisma.outboundCampaign.update({
        where: { id: campaign.id },
        data: { status: 'planning' },
      });
      await this.updateTopicIcon(topicId, 'planning');

      const phases = [
        '🔍 Ищу...',
        '🌐 Ищу варианты...',
        '📊 Анализирую...',
        '📋 Составляю план...',
        '🔍 Проверяю контакты...',
        '🤔 Формирую вопросы...',
      ];
      let phaseIdx = 0;
      const emitTyping = (text: string) => {
        if (this.emitToUser) {
          this.emitToUser(conversationId, 'typing', {
            conversationId,
            topicId,
            userId: BOT_SENDER_ID,
            userName: 'AI Обзвон',
            isTyping: true,
            typingText: text,
          });
        }
      };
      emitTyping(phases[0]);
      const typingInterval = setInterval(() => {
        phaseIdx = (phaseIdx + 1) % phases.length;
        emitTyping(phases[phaseIdx]);
      }, 3000);
      this.planCampaign(
        campaign.id,
        userId,
        conversationId,
        topicId,
        campaign.taskText || text,
        fileUrls,
      )
        .then(() => {
          clearInterval(typingInterval);
          if (this.emitToUser)
            this.emitToUser(conversationId, 'typing', {
              conversationId,
              topicId,
              userId: BOT_SENDER_ID,
              isTyping: false,
            });
        })
        .catch((e) => {
          clearInterval(typingInterval);
          if (this.emitToUser)
            this.emitToUser(conversationId, 'typing', {
              conversationId,
              topicId,
              userId: BOT_SENDER_ID,
              isTyping: false,
            });
          this.logger.error(`Campaign ${campaign.id} failed: ${e.message}`);
          this.postStatus(
            conversationId,
            topicId,
            `❌ Ошибка: ${e.message}`,
          ).catch(() => {});
        });
    } else {
      const updated = (campaign.taskText || '') + '\n' + text;
      await this.prisma.outboundCampaign.update({
        where: { id: campaign.id },
        data: { taskText: updated },
      });

      const followUpPrompt = `Пользователь собирается обзвонить компании. Вот что он уже рассказал:

"${updated}"

Оцени, достаточно ли информации для поиска и обзвона. Если нет — задай 1-2 уточняющих вопроса.

Подумай также, какие вопросы могут задать на стороне компании (марка, модель, год, VIN, размеры, цвет, количество и т.д.), и спроси заранее, чтобы агент мог ответить.

Если информации достаточно — скажи кратко что всё понятно и предложи начать поиск.

Формат: короткий, дружелюбный, по делу.`;

      if (this.emitToUser) {
        this.emitToUser(conversationId, 'typing', {
          conversationId,
          topicId,
          userId: BOT_SENDER_ID,
          userName: 'AI Обзвон',
          isTyping: true,
          typingText: '🤔 Думаю...',
        });
      }

      try {
        const followUp = await this.askClaude(
          followUpPrompt,
          `outbound-gather-${campaign.id}`,
        );
        if (this.emitToUser) {
          this.emitToUser(conversationId, 'typing', {
            conversationId,
            topicId,
            userId: BOT_SENDER_ID,
            isTyping: false,
          });
        }
        await this.postBotMessage(
          conversationId,
          topicId,
          `${followUp}\n\n[ACTION:Далее]`,
        );
      } catch (e) {
        if (this.emitToUser) {
          this.emitToUser(conversationId, 'typing', {
            conversationId,
            topicId,
            userId: BOT_SENDER_ID,
            isTyping: false,
          });
        }
        this.logger.warn(`Claude follow-up failed: ${(e as Error).message}`);
        await this.postBotMessage(
          conversationId,
          topicId,
          'Принято! Если есть ещё детали — пишите. Когда готовы — нажмите **"Далее"**.\n\n[ACTION:Далее]',
        );
      }
    }
  }

  // ── Plan feedback: approve or adjust ──

  private async handlePlanFeedback(
    campaign: any,
    userId: string,
    conversationId: string,
    topicId: string,
    text: string,
  ) {
    const lower = text.toLowerCase().trim();
    const approveWords = [
      'начинай',
      'начать',
      'запускай',
      'поехали',
      'ок',
      'ok',
      'да',
      'start',
    ];

    if (approveWords.some((w) => lower.includes(w))) {
      await this.prisma.outboundCampaign.update({
        where: { id: campaign.id },
        data: { status: 'calling' },
      });
      await this.updateTopicIcon(topicId, 'calling');
      await this.postStatus(conversationId, topicId, '🚀 Запускаю обзвон...');
      this.executeCalls(
        campaign.id,
        userId,
        conversationId,
        topicId,
        campaign.callPlan,
      ).catch((e) => {
        this.logger.error(`Calls failed: ${e.message}`);
        this.postStatus(
          conversationId,
          topicId,
          `❌ Ошибка: ${e.message}`,
        ).catch(() => {});
      });
    } else if (lower.startsWith('промпт:') || lower.startsWith('prompt:')) {
      const newPrompt = text.replace(/^(промпт|prompt):\s*/i, '').trim();
      const plan = campaign.callPlan || {};
      plan.agentPrompt = newPrompt;
      await this.prisma.outboundCampaign.update({
        where: { id: campaign.id },
        data: { callPlan: plan },
      });
      await this.postBotMessage(
        conversationId,
        topicId,
        `✅ Промпт обновлён:\n\n"${newPrompt}"\n\nНажмите кнопку или напишите **"Начинай"**.\n\n[ACTION:Начинай]`,
      );
    } else {
      if (text.length > 50) {
        const plan = campaign.callPlan || {};
        plan.agentPrompt = text;
        await this.prisma.outboundCampaign.update({
          where: { id: campaign.id },
          data: { callPlan: plan },
        });
        await this.postBotMessage(
          conversationId,
          topicId,
          `✅ Промпт обновлён:\n\n"${text}"\n\nНажмите кнопку или напишите **"Начинай"**.\n\n[ACTION:Начинай]`,
        );
      } else {
        await this.postStatus(
          conversationId,
          topicId,
          '🤔 Корректирую план...',
        );
        await this.adjustPlan(campaign, userId, conversationId, topicId, text);
      }
    }
  }

  // ── Plan campaign via Claude ──

  private async planCampaign(
    campaignId: string,
    userId: string,
    conversationId: string,
    topicId: string,
    taskText: string,
    fileUrls?: { url: string; name: string }[],
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
    const ownerName =
      [profile?.firstName, profile?.lastName].filter(Boolean).join(' ') ||
      'клиент';
    const defaultPrompt = `Я — личный ассистент ${ownerName}. Звоню от его имени. Представлюсь и вежливо задам вопросы из плана. Буду краток и по-деловому.`;

    callPlan.agentPrompt = defaultPrompt;
    await this.prisma.outboundCampaign.update({
      where: { id: campaignId },
      data: { callPlan, status: 'pending_approval' },
    });
    await this.updateTopicIcon(topicId, 'pending_approval');

    const planMsg =
      `📋 **План обзвона:**\n\n${callPlan.summary || ''}\n\n` +
      (callPlan.callPlan || [])
        .map(
          (c: any, i: number) =>
            `${i + 1}. **${c.businessName}** — ${c.phone}\n   Вопросы: ${(c.questionsToAsk || []).join(', ')}`,
        )
        .join('\n\n');

    await this.postBotMessage(conversationId, topicId, planMsg);

    // Prompt used internally by the agent; not shown in chat
    await this.postBotMessage(
      conversationId,
      topicId,
      'Нажмите **"Начинай"** чтобы запустить обзвон.\n\n[ACTION:Начинай]',
    );
  }

  // ── Adjust plan ──

  private async adjustPlan(
    campaign: any,
    userId: string,
    conversationId: string,
    topicId: string,
    feedback: string,
  ) {
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
      await this.postBotMessage(
        conversationId,
        topicId,
        'Не удалось скорректировать. Попробуйте уточнить.',
      );
      return;
    }

    await this.prisma.outboundCampaign.update({
      where: { id: campaign.id },
      data: { callPlan: newPlan },
    });

    const msg =
      `📋 **Обновлённый план:**\n\n${newPlan.summary || ''}\n\n` +
      (newPlan.callPlan || [])
        .map(
          (c: any, i: number) => `${i + 1}. **${c.businessName}** — ${c.phone}`,
        )
        .join('\n') +
      `\n\n---\n✅ **"Начинай"** или ещё комментарий.\n\n[ACTION:Начинай]`;
    await this.postBotMessage(conversationId, topicId, msg);
  }

  // ── Execute calls ──

  private async executeCalls(
    campaignId: string,
    userId: string,
    conversationId: string,
    topicId: string,
    callPlan: any,
  ) {
    const calls = callPlan?.callPlan || [];
    for (let i = 0; i < calls.length; i++) {
      // Check if campaign was paused/stopped before starting next call
      const check = await this.prisma.outboundCampaign.findUnique({
        where: { id: campaignId },
      });
      if (!check || check.status !== 'calling') {
        this.logger.log(
          `[calls] Campaign ${campaignId} status=${check?.status}, stopping`,
        );
        return;
      }

      try {
        await this.executeCall(
          campaignId,
          userId,
          conversationId,
          topicId,
          calls[i],
          i,
          calls.length,
        );

        // Check if paused during the call
        const afterCall = await this.prisma.outboundCampaign.findUnique({
          where: { id: campaignId },
        });
        if (!afterCall || afterCall.status !== 'calling') {
          this.logger.log(
            `[calls] Campaign paused/stopped after call, exiting loop`,
          );
          return;
        }

        // After each completed call (except last), ask user
        if (i < calls.length - 1) {
          const completedCalls = await this.prisma.outboundCall.count({
            where: { campaignId, status: 'completed' },
          });
          await this.postBotMessage(
            conversationId,
            topicId,
            `✅ Завершено ${completedCalls} из ${calls.length} звонков.\n\n` +
              `Продолжить или достаточно?\n\n[ACTION:Продолжить обзвон][ACTION:Достаточно]`,
          );
          const decided = await this.waitForCampaignStatus(campaignId, 120000);
          if (decided === 'paused' || decided === 'done') return;
        }
      } catch (e) {
        if ((e as Error).message === 'CAMPAIGN_PAUSED') {
          this.logger.log(`[calls] Campaign paused during call ${i}`);
          return;
        }
        await this.postBotMessage(
          conversationId,
          topicId,
          `❌ ${calls[i].businessName}: ${(e as Error).message}`,
        );
      }
    }
    // Summary triggered inside handleCallCallback when last call finishes (no double-run)
  }

  private async executeCall(
    campaignId: string,
    userId: string,
    conversationId: string,
    topicId: string,
    spec: { businessName: string; phone: string; questionsToAsk: string[] },
    idx: number,
    total: number,
  ) {
    const sessionId = `outbound-${uuidv4()}`;
    const call = await this.prisma.outboundCall.create({
      data: {
        campaignId,
        roomName: sessionId,
        businessName: spec.businessName,
        phoneNumber: spec.phone,
        status: 'dialing',
        startedAt: new Date(),
      },
    });

    const campaign = await this.prisma.outboundCampaign.findUnique({
      where: { id: campaignId },
    });
    const profile = await this.prisma.profile.findUnique({ where: { userId } });
    const ownerName =
      [profile?.firstName, profile?.lastName].filter(Boolean).join(' ') ||
      'клиент';
    const agentPrompt = (campaign?.callPlan as any)?.agentPrompt || '';

    if (OUTBOUND_MODE === 'livekit') {
      // livekit-agents pipeline: LiveKit room + dispatch agent + SIPNET PSTN
      await this.rooms.createRoom({
        name: sessionId,
        emptyTimeout: 300,
        maxParticipants: 5,
      });
      const metadata = JSON.stringify({
        businessName: spec.businessName,
        phoneNumber: spec.phone,
        questionsToAsk: spec.questionsToAsk,
        taskContext: campaign?.taskText || '',
        campaignId,
        callId: call.id,
        ownerName,
        agentPrompt,
        callbackUrl: `${BACKEND_URL}/outbound-bot/call-callback`,
      });
      await this.dispatcher.createDispatch(sessionId, OUTBOUND_AGENT_NAME, {
        metadata,
      });
      // Non-blocking dial — errors (timeout, no-answer) are handled later via call status
      this.sip.dialOutbound(sessionId, spec.phone).catch((e) => {
        this.logger.warn(
          `[SIP] dialOutbound rejected: ${(e as Error).message}`,
        );
      });
      await this.prisma.outboundCall.update({
        where: { id: call.id },
        data: { status: 'in_progress' },
      });
      // Start recorder after SIP+agent join the room
      setTimeout(async () => {
        try {
          await fetch(`${RECORDER_URL}/record`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ roomName: sessionId, withAi: false }),
          });
          this.logger.log(`[recorder] started for room ${sessionId}`);
        } catch (e) {
          this.logger.warn(
            `[recorder] failed to start: ${(e as Error).message}`,
          );
        }
      }, 5000);
    } else {
      // voximplant mode (PSTN + Yandex TTS + voice-turn)
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
          transcript: {
            voxCallSessionHistoryId: result.callSessionHistoryId,
          } as any,
        },
      });
    }

    this.activeCalls.set(campaignId, {
      sessionId,
      businessName: spec.businessName,
      campaignId,
    });
    const listenAction =
      OUTBOUND_MODE === 'livekit' ? '\n\n[ACTION:🎧 Слушать]' : '';
    await this.postBotMessage(
      conversationId,
      topicId,
      `📞 Звоню (${idx + 1}/${total}): **${spec.businessName}**...${listenAction}`,
    );

    // Wait for voice-turn callback (max 7 min), check campaign pause
    const start = Date.now();
    while (Date.now() - start < 420000) {
      const u = await this.prisma.outboundCall.findUnique({
        where: { id: call.id },
      });
      if (u && ['completed', 'failed', 'no_answer'].includes(u.status)) break;

      const camp = await this.prisma.outboundCampaign.findUnique({
        where: { id: campaignId },
      });
      if (camp && camp.status === 'paused') {
        this.logger.log(`[call] Campaign paused during call ${call.id}`);
        this.activeCalls.delete(campaignId);
        await this.prisma.outboundCall.update({
          where: { id: call.id },
          data: { status: 'failed', endedAt: new Date() },
        });
        throw new Error('CAMPAIGN_PAUSED');
      }

      await new Promise((r) => setTimeout(r, 3000));
    }

    this.activeCalls.delete(campaignId);

    const final_ = await this.prisma.outboundCall.findUnique({
      where: { id: call.id },
    });
    if (
      !final_ ||
      !['completed', 'failed', 'no_answer'].includes(final_.status)
    ) {
      await this.postStatus(
        conversationId,
        topicId,
        `⏳ ${spec.businessName}: ${final_?.status || 'timeout'}`,
      );
    }

    // livekit mode: tear down room so SIP call ends (BYE sent)
    if (
      OUTBOUND_MODE === 'livekit' &&
      final_ &&
      final_.status === 'completed'
    ) {
      try {
        await this.rooms.deleteRoom(sessionId);
      } catch {}
    }
  }

  // ── Analyze results ──

  private async analyzeResults(
    campaignId: string,
    userId: string,
    conversationId: string,
    topicId: string,
  ) {
    await this.postStatus(
      conversationId,
      topicId,
      '📊 Анализирую результаты...',
    );
    const campaign = await this.prisma.outboundCampaign.findUnique({
      where: { id: campaignId },
      include: { calls: true },
    });
    if (!campaign) return;

    const completed = campaign.calls.filter((c) => c.status === 'completed');
    if (completed.length === 0) {
      await this.postBotMessage(
        conversationId,
        topicId,
        '⚠️ Ни один звонок не завершён успешно.',
      );
      await this.prisma.outboundCampaign.update({
        where: { id: campaignId },
        data: { status: 'done' },
      });
      await this.updateTopicIcon(topicId, 'done');
      return;
    }

    const transcripts = completed
      .map(
        (c) =>
          `--- ${c.businessName} (${c.phoneNumber}) ---\n${c.summary || ''}`,
      )
      .join('\n\n');
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

    await this.prisma.outboundCampaign.update({
      where: { id: campaignId },
      data: { status: 'done', summary: { text: analysis } },
    });
    await this.updateTopicIcon(topicId, 'done');
    await this.postBotMessage(
      conversationId,
      topicId,
      `📊 **Сводка:**\n\n${analysis || 'Нет данных.'}`,
    );
  }

  // ── Call callback from voice-turn service ──

  async handleCallCallback(data: {
    callId: string;
    campaignId: string;
    transcript: any;
    summary: string;
    durationSec: number;
    status: string;
    recordingUrl?: string;
  }) {
    const existing = await this.prisma.outboundCall.findUnique({
      where: { id: data.callId },
    });
    const voxId = (existing?.transcript as any)?.voxCallSessionHistoryId;

    const call = await this.prisma.outboundCall.update({
      where: { id: data.callId },
      data: {
        transcript:
          voxId &&
          data.transcript &&
          !Array.isArray(data.transcript) &&
          typeof data.transcript === 'object'
            ? { ...data.transcript, voxCallSessionHistoryId: voxId }
            : (data.transcript ?? {}),
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
      this.fetchVoxRecording(call.id, voxId, data.campaignId).catch((e) => {
        this.logger.warn(
          `[recording] Failed to fetch: ${(e as Error).message}`,
        );
      });
    }

    // livekit mode: stop recorder and fetch recording URL (async)
    if (OUTBOUND_MODE === 'livekit' && call.roomName) {
      this.stopRecorderAndPost(call.id, call.roomName).catch((e) => {
        this.logger.warn(
          `[recorder] failed to stop/fetch: ${(e as Error).message}`,
        );
      });
    }

    const goalAchieved =
      data.summary && /GOAL_ACHIEVED:\s*да/i.test(data.summary);
    const cleanSummary = (data.summary || '')
      .replace(/\n?GOAL_ACHIEVED:\s*(да|нет).*/i, '')
      .trim();

    const campaign = await this.prisma.outboundCampaign.findUnique({
      where: { id: data.campaignId },
      include: { calls: true },
    });
    if (campaign) {
      // Count remaining calls (not yet dialed)
      const totalPlanned = ((campaign.callPlan as any)?.callPlan || []).length;
      const doneStatuses = ['completed', 'failed', 'no_answer'];
      const doneCount = campaign.calls.filter((c) =>
        doneStatuses.includes(c.status),
      ).length;
      const hasMore = doneCount < totalPlanned;

      if (goalAchieved) {
        await this.postBotMessage(
          campaign.conversationId,
          campaign.topicId,
          `🎉 **${call.businessName}** — цель достигнута! (${data.durationSec}с)\n\n${cleanSummary}`,
        );
        if (hasMore) {
          await this.prisma.outboundCampaign.update({
            where: { id: data.campaignId },
            data: { status: 'paused' },
          });
          await this.updateTopicIcon(campaign.topicId, 'paused');
          await this.postBotMessage(
            campaign.conversationId,
            campaign.topicId,
            '✅ **Цель достигнута!** Продолжить обзвон или достаточно?\n\n[ACTION:Продолжить обзвон][ACTION:Сводка]',
          );
        } else {
          // All calls done — auto-summary
          await this.analyzeResults(
            campaign.id,
            campaign.userId,
            campaign.conversationId,
            campaign.topicId,
          );
        }
      } else {
        await this.postBotMessage(
          campaign.conversationId,
          campaign.topicId,
          `✅ **${call.businessName}** (${data.durationSec}с)\n\n${cleanSummary}`,
        );
        // If this was the last call — auto-summary
        if (!hasMore) {
          await this.analyzeResults(
            campaign.id,
            campaign.userId,
            campaign.conversationId,
            campaign.topicId,
          );
        }
      }
    }
  }

  // ── Stop livekit-ai-agent recorder and publish recording link ──

  private async stopRecorderAndPost(callId: string, roomName: string) {
    try {
      const stopRes = await fetch(`${RECORDER_URL}/stop-record`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roomName }),
      });
      this.logger.log(
        `[recorder] stop for room ${roomName}: ${stopRes.status}`,
      );

      // Poll MeetingSummary for recordingUrl
      for (let attempt = 0; attempt < 40; attempt++) {
        await new Promise((r) => setTimeout(r, 3000));
        const summary = await this.prisma.meetingSummary.findFirst({
          where: { roomName },
        });
        if (summary?.recordingUrl) {
          const decodedUrl = decodeURIComponent(summary.recordingUrl);
          await this.prisma.outboundCall.update({
            where: { id: callId },
            data: { recordingUrl: decodedUrl },
          });
          const c = await this.prisma.outboundCall.findUnique({
            where: { id: callId },
            include: { campaign: true },
          });
          if (c?.campaign) {
            await this.postBotMessage(
              c.campaign.conversationId,
              c.campaign.topicId,
              `🎧 **Запись: ${c.businessName}**\n[▶ Слушать / Скачать](${decodedUrl})`,
            );
          }
          this.logger.log(
            `[recorder] recording URL for call ${callId}: ${decodedUrl}`,
          );
          return;
        }
      }
      this.logger.warn(`[recorder] no URL after 120s for room ${roomName}`);
    } catch (e) {
      this.logger.warn(`[recorder] error: ${(e as Error).message}`);
    }
  }

  // ── Fetch recording URL from Voximplant (polled after call ends) ──

  private async fetchVoxRecording(
    callId: string,
    voxCallSessionHistoryId: number,
    campaignId: string,
  ) {
    // Voximplant needs ~10-30s to finalize the recording after call ends
    for (let attempt = 0; attempt < 30; attempt++) {
      await new Promise((r) => setTimeout(r, 5000));
      const voxUrl = await this.vox.getCallRecording(voxCallSessionHistoryId);
      if (!voxUrl) continue;

      // Voximplant URL requires auth; download to our /var/www/recordings/ and serve publicly
      const RECORDINGS_DIR =
        process.env.RECORDINGS_DIR || '/var/www/recordings';
      const RECORDINGS_BASE_URL =
        process.env.RECORDINGS_BASE_URL || 'https://id.taler.tirol/recordings';
      const filename = `outbound-${callId}.mp3`;
      const localPath = `${RECORDINGS_DIR}/${filename}`;
      const ok = await this.vox.downloadRecording(voxUrl, localPath);
      const publicUrl = ok ? `${RECORDINGS_BASE_URL}/${filename}` : voxUrl;

      await this.prisma.outboundCall.update({
        where: { id: callId },
        data: { recordingUrl: publicUrl },
      });
      const call = await this.prisma.outboundCall.findUnique({
        where: { id: callId },
        include: { campaign: true },
      });
      if (call?.campaign) {
        await this.postBotMessage(
          call.campaign.conversationId,
          call.campaign.topicId,
          `🎧 **Запись: ${call.businessName}**\n[▶ Слушать / Скачать](${publicUrl})`,
        );
      }
      this.logger.log(`[recording] Saved call ${callId}: ${publicUrl}`);
      return;
    }
    this.logger.warn(`[recording] No URL found after 150s for call ${callId}`);
  }

  // ── Topic icon by campaign status ──

  private async updateTopicIcon(topicId: string, status: string) {
    const icons: Record<string, string> = {
      gathering: '📝',
      planning: '🔍',
      pending_approval: '📋',
      calling: '📞',
      paused: '⏸',
      analyzing: '📊',
      done: '✅',
      failed: '❌',
    };
    const icon = icons[status] || '📞';
    try {
      const topic = await this.prisma.topic.update({
        where: { id: topicId },
        data: { icon },
      });
      // Notify mobile so topics list refreshes immediately
      if (this.emitToUser && topic.conversationId) {
        this.emitToUser(topic.conversationId, 'topic_updated', {
          topicId,
          icon,
          status,
        });
      }
    } catch {}
  }

  // ── Helpers ──

  private async postBotMessage(
    conversationId: string,
    topicId: string,
    content: string,
  ) {
    const msg = await this.prisma.message.create({
      data: {
        conversationId,
        topicId,
        senderId: BOT_SENDER_ID,
        content,
        isSystem: false,
      },
    });
    this.emitMsg(conversationId, msg);
  }

  private async postStatus(
    conversationId: string,
    topicId: string,
    content: string,
  ) {
    const msg = await this.prisma.message.create({
      data: {
        conversationId,
        topicId,
        senderId: BOT_SENDER_ID,
        content,
        isSystem: true,
      },
    });
    this.emitMsg(conversationId, msg);
    return msg;
  }

  private emitMsg(conversationId: string, msg: any) {
    if (this.emitToUser)
      this.emitToUser(conversationId, 'new_message', {
        ...msg,
        senderName: 'AI Обзвон',
        reactions: [],
      });
  }

  private emit(userId: string, event: string, data: any) {
    if (this.emitToUser) this.emitToUser(`user:${userId}`, event, data);
  }

  private async askClaude(message: string, sessionId: string): Promise<string> {
    const resp = await fetch(`${CLAUDE_WORKER_URL}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, sessionId }),
    });
    if (!resp.ok) throw new Error(`Claude Worker returned ${resp.status}`);

    const reader = resp.body?.getReader();
    if (!reader) throw new Error('No response body');
    const decoder = new TextDecoder();
    let result = '',
      buf = '';
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
          else if (
            ev.type === 'result' &&
            ev.text &&
            ev.text.length > result.length
          )
            result = ev.text;
        } catch {}
      }
    }
    return result;
  }

  async getCampaigns(userId: string, conversationId: string) {
    return this.prisma.outboundCampaign.findMany({
      where: { userId, conversationId },
      include: { calls: { orderBy: { createdAt: 'asc' } } },
      orderBy: { createdAt: 'desc' },
    });
  }

  async getCampaign(campaignId: string) {
    return this.prisma.outboundCampaign.findUnique({
      where: { id: campaignId },
      include: { calls: { orderBy: { createdAt: 'asc' } } },
    });
  }
}
