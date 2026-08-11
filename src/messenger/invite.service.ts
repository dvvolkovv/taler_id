import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  generateInviteCode,
  inviteUnusable,
  normalizePublicUsername,
} from './invite.util';

/** Больше — уже не «раздать команде», а инструмент для мусора. */
const MAX_ACTIVE_INVITES = 20;

/** Роли, которым позволено звать людей и менять публичное имя. */
const MANAGER_ROLES = ['OWNER', 'ADMIN'];

@Injectable()
export class InviteService {
  constructor(private readonly prisma: PrismaService) {}

  /** Ссылка вида `https://<web>/invite/<code>` — этот путь перехватывает приложение. */
  private inviteUrl(code: string): string {
    const base = (process.env.WEB_URL ?? process.env.BASE_URL ?? 'https://staging.id.taler.tirol')
      .replace(/\/$/, '');
    return `${base}/invite/${code}`;
  }

  private async assertManager(conversationId: string, userId: string) {
    const conv = await this.prisma.conversation.findUnique({
      where: { id: conversationId },
      select: { id: true, type: true, isSystem: true },
    });
    if (!conv) throw new NotFoundException('Conversation not found');
    if (conv.type !== 'GROUP' && conv.type !== 'CHANNEL') {
      // Звать в личную переписку третьего человека нельзя: это уже другая
      // беседа, а не эта.
      throw new BadRequestException('Only groups and channels can be shared');
    }
    const me = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId, userId } },
      select: { role: true },
    });
    if (!me || !MANAGER_ROLES.includes(me.role)) {
      throw new ForbiddenException('Only owners and admins can do this');
    }
    return conv;
  }

  async createInvite(
    conversationId: string,
    userId: string,
    opts: { expiresInHours?: number | null; maxUses?: number | null } = {},
  ) {
    await this.assertManager(conversationId, userId);

    const active = await this.prisma.conversationInvite.count({
      where: { conversationId, revokedAt: null },
    });
    if (active >= MAX_ACTIVE_INVITES) {
      throw new BadRequestException(
        `Too many active invites (max ${MAX_ACTIVE_INVITES}); revoke some first`,
      );
    }

    const hours = opts.expiresInHours ?? null;
    if (hours !== null && (!Number.isFinite(hours) || hours <= 0)) {
      throw new BadRequestException('expiresInHours must be positive');
    }
    const maxUses = opts.maxUses ?? null;
    if (maxUses !== null && (!Number.isInteger(maxUses) || maxUses <= 0)) {
      throw new BadRequestException('maxUses must be a positive integer');
    }

    const invite = await this.prisma.conversationInvite.create({
      data: {
        conversationId,
        code: generateInviteCode(),
        createdById: userId,
        expiresAt: hours ? new Date(Date.now() + hours * 3600_000) : null,
        maxUses,
      },
    });
    return { ...invite, url: this.inviteUrl(invite.code) };
  }

  async listInvites(conversationId: string, userId: string) {
    await this.assertManager(conversationId, userId);
    const rows = await this.prisma.conversationInvite.findMany({
      where: { conversationId, revokedAt: null },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((r) => ({ ...r, url: this.inviteUrl(r.code) }));
  }

  async revokeInvite(code: string, userId: string) {
    const invite = await this.prisma.conversationInvite.findUnique({
      where: { code },
      select: { id: true, conversationId: true, revokedAt: true },
    });
    if (!invite) throw new NotFoundException('Invite not found');
    await this.assertManager(invite.conversationId, userId);
    if (invite.revokedAt) return { revoked: true, alreadyRevoked: true };
    await this.prisma.conversationInvite.update({
      where: { id: invite.id },
      data: { revokedAt: new Date() },
    });
    return { revoked: true, alreadyRevoked: false };
  }

  /**
   * Что показать человеку, открывшему ссылку, до того как он согласится войти.
   *
   * Нерабочая ссылка — не ошибка, а состояние: пользователю надо объяснить,
   * что именно с ней не так, а не показать пустой экран.
   */
  async previewInvite(code: string, userId: string) {
    const invite = await this.prisma.conversationInvite.findUnique({
      where: { code },
      include: {
        conversation: {
          select: {
            id: true,
            type: true,
            name: true,
            avatarUrl: true,
            description: true,
            _count: { select: { participants: true } },
          },
        },
      },
    });
    if (!invite) throw new NotFoundException('Invite not found');

    const problem = inviteUnusable(invite);
    const already = await this.prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: { conversationId: invite.conversationId, userId },
      },
      select: { id: true },
    });

    return {
      conversationId: invite.conversation.id,
      type: invite.conversation.type,
      name: invite.conversation.name,
      avatarUrl: invite.conversation.avatarUrl,
      description: invite.conversation.description,
      participantCount: invite.conversation._count.participants,
      alreadyMember: !!already,
      usable: problem === null,
      problem,
    };
  }

  /**
   * Вступление по ссылке.
   *
   * Счётчик использований увеличивается условием в WHERE, а не чтением с
   * последующей записью: две одновременные попытки по ссылке на одно место
   * иначе прошли бы обе.
   */
  async joinByInvite(code: string, userId: string) {
    const invite = await this.prisma.conversationInvite.findUnique({
      where: { code },
    });
    if (!invite) throw new NotFoundException('Invite not found');

    const problem = inviteUnusable(invite);
    if (problem) throw new BadRequestException(`Invite is ${problem}`);

    const existing = await this.prisma.conversationParticipant.findUnique({
      where: {
        conversationId_userId: { conversationId: invite.conversationId, userId },
      },
      select: { id: true },
    });
    // Повторный переход по своей же ссылке — не ошибка и не повод жечь место.
    if (existing) {
      return { conversationId: invite.conversationId, joined: false, already: true };
    }

    if (invite.maxUses !== null) {
      const claimed = await this.prisma.conversationInvite.updateMany({
        where: { id: invite.id, uses: { lt: invite.maxUses }, revokedAt: null },
        data: { uses: { increment: 1 } },
      });
      if (claimed.count === 0) {
        throw new BadRequestException('Invite is exhausted');
      }
    } else {
      await this.prisma.conversationInvite.update({
        where: { id: invite.id },
        data: { uses: { increment: 1 } },
      });
    }

    const conv = await this.prisma.conversation.findUnique({
      where: { id: invite.conversationId },
      select: { type: true },
    });
    await this.prisma.conversationParticipant.create({
      data: {
        conversationId: invite.conversationId,
        userId,
        // В канале пришедший по ссылке — подписчик, в группе — обычный участник.
        role: conv?.type === 'CHANNEL' ? 'SUBSCRIBER' : 'MEMBER',
      },
    });
    return { conversationId: invite.conversationId, joined: true, already: false };
  }

  /**
   * Публичное имя беседы.
   *
   * Уникальность проверяется и против логинов людей: пространство имён одно —
   * `@name` в тексте не должно означать то группу, то человека.
   */
  async setPublicUsername(
    conversationId: string,
    userId: string,
    raw: string | null,
  ) {
    await this.assertManager(conversationId, userId);

    if (raw === null || raw.trim() === '') {
      await this.prisma.conversation.update({
        where: { id: conversationId },
        data: { publicUsername: null },
      });
      return { publicUsername: null };
    }

    const username = normalizePublicUsername(raw);
    if (!username) {
      throw new BadRequestException(
        'Handle must be 5-32 chars, start with a letter, and use only a-z, 0-9 and _',
      );
    }

    const takenByUser = await this.prisma.user.findFirst({
      where: { username: { equals: username, mode: 'insensitive' } },
      select: { id: true },
    });
    if (takenByUser) throw new ConflictException('Handle is already taken');

    const takenByConv = await this.prisma.conversation.findFirst({
      where: { publicUsername: username, NOT: { id: conversationId } },
      select: { id: true },
    });
    if (takenByConv) throw new ConflictException('Handle is already taken');

    await this.prisma.conversation.update({
      where: { id: conversationId },
      data: { publicUsername: username },
    });
    return { publicUsername: username, url: `${this.inviteUrl('').replace(/\/invite\/$/, '')}/@${username}` };
  }

  /** Беседа по публичному имени — для открытия ссылки `/@name`. */
  async resolvePublicUsername(rawUsername: string, userId: string) {
    const username = normalizePublicUsername(rawUsername);
    if (!username) throw new NotFoundException('No such conversation');
    const conv = await this.prisma.conversation.findFirst({
      where: { publicUsername: username },
      select: {
        id: true,
        type: true,
        name: true,
        avatarUrl: true,
        description: true,
        publicUsername: true,
        _count: { select: { participants: true } },
      },
    });
    if (!conv) throw new NotFoundException('No such conversation');
    const already = await this.prisma.conversationParticipant.findUnique({
      where: { conversationId_userId: { conversationId: conv.id, userId } },
      select: { id: true },
    });
    return {
      conversationId: conv.id,
      type: conv.type,
      name: conv.name,
      avatarUrl: conv.avatarUrl,
      description: conv.description,
      publicUsername: conv.publicUsername,
      participantCount: conv._count.participants,
      alreadyMember: !!already,
    };
  }

  /** Вступление по публичному имени — без кода, беседа сама открыта. */
  async joinByPublicUsername(rawUsername: string, userId: string) {
    const info = await this.resolvePublicUsername(rawUsername, userId);
    if (info.alreadyMember) {
      return { conversationId: info.conversationId, joined: false, already: true };
    }
    await this.prisma.conversationParticipant.create({
      data: {
        conversationId: info.conversationId,
        userId,
        role: info.type === 'CHANNEL' ? 'SUBSCRIBER' : 'MEMBER',
      },
    });
    return { conversationId: info.conversationId, joined: true, already: false };
  }
}
