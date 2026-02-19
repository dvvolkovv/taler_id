import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { TenantRole, KycStatus } from '@prisma/client';
import { CreateTenantDto, UpdateTenantDto, InviteMemberDto, ChangeRoleDto } from './dto/create-tenant.dto';
import * as crypto from 'crypto';
import { EmailService } from '../email/email.service';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class TenantService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly email: EmailService,
  ) {}

  async createTenant(userId: string, dto: CreateTenantDto) {
    const tenant = await this.prisma.tenant.create({
      data: {
        name: dto.name,
        description: dto.description,
        legalAddress: dto.legalAddress,
        website: dto.website,
        contactEmail: dto.email,
        contactPhone: dto.phone,
        members: {
          create: {
            userId,
            role: TenantRole.OWNER,
          },
        },
      },
      include: { members: true },
    });
    return tenant;
  }

  async getMyTenants(userId: string) {
    const memberships = await this.prisma.tenantMember.findMany({
      where: { userId },
      include: {
        tenant: true,
      },
    });
    return memberships.map((m) => ({
      ...m.tenant,
      role: m.role,
    }));
  }

  async getTenant(tenantId: string, userId: string) {
    await this.assertMember(tenantId, userId);
    const tenant = await this.prisma.tenant.findUnique({
      where: { id: tenantId },
      include: {
        members: {
          include: {
            user: {
              select: {
                id: true,
                email: true,
                phone: true,
              },
            },
          },
        },
      },
    });
    if (!tenant) throw new NotFoundException('Tenant not found');
    return tenant;
  }

  async updateTenant(tenantId: string, userId: string, dto: UpdateTenantDto) {
    await this.assertRole(tenantId, userId, [TenantRole.OWNER, TenantRole.ADMIN]);
    return this.prisma.tenant.update({
      where: { id: tenantId },
      data: {
        name: dto.name,
        description: dto.description,
        legalAddress: dto.legalAddress,
        website: dto.website,
        contactEmail: dto.email,
        contactPhone: dto.phone,
      },
    });
  }

  async startKyb(tenantId: string, userId: string) {
    await this.assertRole(tenantId, userId, [TenantRole.OWNER]);
    const tenant = await this.prisma.tenant.findUnique({ where: { id: tenantId } });
    if (!tenant) throw new NotFoundException('Tenant not found');

    const appToken = this.config.get<string>('sumsub.appToken');
    const isMock = !appToken || appToken === 'test_token';

    let applicantId: string;
    let sdkToken: string;

    if (isMock) {
      applicantId = `mock_company_${tenantId}`;
      sdkToken = `mock_kyb_sdk_token_${Date.now()}`;
    } else {
      // Real Sumsub KYB applicant creation
      const ts = Math.floor(Date.now() / 1000);
      const secretKey = this.config.get<string>('sumsub.secretKey') ?? '';
      const baseUrl = this.config.get<string>('sumsub.baseUrl') ?? 'https://api.sumsub.com';

      const method = 'POST';
      const path = `/resources/applicants?levelName=basic-kyb-level`;
      const body = JSON.stringify({
        externalUserId: tenantId,
        type: 'company',
        info: { companyName: tenant.name },
      });

      const sigData = `${ts}${method}${path}${body}`;
      const sig = crypto.createHmac('sha256', secretKey).update(sigData).digest('hex');

      const headers = {
        'X-App-Token': appToken!,
        'X-App-Access-Sig': sig,
        'X-App-Access-Ts': ts.toString(),
        'Content-Type': 'application/json',
      };

      const resp = await fetch(`${baseUrl}${path}`, { method, headers, body });
      if (!resp.ok) {
        throw new BadRequestException('Failed to create Sumsub KYB applicant');
      }
      const data = await resp.json() as any;
      applicantId = data.id;

      // Get SDK token
      const tokenPath = `/resources/accessTokens?userId=${tenantId}&levelName=basic-kyb-level`;
      const tokenSig = crypto.createHmac('sha256', secretKey)
        .update(`${ts}POST${tokenPath}`)
        .digest('hex');
      const tokenResp = await fetch(`${baseUrl}${tokenPath}`, {
        method: 'POST',
        headers: {
          'X-App-Token': appToken!,
          'X-App-Access-Sig': tokenSig,
          'X-App-Access-Ts': ts.toString(),
        },
      });
      const tokenData = await tokenResp.json() as any;
      sdkToken = tokenData.token;
    }

    await this.prisma.tenant.update({
      where: { id: tenantId },
      data: {
        sumsubApplicantId: applicantId,
        kybStatus: KycStatus.PENDING,
      },
    });

    return { applicantId, sdkToken };
  }

  async handleKybWebhook(payload: any) {
    const { applicantId, reviewResult, type } = payload;
    if (type !== 'applicantReviewed') return { processed: false };

    const tenant = await this.prisma.tenant.findFirst({
      where: { sumsubApplicantId: applicantId },
    });
    if (!tenant) return { processed: false };

    const status =
      reviewResult?.reviewAnswer === 'GREEN'
        ? KycStatus.VERIFIED
        : KycStatus.REJECTED;

    await this.prisma.tenant.update({
      where: { id: tenant.id },
      data: { kybStatus: status },
    });

    return { processed: true, tenantId: tenant.id, status };
  }

  async inviteMember(tenantId: string, userId: string, dto: InviteMemberDto) {
    await this.assertRole(tenantId, userId, [TenantRole.OWNER, TenantRole.ADMIN]);

    const role = dto.role.toUpperCase() as TenantRole;
    if (!Object.values(TenantRole).includes(role)) {
      throw new BadRequestException(`Invalid role: ${dto.role}`);
    }
    if (role === TenantRole.OWNER) {
      throw new ForbiddenException('Cannot invite as OWNER');
    }

    // Check if user already exists
    const existingUser = await this.prisma.user.findFirst({
      where: { email: dto.email },
    });

    if (existingUser) {
      // Check if already a member
      const existing = await this.prisma.tenantMember.findFirst({
        where: { tenantId, userId: existingUser.id },
      });
      if (existing) throw new ConflictException('User is already a member');

      // Add directly
      const member = await this.prisma.tenantMember.create({
        data: { tenantId, userId: existingUser.id, role },
        include: { user: { select: { id: true, email: true } } },
      });
      return { type: 'added', member };
    }

    // Create pending invite - token must be provided explicitly (no @default in schema)
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    const token = uuidv4();
    const invite = await this.prisma.pendingInvite.create({
      data: { tenantId, email: dto.email, role, expiresAt, token },
    });

    // Send invite email (non-blocking)
    const tenant = await this.prisma.tenant.findUnique({ where: { id: tenantId }, select: { name: true } });
    const inviter = await this.prisma.user.findUnique({ where: { id: userId }, select: { email: true } });
    this.email.sendInvite(dto.email, tenant?.name ?? tenantId, invite.token, inviter?.email ?? 'Taler ID').catch(() => {});

    return { type: 'invited', inviteToken: invite.token, email: dto.email };
  }

  async acceptInvite(token: string, userId: string) {
    const invite = await this.prisma.pendingInvite.findUnique({ where: { token } });
    if (!invite) throw new NotFoundException('Invite not found');
    if (invite.expiresAt < new Date()) throw new BadRequestException('Invite expired');

    // Check user's email matches invite
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.email !== invite.email) {
      throw new ForbiddenException('This invite is not for your account');
    }

    const member = await this.prisma.tenantMember.create({
      data: { tenantId: invite.tenantId, userId, role: invite.role },
    });

    await this.prisma.pendingInvite.delete({ where: { token } });
    return member;
  }

  async changeRole(tenantId: string, requesterId: string, targetUserId: string, dto: ChangeRoleDto) {
    const requesterMember = await this.assertRole(tenantId, requesterId, [TenantRole.OWNER, TenantRole.ADMIN]);

    const newRole = dto.role.toUpperCase() as TenantRole;
    if (!Object.values(TenantRole).includes(newRole)) {
      throw new BadRequestException(`Invalid role: ${dto.role}`);
    }

    const targetMember = await this.prisma.tenantMember.findFirst({
      where: { tenantId, userId: targetUserId },
    });
    if (!targetMember) throw new NotFoundException('Member not found');

    // ADMIN cannot change OWNER's role or assign OWNER role
    if (requesterMember.role === TenantRole.ADMIN) {
      if (targetMember.role === TenantRole.OWNER || newRole === TenantRole.OWNER) {
        throw new ForbiddenException('Admins cannot modify owner role');
      }
    }

    return this.prisma.tenantMember.update({
      where: { id: targetMember.id },
      data: { role: newRole },
    });
  }

  async removeMember(tenantId: string, requesterId: string, targetUserId: string) {
    await this.assertRole(tenantId, requesterId, [TenantRole.OWNER, TenantRole.ADMIN]);

    const targetMember = await this.prisma.tenantMember.findFirst({
      where: { tenantId, userId: targetUserId },
    });
    if (!targetMember) throw new NotFoundException('Member not found');
    if (targetMember.role === TenantRole.OWNER) {
      throw new ForbiddenException('Cannot remove the owner');
    }

    await this.prisma.tenantMember.delete({ where: { id: targetMember.id } });
    return { success: true };
  }

  async getKybStatus(tenantId: string, userId: string) {
    await this.assertMember(tenantId, userId);
    const tenant = await this.prisma.tenant.findUnique({
      where: { id: tenantId },
      select: { kybStatus: true, sumsubApplicantId: true },
    });
    if (!tenant) throw new NotFoundException('Tenant not found');
    return { status: tenant.kybStatus, applicantId: tenant.sumsubApplicantId };
  }

  private async assertMember(tenantId: string, userId: string) {
    const member = await this.prisma.tenantMember.findFirst({
      where: { tenantId, userId },
    });
    if (!member) throw new ForbiddenException('Not a member of this tenant');
    return member;
  }

  private async assertRole(tenantId: string, userId: string, roles: TenantRole[]) {
    const member = await this.prisma.tenantMember.findFirst({
      where: { tenantId, userId },
    });
    if (!member) throw new ForbiddenException('Not a member of this tenant');
    if (!roles.includes(member.role)) {
      throw new ForbiddenException(`Required role: ${roles.join(' or ')}`);
    }
    return member;
  }
}
