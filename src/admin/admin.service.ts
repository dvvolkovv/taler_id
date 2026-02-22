import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { BlockchainService } from '../blockchain/blockchain.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as fs from 'fs';

@Injectable()
export class AdminService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly blockchain: BlockchainService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async adminLogin(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash) throw new BadRequestException('Invalid credentials');
    if (!user.isAdmin) throw new BadRequestException('Not an admin');
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) throw new BadRequestException('Invalid credentials');

    const privateKeyPath = this.config.get<string>('jwt.privateKeyPath') ?? '';
    const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

    const token = this.jwt.sign(
      { sub: user.id, email: user.email, isAdmin: true },
      { algorithm: 'RS256', privateKey, expiresIn: '8h' } as any,
    );
    return { token };
  }

  async getUsers(search = '', page = 1, limit = 20) {
    const skip = (page - 1) * limit;
    const where: any = { deletedAt: null };
    if (search) {
      where.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { phone: { contains: search } },
      ];
    }
    const [users, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          email: true,
          phone: true,
          emailVerified: true,
          isAdmin: true,
          createdAt: true,
          deletedAt: true,
        },
      }),
      this.prisma.user.count({ where }),
    ]);

    const userIds = users.map((u: any) => u.id);
    const kycRecords = await this.prisma.kycRecord.findMany({
      where: { userId: { in: userIds } },
      select: { userId: true, status: true },
    });
    const kycMap = Object.fromEntries(kycRecords.map((k: any) => [k.userId, k.status]));

    return {
      data: users.map((u: any) => ({ ...u, kycStatus: kycMap[u.id] ?? 'UNVERIFIED' })),
      total,
      page,
      limit,
    };
  }

  async getUserDetail(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        phone: true,
        emailVerified: true,
        isAdmin: true,
        createdAt: true,
        deletedAt: true,
      },
    });
    if (!user) throw new NotFoundException('User not found');

    const kyc = await (this.prisma.kycRecord.findUnique({
      where: { userId },
    }) as Promise<any>).catch(() => null);

    const tenantMembers = await this.prisma.tenantMember.findMany({
      where: { userId },
      include: { tenant: { select: { id: true, name: true, kybStatus: true } } },
    });

    let onChain: any = null;
    try {
      onChain = await this.blockchain.getOnChainVerification(userId);
    } catch {
      onChain = null;
    }

    return {
      ...user,
      kycStatus: kyc?.status ?? 'UNVERIFIED',
      kycRecord: kyc,
      tenants: tenantMembers.map((m: any) => ({
        id: m.tenant.id,
        name: m.tenant.name,
        kybStatus: m.tenant.kybStatus,
        role: m.role,
      })),
      onChain,
    };
  }

  async updateKycStatus(userId: string, status: string) {
    const validStatuses = ['UNVERIFIED', 'PENDING', 'VERIFIED', 'REJECTED'];
    if (!validStatuses.includes(status)) throw new BadRequestException('Invalid status');

    const existing = await this.prisma.kycRecord.findUnique({ where: { userId } });
    if (existing) {
      await this.prisma.kycRecord.update({
        where: { userId },
        data: { status: status as any },
      });
    } else {
      await this.prisma.kycRecord.create({
        data: { userId, status: status as any },
      });
    }
    return { success: true, status };
  }

  async deleteUser(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { deletedAt: new Date() },
    });
    return { success: true };
  }

  async unblockUser(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { deletedAt: null },
    });
    return { success: true };
  }

  async attestUserBlockchain(userId: string, kycStatus: number) {
    if (![1, 2, 3].includes(kycStatus)) throw new BadRequestException('kycStatus must be 1, 2, or 3');
    await this.blockchain.attestVerification(userId, kycStatus as 1 | 2 | 3);
    return { success: true };
  }

  async revokeUserBlockchain(userId: string) {
    await this.blockchain.revokeVerification(userId);
    return { success: true };
  }

  async getTenants(search = '', page = 1, limit = 20) {
    const skip = (page - 1) * limit;
    const where: any = {};
    if (search) {
      where.name = { contains: search, mode: 'insensitive' };
    }
    const [tenants, total] = await Promise.all([
      this.prisma.tenant.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: {
          members: {
            where: { role: 'OWNER' },
            include: { user: { select: { id: true, email: true } } },
          },
          _count: { select: { members: true } },
        },
      }),
      this.prisma.tenant.count({ where }),
    ]);
    return {
      data: tenants.map((t: any) => ({
        id: t.id,
        name: t.name,
        kybStatus: t.kybStatus,
        memberCount: t._count.members,
        owner: t.members[0]?.user ?? null,
        createdAt: t.createdAt,
      })),
      total,
      page,
      limit,
    };
  }

  async getTenantDetail(tenantId: string) {
    const tenant = await this.prisma.tenant.findUnique({
      where: { id: tenantId },
      include: {
        members: {
          include: { user: { select: { id: true, email: true, phone: true } } },
        },
      },
    });
    if (!tenant) throw new NotFoundException('Tenant not found');

    const owner = tenant.members.find((m: any) => m.role === 'OWNER');
    let ownerOnChain: any = null;
    if (owner) {
      try {
        ownerOnChain = await this.blockchain.getOnChainVerification(owner.userId);
      } catch {
        ownerOnChain = null;
      }
    }

    return {
      ...tenant,
      ownerOnChain,
    };
  }

  async updateKybStatus(tenantId: string, status: string) {
    const validStatuses = ['UNVERIFIED', 'PENDING', 'VERIFIED', 'REJECTED'];
    if (!validStatuses.includes(status)) throw new BadRequestException('Invalid status');
    await this.prisma.tenant.update({
      where: { id: tenantId },
      data: { kybStatus: status as any },
    });
    return { success: true, status };
  }

  async attestTenantBlockchain(tenantId: string) {
    const owner = await this.prisma.tenantMember.findFirst({
      where: { tenantId, role: 'OWNER' },
    });
    if (!owner) throw new NotFoundException('Tenant owner not found');
    await this.blockchain.attestKyb(owner.userId, true);
    return { success: true };
  }

  async deleteTenant(tenantId: string) {
    await this.prisma.pendingInvite.deleteMany({ where: { tenantId } });
    await this.prisma.tenantMember.deleteMany({ where: { tenantId } });
    await this.prisma.tenant.delete({ where: { id: tenantId } });
    return { success: true };
  }
}
