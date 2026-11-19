import { BadRequestException, Injectable } from '@nestjs/common';
import type { TenantRole } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { loadCompanies } from './company-eligibility';
import {
  CompanySelectionError,
  CompanySelectionInput,
  ResolvedSelection,
  findLastSelection,
  resolveSelection,
  saveSelection,
} from './company-selection';

/** Что экраны согласия (веб и приложение) показывают в блоке «компании». */
export interface CompanyConsentBlock {
  person: { name: string };
  eligible: { id: string; name: string; legal_name: string | null; logo_url: string | null; role: TenantRole }[];
  unverified: { id: string; name: string }[];
  last_selection: { act_as: string; company_ids: string[] } | null;
}

@Injectable()
export class CompanyConsentService {
  constructor(private readonly prisma: PrismaService) {}

  async consentBlock(userId: string, clientId: string): Promise<CompanyConsentBlock> {
    const [{ eligible, unverified }, profile, last] = await Promise.all([
      loadCompanies(this.prisma, userId),
      this.prisma.profile.findUnique({ where: { userId }, select: { firstName: true, lastName: true } }),
      findLastSelection(this.prisma, userId, clientId),
    ]);
    const ids = new Set(eligible.map((c) => c.tenantId));
    return {
      person: { name: [profile?.firstName, profile?.lastName].map((s) => s?.trim()).filter(Boolean).join(' ') },
      eligible: eligible.map((c) => ({
        id: c.tenantId,
        name: c.name,
        legal_name: c.profile.legalName,
        logo_url: c.logoUrl,
        role: c.role,
      })),
      unverified: unverified.map((c) => ({ id: c.tenantId, name: c.name })),
      // Прошлый выбор — только отметки по умолчанию: компании, которые с тех пор
      // перестали подходить, из него выпадают.
      last_selection: last
        ? {
            act_as: last.actAsTenantId !== null && ids.has(last.actAsTenantId) ? last.actAsTenantId : 'person',
            company_ids: last.sharedTenantIds.filter((id) => ids.has(id)),
          }
        : null,
    };
  }

  /** До создания согласия: неподходящая компания — 400, согласия нет. */
  async validate(userId: string, input: CompanySelectionInput): Promise<ResolvedSelection> {
    const { eligible } = await loadCompanies(this.prisma, userId);
    try {
      return resolveSelection(input, new Set(eligible.map((c) => c.tenantId)));
    } catch (e) {
      if (e instanceof CompanySelectionError) throw new BadRequestException(e.message);
      throw e;
    }
  }

  /** Выбор и запись аудита — одной транзакцией: без аудита выбор не сохраняется. */
  async save(args: { grantId: string; userId: string; clientId: string; selection: ResolvedSelection }): Promise<void> {
    const { actAsTenantId, sharedTenantIds } = args.selection;
    await this.prisma.$transaction(async (tx) => {
      await saveSelection(tx, args);
      if (actAsTenantId === null && sharedTenantIds.length === 0) return;
      await tx.auditLog.create({
        data: {
          userId: args.userId,
          action: 'OAUTH_COMPANIES_SHARED',
          meta: {
            grantId: args.grantId,
            clientId: args.clientId,
            actAs: actAsTenantId ?? 'person',
            companyIds: sharedTenantIds,
          },
        },
      });
    });
  }
}
