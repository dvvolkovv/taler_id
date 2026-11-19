import type { OAuthCompanySelection, Prisma } from '@prisma/client';
import { SELECTION_TTL_DAYS } from './companies.constants';

/** Как выбор приходит со страницы согласия или из приложения. */
export interface CompanySelectionInput {
  /** 'person' или id компании; не пришло — физлицо. */
  actAs?: unknown;
  companyIds?: unknown;
}

export interface ResolvedSelection {
  actAsTenantId: string | null;
  sharedTenantIds: string[];
}

export class CompanySelectionError extends Error {}

/**
 * Проверка выбора против подходящих компаний — странице не верим.
 * Компания, от имени которой входят, передаётся всегда и идёт первой.
 */
export function resolveSelection(
  input: CompanySelectionInput,
  eligibleIds: ReadonlySet<string>,
): ResolvedSelection {
  const actAs = input.actAs ?? 'person';
  if (typeof actAs !== 'string') throw new CompanySelectionError('act_as must be a string');
  const ids = input.companyIds ?? [];
  if (!Array.isArray(ids) || ids.some((x) => typeof x !== 'string')) {
    throw new CompanySelectionError('company_ids must be an array of strings');
  }
  // Всё, что не 'person', — id компании, включая пустую строку: она пройдёт
  // проверку ниже и получит отказ, а не станет тихим «физлицом».
  const actAsTenantId = actAs === 'person' ? null : actAs;
  const shared = [
    ...new Set([...(actAsTenantId !== null ? [actAsTenantId] : []), ...(ids as string[])]),
  ];
  for (const id of shared) {
    // id в текст не кладём: сообщение уходит телом 400, а прислать могут что угодно.
    if (!eligibleIds.has(id)) throw new CompanySelectionError('company is not available');
  }
  return { actAsTenantId, sharedTenantIds: shared };
}

/** PrismaService, PrismaClient и клиент транзакции подходят одинаково. */
type SelectionDb = Pick<Prisma.TransactionClient, 'oAuthCompanySelection'>;

/**
 * Новая запись на каждое согласие. Экрана отзыва доступа нет, поэтому заодно
 * убираем записи этой пары человек–сайт старше срока жизни согласия.
 */
export async function saveSelection(
  db: SelectionDb,
  args: { grantId: string; userId: string; clientId: string; selection: ResolvedSelection },
): Promise<void> {
  const cutoff = new Date(Date.now() - SELECTION_TTL_DAYS * 24 * 60 * 60 * 1000);
  await db.oAuthCompanySelection.deleteMany({
    where: { userId: args.userId, clientId: args.clientId, createdAt: { lt: cutoff } },
  });
  await db.oAuthCompanySelection.create({
    data: {
      grantId: args.grantId,
      userId: args.userId,
      clientId: args.clientId,
      actAsTenantId: args.selection.actAsTenantId,
      sharedTenantIds: args.selection.sharedTenantIds,
    },
  });
}

export function findSelection(
  db: SelectionDb,
  grantId: string,
): Promise<OAuthCompanySelection | null> {
  return db.oAuthCompanySelection.findUnique({ where: { grantId } });
}

/** Отметки по умолчанию для следующего входа на тот же сайт. */
export function findLastSelection(
  db: SelectionDb,
  userId: string,
  clientId: string,
): Promise<OAuthCompanySelection | null> {
  // grantId — второй ключ, чтобы при одинаковом createdAt ответ не плавал.
  return db.oAuthCompanySelection.findFirst({
    where: { userId, clientId },
    orderBy: [{ createdAt: 'desc' }, { grantId: 'desc' }],
  });
}
