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
  const actAsTenantId = actAs === 'person' ? null : actAs;
  const shared = [...new Set([...(actAsTenantId ? [actAsTenantId] : []), ...(ids as string[])])];
  for (const id of shared) {
    if (!eligibleIds.has(id)) throw new CompanySelectionError(`company ${id} is not available`);
  }
  return { actAsTenantId, sharedTenantIds: shared };
}

type Db = {
  oAuthCompanySelection: {
    deleteMany: (args: any) => Promise<unknown>;
    create: (args: any) => Promise<unknown>;
    findFirst: (args: any) => Promise<any>;
    findUnique: (args: any) => Promise<any>;
  };
};

/**
 * Новая запись на каждое согласие. Экрана отзыва доступа нет, поэтому заодно
 * убираем записи этой пары человек–сайт старше срока жизни согласия.
 */
export async function saveSelection(
  db: Pick<Db, 'oAuthCompanySelection'> | any,
  args: { grantId: string; userId: string; clientId: string; selection: ResolvedSelection },
) {
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

export function findSelection(db: any, grantId: string) {
  return db.oAuthCompanySelection.findUnique({ where: { grantId } });
}

/** Отметки по умолчанию для следующего входа на тот же сайт. */
export function findLastSelection(db: any, userId: string, clientId: string) {
  return db.oAuthCompanySelection.findFirst({
    where: { userId, clientId },
    orderBy: { createdAt: 'desc' },
  });
}
