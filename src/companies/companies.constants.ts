import { TenantRole } from '@prisma/client';

/**
 * Вход от имени компании и передача проверенных компаний сайтам.
 * Спека: docs/superpowers/specs/2026-11-19-companies-oauth-design.md
 */

/** Scope, под которым сайт получает `acting_as` и `companies` в /oauth/me. */
export const COMPANIES_SCOPE = 'companies';

/** Кто может войти от имени компании и передать её данные. */
export const COMPANY_ACTOR_ROLES: readonly TenantRole[] = [TenantRole.OWNER, TenantRole.ADMIN];

/** Столько живёт согласие (ttl.Grant провайдера); выбор старше не нужен. */
export const SELECTION_TTL_DAYS = 30;
