/**
 * Анкета компании из welID → снимок реквизитов для CompanyKybProfile.
 * Спека 2026-11-19-companies-oauth-design.md.
 *
 * У welID реквизиты в корневом companyInfo (не в info.companyInfo, как у
 * Sumsub) — проверено на DEV 2026-11-19, фикстура рядом. Ничего не угадываем:
 * нет поля или оно пустое — null. Город — поле места регистрации
 * (registrationLocation), строку адреса не разбираем.
 */
export interface CompanyKybData {
  applicantId: string;
  legalName: string | null;
  registrationNumber: string | null;
  taxId: string | null;
  legalForm: string | null;
  incorporatedOn: Date | null;
  country: string | null;
  city: string | null;
  legalAddress: string | null;
  website: string | null;
  /** Сырой companyInfo из welID без данных владельцев — только реквизиты, не анкета целиком. */
  raw: Record<string, unknown>;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function text(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return s ? s : null;
}

function day(v: unknown): Date | null {
  const s = text(v);
  if (!s || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const d = new Date(`${s}T00:00:00.000Z`);
  if (Number.isNaN(d.getTime())) return null;
  // 2015-02-31 Date молча превращает в 3 марта — такую дату не принимаем.
  if (d.toISOString().slice(0, 10) !== s) return null;
  if (d.getUTCFullYear() < 1800 || d.getTime() > Date.now()) return null;
  return d;
}

function httpUrl(v: unknown): string | null {
  const s = text(v);
  // Наружу уходит как проверенное — только http(s), никаких javascript: и голых доменов.
  return s && /^https?:\/\//i.test(s) ? s : null;
}

// Персональные данные владельцев не храним — в снимке только реквизиты компании.
const OWNER_KEYS = new Set(['beneficiaries', 'controlScheme']);

export function mapWelidCompany(applicant: unknown): CompanyKybData {
  const a: Record<string, unknown> = isPlainObject(applicant) ? applicant : {};
  const ci: Record<string, unknown> = isPlainObject(a.companyInfo)
    ? a.companyInfo
    : {};
  return {
    applicantId:
      typeof a.id === 'string' || typeof a.id === 'number' ? String(a.id) : '',
    legalName: text(ci.companyName),
    registrationNumber: text(ci.registrationNumber),
    taxId: text(ci.taxId),
    legalForm: text(ci.type),
    incorporatedOn: day(ci.incorporatedOn),
    country: text(ci.country),
    city: text(ci.registrationLocation),
    legalAddress: text(ci.legalAddress),
    website: httpUrl(ci.website),
    raw: Object.fromEntries(
      Object.entries(ci).filter(([k]) => !OWNER_KEYS.has(k)),
    ),
  };
}
