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
  /** Известные реквизиты из companyInfo welID — без данных людей, не анкета целиком. */
  raw: Record<string, unknown>;
}

// Без проверки прототипа: объекты из Response.json() под Jest — из другого realm.
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
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
  if (!s || !/^https?:\/\//i.test(s)) return null;
  try {
    const u = new URL(s);
    const ok =
      (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname !== '';
    return ok ? s : null;
  } catch {
    return null;
  }
}

// Только известные реквизиты компании: новое поле welID с данными людей
// (бенефициары, директора…) не должно молча попасть в бессрочный снимок.
const COMPANY_FIELDS = new Set([
  'companyName',
  'registrationNumber',
  'country',
  'legalAddress',
  'postalAddress',
  'incorporatedOn',
  'type',
  'email',
  'phone',
  'website',
  'registrationLocation',
  'taxId',
]);

export function mapWelidCompany(applicant: unknown): CompanyKybData {
  const a: Record<string, unknown> = isRecord(applicant) ? applicant : {};
  const ci: Record<string, unknown> = isRecord(a.companyInfo)
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
      Object.entries(ci).filter(([k]) => COMPANY_FIELDS.has(k)),
    ),
  };
}
