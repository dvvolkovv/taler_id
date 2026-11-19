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
  /** Сырой companyInfo из welID — только реквизиты, не анкета целиком. */
  raw: Record<string, unknown>;
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
  return Number.isNaN(d.getTime()) ? null : d;
}

export function mapWelidCompany(applicant: any): CompanyKybData {
  const ci = applicant?.companyInfo ?? {};
  return {
    applicantId: String(applicant?.id ?? ''),
    legalName: text(ci.companyName),
    registrationNumber: text(ci.registrationNumber),
    taxId: text(ci.taxId),
    legalForm: text(ci.type),
    incorporatedOn: day(ci.incorporatedOn),
    country: text(ci.country),
    city: text(ci.registrationLocation),
    legalAddress: text(ci.legalAddress),
    website: text(ci.website),
    raw: ci,
  };
}
