import * as fs from 'fs';
import * as path from 'path';
import * as vm from 'vm';
import { mapWelidCompany } from './welid-company.mapper';

const fixture: unknown = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '__fixtures__/welid-company-applicant.json'),
    'utf8',
  ),
);

// Формат welID (разведка на DEV 2026-11-19): реквизиты в корневом
// companyInfo, а не в Sumsub-овском info.companyInfo; структурного адреса нет,
// место регистрации — registrationLocation.
const welidShaped = {
  id: 'app-1',
  externalUserId: 'tenant-1',
  type: 'company',
  companyInfo: {
    companyName: '  ООО «Ромашка» ',
    registrationNumber: '1027700132195',
    country: 'RUS',
    legalAddress: 'Москва, ул. Пробная, 1',
    incorporatedOn: '2015-03-02',
    type: 'LLC',
    taxId: '7701234567',
    website: 'https://romashka.example',
    registrationLocation: 'Москва',
    controlScheme: null,
    beneficiaries: [],
  },
  review: {
    reviewStatus: 'completed',
    reviewResult: { reviewAnswer: 'GREEN' },
  },
};

describe('mapWelidCompany', () => {
  it('takes company details from companyInfo', () => {
    const d = mapWelidCompany(welidShaped);
    expect(d).toMatchObject({
      applicantId: 'app-1',
      legalName: 'ООО «Ромашка»',
      registrationNumber: '1027700132195',
      taxId: '7701234567',
      legalForm: 'LLC',
      country: 'RUS',
      city: 'Москва',
      legalAddress: 'Москва, ул. Пробная, 1',
      website: 'https://romashka.example',
    });
    expect(d.incorporatedOn?.toISOString()).toBe('2015-03-02T00:00:00.000Z');
    // Храним только реквизиты компании, не анкету целиком (риск-метки, скоринг,
    // бенефициары и прочее бессрочно держать незачем).
    const details: Record<string, unknown> = { ...welidShaped.companyInfo };
    delete details.beneficiaries;
    delete details.controlScheme;
    expect(d.raw).toEqual(details);
    expect(d.raw).not.toBe(welidShaped.companyInfo);
  });

  it('drops personal data of owners (beneficiaries, controlScheme) from raw', () => {
    const d = mapWelidCompany({
      id: 'app-5',
      companyInfo: {
        companyName: 'ООО «Ромашка»',
        beneficiaries: [{ firstName: 'Иван' }],
        controlScheme: 'x',
      },
    });
    expect(d.raw).toEqual({ companyName: 'ООО «Ромашка»' });
    expect(d.raw).not.toHaveProperty('beneficiaries');
    expect(d.raw).not.toHaveProperty('controlScheme');
  });

  it('stores only known company fields — an unknown new field is not kept', () => {
    const d = mapWelidCompany({
      id: 'app-11',
      companyInfo: {
        companyName: 'ООО «Ромашка»',
        taxId: '7701234567',
        directors: [{ name: 'Иван' }],
      },
    });
    expect(d.raw).toEqual({
      companyName: 'ООО «Ромашка»',
      taxId: '7701234567',
    });
    expect(d.raw).not.toHaveProperty('directors');
  });

  it('accepts objects from another realm (Response.json() under Jest)', () => {
    const foreign: unknown = vm.runInNewContext(
      '({ id: "app-12", companyInfo: { companyName: "ООО «Ромашка»" } })',
    );
    const d = mapWelidCompany(foreign);
    expect(d.applicantId).toBe('app-12');
    expect(d.legalName).toBe('ООО «Ромашка»');
    expect(d.raw).toEqual({ companyName: 'ООО «Ромашка»' });
  });

  it('keeps missing or blank fields as null instead of guessing', () => {
    const d = mapWelidCompany({
      id: 'app-3',
      companyInfo: { companyName: ' ', incorporatedOn: 'вчера' },
    });
    expect(d).toMatchObject({
      legalName: null,
      incorporatedOn: null,
      city: null,
      country: null,
    });
  });

  it('a non-string value is null, not stringified', () => {
    const d = mapWelidCompany({
      id: 'app-6',
      companyInfo: { taxId: 7701234567 },
    });
    expect(d.taxId).toBeNull();
  });

  it.each([
    ['impossible calendar date', '2015-02-31'],
    ['year before 1800', '1799-12-31'],
    ['not ISO', '02.03.2015'],
    ['with time part', '2015-03-02T00:00:00Z'],
  ])('incorporatedOn: %s (%s) → null', (_label, value) => {
    const d = mapWelidCompany({
      id: 'app-7',
      companyInfo: { incorporatedOn: value },
    });
    expect(d.incorporatedOn).toBeNull();
  });

  it('incorporatedOn in the future → null', () => {
    const next = new Date();
    next.setUTCFullYear(next.getUTCFullYear() + 1);
    const d = mapWelidCompany({
      id: 'app-8',
      companyInfo: { incorporatedOn: next.toISOString().slice(0, 10) },
    });
    expect(d.incorporatedOn).toBeNull();
  });

  it.each([
    ['javascript:alert(1)'],
    ['romashka.example'],
    ['ftp://romashka.example'],
    ['https://'],
    ['https://exa mple.com'],
  ])('website %s → null (only valid http/https URLs)', (value) => {
    const d = mapWelidCompany({ id: 'app-9', companyInfo: { website: value } });
    expect(d.website).toBeNull();
  });

  it('website scheme check is case-insensitive and trims', () => {
    const d = mapWelidCompany({
      id: 'app-10',
      companyInfo: { website: '  HTTP://Romashka.example ' },
    });
    expect(d.website).toBe('HTTP://Romashka.example');
  });

  it.each([
    ['a string', 'oops'],
    ['an array', []],
    ['a number', 42],
    ['null', null],
  ])('companyInfo that is %s is treated as empty', (_label, value) => {
    const d = mapWelidCompany({ id: 'a', companyInfo: value });
    expect(d.raw).toEqual({});
    expect(d.legalName).toBeNull();
  });

  it('a GREEN applicant without company details still maps (all nulls, empty raw)', () => {
    const d = mapWelidCompany({ id: 'app-4' });
    expect(d).toEqual({
      applicantId: 'app-4',
      legalName: null,
      registrationNumber: null,
      taxId: null,
      legalForm: null,
      incorporatedOn: null,
      country: null,
      city: null,
      legalAddress: null,
      website: null,
      raw: {},
    });
  });

  it('reads the real welID answer captured on DEV', () => {
    const d = mapWelidCompany(fixture);
    expect(d.applicantId).toBe('d4bc40632a73404c972c42c3c3039d95');
    expect(d).toMatchObject({
      legalName: 'ООО «Пробная Ромашка»',
      registrationNumber: '1027700132195',
      country: 'RUS',
      taxId: '7701234567',
      legalForm: 'LLC',
    });
    expect(d.city).toBeNull(); // registrationLocation в фикстуре пустое
    expect(d.raw).not.toHaveProperty('beneficiaries');
    expect(d.raw).not.toHaveProperty('controlScheme');
  });
});
