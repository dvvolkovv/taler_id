import * as fs from 'fs';
import * as path from 'path';
import { mapWelidCompany } from './welid-company.mapper';

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, '__fixtures__/welid-company-applicant.json'), 'utf8'),
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
  },
  review: { reviewStatus: 'completed', reviewResult: { reviewAnswer: 'GREEN' } },
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
    expect(d.raw).toBe(welidShaped.companyInfo);
  });

  it('keeps missing or blank fields as null instead of guessing', () => {
    const d = mapWelidCompany({ id: 'app-3', companyInfo: { companyName: ' ', incorporatedOn: 'вчера' } });
    expect(d).toMatchObject({ legalName: null, incorporatedOn: null, city: null, country: null });
  });

  it('a GREEN applicant without company details still maps (all nulls, empty raw)', () => {
    const d = mapWelidCompany({ id: 'app-4' });
    expect(d.applicantId).toBe('app-4');
    expect(d.legalName).toBeNull();
    expect(d.raw).toEqual({});
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
  });
});
