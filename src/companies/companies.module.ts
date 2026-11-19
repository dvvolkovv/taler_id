import { Module } from '@nestjs/common';
import { CompanyConsentService } from './company-consent.service';

@Module({
  providers: [CompanyConsentService],
  exports: [CompanyConsentService],
})
export class CompaniesModule {}
