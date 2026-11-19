import { Module } from '@nestjs/common';
import { KycModule } from '../kyc/kyc.module';
import { KybPollerService } from './kyb-poller.service';

@Module({
  imports: [KycModule],
  providers: [KybPollerService],
})
export class KybModule {}
