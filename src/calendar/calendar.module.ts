import { Module } from '@nestjs/common';
import { CalendarController } from './calendar.controller';
import { CalendarService } from './calendar.service';
import { PrismaModule } from '../prisma/prisma.module';
import { FcmService } from '../common/fcm.service';

@Module({
  imports: [PrismaModule],
  controllers: [CalendarController],
  providers: [CalendarService, FcmService],
  exports: [CalendarService],
})
export class CalendarModule {}
