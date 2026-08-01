import { Module } from '@nestjs/common';
import { TasksService } from './tasks.service';

// PrismaService is provided by the @Global PrismaModule.
@Module({
  providers: [TasksService],
  exports: [TasksService],
})
export class TasksModule {}
