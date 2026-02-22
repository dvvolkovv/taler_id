import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';
import { AdminGuard } from './admin.guard';
import { BlockchainModule } from '../blockchain/blockchain.module';
// PrismaModule is @Global - no need to import here

@Module({
  imports: [
    JwtModule.register({}),
    BlockchainModule,
  ],
  controllers: [AdminController],
  providers: [AdminService, AdminGuard],
})
export class AdminModule {}
