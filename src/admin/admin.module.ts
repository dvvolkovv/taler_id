import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';
import { AdminGuard } from './admin.guard';
import { BlockchainModule } from '../blockchain/blockchain.module';
import { SystemChannelModule } from '../system-channel/system-channel.module';
// PrismaModule is @Global - no need to import here

@Module({
  imports: [JwtModule.register({}), BlockchainModule, SystemChannelModule],
  controllers: [AdminController],
  providers: [AdminService, AdminGuard],
})
export class AdminModule {}
