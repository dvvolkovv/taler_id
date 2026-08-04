import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { PrismaModule } from '../prisma/prisma.module';
import { RedisModule } from '../redis/redis.module';
import { SystemChannelModule } from '../system-channel/system-channel.module';
import { DeviceApprovalService } from './device-approval.service';
import { TrustedDeviceService } from './trusted-device.service';
// FcmService не завёрнут в общий модуль — каждый потребитель объявляет его сам.
import { FcmService } from '../common/fcm.service';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({}),
    PrismaModule,
    RedisModule,
    SystemChannelModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    DeviceApprovalService,
    TrustedDeviceService,
    FcmService,
  ],
  exports: [AuthService, JwtStrategy, DeviceApprovalService],
})
export class AuthModule {}
