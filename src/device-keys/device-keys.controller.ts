import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { DeviceKeysService } from './device-keys.service';
import { RegisterDeviceKeyDto } from './dto/register-device-key.dto';
import { RevokeDeviceKeyDto } from './dto/revoke-device-key.dto';

@Controller('profile')
@UseGuards(JwtAuthGuard)
export class DeviceKeysController {
  constructor(private readonly svc: DeviceKeysService) {}

  @Post('device-keys')
  register(@CurrentUser() user: any, @Body() dto: RegisterDeviceKeyDto) {
    return this.svc.register(user.sub, dto);
  }

  @Get('contacts/:userId/keys')
  listForContact(
    @CurrentUser() user: any,
    @Param('userId') userId: string,
  ) {
    return this.svc.listForContact(user.sub, userId);
  }

  @Post('device-keys/:id/revoke')
  revoke(
    @CurrentUser() user: any,
    @Param('id') id: string,
    @Body() dto: RevokeDeviceKeyDto,
  ) {
    return this.svc.revoke(user.sub, id, dto);
  }
}
