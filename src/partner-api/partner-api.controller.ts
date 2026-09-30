import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Patch,
  Post,
  Put,
  Query,
  Req,
} from '@nestjs/common';
import type { PartnerRecord } from '../partner-core/partner-registry.service';
import { DeleteUserQueryDto } from './dto/delete-user-query.dto';
import { PatchUserDto } from './dto/patch-user.dto';
import { ProvisionUserDto } from './dto/provision-user.dto';
import { VerifyLinkCodeDto } from './dto/verify-link-code.dto';
import { assertExternalId } from './external-id.util';
import { PartnerApi } from './partner-api.decorator';
import { PartnerContactsService } from './partner-contacts.service';
import { PartnerLinkCodeService } from './partner-link-code.service';
import { PartnerRateBucket } from './partner-rate-limit.guard';
import { PartnerUsersService } from './partner-users.service';

interface PartnerRequest {
  partner: PartnerRecord;
  ip?: string;
}

/**
 * Партнёрский API мессенджера. Зовёт только сервер партнёра с ключом.
 * @PartnerApi(): проверка ключа, лимит по партнёру вместо глобальных лимитов
 * по IP (весь партнёр ходит с одного адреса) — см. partner-api.decorator.ts.
 * Документация для партнёров: docs/partner-messenger-api.md
 */
@Controller('partner/v1')
@PartnerApi()
export class PartnerApiController {
  constructor(
    private readonly users: PartnerUsersService,
    private readonly codes: PartnerLinkCodeService,
    private readonly contacts: PartnerContactsService,
  ) {}

  @Post('users')
  @HttpCode(200)
  provision(@Req() req: PartnerRequest, @Body() dto: ProvisionUserDto) {
    return this.users.provision(req.partner, dto, req.ip);
  }

  @Get('users/:externalId')
  getUser(@Req() req: PartnerRequest, @Param('externalId') externalId: string) {
    return this.users.getUser(req.partner, assertExternalId(externalId));
  }

  @Patch('users/:externalId')
  patchUser(
    @Req() req: PartnerRequest,
    @Param('externalId') externalId: string,
    @Body() dto: PatchUserDto,
  ) {
    return this.users.patchUser(req.partner, assertExternalId(externalId), dto, req.ip);
  }

  @Delete('users/:externalId')
  @HttpCode(204)
  async deleteUser(
    @Req() req: PartnerRequest,
    @Param('externalId') externalId: string,
    @Query() query: DeleteUserQueryDto,
  ): Promise<void> {
    await this.users.deleteUser(req.partner, assertExternalId(externalId), query.deleteAccount === 'true', req.ip);
  }

  @Post('users/:externalId/link-code')
  @HttpCode(200)
  sendLinkCode(@Req() req: PartnerRequest, @Param('externalId') externalId: string) {
    return this.codes.send(req.partner, assertExternalId(externalId), req.ip);
  }

  @Post('users/:externalId/link-code/verify')
  @HttpCode(200)
  verifyLinkCode(
    @Req() req: PartnerRequest,
    @Param('externalId') externalId: string,
    @Body() dto: VerifyLinkCodeDto,
  ) {
    return this.codes.verify(req.partner, assertExternalId(externalId), dto.code, req.ip);
  }

  @Post('users/:externalId/token')
  @HttpCode(200)
  @PartnerRateBucket('token')
  token(@Req() req: PartnerRequest, @Param('externalId') externalId: string) {
    return this.users.issueToken(req.partner, assertExternalId(externalId));
  }

  @Put('contacts/:a/:b')
  putContact(@Req() req: PartnerRequest, @Param('a') a: string, @Param('b') b: string) {
    return this.contacts.put(req.partner, a, b, req.ip);
  }

  @Delete('contacts/:a/:b')
  removeContact(@Req() req: PartnerRequest, @Param('a') a: string, @Param('b') b: string) {
    return this.contacts.remove(req.partner, a, b, req.ip);
  }
}
