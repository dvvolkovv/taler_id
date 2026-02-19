import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { TenantService } from './tenant.service';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { CreateTenantDto, UpdateTenantDto, InviteMemberDto, ChangeRoleDto } from './dto/create-tenant.dto';

@Controller('tenant')
@UseGuards(JwtAuthGuard)
export class TenantController {
  constructor(private readonly tenantService: TenantService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  create(@CurrentUser() user: any, @Body() dto: CreateTenantDto) {
    return this.tenantService.createTenant(user.sub, dto);
  }

  @Get()
  getMyTenants(@CurrentUser() user: any) {
    return this.tenantService.getMyTenants(user.sub);
  }

  @Get(':id')
  getTenant(@Param('id') tenantId: string, @CurrentUser() user: any) {
    return this.tenantService.getTenant(tenantId, user.sub);
  }

  @Put(':id')
  updateTenant(
    @Param('id') tenantId: string,
    @CurrentUser() user: any,
    @Body() dto: UpdateTenantDto,
  ) {
    return this.tenantService.updateTenant(tenantId, user.sub, dto);
  }

  @Post(':id/kyb/start')
  startKyb(@Param('id') tenantId: string, @CurrentUser() user: any) {
    return this.tenantService.startKyb(tenantId, user.sub);
  }

  @Get(':id/kyb/status')
  getKybStatus(@Param('id') tenantId: string, @CurrentUser() user: any) {
    return this.tenantService.getKybStatus(tenantId, user.sub);
  }

  @Post(':id/members/invite')
  inviteMember(
    @Param('id') tenantId: string,
    @CurrentUser() user: any,
    @Body() dto: InviteMemberDto,
  ) {
    return this.tenantService.inviteMember(tenantId, user.sub, dto);
  }

  @Post('invites/:token/accept')
  acceptInvite(@Param('token') token: string, @CurrentUser() user: any) {
    return this.tenantService.acceptInvite(token, user.sub);
  }

  @Put(':id/members/:userId/role')
  changeRole(
    @Param('id') tenantId: string,
    @Param('userId') targetUserId: string,
    @CurrentUser() user: any,
    @Body() dto: ChangeRoleDto,
  ) {
    return this.tenantService.changeRole(tenantId, user.sub, targetUserId, dto);
  }

  @Delete(':id/members/:userId')
  removeMember(
    @Param('id') tenantId: string,
    @Param('userId') targetUserId: string,
    @CurrentUser() user: any,
  ) {
    return this.tenantService.removeMember(tenantId, user.sub, targetUserId);
  }
}
