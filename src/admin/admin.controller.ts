import {
  Controller, Get, Post, Patch, Delete, Param, Query, Body,
  UseGuards, HttpCode, HttpStatus,
} from '@nestjs/common';
import { AdminService } from './admin.service';
import { AdminGuard } from './admin.guard';

@Controller('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Post('auth/login')
  @HttpCode(HttpStatus.OK)
  login(@Body() body: { email: string; password: string }) {
    return this.adminService.adminLogin(body.email, body.password);
  }

  @Get('users')
  @UseGuards(AdminGuard)
  getUsers(
    @Query('search') search = '',
    @Query('page') page = '1',
    @Query('limit') limit = '20',
  ) {
    return this.adminService.getUsers(search, parseInt(page), parseInt(limit));
  }

  @Get('users/:id')
  @UseGuards(AdminGuard)
  getUserDetail(@Param('id') id: string) {
    return this.adminService.getUserDetail(id);
  }

  @Patch('users/:id/kyc-status')
  @UseGuards(AdminGuard)
  updateKycStatus(@Param('id') id: string, @Body() body: { status: string }) {
    return this.adminService.updateKycStatus(id, body.status);
  }

  @Post('users/:id/blockchain/attest')
  @UseGuards(AdminGuard)
  @HttpCode(HttpStatus.OK)
  attestUser(@Param('id') id: string, @Body() body: { kycStatus: number }) {
    return this.adminService.attestUserBlockchain(id, body.kycStatus);
  }

  @Post('users/:id/blockchain/revoke')
  @UseGuards(AdminGuard)
  @HttpCode(HttpStatus.OK)
  revokeUser(@Param('id') id: string) {
    return this.adminService.revokeUserBlockchain(id);
  }

  @Delete('users/:id')
  @UseGuards(AdminGuard)
  deleteUser(@Param('id') id: string) {
    return this.adminService.deleteUser(id);
  }

  @Post('users/:id/unblock')
  @UseGuards(AdminGuard)
  @HttpCode(HttpStatus.OK)
  unblockUser(@Param('id') id: string) {
    return this.adminService.unblockUser(id);
  }

  @Get('tenants')
  @UseGuards(AdminGuard)
  getTenants(
    @Query('search') search = '',
    @Query('page') page = '1',
    @Query('limit') limit = '20',
  ) {
    return this.adminService.getTenants(search, parseInt(page), parseInt(limit));
  }

  @Get('tenants/:id')
  @UseGuards(AdminGuard)
  getTenantDetail(@Param('id') id: string) {
    return this.adminService.getTenantDetail(id);
  }

  @Patch('tenants/:id/kyb-status')
  @UseGuards(AdminGuard)
  updateKybStatus(@Param('id') id: string, @Body() body: { status: string }) {
    return this.adminService.updateKybStatus(id, body.status);
  }

  @Post('tenants/:id/blockchain/attest')
  @UseGuards(AdminGuard)
  @HttpCode(HttpStatus.OK)
  attestTenant(@Param('id') id: string) {
    return this.adminService.attestTenantBlockchain(id);
  }

  @Delete('tenants/:id')
  @UseGuards(AdminGuard)
  deleteTenant(@Param('id') id: string) {
    return this.adminService.deleteTenant(id);
  }
}
