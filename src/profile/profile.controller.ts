import {
  Controller, Get, Put, Delete, Body, Param, UseGuards,
} from "@nestjs/common";
import { JwtAuthGuard } from "../common/guards/jwt-auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { ProfileService } from "./profile.service";
import { UpdateProfileDto, LinkWalletDto } from "./dto/update-profile.dto";

@Controller("profile")
@UseGuards(JwtAuthGuard)
export class ProfileController {
  constructor(private readonly profileService: ProfileService) {}

  @Get()
  getProfile(@CurrentUser() user: any) {
    return this.profileService.getProfile(user.sub);
  }

  @Put()
  updateProfile(@Body() dto: UpdateProfileDto, @CurrentUser() user: any) {
    return this.profileService.updateProfile(user.sub, dto);
  }

  @Put("phone")
  updatePhone(@Body() body: { phone?: string }, @CurrentUser() user: any) {
    return this.profileService.updatePhone(user.sub, body.phone);
  }

  @Put("wallet")
  linkWallet(@Body() dto: LinkWalletDto, @CurrentUser() user: any) {
    return this.profileService.linkWallet(user.sub, dto);
  }

  @Delete("wallet")
  unlinkWallet(@CurrentUser() user: any) {
    return this.profileService.unlinkWallet(user.sub);
  }

  @Get("export")
  exportData(@CurrentUser() user: any) {
    return this.profileService.exportData(user.sub);
  }

  @Delete()
  deleteAccount(@CurrentUser() user: any) {
    return this.profileService.deleteAccount(user.sub);
  }
}
