import {
  Controller, Get, Put, Post, Delete, Body, Param, UseGuards,
  UseInterceptors, UploadedFile,
} from "@nestjs/common";
import { FileInterceptor } from "@nestjs/platform-express";
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

  @Put("wallet")
  linkWallet(@Body() dto: LinkWalletDto, @CurrentUser() user: any) {
    return this.profileService.linkWallet(user.sub, dto);
  }

  @Delete("wallet")
  unlinkWallet(@CurrentUser() user: any) {
    return this.profileService.unlinkWallet(user.sub);
  }

  @Get("documents")
  getDocuments(@CurrentUser() user: any) {
    return this.profileService.getDocuments(user.sub);
  }

  @Post("documents")
  @UseInterceptors(FileInterceptor("file"))
  uploadDocument(
    @UploadedFile() file: Express.Multer.File,
    @Body("type") type: string,
    @CurrentUser() user: any,
  ) {
    return this.profileService.uploadDocument(user.sub, file, type);
  }

  @Get("documents/:id/download")
  getDocumentUrl(@Param("id") id: string, @CurrentUser() user: any) {
    return this.profileService.getDocumentDownloadUrl(user.sub, id);
  }

  @Delete("documents/:id")
  deleteDocument(@Param("id") id: string, @CurrentUser() user: any) {
    return this.profileService.deleteDocument(user.sub, id);
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
