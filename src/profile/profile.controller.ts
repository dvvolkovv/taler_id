import {
  Controller, Get, Put, Patch, Post, Delete, Body, Param, UseGuards,
  UseInterceptors, UploadedFile,
} from "@nestjs/common";
import { FileInterceptor } from "@nestjs/platform-express";
import { diskStorage } from "multer";
import { extname } from "path";
import { v4 as uuidv4 } from "uuid";
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

  @Get(':userId')
  getPublicProfile(@Param('userId') userId: string) {
    return this.profileService.getPublicProfile(userId);
  }

  @Delete()
  deleteAccount(@CurrentUser() user: any) {
    return this.profileService.deleteAccount(user.sub);
  }

  @Patch()
  updateProfilePatch(@Body() dto: UpdateProfileDto, @CurrentUser() user: any) {
    return this.profileService.updateProfile(user.sub, dto);
  }

  @Patch('username')
  updateUsername(@Body('username') username: string, @CurrentUser() user: any) {
    return this.profileService.updateUsername(user.sub, username);
  }

  @Post("avatar")
  @UseInterceptors(
    FileInterceptor("file", {
      storage: diskStorage({
        destination: "/home/dvolkov/taler-id/uploads/avatars",
        filename: (_req, file, cb) => {
          cb(null, `${uuidv4()}${extname(file.originalname)}`);
        },
      }),
      limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
      fileFilter: (_req, file, cb) => {
        if (!file.mimetype.match(/^image\//)) {
          return cb(new Error("Only image files are allowed"), false);
        }
        cb(null, true);
      },
    }),
  )
  uploadAvatar(@UploadedFile() file: Express.Multer.File, @CurrentUser() user: any) {
    return this.profileService.uploadAvatar(user.sub, file.filename);
  }

  // ── Video Backgrounds ──────────────────────────────────────────────

  @Get('backgrounds')
  getBackgrounds(@CurrentUser() user: any) {
    return this.profileService.getBackgrounds(user.sub);
  }

  @Post('backgrounds')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: require('multer').memoryStorage(),
      limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
      fileFilter: (_req, file, cb) => {
        if (!file.mimetype.match(/^image\//)) {
          return cb(new Error('Only image files are allowed'), false);
        }
        cb(null, true);
      },
    }),
  )
  uploadBackground(@UploadedFile() file: Express.Multer.File, @CurrentUser() user: any) {
    return this.profileService.uploadBackground(user.sub, file);
  }

  @Delete('backgrounds/:id')
  deleteBackground(@Param('id') id: string, @CurrentUser() user: any) {
    return this.profileService.deleteBackground(user.sub, id);
  }
}
