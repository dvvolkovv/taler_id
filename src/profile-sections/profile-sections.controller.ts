import {
  Controller, Get, Put, Delete, Patch, Body, Param, UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { ProfileSectionsService } from './profile-sections.service';
import { UpsertSectionDto, UpdateVisibilityDto, SectionType } from './dto/upsert-section.dto';

@Controller('profile-sections')
@UseGuards(JwtAuthGuard)
export class ProfileSectionsController {
  constructor(private readonly service: ProfileSectionsService) {}

  @Get()
  getMySections(@CurrentUser() user: any) {
    return this.service.getMySections(user.sub);
  }

  @Put()
  upsertSection(@Body() dto: UpsertSectionDto, @CurrentUser() user: any) {
    return this.service.upsertSection(user.sub, dto);
  }

  @Delete(':type')
  deleteSection(@Param('type') type: SectionType, @CurrentUser() user: any) {
    return this.service.deleteSection(user.sub, type);
  }

  @Patch(':type/visibility')
  updateVisibility(
    @Param('type') type: SectionType,
    @Body() dto: UpdateVisibilityDto,
    @CurrentUser() user: any,
  ) {
    return this.service.updateVisibility(user.sub, type, dto.visibility);
  }

  @Get('user/:userId')
  getUserSections(@Param('userId') userId: string, @CurrentUser() user: any) {
    return this.service.getUserSections(user.sub, userId);
  }
}
