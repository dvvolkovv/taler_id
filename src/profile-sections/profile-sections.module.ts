import { Module } from '@nestjs/common';
import { ProfileSectionsController } from './profile-sections.controller';
import { ProfileSectionsService } from './profile-sections.service';

@Module({
  controllers: [ProfileSectionsController],
  providers: [ProfileSectionsService],
  exports: [ProfileSectionsService],
})
export class ProfileSectionsModule {}
