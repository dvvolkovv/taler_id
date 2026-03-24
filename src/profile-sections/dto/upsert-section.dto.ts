import { IsEnum, IsObject, IsOptional, IsArray, IsString } from 'class-validator';

export enum SectionType {
  VALUES = 'VALUES',
  WORLDVIEW = 'WORLDVIEW',
  SKILLS = 'SKILLS',
  INTERESTS = 'INTERESTS',
  DESIRES = 'DESIRES',
  BACKGROUND = 'BACKGROUND',
  LIKES_DISLIKES = 'LIKES_DISLIKES',
}

export enum SectionVisibility {
  PUBLIC = 'PUBLIC',
  CONTACTS = 'CONTACTS',
  PRIVATE = 'PRIVATE',
}

export class UpsertSectionDto {
  @IsEnum(SectionType)
  type: SectionType;

  @IsObject()
  content: { items: string[]; freeText?: string };

  @IsOptional()
  @IsEnum(SectionVisibility)
  visibility?: SectionVisibility;
}

export class UpdateVisibilityDto {
  @IsEnum(SectionVisibility)
  visibility: SectionVisibility;
}
