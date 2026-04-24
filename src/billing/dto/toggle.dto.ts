import { IsBoolean } from 'class-validator';

export class UpdateToggleDto {
  @IsBoolean()
  enabled!: boolean;
}
