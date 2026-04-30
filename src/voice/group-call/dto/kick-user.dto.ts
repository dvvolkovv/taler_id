import { IsUUID } from 'class-validator';

export class KickUserDto {
  @IsUUID('4')
  userId!: string;
}
