import { ArrayMaxSize, ArrayMinSize, IsArray, IsUUID } from 'class-validator';

export class InviteUsersDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(7)
  @IsUUID('4', { each: true })
  userIds!: string[];
}
