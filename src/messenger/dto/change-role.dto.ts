import { IsString, IsIn } from 'class-validator';

export class ChangeGroupRoleDto {
  @IsString()
  @IsIn(['OWNER', 'ADMIN', 'MEMBER'])
  role: string;
}
