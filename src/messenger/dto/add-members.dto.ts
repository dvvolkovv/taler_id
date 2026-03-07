import { IsArray, ArrayMinSize, IsString } from "class-validator";

export class AddMembersDto {
  @IsArray()
  @ArrayMinSize(1)
  @IsString({ each: true })
  userIds: string[];
}
