import { IsString, Length } from 'class-validator';

export class ApprovalTokenDto {
  @IsString()
  approvalToken: string;
}

export class ApprovalCodeDto {
  @IsString()
  approvalToken: string;

  @IsString()
  @Length(6, 6)
  code: string;
}
