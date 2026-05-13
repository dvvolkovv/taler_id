import {
  IsOptional,
  IsNumberString,
  IsString,
  IsBoolean,
} from 'class-validator';

export class AdminCreditDto {
  @IsNumberString()
  amountPlanck!: string;

  @IsString()
  reason!: string;
}

export class AdminDebitDto {
  @IsNumberString()
  amountPlanck!: string;

  @IsString()
  reason!: string;
}

export class AdminUpdatePricebookDto {
  @IsOptional()
  @IsNumberString()
  costUsdPerUnit?: string;

  @IsOptional()
  @IsNumberString()
  markupMultiplier?: string;

  @IsOptional()
  @IsNumberString()
  minReservePlanck?: string;
}

export class AdminUpdateConfigDto {
  @IsOptional()
  @IsNumberString()
  talUsdRate?: string;

  @IsOptional()
  @IsBoolean()
  billingEnforced?: boolean;

  @IsOptional()
  @IsNumberString()
  welcomeBonusPlanck?: string;
}
