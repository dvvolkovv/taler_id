export class BalanceResponseDto {
  balancePlanck!: string;
  balanceMicroTal!: string;
  recentTx!: Array<{
    id: string;
    type: string;
    amountPlanck: string;
    featureKey: string | null;
    createdAt: string;
  }>;
}
