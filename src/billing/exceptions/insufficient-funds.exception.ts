export class InsufficientFundsException extends Error {
  constructor(
    public readonly featureKey: string,
    public readonly requiredPlanck: bigint,
    public readonly availablePlanck: bigint,
    public readonly suggestedPackage?: string,
  ) {
    super(`insufficient funds for ${featureKey}: need ${requiredPlanck}, have ${availablePlanck}`);
  }
}
