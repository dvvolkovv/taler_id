export class FeatureDisabledException extends Error {
  constructor(public readonly featureKey: string) {
    super(`feature ${featureKey} disabled by user`);
  }
}
