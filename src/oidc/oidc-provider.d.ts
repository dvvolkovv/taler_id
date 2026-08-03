declare module 'oidc-provider' {
  export default class Provider {
    constructor(issuer: string, configuration?: any);
    proxy: boolean;
    callback(): (req: any, res: any) => void;
    interactionDetails(req: any, res: any): Promise<any>;
    interactionFinished(
      req: any,
      res: any,
      result: any,
      options?: any,
    ): Promise<void>;
    /** Stores the result and resolves with the URL to continue the flow at. */
    interactionResult(
      req: any,
      res: any,
      result: any,
      options?: any,
    ): Promise<string>;
    Grant: any;
  }
}
