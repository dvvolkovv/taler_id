import { Injectable, Inject } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

export const OIDC_PROVIDER = 'OIDC_PROVIDER';

@Injectable()
export class OidcService {
  constructor(
    @Inject(OIDC_PROVIDER) private readonly provider: any,
    private readonly prisma: PrismaService,
  ) {}

  getProvider() {
    return this.provider;
  }

  async getInteractionDetails(req: any, res: any) {
    return this.provider.interactionDetails(req, res);
  }

  async finishInteraction(req: any, res: any, result: any) {
    return this.provider.interactionFinished(req, res, result, {
      mergeWithLastSubmission: false,
    });
  }

  /**
   * Stores the interaction result and returns the URL to continue at, instead
   * of writing a redirect response like `finishInteraction` does.
   *
   * The consent page needs this: it submits over `fetch`, and the redirect
   * chain ends at the client's own callback — a cross-origin hop that our CSP
   * `connect-src` blocks, so the flow died silently at "Allow". Handing the URL
   * back as JSON lets the page do a top-level navigation, which CSP does not
   * police.
   */
  async resolveInteractionRedirect(req: any, res: any, result: any) {
    return this.provider.interactionResult(req, res, result, {
      mergeWithLastSubmission: false,
    });
  }

  async findClient(clientId: string) {
    return this.prisma.oAuthClient.findUnique({ where: { clientId } });
  }
}
