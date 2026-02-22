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

  async findClient(clientId: string) {
    return this.prisma.oAuthClient.findUnique({ where: { clientId } });
  }
}
