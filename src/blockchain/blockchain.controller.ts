import { Controller, Get, Param, NotFoundException } from '@nestjs/common';
import { BlockchainService } from './blockchain.service';

@Controller('kyc/on-chain')
export class BlockchainController {
  constructor(private readonly blockchain: BlockchainService) {}

  /**
   * GET /kyc/on-chain/:userId
   * Public endpoint: anyone can query on-chain KYC status by Taler ID (userId).
   * Returns derived hash + blockchain record — no personal data exposed.
   */
  @Get(':userId')
  async getOnChainStatus(@Param('userId') userId: string) {
    const result = await this.blockchain.getOnChainVerification(userId);
    if (!result) {
      throw new NotFoundException('No on-chain record found for this user');
    }
    return {
      talerId: userId,
      onChain: {
        kycStatus: result.kycStatus,
        kycTimestamp: result.kycTimestamp,
        kybStatus: result.kybStatus,
        isActive: result.isActive,
      },
      statusLabel: {
        0: 'None',
        1: 'Pending',
        2: 'Verified',
        3: 'Rejected',
      }[result.kycStatus] ?? 'Unknown',
    };
  }
}
