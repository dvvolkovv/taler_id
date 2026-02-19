import { Injectable, BadRequestException, NotFoundException, Logger } from "@nestjs/common";
import { BlockchainService } from "../blockchain/blockchain.service";
import { ConfigService } from "@nestjs/config";
import { PrismaService } from "../prisma/prisma.service";
import * as crypto from "crypto";
import { EmailService } from "../email/email.service";

@Injectable()
export class KycService {
  private readonly logger = new Logger(KycService.name);

  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
    private blockchain: BlockchainService,
    private email: EmailService,
  ) {}

  async startKyc(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException("User not found");

    // Create Sumsub applicant
    const applicantId = await this.createSumsubApplicant(userId, user.email || user.phone || "");

    await this.prisma.kycRecord.upsert({
      where: { userId },
      create: { userId, sumsubApplicantId: applicantId, status: "PENDING" },
      update: { sumsubApplicantId: applicantId, status: "PENDING" },
    });

    // Get SDK token for frontend
    const sdkToken = await this.getSumsubSdkToken(applicantId);

    return { sumsubApplicantId: applicantId, sdkToken, status: "PENDING" };
  }

  async getKycStatus(userId: string) {
    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    if (!kyc) return { status: "UNVERIFIED" };
    return {
      status: kyc.status,
      verifiedAt: kyc.verifiedAt,
      rejectionReason: kyc.rejectionReason,
    };
  }

  async handleWebhook(body: Buffer, signature: string) {
    // Verify Sumsub webhook signature
    const secretKey = this.configService.get<string>("SUMSUB_SECRET_KEY") || process.env.SUMSUB_SECRET_KEY || "";
    const expectedSignature = crypto
      .createHmac("sha256", secretKey)
      .update(body)
      .digest("hex");

    if (signature !== expectedSignature) {
      throw new BadRequestException("Invalid webhook signature");
    }

    const payload = JSON.parse(body.toString());
    const { applicantId, type, reviewResult } = payload;

    if (!applicantId) return { received: true };

    const kyc = await this.prisma.kycRecord.findFirst({
      where: { sumsubApplicantId: applicantId },
    });
    if (!kyc) return { received: true };

    if (type === "applicantReviewed") {
      if (reviewResult?.reviewAnswer === "GREEN") {
        const updated = await this.prisma.kycRecord.update({
          where: { id: kyc.id },
          data: { status: "VERIFIED", verifiedAt: new Date(), rejectionReason: null },
          include: { user: { select: { id: true } } },
        });

        // Send email notification (async, non-blocking)
        this.prisma.user.findUnique({ where: { id: updated.userId } }).then((u) => {
          if (u?.email) this.email.sendKycStatusUpdate(u.email, 'VERIFIED').catch(() => {});
        }).catch(() => {});

        // Attest KYC verification on Taler blockchain (async, non-blocking)
        this.blockchain.attestVerification(updated.userId, 2).then((result) => {
          if (result) {
            this.logger.log(`On-chain KYC attestation: userId=${updated.userId} tx=${result.txHash}`);
          }
        }).catch((err) => {
          this.logger.error(`On-chain attestation failed for ${updated.userId}: ${err.message}`);
        });
      } else if (reviewResult?.reviewAnswer === "RED") {
        const reason = reviewResult?.rejectLabels?.join(", ") || "Verification failed";
        await this.prisma.kycRecord.update({
          where: { id: kyc.id },
          data: { status: "REJECTED", rejectionReason: reason },
        });
        // Send rejection email (async, non-blocking)
        this.prisma.user.findUnique({ where: { id: kyc.userId } }).then((u) => {
          if (u?.email) this.email.sendKycStatusUpdate(u.email, 'REJECTED', reason).catch(() => {});
        }).catch(() => {});
      }
    } else if (type === "applicantPending") {
      await this.prisma.kycRecord.update({
        where: { id: kyc.id },
        data: { status: "PENDING" },
      });
    }

    return { received: true };
  }

  private async createSumsubApplicant(userId: string, email: string): Promise<string> {
    const appToken = process.env.SUMSUB_APP_TOKEN || "";
    const secretKey = process.env.SUMSUB_SECRET_KEY || "";
    const baseUrl = process.env.SUMSUB_BASE_URL || "https://api.sumsub.com";

    const ts = Math.floor(Date.now() / 1000).toString();
    const method = "POST";
    const urlPath = "/resources/applicants?levelName=basic-kyc-level";
    const body = JSON.stringify({ externalUserId: userId, email });

    const signature = crypto
      .createHmac("sha256", secretKey)
      .update(ts + method + urlPath + body)
      .digest("hex");

    // In test/dev mode, return a mock applicant ID
    if (appToken === "test_token" || !appToken) {
      return "mock_applicant_" + userId.substring(0, 8);
    }

    const response = await fetch(baseUrl + urlPath, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-App-Token": appToken,
        "X-App-Access-Sig": signature,
        "X-App-Access-Ts": ts,
      },
      body,
    });

    const data: any = await response.json();
    if (!response.ok) throw new BadRequestException("Sumsub error: " + data.description);
    return data.id;
  }

  private async getSumsubSdkToken(applicantId: string): Promise<string> {
    const appToken = process.env.SUMSUB_APP_TOKEN || "";
    const secretKey = process.env.SUMSUB_SECRET_KEY || "";
    const baseUrl = process.env.SUMSUB_BASE_URL || "https://api.sumsub.com";

    // In test/dev mode, return a mock SDK token
    if (appToken === "test_token" || !appToken) {
      return "mock_sdk_token_" + applicantId;
    }

    const ts = Math.floor(Date.now() / 1000).toString();
    const method = "POST";
    const urlPath = "/resources/accessTokens?userId=" + applicantId + "&ttlInSecs=600";

    const signature = crypto
      .createHmac("sha256", secretKey)
      .update(ts + method + urlPath)
      .digest("hex");

    const response = await fetch(baseUrl + urlPath, {
      method,
      headers: {
        "X-App-Token": appToken,
        "X-App-Access-Sig": signature,
        "X-App-Access-Ts": ts,
      },
    });

    const data: any = await response.json();
    if (!response.ok) throw new BadRequestException("Sumsub token error: " + data.description);
    return data.token;
  }
}
