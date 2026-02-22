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

    // Get SDK token for frontend (pass our externalUserId, not Sumsub applicantId)
    const sdkToken = await this.getSumsubSdkToken(userId);

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
    // Verify Sumsub webhook signature only if SUMSUB_WEBHOOK_SECRET is configured
    const webhookSecret = process.env.SUMSUB_WEBHOOK_SECRET || "";
    if (webhookSecret) {
      const expectedSignature = crypto
        .createHmac("sha256", webhookSecret)
        .update(body)
        .digest("hex");
      if (signature !== expectedSignature) {
        throw new BadRequestException("Invalid webhook signature");
      }
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

  async getApplicantData(userId: string) {
    const kyc = await this.prisma.kycRecord.findUnique({ where: { userId } });
    if (!kyc || !kyc.sumsubApplicantId) {
      throw new NotFoundException("KYC record not found");
    }

    const appToken = process.env.SUMSUB_APP_TOKEN || "";
    const secretKey = process.env.SUMSUB_SECRET_KEY || "";
    const baseUrl = process.env.SUMSUB_BASE_URL || "https://api.sumsub.com";

    // In test/dev mode, return mock data
    if (appToken === "test_token" || !appToken) {
      return {
        applicantId: kyc.sumsubApplicantId,
        createdAt: kyc.createdAt.toISOString(),
        reviewStatus: kyc.status === "VERIFIED" ? "completed" : "pending",
        reviewResult: { reviewAnswer: kyc.status === "VERIFIED" ? "GREEN" : null, rejectLabels: [] },
        info: { firstName: null, lastName: null, middleName: null, dob: null, placeOfBirth: null, country: null, nationality: null, gender: null },
        addresses: [],
        idDocs: [],
      };
    }

    // Fetch applicant info from Sumsub
    const applicantData = await this.sumsubApiGet(
      `/resources/applicants/${kyc.sumsubApplicantId}/one`,
      appToken, secretKey, baseUrl,
    );

    // Fetch document check status
    let docStatus: any = {};
    try {
      docStatus = await this.sumsubApiGet(
        `/resources/applicants/${kyc.sumsubApplicantId}/requiredIdDocsStatus`,
        appToken, secretKey, baseUrl,
      );
    } catch (e) {
      this.logger.warn(`Failed to fetch doc status for ${kyc.sumsubApplicantId}: ${e}`);
    }

    const info = applicantData.fixedInfo || applicantData.info || {};
    const idDocs = (info.idDocs || []).map((doc: any) => ({
      idDocType: doc.idDocType,
      number: doc.number,
      firstName: doc.firstName,
      lastName: doc.lastName,
      issuedDate: doc.issuedDate,
      validUntil: doc.validUntil,
      issuedBy: doc.issuedBy,
      country: doc.country,
    }));

    const addresses = (info.addresses || applicantData.addresses || []).map((addr: any) => ({
      street: addr.street,
      buildingNumber: addr.buildingNumber,
      flatNumber: addr.flatNumber,
      town: addr.town,
      state: addr.state,
      postCode: addr.postCode,
      country: addr.country,
    }));

    return {
      applicantId: kyc.sumsubApplicantId,
      createdAt: applicantData.createdAt,
      reviewStatus: applicantData.review?.reviewStatus || null,
      reviewResult: {
        reviewAnswer: applicantData.review?.reviewResult?.reviewAnswer || null,
        rejectLabels: applicantData.review?.reviewResult?.rejectLabels || [],
      },
      info: {
        firstName: info.firstName || info.firstNameEn || null,
        lastName: info.lastName || info.lastNameEn || null,
        middleName: info.middleName || info.middleNameEn || null,
        dob: info.dob || null,
        placeOfBirth: info.placeOfBirth || info.placeOfBirthEn || null,
        country: info.country || null,
        nationality: info.nationality || null,
        gender: info.gender || null,
      },
      addresses,
      idDocs,
      documentStatus: docStatus,
    };
  }

  private async sumsubApiGet(urlPath: string, appToken: string, secretKey: string, baseUrl: string): Promise<any> {
    const ts = Math.floor(Date.now() / 1000).toString();
    const signature = crypto
      .createHmac("sha256", secretKey)
      .update(ts + "GET" + urlPath)
      .digest("hex");

    const response = await fetch(baseUrl + urlPath, {
      method: "GET",
      headers: {
        "X-App-Token": appToken,
        "X-App-Access-Sig": signature,
        "X-App-Access-Ts": ts,
      },
    });

    const data = await response.json();
    if (!response.ok) {
      throw new BadRequestException("Sumsub API error: " + (data as any).description);
    }
    return data;
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
    if (!response.ok) {
      // If applicant already exists, fetch their Sumsub ID
      if (data.description && data.description.includes("already exists")) {
        return this.getSumsubApplicantByExternalId(userId, appToken, secretKey, baseUrl);
      }
      throw new BadRequestException("Sumsub error: " + data.description);
    }
    return data.id;
  }

  private async getSumsubApplicantByExternalId(
    externalUserId: string,
    appToken: string,
    secretKey: string,
    baseUrl: string,
  ): Promise<string> {
    const ts = Math.floor(Date.now() / 1000).toString();
    const urlPath = `/resources/applicants/-;externalUserId=${externalUserId}/one`;
    const signature = crypto
      .createHmac("sha256", secretKey)
      .update(ts + "GET" + urlPath)
      .digest("hex");

    const response = await fetch(baseUrl + urlPath, {
      method: "GET",
      headers: {
        "X-App-Token": appToken,
        "X-App-Access-Sig": signature,
        "X-App-Access-Ts": ts,
      },
    });
    const data: any = await response.json();
    if (!response.ok) throw new BadRequestException("Sumsub fetch error: " + data.description);
    return data.id;
  }

  private async getSumsubSdkToken(externalUserId: string): Promise<string> {
    const appToken = process.env.SUMSUB_APP_TOKEN || "";
    const secretKey = process.env.SUMSUB_SECRET_KEY || "";
    const baseUrl = process.env.SUMSUB_BASE_URL || "https://api.sumsub.com";

    // In test/dev mode, return a mock SDK token
    if (appToken === "test_token" || !appToken) {
      return "mock_sdk_token_" + externalUserId;
    }

    const levelName = process.env.SUMSUB_LEVEL_NAME || "basic-kyc-level";
    const ts = Math.floor(Date.now() / 1000).toString();
    const method = "POST";
    const urlPath = "/resources/accessTokens?userId=" + externalUserId + "&ttlInSecs=600&levelName=" + levelName;

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
