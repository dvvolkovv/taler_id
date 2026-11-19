import type { PrismaService } from '../prisma/prisma.service';
import { COMPANIES_SCOPE } from '../companies/companies.constants';
import { companyClaimsFor } from '../companies/company-claims';

/** findAccount для oidc-provider: аккаунт и его claims по scope. */
export function createFindAccount(prisma: PrismaService) {
  return async (_ctx: any, sub: string, token?: { grantId?: string }) => {
    const user = await prisma.user.findUnique({
      where: { id: sub },
      include: { profile: true, kycRecord: true },
    });
    // Удалённый (DELETE /profile) или заблокированный админом аккаунт —
    // оба ставят deletedAt. Без аккаунта провайдер отвечает /oauth/me 401
    // invalid_token, а обмен кода и refresh — invalid_grant: сайт узнаёт, что
    // человека больше нет, а не получает «физлицо» вместо запомненной компании.
    if (!user || user.deletedAt) return undefined;

    return {
      accountId: sub,
      async claims(use: string, scope: string) {
        const scopes = typeof scope === 'string' ? scope.split(' ') : [];
        const result: Record<string, any> = { sub };

        if (scopes.includes('profile') && user.profile) {
          result.given_name = user.profile.firstName;
          result.family_name = user.profile.lastName;
          result.middle_name = user.profile.middleName;
          result.name = [user.profile.firstName, user.profile.lastName]
            .filter(Boolean)
            .join(' ');
          result.locale = user.profile.language;
          result.updated_at = Math.floor(
            user.profile.updatedAt.getTime() / 1000,
          );
        }

        if (scopes.includes('email')) {
          result.email = user.email;
          result.email_verified = user.emailVerified;
        }

        if (scopes.includes('phone')) {
          result.phone_number = user.phone;
          result.phone_number_verified = user.phoneVerified;
        }

        if (scopes.includes('kyc') && user.kycRecord) {
          result.kyc_status = user.kycRecord.status;
          result.kyc_type = user.kycRecord.kycType;
          result.kyc_verified_at = user.kycRecord.verifiedAt
            ? user.kycRecord.verifiedAt.toISOString()
            : null;
        }

        if (scopes.includes('wallet') && user.profile) {
          result.wallet_address = user.profile.walletAddress;
        }

        // Только в /oauth/me: в ID-токен claims из scope при входе с кодом не
        // идут (conformIdTokenClaims). Выбор берём по согласию этого входа.
        if (scopes.includes(COMPANIES_SCOPE) && use === 'userinfo') {
          Object.assign(
            result,
            await companyClaimsFor(prisma, sub, token?.grantId),
          );
        }

        return result;
      },
    };
  };
}
