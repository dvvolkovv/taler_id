import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { randomBytes } from 'crypto';
import * as fs from 'fs';
import { PrismaService } from '../prisma/prisma.service';
import { OIDC_PROVIDER } from '../oidc/oidc.service';
import { MailAccountService } from '../mail/mail-account.service';
import { ProvisionDto } from './dto/provision.dto';
import { AttachPhoneDto } from './dto/attach-phone.dto';

export const PARTNER_CLIENT_ID = 'linkeon-partner';
export const PARTNER_WEB_CLIENT_ID = 'linkeon-partner-web';
// Reject id_tokens older than this (anti-replay of a captured login token).
const ID_TOKEN_MAX_AGE_SEC = 600;

export interface ProvisionResult {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  scope: string;
  talerid_user_id: string;
}

export interface AttachPhoneResult {
  talerid_user_id: string;
  attached: true;
  merged: {
    notes: number;
    calendar: number;
    mail: 'moved' | 'dropped' | 'none';
    duplicate_deleted: boolean;
  };
}

@Injectable()
export class PartnerService {
  private readonly logger = new Logger(PartnerService.name);
  private readonly jwtPublicKey: string;
  private readonly oidcIssuer: string;

  constructor(
    private readonly prisma: PrismaService,
    @Inject(OIDC_PROVIDER) private readonly provider: any,
    private readonly mailAccounts: MailAccountService,
    private readonly jwt: JwtService,
    config: ConfigService,
  ) {
    const pub = config.get<string>('jwt.publicKeyPath') ?? '';
    this.jwtPublicKey = pub ? fs.readFileSync(pub, 'utf8') : '';
    this.oidcIssuer =
      config.get<string>('oidc.issuer') ||
      `${config.get<string>('baseUrl') || 'http://localhost:3000'}/oauth`;
  }

  async provision(dto: ProvisionDto): Promise<ProvisionResult> {
    const phone = normalizePhone(dto.phone);
    if (!phone) {
      throw new BadRequestException('phone must be a valid E.164 number');
    }

    // Resolve the verifiedPartner client and its allowed scopes.
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId: PARTNER_CLIENT_ID },
    });
    if (!client || !client.verifiedPartner) {
      this.logger.error(
        `partner client '${PARTNER_CLIENT_ID}' missing or not verifiedPartner`,
      );
      throw new InternalServerErrorException('partner client not configured');
    }

    const scope = computeGrantedScope(dto.scopes, client.allowedScopes);

    const user = await this.upsertUserByPhone(
      phone,
      dto.email,
      dto.firstName,
    );

    // Auto-provision an @talerid.io mailbox when mail scope is granted, so
    // check_mail/read_mail/send_mail don't return no_mailbox_yet. Idempotent
    // (skips if the user already has one) and non-fatal (a mailbox failure must
    // not block token issuance — a repeat provision retries).
    if (/(^|\s)mcp:mail\./.test(scope)) {
      await this.ensureMailbox(user.id, dto.firstName);
    }

    const tokens = await this.mintTokens(user.id, scope);

    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: 900,
      scope,
      talerid_user_id: user.id,
    };
  }

  /**
   * Create-or-find a user by phone. Idempotent on the canonical +E.164 phone.
   *
   * Matching order (safety first — never bind partner tokens to the wrong
   * account):
   *   1. exact canonical +E.164 match -> reuse, no overwrite.
   *   2. legacy fallback: among phoneVerified users whose stored phone is NOT
   *      already canonical (no leading '+') and ends with the same 10 digits —
   *      exactly one match heals to canonical and is reused; two or more is
   *      ambiguous and rejected with 409 (never guessed).
   *   3. otherwise create a new phoneVerified user.
   */
  private async upsertUserByPhone(
    phone: string,
    email?: string,
    firstName?: string,
  ): Promise<{ id: string }> {
    const exact = await this.prisma.user.findUnique({
      where: { phone },
      select: { id: true },
    });
    if (exact) return exact;

    const last10 = phone.replace(/[^0-9]/g, '').slice(-10);
    const legacy = await this.prisma.user.findMany({
      where: {
        phoneVerified: true,
        phone: { endsWith: last10 },
        NOT: { phone: { startsWith: '+' } },
      },
      select: { id: true },
    });
    if (legacy.length === 1) {
      const healed = await this.prisma.user.update({
        where: { id: legacy[0].id },
        data: { phone },
        select: { id: true },
      });
      this.logger.log(`healed legacy phone -> ${phone} for user ${healed.id}`);
      return healed;
    }
    if (legacy.length >= 2) {
      this.logger.warn(
        `ambiguous phone match for ${phone} (${legacy.length} legacy candidates) — refusing`,
      );
      throw new ConflictException('ambiguous phone match — manual review');
    }

    // Create. email/firstName are best-effort enrichment; email only if free.
    const data: any = { phone, phoneVerified: true };
    if (firstName) {
      data.profile = { create: { firstName } };
    }
    if (email) {
      const taken = await this.prisma.user.findUnique({
        where: { email },
        select: { id: true },
      });
      if (!taken) data.email = email;
    }
    const created = await this.prisma.user.create({
      data,
      select: { id: true },
    });
    this.logger.log(`provisioned new user ${created.id} for ${phone}`);
    return created;
  }

  /**
   * Attach a Linkeon-SMS-verified phone to the EXISTING TalerID account the
   * user logged into (proven by an id_token from the linkeon-partner-web code
   * flow), merging any phone-provisioned duplicate. Lets email-first users link
   * instead of getting a second phone account. See contract §4.
   */
  async attachPhone(dto: AttachPhoneDto): Promise<AttachPhoneResult> {
    const phone = normalizePhone(dto.phone);
    if (!phone) throw new BadRequestException('phone must be a valid E.164 number');

    // 1. Verify id_token: our RS256 key, our issuer, aud = web client, fresh.
    let payload: any;
    try {
      payload = this.jwt.verify(dto.id_token, {
        publicKey: this.jwtPublicKey,
        algorithms: ['RS256'],
        issuer: this.oidcIssuer,
        audience: PARTNER_WEB_CLIENT_ID,
      });
    } catch (e) {
      throw new UnauthorizedException(`invalid_id_token: ${(e as Error).message}`);
    }
    const iat = Number(payload?.iat ?? 0);
    if (!iat || Date.now() / 1000 - iat > ID_TOKEN_MAX_AGE_SEC) {
      throw new UnauthorizedException('invalid_id_token: stale');
    }
    const sub = String(payload?.sub ?? '');
    if (!sub) throw new UnauthorizedException('invalid_id_token: no sub');

    // 2. Target = the account the user logged into.
    const target = await this.prisma.user.findUnique({
      where: { id: sub },
      select: { id: true, phone: true, mailAccount: { select: { id: true } } },
    });
    if (!target) throw new UnauthorizedException('invalid_id_token: account not found');

    const noMerge = { notes: 0, calendar: 0, mail: 'none' as const, duplicate_deleted: false };
    // 3. Idempotent: phone already attached to this account.
    if (target.phone === phone) {
      return { talerid_user_id: target.id, attached: true, merged: noMerge };
    }
    // 4. Gate: account already has a DIFFERENT phone — never silently swap.
    if (target.phone && target.phone !== phone) {
      throw new ConflictException('account_has_different_phone');
    }

    // 5. Who owns this phone (the would-be duplicate)?
    const owner = await this.prisma.user.findUnique({
      where: { phone },
      select: { id: true, passwordHash: true, emailVerified: true, mailAccount: { select: { id: true } } },
    });

    const merged = { notes: 0, calendar: 0, mail: 'none' as 'moved' | 'dropped' | 'none', duplicate_deleted: false };

    if (owner && owner.id !== target.id) {
      // A "real" account (password or verified email) is not a mergeable dupe.
      if (owner.passwordHash || owner.emailVerified) {
        throw new ConflictException('phone_belongs_to_another_account');
      }
      // v1 doesn't merge messenger identity — refuse rather than lose data.
      // Only REAL correspondence blocks the merge: messages the dupe sent, or
      // membership in a DIRECT/GROUP conversation. System CHANNELs (broadcast,
      // every user is auto-subscribed) are not correspondence — they're dropped
      // with the dupe, so they must not trip the guard (false-positive fixed
      // 2026-07-27: a fresh dupe's only membership is the all-users channel).
      const [msgs, realConvs] = await Promise.all([
        this.prisma.message.count({ where: { senderId: owner.id } }),
        this.prisma.conversationParticipant.count({
          where: { userId: owner.id, conversation: { type: { not: 'CHANNEL' } } },
        }),
      ]);
      if (msgs > 0 || realConvs > 0) throw new ConflictException('merge_has_messenger_data');

      // Mail: move the dupe's mailbox to the target if it has none, else drop
      // the dupe's mailbox (mailcow + row) before deleting the dupe.
      let moveMail = false;
      if (owner.mailAccount) {
        if (target.mailAccount) {
          await this.mailAccounts.deleteAccount(owner.id);
          merged.mail = 'dropped';
        } else {
          moveMail = true;
        }
      }

      await this.prisma.$transaction(async (tx) => {
        merged.notes = (
          await tx.note.updateMany({ where: { userId: owner.id }, data: { userId: target.id } })
        ).count;
        merged.calendar = (
          await tx.calendarEvent.updateMany({ where: { userId: owner.id }, data: { userId: target.id } })
        ).count;
        await tx.calendarInvite.updateMany({ where: { userId: owner.id }, data: { userId: target.id } });
        if (moveMail) {
          await tx.mailAccount.update({ where: { userId: owner.id }, data: { userId: target.id } });
          merged.mail = 'moved';
        }
        // Drop the dupe's channel/conversation memberships (system CHANNEL etc.)
        // so the user delete below isn't blocked by a participant FK. Any real
        // DIRECT/GROUP membership was already refused by the guard above.
        await tx.conversationParticipant.deleteMany({ where: { userId: owner.id } });
        await tx.user.delete({ where: { id: owner.id } }); // frees the unique phone
        await tx.user.update({ where: { id: target.id }, data: { phone, phoneVerified: true } });
      });
      merged.duplicate_deleted = true;
      this.logger.log(`attach-phone: merged dupe ${owner.id} -> ${target.id} ${JSON.stringify(merged)}`);
    } else {
      // No duplicate — just attach the phone.
      await this.prisma.user.update({
        where: { id: target.id },
        data: { phone, phoneVerified: true },
      });
      this.logger.log(`attach-phone: attached phone to ${target.id} (no dupe)`);
    }

    return { talerid_user_id: target.id, attached: true, merged };
  }

  /**
   * Ensure the user has an @talerid.io mailbox (idempotent, best-effort).
   * Skips if one already exists; on localpart collision retries with a fresh
   * auto-name; any other failure is logged and swallowed so token issuance is
   * never blocked (the mail tools then report no_mailbox_yet and a repeat
   * provision retries).
   */
  private async ensureMailbox(userId: string, firstName?: string): Promise<void> {
    const existing = await this.prisma.mailAccount.findUnique({
      where: { userId },
      select: { id: true },
    });
    if (existing) return;

    for (let attempt = 0; attempt < 5; attempt++) {
      const localpart = generateLocalpart(firstName);
      try {
        await this.mailAccounts.createAccount(userId, localpart);
        this.logger.log(`provisioned mailbox ${localpart} for user ${userId}`);
        return;
      } catch (e) {
        const msg = (e as Error).message || '';
        if (msg === 'mail_account_already_exists') return; // concurrent create won
        if (msg.includes('localpart_') || msg.includes('taken')) continue; // collision → new name
        this.logger.warn(`mailbox provisioning failed for ${userId}: ${msg}`);
        return; // non-fatal
      }
    }
    this.logger.warn(`mailbox provisioning gave up (localpart collisions) for ${userId}`);
  }

  /**
   * Issue real provider access + refresh tokens (validated by the same
   * MCP guard as any other token) for the linkeon-partner client, tied to a
   * fresh Grant. Linkeon later refreshes via the standard
   * POST /oauth/token grant_type=refresh_token.
   */
  private async mintTokens(
    accountId: string,
    scope: string,
  ): Promise<{ access_token: string; refresh_token: string }> {
    const provider = this.provider;
    const client = await provider.Client.find(PARTNER_CLIENT_ID);
    if (!client) {
      throw new InternalServerErrorException('partner client not loadable');
    }

    const grant = new provider.Grant({
      accountId,
      clientId: PARTNER_CLIENT_ID,
    });
    grant.addOIDCScope(scope);
    const grantId = await grant.save();

    const at = new provider.AccessToken({
      accountId,
      client,
      grantId,
      scope,
      gty: 'authorization_code',
    });
    const access_token = await at.save();

    const rt = new provider.RefreshToken({
      accountId,
      client,
      grantId,
      scope,
      gty: 'authorization_code',
    });
    const refresh_token = await rt.save();

    return { access_token, refresh_token };
  }
}

// --- helpers ---

// Canonicalize to +<digits> (E.164). Returns null if it isn't a plausible
// international number (7–15 digits). Does not attempt trunk-prefix rewrites
// (e.g. RU 8 -> +7); Linkeon sends already-verified E.164 with a leading '+'.
export function normalizePhone(raw: string): string | null {
  if (!raw) return null;
  const digits = String(raw).replace(/[^0-9]/g, '');
  if (digits.length < 7 || digits.length > 15) return null;
  return `+${digits}`;
}

// Auto-generate a valid, ~unique mailbox localpart. Slug of firstName (ASCII,
// accents stripped) when usable, else "user"; always suffixed with random hex
// for uniqueness. Matches src/mail/localpart LOCALPART_RE and is never reserved
// (the suffix guarantees it). Collisions are retried by the caller.
export function generateLocalpart(firstName?: string): string {
  const base = String(firstName ?? '')
    .toLowerCase()
    .normalize('NFKD') // decompose accents; the [^a-z0-9] strip drops the marks
    .replace(/[^a-z0-9]/g, '')
    .slice(0, 18);
  const stem = base.length >= 2 ? base : 'user';
  return `${stem}${randomBytes(4).toString('hex')}`;
}

// Granted scope = requested ∩ allowed (per contract §2.3): scopes the client
// isn't allowed are silently dropped, not rejected — so a caller may request a
// superset and take what's permitted (no per-env request coordination). We only
// 400 when the request is empty or the intersection yields no usable mcp:* scope
// (can't mint a token that grants nothing). openid + offline_access are added
// when the client allows them.
export function computeGrantedScope(
  requested: string[],
  allowed: string[],
): string {
  const allowedSet = new Set(allowed);
  const cleaned = requested.map((s) => s.trim()).filter(Boolean);
  if (cleaned.length === 0) {
    throw new BadRequestException('scopes must be a non-empty array');
  }
  const grantedMcp = cleaned.filter(
    (s) => s.startsWith('mcp:') && allowedSet.has(s),
  );
  if (grantedMcp.length === 0) {
    throw new BadRequestException(
      'none of the requested scopes are permitted for this client',
    );
  }
  const parts = new Set<string>(['openid', ...grantedMcp]);
  if (allowedSet.has('offline_access')) parts.add('offline_access');
  return Array.from(parts).join(' ');
}
