import { ConflictException, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { randomBytes, randomUUID } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import type { RegisterClientDto } from './dto/register-client.dto';
import type { UpdateClientDto } from './dto/update-client.dto';

export const SELF_REGISTRATION_ALLOWED_SCOPES = [
  'openid',
  'profile',
  'email',
  'offline_access',
] as const;
export const MAX_CLIENTS_PER_USER = 10;

const DEFAULT_SCOPES = 'openid profile email offline_access';

@Injectable()
export class OAuthRegistrationService {
  constructor(private readonly prisma: PrismaService) {}

  private parseAndValidateScope(scope: string | undefined): string[] {
    const requested = (scope ?? DEFAULT_SCOPES).trim().split(/\s+/).filter(Boolean);
    const invalid = requested.filter(
      (s) => !(SELF_REGISTRATION_ALLOWED_SCOPES as readonly string[]).includes(s),
    );
    if (invalid.length > 0) {
      throw new ForbiddenException({
        error: 'invalid_scope',
        error_description: `Self-registered clients may only request: ${SELF_REGISTRATION_ALLOWED_SCOPES.join(' ')}. Rejected: ${invalid.join(' ')}`,
      });
    }
    return requested;
  }

  async register(userId: string, dto: RegisterClientDto, ip: string, userAgent: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { emailVerified: true },
    });
    if (!user || !user.emailVerified) {
      throw new ForbiddenException({
        error: 'email_not_verified',
        error_description: 'Verify your email address before registering OAuth clients.',
      });
    }

    const existingCount = await this.prisma.oAuthClient.count({ where: { userId } });
    if (existingCount >= MAX_CLIENTS_PER_USER) {
      throw new ForbiddenException({
        error: 'client_limit_exceeded',
        error_description: `You may register at most ${MAX_CLIENTS_PER_USER} OAuth clients. Delete unused ones first.`,
      });
    }

    const scopes = this.parseAndValidateScope(dto.scope);

    let attempt = 0;
    let clientId = randomUUID();
    while (attempt < 2) {
      try {
        const clientSecret = randomBytes(32).toString('base64url');
        const created = await this.prisma.oAuthClient.create({
          data: {
            clientId,
            clientSecret,
            name: dto.client_name,
            redirectUris: dto.redirect_uris,
            allowedScopes: scopes,
            logoUri: dto.logo_uri ?? null,
            userId,
          },
        });

        await this.writeAuditLog(userId, 'OAUTH_CLIENT_REGISTERED', ip, userAgent, {
          clientId: created.clientId,
          name: created.name,
          scopes,
        });

        return {
          client_id: created.clientId,
          client_secret: created.clientSecret,
          client_id_issued_at: Math.floor(created.createdAt.getTime() / 1000),
          client_secret_expires_at: 0,
          client_name: created.name,
          redirect_uris: created.redirectUris,
          scope: created.allowedScopes.join(' '),
          logo_uri: created.logoUri ?? undefined,
          token_endpoint_auth_method: 'client_secret_basic',
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
        };
      } catch (e: any) {
        if (e?.code === 'P2002' && attempt === 0) {
          attempt++;
          clientId = randomUUID();
          continue;
        }
        throw new ConflictException({
          error: 'registration_failed',
          error_description: 'Could not create client. Try again.',
        });
      }
    }
    throw new ConflictException({
      error: 'registration_failed',
      error_description: 'Could not generate a unique client_id after retry.',
    });
  }

  private async writeAuditLog(
    userId: string | null,
    action: string,
    ip: string,
    userAgent: string,
    meta?: any,
  ): Promise<void> {
    // Mirrors the pattern in AuthService.auditLog (auth.service.ts:339-349) —
    // private there, so we inline the same Prisma call here rather than
    // creating a new shared service for one-off use.
    await this.prisma.auditLog.create({
      data: {
        userId,
        action,
        ipAddress: ip,
        userAgent: userAgent?.substring(0, 200) ?? '',
        meta: meta ?? {},
      },
    });
  }

  async listMine(userId: string) {
    const rows = await this.prisma.oAuthClient.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
    return rows.map((c) => ({
      client_id: c.clientId,
      client_id_issued_at: Math.floor(c.createdAt.getTime() / 1000),
      client_name: c.name,
      redirect_uris: c.redirectUris,
      scope: c.allowedScopes.join(' '),
      logo_uri: c.logoUri ?? undefined,
      token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    }));
  }

  async getMine(userId: string, clientId: string) {
    const c = await this.prisma.oAuthClient.findFirst({ where: { clientId, userId } });
    if (!c) {
      throw new NotFoundException({ error: 'client_not_found' });
    }
    return {
      client_id: c.clientId,
      client_id_issued_at: Math.floor(c.createdAt.getTime() / 1000),
      client_name: c.name,
      redirect_uris: c.redirectUris,
      scope: c.allowedScopes.join(' '),
      logo_uri: c.logoUri ?? undefined,
      token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    };
  }

  async updateMine(
    userId: string,
    clientId: string,
    dto: UpdateClientDto,
    ip: string,
    userAgent: string,
  ) {
    const existing = await this.prisma.oAuthClient.findFirst({
      where: { clientId, userId },
    });
    if (!existing) {
      throw new NotFoundException({ error: 'client_not_found' });
    }

    const scopes = dto.scope === undefined
      ? existing.allowedScopes
      : this.parseAndValidateScope(dto.scope);

    const updated = await this.prisma.oAuthClient.update({
      where: { id: existing.id },
      data: {
        name: dto.client_name ?? existing.name,
        redirectUris: dto.redirect_uris ?? existing.redirectUris,
        logoUri: dto.logo_uri ?? existing.logoUri,
        allowedScopes: scopes,
      },
    });

    await this.writeAuditLog(userId, 'OAUTH_CLIENT_UPDATED', ip, userAgent, {
      clientId,
      changes: Object.keys(dto),
    });

    return {
      client_id: updated.clientId,
      client_id_issued_at: Math.floor(updated.createdAt.getTime() / 1000),
      client_name: updated.name,
      redirect_uris: updated.redirectUris,
      scope: updated.allowedScopes.join(' '),
      logo_uri: updated.logoUri ?? undefined,
      token_endpoint_auth_method: 'client_secret_basic',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    };
  }

  async deleteMine(userId: string, clientId: string, ip: string, userAgent: string) {
    const existing = await this.prisma.oAuthClient.findFirst({
      where: { clientId, userId },
    });
    if (!existing) {
      throw new NotFoundException({ error: 'client_not_found' });
    }
    await this.prisma.oAuthClient.delete({ where: { id: existing.id } });
    await this.writeAuditLog(userId, 'OAUTH_CLIENT_DELETED', ip, userAgent, { clientId });
    return { deleted: true, client_id: clientId };
  }

  async rotateSecret(userId: string, clientId: string, ip: string, userAgent: string) {
    const existing = await this.prisma.oAuthClient.findFirst({
      where: { clientId, userId },
    });
    if (!existing) {
      throw new NotFoundException({ error: 'client_not_found' });
    }

    const newSecret = randomBytes(32).toString('base64url');
    await this.prisma.oAuthClient.update({
      where: { id: existing.id },
      data: { clientSecret: newSecret },
    });

    await this.writeAuditLog(userId, 'OAUTH_CLIENT_ROTATED', ip, userAgent, {
      clientId,
    });

    return {
      client_id: clientId,
      client_secret: newSecret,
      client_secret_rotated_at: Math.floor(Date.now() / 1000),
    };
  }
}
