import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Req,
  Res,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiParam,
  ApiBody,
  ApiResponse,
} from '@nestjs/swagger';
// Using 'any' for req/res to avoid TS1272 with isolatedModules + emitDecoratorMetadata
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { OidcService } from './oidc.service';
import { MCP_SCOPE_DESCRIPTIONS } from '../mcp/mcp.constants';
import * as bcrypt from 'bcrypt';

@ApiTags('oauth-interaction')
@Controller('oauth/interaction')
export class OidcInteractionController {
  constructor(
    private readonly oidcService: OidcService,
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
  ) {}

  @Get(':uid')
  @ApiOperation({
    summary: 'Get interaction details',
    description:
      'Returns details about the current OAuth interaction (login or consent). The uid is provided by the authorization endpoint redirect.',
  })
  @ApiParam({
    name: 'uid',
    description: 'Interaction UID from the authorization redirect',
  })
  @ApiResponse({
    status: 200,
    description: 'Interaction details (login or consent)',
  })
  async interaction(
    @Param('uid') uid: string,
    @Req() req: any,
    @Res() res: any,
  ) {
    // Content negotiation: when the user navigates here in a browser, serve the
    // consent.html SPA shell. When the SPA itself or another script does a
    // `fetch(..., { headers: { Accept: 'application/json' } })`, return JSON.
    // Most browsers send `Accept: text/html,...` for navigations; fetch defaults
    // to `*/*` but our SPA explicitly sets `Accept: application/json`.
    const acceptsHtml = (req.headers?.accept as string | undefined)?.includes(
      'text/html',
    );
    const acceptsJson = (req.headers?.accept as string | undefined)?.includes(
      'application/json',
    );

    if (acceptsHtml && !acceptsJson) {
      // Send the consent.html SPA from disk. The SPA itself does the
      // /oauth/interaction/:uid fetch (with Accept: application/json) to
      // populate its state.
      const fs = await import('fs');
      const path = await import('path');
      const htmlPath = path.resolve(
        process.cwd(),
        'public',
        'consent.html',
      );
      const html = fs.readFileSync(htmlPath, 'utf8');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(html);
    }

    const details = await this.oidcService.getInteractionDetails(req, res);
    const { prompt, params } = details;

    if (prompt.name === 'login') {
      return res.json({
        interaction: 'login',
        uid,
        client: params.client_id,
        scope: params.scope,
      });
    }

    if (prompt.name === 'consent') {
      const client = await this.oidcService.findClient(
        params.client_id as string,
      );
      const consentScopes = (params.scope as string).split(' ').filter(Boolean);
      return res.json({
        interaction: 'consent',
        uid,
        client: {
          name: client?.name,
          logoUri: client?.logoUri,
        },
        scopes: consentScopes,
        scopeDescriptions: Object.fromEntries(
          consentScopes
            .filter((s) => MCP_SCOPE_DESCRIPTIONS[s])
            .map((s) => [s, MCP_SCOPE_DESCRIPTIONS[s]]),
        ),
      });
    }

    return res.json({ interaction: prompt.name, uid });
  }

  @Post(':uid/login')
  @ApiOperation({
    summary: 'Submit login credentials',
    description:
      'Authenticates the user during OAuth flow. On success, redirects to consent or back to client with authorization code.',
  })
  @ApiParam({ name: 'uid', description: 'Interaction UID' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          description: 'User email',
          example: 'user@example.com',
        },
        phone: {
          type: 'string',
          description: 'Or phone number (alternative to email)',
        },
        password: { type: 'string', description: 'User password' },
        remember: {
          type: 'boolean',
          description: 'Remember login session',
          default: true,
        },
      },
      required: ['password'],
    },
  })
  @ApiResponse({
    status: 303,
    description: 'Redirect to consent or back to client',
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({
    status: 403,
    description: 'Account locked (5+ failed attempts, 15min lockout)',
  })
  async login(
    @Param('uid') _uid: string,
    @Body() body: any,
    @Req() req: any,
    @Res() res: any,
  ) {
    const user = await this.authenticateUser(
      body.email || body.phone,
      body.password,
    );

    const result = {
      login: {
        accountId: user.id,
        remember: body.remember ?? true,
      },
    };

    await this.auditLog(user.id, 'OAUTH_LOGIN', req);
    return this.finish(req, res, result);
  }

  @Post(':uid/consent')
  @ApiOperation({
    summary: 'Submit consent decision',
    description:
      'Approves the requested scopes (all or partial). On success, redirects back to client with authorization code.',
  })
  @ApiParam({ name: 'uid', description: 'Interaction UID' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        approved_scopes: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Scopes to approve. If omitted, all requested scopes are approved.',
          example: ['openid', 'profile', 'email'],
        },
      },
    },
  })
  @ApiResponse({
    status: 303,
    description: 'Redirect to client with authorization code',
  })
  @ApiResponse({ status: 401, description: 'Not logged in' })
  async consent(
    @Param('uid') _uid: string,
    @Body() body: any,
    @Req() req: any,
    @Res() res: any,
  ) {
    const details = await this.oidcService.getInteractionDetails(req, res);
    const { params, session } = details;

    if (!session?.accountId) {
      throw new UnauthorizedException('Not logged in');
    }

    const provider = this.oidcService.getProvider();
    const Grant = provider.Grant;
    const grant = new Grant({
      accountId: session.accountId,
      clientId: params.client_id,
    });

    const requestedScopes = (params.scope as string).split(' ');
    const approvedScopes = body.approved_scopes || requestedScopes;
    grant.addOIDCScope(approvedScopes.join(' '));

    const grantId = await grant.save();

    const result = {
      consent: { grantId },
    };

    await this.auditLog(session.accountId, 'OAUTH_CONSENT', req, {
      clientId: params.client_id,
      scopes: approvedScopes,
    });

    return this.finish(req, res, result);
  }

  /**
   * Completes an interaction, answering in whichever shape the caller can act on.
   *
   * A 303 is right for a browser navigation, but the consent page submits over
   * `fetch`: the redirect chain ends at the client's callback, and following a
   * cross-origin hop from `fetch` is blocked by our CSP `connect-src`, so the
   * flow died silently at "Allow" for every client with an external callback.
   * Callers that ask for JSON get the URL to navigate to instead — a top-level
   * navigation, which CSP does not restrict.
   *
   * Redirecting stays the default so existing server-to-server callers, which
   * follow redirects natively, are unaffected.
   */
  private async finish(req: any, res: any, result: any) {
    const accept = (req.headers?.accept as string | undefined) ?? '';
    if (!accept.includes('application/json')) {
      return this.oidcService.finishInteraction(req, res, result);
    }

    const redirectTo = await this.oidcService.resolveInteractionRedirect(
      req,
      res,
      result,
    );
    return res.json({ redirectTo });
  }

  @Get(':uid/abort')
  @ApiOperation({
    summary: 'Abort interaction',
    description:
      'Cancels the OAuth flow. Redirects back to the client with error=access_denied.',
  })
  @ApiParam({ name: 'uid', description: 'Interaction UID' })
  @ApiResponse({
    status: 303,
    description: 'Redirect to client with error=access_denied',
  })
  async abort(@Param('uid') _uid: string, @Req() req: any, @Res() res: any) {
    const result = {
      error: 'access_denied',
      error_description: 'End-User aborted interaction',
    };
    return this.oidcService.finishInteraction(req, res, result);
  }

  private async authenticateUser(identifier: string, password: string) {
    if (!identifier || !password) {
      throw new UnauthorizedException('Email/phone and password are required');
    }

    const orConditions: any[] = [];
    if (identifier.includes('@')) {
      orConditions.push({ email: identifier });
    } else {
      orConditions.push({ phone: identifier });
    }

    const user = await this.prisma.user.findFirst({
      where: { OR: orConditions, deletedAt: null },
    });

    // Lockout has to be read under the same key the failure counter writes.
    // This used to read `lockout:<email>` while writing `lockout:<userId>`, so
    // the two never met and password guessing on this route was unlimited.
    // Unknown identifiers get their own bucket, so enumeration is throttled too.
    const subject = user?.id ?? `identifier:${identifier.toLowerCase()}`;
    if (await this.redis.get(`lockout:${subject}`)) {
      throw new ForbiddenException(
        'Account locked due to too many failed attempts',
      );
    }

    if (!user?.passwordHash) {
      await this.registerFailedAttempt(subject);
      throw new UnauthorizedException('Invalid credentials');
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      await this.registerFailedAttempt(user.id);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Clear failed attempts
    await this.redis.del(`failed:${user.id}`);
    return user;
  }

  private async registerFailedAttempt(subject: string) {
    const failedKey = `failed:${subject}`;
    const attempts = await this.redis.incr(failedKey);
    await this.redis.expire(failedKey, 900);
    if (attempts >= 5) {
      await this.redis.setEx(`lockout:${subject}`, 900, '1');
      await this.redis.del(failedKey);
    }
  }

  private async auditLog(userId: string, action: string, req: any, meta?: any) {
    await this.prisma.auditLog.create({
      data: {
        userId,
        action,
        ipAddress: req.ip ?? req.socket?.remoteAddress,
        userAgent: req.headers['user-agent']?.substring(0, 200),
        meta: meta || {},
      },
    });
  }
}
