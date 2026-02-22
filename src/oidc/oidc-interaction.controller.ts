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
import { ApiTags, ApiOperation, ApiParam, ApiBody, ApiResponse } from '@nestjs/swagger';
// Using 'any' for req/res to avoid TS1272 with isolatedModules + emitDecoratorMetadata
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { OidcService } from './oidc.service';
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
    description: 'Returns details about the current OAuth interaction (login or consent). The uid is provided by the authorization endpoint redirect.',
  })
  @ApiParam({ name: 'uid', description: 'Interaction UID from the authorization redirect' })
  @ApiResponse({ status: 200, description: 'Interaction details (login or consent)' })
  async interaction(
    @Param('uid') uid: string,
    @Req() req: any,
    @Res() res: any,
  ) {
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
      const client = await this.oidcService.findClient(params.client_id as string);
      return res.json({
        interaction: 'consent',
        uid,
        client: {
          name: client?.name,
          logoUri: client?.logoUri,
        },
        scopes: (params.scope as string).split(' '),
      });
    }

    return res.json({ interaction: prompt.name, uid });
  }

  @Post(':uid/login')
  @ApiOperation({
    summary: 'Submit login credentials',
    description: 'Authenticates the user during OAuth flow. On success, redirects to consent or back to client with authorization code.',
  })
  @ApiParam({ name: 'uid', description: 'Interaction UID' })
  @ApiBody({ schema: {
    type: 'object',
    properties: {
      email: { type: 'string', description: 'User email', example: 'user@example.com' },
      phone: { type: 'string', description: 'Or phone number (alternative to email)' },
      password: { type: 'string', description: 'User password' },
      remember: { type: 'boolean', description: 'Remember login session', default: true },
    },
    required: ['password'],
  }})
  @ApiResponse({ status: 303, description: 'Redirect to consent or back to client' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 403, description: 'Account locked (5+ failed attempts, 15min lockout)' })
  async login(
    @Param('uid') _uid: string,
    @Body() body: any,
    @Req() req: any,
    @Res() res: any,
  ) {
    const user = await this.authenticateUser(body.email || body.phone, body.password);

    const result = {
      login: {
        accountId: user.id,
        remember: body.remember ?? true,
      },
    };

    await this.auditLog(user.id, 'OAUTH_LOGIN', req);
    return this.oidcService.finishInteraction(req, res, result);
  }

  @Post(':uid/consent')
  @ApiOperation({
    summary: 'Submit consent decision',
    description: 'Approves the requested scopes (all or partial). On success, redirects back to client with authorization code.',
  })
  @ApiParam({ name: 'uid', description: 'Interaction UID' })
  @ApiBody({ schema: {
    type: 'object',
    properties: {
      approved_scopes: {
        type: 'array',
        items: { type: 'string' },
        description: 'Scopes to approve. If omitted, all requested scopes are approved.',
        example: ['openid', 'profile', 'email'],
      },
    },
  }})
  @ApiResponse({ status: 303, description: 'Redirect to client with authorization code' })
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

    return this.oidcService.finishInteraction(req, res, result);
  }

  @Get(':uid/abort')
  @ApiOperation({
    summary: 'Abort interaction',
    description: 'Cancels the OAuth flow. Redirects back to the client with error=access_denied.',
  })
  @ApiParam({ name: 'uid', description: 'Interaction UID' })
  @ApiResponse({ status: 303, description: 'Redirect to client with error=access_denied' })
  async abort(
    @Param('uid') _uid: string,
    @Req() req: any,
    @Res() res: any,
  ) {
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

    // Check lockout
    const lockoutKey = `lockout:${identifier}`;
    const lockout = await this.redis.get(lockoutKey);
    if (lockout) {
      throw new ForbiddenException('Account locked due to too many failed attempts');
    }

    const user = await this.prisma.user.findFirst({
      where: { OR: orConditions, deletedAt: null },
    });

    if (!user?.passwordHash) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      // Increment failed attempts
      const failedKey = `failed:${user.id}`;
      const attempts = await this.redis.incr(failedKey);
      await this.redis.expire(failedKey, 900);
      if (attempts >= 5) {
        await this.redis.setEx(`lockout:${user.id}`, 900, '1');
        await this.redis.del(failedKey);
      }
      throw new UnauthorizedException('Invalid credentials');
    }

    // Clear failed attempts
    await this.redis.del(`failed:${user.id}`);
    return user;
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
