import { Controller, Get, Query, Res } from '@nestjs/common';
import type { Response } from 'express';
import { createHash, randomBytes, randomUUID } from 'crypto';
import { RedisService } from '../redis/redis.service';

/**
 * Live "Try it live" demo for the OAuth integration guide.
 *
 * Acts as a registered OAuth client (`taler-id-demo`, system client with userId=null)
 * exposed at `/demo/*`. The flow exercises the same Authorization Code + PKCE
 * pipeline that any third-party integrator would use, ending with a userinfo
 * fetch from /oauth/me.
 *
 * Linked from `public/oauth-guide.html` (Working Example section).
 */
@Controller('demo')
export class DemoController {
  constructor(private readonly redis: RedisService) {}

  // PKCE state stored in Redis with 5-minute TTL — survives pm2 restarts and
  // any future multi-worker deployment. Key: `demo:pkce:<state>`, value: code_verifier.
  private static readonly STATE_TTL_SECONDS = 5 * 60;
  private static readonly STATE_KEY_PREFIX = 'demo:pkce:';

  private get clientId(): string | undefined {
    return process.env.DEMO_OAUTH_CLIENT_ID;
  }

  private get clientSecret(): string | undefined {
    return process.env.DEMO_OAUTH_CLIENT_SECRET;
  }

  private get baseUrl(): string {
    const issuer = process.env.OIDC_ISSUER;
    if (issuer) return issuer.replace(/\/oauth\/?$/, '');
    return process.env.BACKEND_URL || 'https://staging.id.taler.tirol';
  }

  private get redirectUri(): string {
    return `${this.baseUrl}/demo/callback`;
  }

  @Get('/')
  index(@Res() res: Response): void {
    res.type('html').send(this.renderLanding());
  }

  @Get('/login')
  async login(@Res() res: Response): Promise<void> {
    if (!this.clientId || !this.clientSecret) {
      res
        .status(503)
        .type('html')
        .send(
          this.renderError(
            'Demo client is not configured on this server. Set DEMO_OAUTH_CLIENT_ID and DEMO_OAUTH_CLIENT_SECRET in env.',
          ),
        );
      return;
    }
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const state = randomUUID();
    await this.redis.setEx(
      `${DemoController.STATE_KEY_PREFIX}${state}`,
      DemoController.STATE_TTL_SECONDS,
      verifier,
    );

    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: 'openid profile email',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    });
    res.redirect(`${this.baseUrl}/oauth/auth?${params.toString()}`);
  }

  @Get('/callback')
  async callback(
    @Query('code') code: string | undefined,
    @Query('state') state: string | undefined,
    @Query('error') error: string | undefined,
    @Query('error_description') errorDescription: string | undefined,
    @Res() res: Response,
  ): Promise<void> {
    if (error) {
      res
        .type('html')
        .send(
          this.renderError(`OAuth error: ${error}${errorDescription ? `\n${errorDescription}` : ''}`),
        );
      return;
    }
    if (!code || !state) {
      res.type('html').send(this.renderError('Missing code or state in callback.'));
      return;
    }
    const stateKey = `${DemoController.STATE_KEY_PREFIX}${state}`;
    const verifier = await this.redis.get(stateKey);
    if (verifier) await this.redis.del(stateKey);
    if (!verifier) {
      res
        .type('html')
        .send(this.renderError('Unknown or expired state. Try logging in again.'));
      return;
    }

    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.redirectUri,
      code_verifier: verifier,
    });
    const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString(
      'base64',
    );

    const tokenRes = await fetch(`${this.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: tokenBody.toString(),
    });

    if (!tokenRes.ok) {
      const errBody = await tokenRes.text();
      res
        .type('html')
        .send(
          this.renderError(
            `Token exchange failed: ${tokenRes.status} ${tokenRes.statusText}\n${errBody}`,
          ),
        );
      return;
    }
    const tokens = (await tokenRes.json()) as {
      access_token: string;
      id_token?: string;
      refresh_token?: string;
      token_type: string;
      expires_in: number;
    };

    const userInfoRes = await fetch(`${this.baseUrl}/oauth/me`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (!userInfoRes.ok) {
      const errBody = await userInfoRes.text();
      res
        .type('html')
        .send(
          this.renderError(
            `Userinfo fetch failed: ${userInfoRes.status} ${userInfoRes.statusText}\n${errBody}`,
          ),
        );
      return;
    }
    const userInfo = (await userInfoRes.json()) as Record<string, unknown>;

    res.type('html').send(this.renderSuccess(userInfo, tokens));
  }

  private renderLanding(): string {
    return this.shell(
      'Try Sign-In with Taler ID',
      `
      <h1>Sign In with Taler ID — Live Demo</h1>
      <p>
        Click the button below to log in with your Taler ID account. You'll be
        redirected to the standard Taler ID login screen, then a consent page,
        then back here — where this app calls <code>/oauth/me</code> and shows
        the claims it received.
      </p>
      <p>This demo is itself a registered OAuth client (<code>taler-id-demo</code>) using the
      same Authorization Code + PKCE flow that any integrator would implement.</p>
      <p style="margin: 32px 0">
        <a href="/demo/login" class="btn">Sign In with Taler ID</a>
      </p>
      <p><a href="/ui/oauth-guide.html#example-app">← Back to integration guide</a></p>
      `,
    );
  }

  private renderSuccess(
    userInfo: Record<string, unknown>,
    tokens: { access_token: string; id_token?: string; refresh_token?: string; expires_in: number },
  ): string {
    const safeUserInfo = JSON.stringify(userInfo, null, 2);
    const tokenSummary = JSON.stringify(
      {
        token_type: 'Bearer',
        access_token_length: tokens.access_token.length,
        access_token_preview: `${tokens.access_token.slice(0, 24)}...`,
        id_token_present: Boolean(tokens.id_token),
        refresh_token_present: Boolean(tokens.refresh_token),
        expires_in_seconds: tokens.expires_in,
      },
      null,
      2,
    );
    return this.shell(
      'Logged in via Taler ID',
      `
      <h1>✅ Logged in</h1>
      <p>The demo backend exchanged your authorization code for tokens, then
      called <code>GET /oauth/me</code> with the access token. Below is what
      Taler ID returned about you.</p>

      <h3>Tokens received</h3>
      <pre>${this.escape(tokenSummary)}</pre>

      <h3>Userinfo (<code>/oauth/me</code>)</h3>
      <pre>${this.escape(safeUserInfo)}</pre>

      <p style="margin-top: 24px">
        <a href="/demo/login" class="btn">Sign in again</a>
        <a href="/ui/oauth-guide.html#example-app" style="margin-left: 16px">← Back to guide</a>
      </p>
      `,
    );
  }

  private renderError(message: string): string {
    return this.shell(
      'Demo error',
      `
      <h1>⚠️ Demo error</h1>
      <pre>${this.escape(message)}</pre>
      <p><a href="/demo/" class="btn-secondary">Try again</a></p>
      `,
    );
  }

  private shell(title: string, body: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${this.escape(title)}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 16px; color: #1a1a1a; line-height: 1.6; }
  h1 { font-size: 28px; margin-bottom: 8px; }
  h3 { margin-top: 28px; }
  pre { background: #f5f5f7; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; line-height: 1.4; }
  code { background: #f5f5f7; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
  pre code { background: none; padding: 0; }
  a { color: #167EF2; }
  .btn {
    display: inline-block; padding: 14px 28px; background: #167EF2; color: white;
    text-decoration: none; border-radius: 10px; font-weight: 600; font-size: 16px;
    transition: background 0.2s;
  }
  .btn:hover { background: #0F66C7; }
  .btn-secondary {
    display: inline-block; padding: 10px 20px; background: #e5e5e7; color: #1a1a1a;
    text-decoration: none; border-radius: 8px; font-weight: 500;
  }
</style>
</head>
<body>${body}</body>
</html>`;
  }

  private escape(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}
