import { Controller, Get, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
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

  // PKCE state stored in Redis with 30-minute TTL — survives pm2 restarts,
  // multi-worker deployment, and gives the user enough time to complete login
  // + consent without the state expiring under them. Key: `demo:pkce:<state>`.
  private static readonly STATE_TTL_SECONDS = 30 * 60;
  private static readonly STATE_KEY_PREFIX = 'demo:pkce:';

  // After a successful /callback (PRG pattern), the user info + token summary
  // are stashed in Redis under `demo:session:<sid>`, sid stored in an HttpOnly
  // cookie. This makes the success page survive browser refresh / back-button.
  private static readonly SESSION_TTL_SECONDS = 60 * 60; // 1h
  private static readonly SESSION_KEY_PREFIX = 'demo:session:';
  private static readonly SESSION_COOKIE = 'demo_sid';

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
    try {
      await this.redis.setEx(
        `${DemoController.STATE_KEY_PREFIX}${state}`,
        DemoController.STATE_TTL_SECONDS,
        verifier,
      );
      // eslint-disable-next-line no-console
      console.log(
        `[demo/login] stored state=${state.slice(0, 8)}... in Redis (TTL ${DemoController.STATE_TTL_SECONDS}s)`,
      );
    } catch (e: any) {
      // eslint-disable-next-line no-console
      console.error(`[demo/login] FAILED to store state in Redis:`, e?.message ?? e);
      throw e;
    }

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
      // Log to help diagnose stale-callback issues. Includes Redis key existence
      // (without value, since the value is the PKCE verifier).
      const allKeys = await this.redis.getClient().keys('demo:pkce:*');
      // eslint-disable-next-line no-console
      console.log(
        `[demo/callback] Unknown state="${state}". Redis has ${allKeys.length} other demo states (other UIDs): ${allKeys.slice(0, 3).map((k) => k.replace('demo:pkce:', '').slice(0, 8)).join(', ')}...`,
      );
      res
        .type('html')
        .send(
          this.renderError(
            `Unknown or expired state. Try logging in again. (state=${state.slice(0, 12)}... — likely a stale URL from a previous attempt; click 'Try again' to start fresh.)`,
          ),
        );
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

    // PRG: stash the result in a session, set a cookie, redirect to /demo/me.
    // This makes the success page survive browser refresh / back-button — and
    // a re-load of the (now-stale) callback URL won't show "Unknown state".
    const sid = randomUUID();
    const sessionPayload = JSON.stringify({
      userInfo,
      tokens: {
        token_type: 'Bearer',
        access_token_length: tokens.access_token.length,
        access_token_preview: `${tokens.access_token.slice(0, 24)}...`,
        id_token_present: Boolean(tokens.id_token),
        id_token: tokens.id_token, // kept for Sign Out's id_token_hint
        refresh_token_present: Boolean(tokens.refresh_token),
        expires_in_seconds: tokens.expires_in,
      },
    });
    await this.redis.setEx(
      `${DemoController.SESSION_KEY_PREFIX}${sid}`,
      DemoController.SESSION_TTL_SECONDS,
      sessionPayload,
    );
    res.cookie(DemoController.SESSION_COOKIE, sid, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: DemoController.SESSION_TTL_SECONDS * 1000,
      path: '/demo',
    });
    res.redirect('/demo/me');
  }

  private extractCookie(req: Request, name: string): string | undefined {
    // No cookie-parser middleware in this project; parse manually from raw header.
    const header = req.headers?.cookie ?? '';
    for (const part of header.split(';')) {
      const [k, ...v] = part.trim().split('=');
      if (k === name) return decodeURIComponent(v.join('='));
    }
    return undefined;
  }

  @Get('/me')
  async me(@Req() req: Request, @Res() res: Response): Promise<void> {
    const sid = this.extractCookie(req, DemoController.SESSION_COOKIE) ?? '';
    if (!sid) {
      res.redirect('/demo/');
      return;
    }
    const raw = await this.redis.get(`${DemoController.SESSION_KEY_PREFIX}${sid}`);
    if (!raw) {
      res.clearCookie(DemoController.SESSION_COOKIE, { path: '/demo' });
      res.redirect('/demo/');
      return;
    }
    const session = JSON.parse(raw) as {
      userInfo: Record<string, unknown>;
      tokens: {
        access_token_length: number;
        access_token_preview: string;
        id_token_present: boolean;
        id_token?: string;
        refresh_token_present: boolean;
        expires_in_seconds: number;
      };
    };
    res.type('html').send(this.renderSuccess(session.userInfo, session.tokens));
  }

  @Get('/signout')
  async signout(@Req() req: Request, @Res() res: Response): Promise<void> {
    const sid = this.extractCookie(req, DemoController.SESSION_COOKIE) ?? '';
    let idToken: string | undefined;
    if (sid) {
      const raw = await this.redis.get(`${DemoController.SESSION_KEY_PREFIX}${sid}`);
      if (raw) {
        try {
          const parsed = JSON.parse(raw) as { tokens?: { id_token?: string } };
          idToken = parsed.tokens?.id_token;
        } catch {
          /* ignore */
        }
      }
      await this.redis.del(`${DemoController.SESSION_KEY_PREFIX}${sid}`);
      res.clearCookie(DemoController.SESSION_COOKIE, { path: '/demo' });
    }
    res.redirect(this.buildLogoutUrl(idToken));
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
    tokens: {
      access_token_length: number;
      access_token_preview: string;
      id_token_present: boolean;
      id_token?: string;
      refresh_token_present: boolean;
      expires_in_seconds: number;
    },
  ): string {
    const safeUserInfo = JSON.stringify(userInfo, null, 2);
    const tokenSummary = JSON.stringify(
      {
        token_type: 'Bearer',
        access_token_length: tokens.access_token_length,
        access_token_preview: tokens.access_token_preview,
        id_token_present: tokens.id_token_present,
        refresh_token_present: tokens.refresh_token_present,
        expires_in_seconds: tokens.expires_in_seconds,
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
        <a href="/demo/signout" class="btn-secondary" style="margin-left: 12px">Sign Out</a>
        <a href="/ui/oauth-guide.html#example-app" style="margin-left: 16px">← Back to guide</a>
      </p>
      `,
    );
  }

  private buildLogoutUrl(idToken?: string): string {
    // OIDC RP-initiated logout. Without id_token_hint oidc-provider shows a
    // confirmation page; with it the flow auto-completes. post_logout_redirect_uri
    // must match a value registered on the client (see PrismaClientAdapter
    // hardcoding for taler-id-demo).
    const params = new URLSearchParams({
      post_logout_redirect_uri: `${this.baseUrl}/demo/`,
      client_id: this.clientId ?? '',
    });
    if (idToken) params.set('id_token_hint', idToken);
    return `${this.baseUrl}/oauth/session/end?${params.toString()}`;
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
