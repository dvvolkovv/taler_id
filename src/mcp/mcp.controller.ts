import { All, Controller, Get, Logger, Post, Req, Res, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { McpAuthGuard } from './mcp-auth.guard';
import { McpServerFactory } from './mcp-server.factory';
import { MCP_SCOPES } from './mcp.constants';

@Controller()
export class McpController {
  constructor(private readonly factory: McpServerFactory) {}

  // POST /mcp — Streamable HTTP MCP endpoint (stateless, no sticky sessions needed)
  // Повышенные лимиты против глобальных (100/мин): AI-агент делает десятки
  // tool-вызовов подряд; глобальный medium-лимит выбивался даже e2e-suite'ом.
  @Throttle({
    short: { ttl: 1000, limit: 30 },
    medium: { ttl: 60_000, limit: 600 },
    long: { ttl: 3_600_000, limit: 10_000 },
  })
  @Post('mcp')
  @UseGuards(McpAuthGuard)
  async handle(@Req() req: Request, @Res() res: Response) {
    const { userId, scopes } = (req as any).mcpAuth;
    const server = this.factory.buildServer(userId, scopes);
    const transport = new StreamableHTTPServerTransport({
      // stateless: undefined sessionIdGenerator means no Mcp-Session-Id header
      // is issued; each POST is self-contained — safe behind DO LB without sticky.
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    // Guard against double-close: SDK WebStandardStreamableHTTPServerTransport.close()
    // calls onclose unconditionally — not idempotent. Both res.on('close') and the
    // finally block below can fire, so we deduplicate with this flag.
    let closed = false;
    const cleanup = async () => {
      if (closed) return;
      closed = true;
      await transport.close();
      await server.close();
    };

    res.on('close', () => { void cleanup(); });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, (req as any).body);
    } catch (e) {
      Logger.error(
        `MCP request failed: ${(e as Error).message}`,
        undefined,
        'McpController',
      );
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: 'Internal error' },
          id: null,
        });
      }
    } finally {
      await cleanup();
    }
  }

  // Catch GET/DELETE/PATCH/etc. on /mcp — return a proper JSON-RPC error.
  // The @Post above has already claimed POST so this All catches everything else.
  @All('mcp')
  methodNotAllowed(@Req() req: Request, @Res() res: Response) {
    res.setHeader('Allow', 'POST');
    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }
    res.status(405).json({
      jsonrpc: '2.0',
      error: { code: -32000, message: 'Method not allowed. Use POST.' },
      id: null,
    });
  }

  // OAuth 2.0 Protected Resource Metadata (RFC 9470 / MCP auth spec)
  // Must be served at the root-level path, not under any NestJS global prefix.
  // main.ts does NOT call app.setGlobalPrefix(), so @Controller() routes are
  // already at root.
  @Get('.well-known/oauth-protected-resource')
  protectedResourceMetadata() {
    const issuer =
      process.env.OIDC_ISSUER ||
      `${process.env.BASE_URL || 'https://staging.id.taler.tirol'}/oauth`;
    const base = issuer.replace(/\/oauth$/, '');
    return {
      resource: `${base}/mcp`,
      authorization_servers: [issuer],
      scopes_supported: MCP_SCOPES,
      bearer_methods_supported: ['header'],
    };
  }
}
