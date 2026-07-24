import { All, Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common';
import type { Request, Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { McpAuthGuard } from './mcp-auth.guard';
import { McpServerFactory } from './mcp-server.factory';

const MCP_SCOPES = [
  'mcp:calendar',
  'mcp:notes',
  'mcp:messages.read',
  'mcp:messages.send',
];

@Controller()
export class McpController {
  constructor(private readonly factory: McpServerFactory) {}

  // POST /mcp — Streamable HTTP MCP endpoint (stateless, no sticky sessions needed)
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
    res.on('close', () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, (req as any).body);
  }

  // Catch GET/DELETE/PATCH/etc. on /mcp — return a proper JSON-RPC error.
  // The @Post above has already claimed POST so this All catches everything else.
  @All('mcp')
  methodNotAllowed(@Res() res: Response) {
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
