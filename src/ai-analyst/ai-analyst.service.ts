import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';

// The Claude Worker is already deployed at 5.101.115.184:3033 as "file-agent".
// It accepts POST /chat with {message, sessionId} + optional files, returns SSE.
const CLAUDE_WORKER_URL =
  process.env.CLAUDE_WORKER_URL || 'http://5.101.115.184:3033';

// Where Worker-produced output files are mirrored so mobile clients can fetch
// them. The Worker's own static `/files/...` is locked behind an iptables
// allowlist (PROD/DEV only) — phones cannot reach it. We copy files into an
// nginx-served path on the API host so the chat link actually works.
const ANALYST_FILES_DIR =
  process.env.ANALYST_FILES_DIR || '/var/www/ai-analyst';
const ANALYST_FILES_PUBLIC_BASE =
  process.env.ANALYST_FILES_PUBLIC_BASE ||
  'https://id.taler.tirol/ai-analyst';

@Injectable()
export class AiAnalystService {
  private readonly logger = new Logger(AiAnalystService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
  ) {}

  // ── Get or create the per-user AI Analyst conversation ──────────

  async getOrCreateChat(userId: string): Promise<string> {
    const existing = await this.prisma.conversation.findFirst({
      where: { type: 'AI_ANALYST', participants: { some: { userId } } },
    });
    if (existing) return existing.id;
    const conv = await this.prisma.conversation.create({
      data: {
        type: 'AI_ANALYST',
        name: 'AI Аналитик',
        createdById: userId,
        participants: { create: { userId, role: 'OWNER' } },
      },
    });
    this.logger.log(
      `Created AI_ANALYST conversation ${conv.id} for user ${userId}`,
    );
    return conv.id;
  }

  // ── Submit a task to the Claude Worker ──────────────────────────

  /**
   * Sends the user's message (+ optional file S3 keys) to the Claude
   * Worker and streams the response back via the provided callback.
   * Returns the full response text when done.
   */
  async submitTask(input: {
    userId: string;
    conversationId: string;
    messageText: string;
    fileUrls?: { url: string; name: string }[];
    onChunk: (text: string) => void;
    onTool?: (tool: string, input: string) => void;
    // Fires on every Worker SSE event (delta, tool, session, heartbeat,
    // result, done). Lets callers reset idle-timers during quiet phases
    // like image generation or `claude --resume` JSONL load.
    onHeartbeat?: () => void;
  }): Promise<{ text: string; outputFiles: any[] }> {
    // Use conversationId as the Claude Worker sessionId so multi-turn
    // context is preserved across messages in the same analyst chat.
    const sessionId = input.conversationId;

    // Build multipart form if there are files, otherwise plain JSON.
    let response: Response;

    if (input.fileUrls && input.fileUrls.length > 0) {
      // Download files from our S3 / public URLs and forward to Claude Worker
      const formData = new FormData();
      formData.append('message', input.messageText);
      formData.append('sessionId', sessionId);

      for (const file of input.fileUrls) {
        try {
          const fileResp = await fetch(file.url);
          if (fileResp.ok) {
            const blob = await fileResp.blob();
            formData.append('files', blob, file.name);
          }
        } catch (e) {
          this.logger.warn(
            `Failed to download file ${file.name}: ${(e as Error).message}`,
          );
        }
      }

      response = await fetch(`${CLAUDE_WORKER_URL}/chat`, {
        method: 'POST',
        body: formData,
      });
    } else {
      response = await fetch(`${CLAUDE_WORKER_URL}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: input.messageText,
          sessionId,
        }),
      });
    }

    if (!response.ok) {
      const errText = await response.text().catch(() => 'unknown error');
      throw new Error(`Claude Worker returned ${response.status}: ${errText}`);
    }

    // Parse SSE stream
    const reader = response.body?.getReader();
    if (!reader) throw new Error('No response body from Claude Worker');

    const decoder = new TextDecoder();
    let fullText = '';
    let outputFiles: any[] = [];
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const jsonStr = line.slice(6).trim();
        if (!jsonStr) continue;

        try {
          const ev = JSON.parse(jsonStr);
          // Any well-formed SSE event from Worker = proof of life.
          input.onHeartbeat?.();

          if (ev.type === 'delta' && ev.text) {
            fullText += ev.text;
            input.onChunk(ev.text);
          } else if (ev.type === 'tool' && input.onTool) {
            input.onTool(ev.tool, ev.input);
          } else if (ev.type === 'result' && ev.text) {
            // Final result text — may be more complete than accumulated deltas
            if (ev.text.length > fullText.length) {
              fullText = ev.text;
            }
          } else if (ev.type === 'done') {
            outputFiles = ev.outputFiles || [];
          } else if (ev.type === 'error') {
            throw new Error(`Claude Worker error: ${ev.text}`);
          }
        } catch (e) {
          if ((e as Error).message.startsWith('Claude Worker error')) throw e;
          // JSON parse error — skip
        }
      }
    }

    return { text: fullText, outputFiles };
  }

  // ── Mirror output files to a public-served path ────────────────

  /**
   * Downloads each Worker-produced output file via HTTP (PROD/DEV are the
   * only IPs allowed through the Worker's iptables) and writes it under
   * `ANALYST_FILES_DIR/<conversationId>/<rel>`. Returns entries with a
   * publicly reachable URL the mobile client can open.
   *
   * Worker `outputFiles[i].url` looks like `/files/<sessionId>/<rel>`. We
   * preserve the `<rel>` sub-path so files saved into nested directories on
   * the Worker keep their structure.
   */
  async mirrorOutputFiles(
    conversationId: string,
    outputFiles: Array<{ name: string; url: string; size?: number }>,
  ): Promise<Array<{ name: string; publicUrl: string; size?: number }>> {
    if (!outputFiles || outputFiles.length === 0) return [];

    const targetDir = path.join(ANALYST_FILES_DIR, conversationId);
    try {
      await fs.promises.mkdir(targetDir, { recursive: true });
    } catch (e) {
      this.logger.error(
        `mirrorOutputFiles: mkdir ${targetDir} failed: ${(e as Error).message}`,
      );
      return [];
    }

    const out: Array<{ name: string; publicUrl: string; size?: number }> = [];
    for (const f of outputFiles) {
      // f.url is the relative path on Worker, e.g. /files/<sid>/dir/file.pptx
      // f.name is the rel sub-path under outDir, e.g. dir/file.pptx
      const sourceUrl = `${CLAUDE_WORKER_URL}${f.url}`;
      const targetPath = path.join(targetDir, f.name);

      try {
        await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
        const resp = await fetch(sourceUrl);
        if (!resp.ok) {
          this.logger.warn(
            `mirrorOutputFiles: GET ${sourceUrl} -> ${resp.status}, skipping`,
          );
          continue;
        }
        const buf = Buffer.from(await resp.arrayBuffer());
        await fs.promises.writeFile(targetPath, buf);
        const publicUrl = `${ANALYST_FILES_PUBLIC_BASE}/${conversationId}/${f.name
          .split('/')
          .map(encodeURIComponent)
          .join('/')}`;
        out.push({ name: f.name, publicUrl, size: f.size });
      } catch (e) {
        this.logger.warn(
          `mirrorOutputFiles: failed to mirror ${f.name}: ${(e as Error).message}`,
        );
      }
    }
    return out;
  }

  // ── Get latest analyst response for voice assistant ─────────────

  async getLatestResponse(userId: string): Promise<{
    text: string;
    createdAt: string;
  } | null> {
    const conv = await this.prisma.conversation.findFirst({
      where: { type: 'AI_ANALYST', participants: { some: { userId } } },
    });
    if (!conv) return null;

    const msg = await this.prisma.message.findFirst({
      where: {
        conversationId: conv.id,
        isSystem: true, // bot messages are stored as isSystem
      },
      orderBy: { sentAt: 'desc' },
    });
    if (!msg) return null;

    return {
      text: msg.content || '',
      createdAt: msg.sentAt.toISOString(),
    };
  }
}
