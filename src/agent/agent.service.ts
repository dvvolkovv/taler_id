import { Injectable, Logger } from '@nestjs/common';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { RunAgentResponseDto } from './dto/run-agent-response.dto';

interface RunAgentInput {
  goal: string;
  userId: string;
  conversationId?: string;
}

@Injectable()
export class AgentService {
  private readonly logger = new Logger(AgentService.name);
  private readonly ANALYST_HOST =
    process.env.CLAUDE_ANALYST_HOST || 'dv@5.101.115.184';
  private readonly TIMEOUT_MS = 120_000;
  private readonly MAX_BUFFER = 5 * 1024 * 1024;

  async runAgent(input: RunAgentInput): Promise<RunAgentResponseDto> {
    this.logger.debug(
      `agent.run user=${input.userId} goal="${input.goal.slice(0, 80)}"`,
    );

    const cmd = this.buildSshCommand(input.goal);
    const start = Date.now();
    // Lazy promisify so Jest mocks of node:child_process apply per-call
    const execAsync = promisify(exec);

    try {
      const { stdout, stderr } = await execAsync(cmd, {
        timeout: this.TIMEOUT_MS,
        maxBuffer: this.MAX_BUFFER,
      });

      if (stderr) {
        this.logger.warn(`claude stderr: ${stderr.toString().slice(0, 500)}`);
      }

      return {
        finalText: stdout.toString().trim(),
        toolCalls: [],
        aborted: false,
        conversationId: input.conversationId,
        durationMs: Date.now() - start,
      };
    } catch (err: any) {
      const durationMs = Date.now() - start;
      const reason =
        err.killed && err.signal === 'SIGTERM'
          ? `timeout after ${this.TIMEOUT_MS}ms`
          : err.code != null
          ? `exit ${err.code}`
          : 'unknown';
      const stderr = (err.stderr || '').toString().slice(0, 500);
      const stdout = (err.stdout || '').toString().slice(0, 500);

      this.logger.error(
        `agent.run failed user=${input.userId} reason="${reason}" stderr="${stderr}"`,
      );

      return {
        finalText: `(aborted: ${reason}) ${stderr || stdout}`.trim(),
        toolCalls: [],
        aborted: true,
        conversationId: input.conversationId,
        durationMs,
      };
    }
  }

  /**
   * Build the shell command:
   *   ssh -o BatchMode=yes dv@5.101.115.184 'claude --print --output-format text -- "<goal>"'
   *
   * Goal is escaped to be safe inside the OUTER single-quoted shell string
   * AND inside the INNER double-quoted claude argument. Strategy:
   *   1. Escape backslashes first (must be first to avoid double-escaping)
   *   2. Escape double-quotes with \" (safe inside inner double-quoted arg)
   *   3. Escape backticks with \` (prevents command substitution in inner context)
   *   4. Escape $ with \$ (prevents variable/command expansion in inner context)
   *   5. Escape single-quotes with '\\'' (POSIX trick: close, escape, reopen
   *      the outer single-quoted string)
   */
  private buildSshCommand(goal: string): string {
    const innerEscaped = goal
      .replace(/\\/g, '\\\\')   // backslash MUST be first
      .replace(/"/g, '\\"')      // double-quote
      .replace(/`/g, '\\`')      // backtick
      .replace(/\$/g, '\\$');    // dollar sign
    const outerEscaped = innerEscaped.replace(/'/g, "'\\''");
    return `ssh -o BatchMode=yes ${this.ANALYST_HOST} 'claude --print --output-format text -- "${outerEscaped}"'`;
  }
}
