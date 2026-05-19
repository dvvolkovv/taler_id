import { Injectable, Logger } from '@nestjs/common';
import { exec } from 'node:child_process';
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

    return new Promise((resolve) => {
      exec(cmd, { timeout: this.TIMEOUT_MS, maxBuffer: this.MAX_BUFFER }, (err, result: any) => {
        const durationMs = Date.now() - start;

        if (!err) {
          // result may be a string (promisify) or object with stdout/stderr (raw exec)
          const stdout = typeof result === 'object' && result !== null
            ? (result.stdout ?? result)
            : (result ?? '');
          const stderr = typeof result === 'object' && result !== null
            ? (result.stderr ?? '')
            : '';

          if (stderr) {
            this.logger.warn(`claude stderr: ${String(stderr).slice(0, 500)}`);
          }

          resolve({
            finalText: String(stdout).trim(),
            toolCalls: [],
            aborted: false,
            conversationId: input.conversationId,
            durationMs,
          });
          return;
        }

        // Error path
        const isTimeout =
          (err as any).killed === true && (err as any).signal === 'SIGTERM';
        const exitCode = (err as any).code;
        const reason = isTimeout
          ? `timeout after ${this.TIMEOUT_MS}ms`
          : exitCode != null
          ? `exit ${exitCode}`
          : 'unknown';

        const stderr = ((err as any).stderr || '').toString().slice(0, 500);
        const stdout = ((err as any).stdout || '').toString().slice(0, 500);

        this.logger.error(
          `agent.run failed user=${input.userId} reason="${reason}" stderr="${stderr}"`,
        );

        resolve({
          finalText: `(aborted: ${reason}) ${stderr || stdout}`.trim(),
          toolCalls: [],
          aborted: true,
          conversationId: input.conversationId,
          durationMs,
        });
      });
    });
  }

  /**
   * Build the shell command:
   *   ssh -o BatchMode=yes dv@5.101.115.184 'claude --print --output-format text -- "<goal>"'
   *
   * Goal is escaped to be safe inside the OUTER single-quoted shell string
   * AND inside the INNER double-quoted claude argument. Strategy:
   *   1. Replace any double-quote with \" (escapes within inner double-quoted arg)
   *   2. Replace any single-quote with '\\'' (POSIX trick to close, escape, reopen
   *      the outer single-quoted string)
   */
  private buildSshCommand(goal: string): string {
    const innerEscaped = goal.replace(/"/g, '\\"');
    const outerEscaped = innerEscaped.replace(/'/g, "'\\''");
    return `ssh -o BatchMode=yes ${this.ANALYST_HOST} 'claude --print --output-format text -- "${outerEscaped}"'`;
  }
}
