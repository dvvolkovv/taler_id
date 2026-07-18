import { Injectable, InternalServerErrorException } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Server-side assistant system prompt (voice-assistant instructions).
 *
 * The static body of the prompt lives in src/assistant/prompts/{ru,en}.md so
 * prompt edits ship with a backend deploy instead of a mobile release. The
 * client keeps only the dynamic pieces: the name preamble (preferredName /
 * set_preferred_name) and substitution of the {{NOW}} / {{LANG_NAME}}
 * placeholders before passing the text to the OpenAI Realtime session.
 *
 * File-read strategy: nest build does NOT copy .md assets to dist
 * (nest-cli.json has no assets config), so we read from the source tree via
 * process.cwd() — all deploys (aeza pm2, DO pm2) run from the repo root and
 * keep the full repo on disk. A __dirname-based fallback covers the case
 * where the process was started from another cwd. Files are tiny (~10 KB)
 * and the endpoint is hit once per assistant session, so we simply re-read
 * on each request (no cache) — this also picks up hot prompt edits without
 * a restart.
 */
@Injectable()
export class AssistantInstructionsService {
  private resolvePromptPath(file: string): string {
    const candidates = [
      path.join(process.cwd(), 'src', 'assistant', 'prompts', file),
      // dist/src/assistant → repo-root/src/assistant/prompts
      path.join(__dirname, '..', '..', '..', 'src', 'assistant', 'prompts', file),
      // in case assets ever get copied next to the compiled file
      path.join(__dirname, 'prompts', file),
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) return p;
    }
    throw new InternalServerErrorException(`Assistant prompt file not found: ${file}`);
  }

  getInstructions(locale?: string): { locale: 'ru' | 'en'; body: string; updatedAt: string } {
    const resolved: 'ru' | 'en' = locale === 'ru' ? 'ru' : 'en';
    const filePath = this.resolvePromptPath(`${resolved}.md`);
    const body = fs.readFileSync(filePath, 'utf8');
    const updatedAt = fs.statSync(filePath).mtime.toISOString();
    return { locale: resolved, body, updatedAt };
  }
}
