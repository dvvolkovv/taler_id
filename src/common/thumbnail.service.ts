import { Injectable, Logger } from '@nestjs/common';
import sharp = require('sharp');
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const execFileAsync = promisify(execFile);

export interface ThumbnailResult {
  small?: Buffer;  // 100px
  medium?: Buffer; // 320px
  large?: Buffer;  // 800px
}

@Injectable()
export class ThumbnailService {
  private readonly logger = new Logger(ThumbnailService.name);

  async generateImageThumbnails(data: Buffer): Promise<ThumbnailResult> {
    try {
      const [small, medium, large] = await Promise.all([
        sharp(data).rotate().resize(100, 100, { fit: 'inside' }).webp({ quality: 80 }).toBuffer(),
        sharp(data).rotate().resize(320, 320, { fit: 'inside' }).webp({ quality: 80 }).toBuffer(),
        sharp(data).rotate().resize(800, 800, { fit: 'inside' }).webp({ quality: 80 }).toBuffer(),
      ]);
      return { small, medium, large };
    } catch (e) {
      this.logger.error('Image thumbnail generation failed:', e);
      return {};
    }
  }

  async generateVideoThumbnail(data: Buffer): Promise<ThumbnailResult> {
    const tmpDir = os.tmpdir();
    const inputPath = path.join(tmpDir, `vid_${Date.now()}.tmp`);
    const outputPath = path.join(tmpDir, `thumb_${Date.now()}.jpg`);

    try {
      fs.writeFileSync(inputPath, data);

      await execFileAsync('ffmpeg', [
        '-i', inputPath,
        '-ss', '00:00:01',
        '-vframes', '1',
        '-vf', 'scale=320:-1',
        '-q:v', '5',
        '-y',
        outputPath,
      ], { timeout: 15000 });

      if (!fs.existsSync(outputPath)) {
        // Try frame 0 if video is shorter than 1 second
        await execFileAsync('ffmpeg', [
          '-i', inputPath,
          '-vframes', '1',
          '-vf', 'scale=320:-1',
          '-q:v', '5',
          '-y',
          outputPath,
        ], { timeout: 15000 });
      }

      if (fs.existsSync(outputPath)) {
        const jpgData = fs.readFileSync(outputPath);
        // Convert to WebP for smaller size
        const webpData = await sharp(jpgData).webp({ quality: 80 }).toBuffer();
        return { medium: webpData };
      }
      return {};
    } catch (e) {
      this.logger.error('Video thumbnail generation failed:', e);
      return {};
    } finally {
      try { fs.unlinkSync(inputPath); } catch {}
      try { fs.unlinkSync(outputPath); } catch {}
    }
  }
}
