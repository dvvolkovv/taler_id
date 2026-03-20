import { Injectable, Logger } from '@nestjs/common';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { FileStorageService } from './file-storage.service';

const execFileAsync = promisify(execFile);

@Injectable()
export class VideoTranscodeService {
  private readonly logger = new Logger(VideoTranscodeService.name);

  constructor(private readonly fileStorage: FileStorageService) {}

  /**
   * Transcode video to H.264/AAC MP4 in the background.
   * Replaces the original S3 object with the transcoded version.
   * Returns the new file size, or null if transcoding failed/skipped.
   */
  async transcodeToH264(s3Key: string): Promise<{ size: number } | null> {
    const tmpDir = os.tmpdir();
    const inputPath = path.join(tmpDir, `transcode_in_${Date.now()}.tmp`);
    const outputPath = path.join(tmpDir, `transcode_out_${Date.now()}.mp4`);

    try {
      // Download from S3
      const { stream, contentType } = await this.fileStorage.getObject(s3Key);
      const chunks: Buffer[] = [];
      for await (const c of stream) chunks.push(Buffer.from(c));
      const inputData = Buffer.concat(chunks);
      fs.writeFileSync(inputPath, inputData);

      // Probe to check if already H.264
      try {
        const { stdout } = await execFileAsync('ffprobe', [
          '-v', 'quiet',
          '-select_streams', 'v:0',
          '-show_entries', 'stream=codec_name',
          '-of', 'csv=p=0',
          inputPath,
        ], { timeout: 10000 });

        const codec = stdout.trim();
        if (codec === 'h264') {
          this.logger.log(`[transcode] ${s3Key} already H.264, skipping`);
          return null;
        }
        this.logger.log(`[transcode] ${s3Key} codec=${codec}, transcoding to H.264`);
      } catch {
        this.logger.warn(`[transcode] ffprobe failed for ${s3Key}, attempting transcode anyway`);
      }

      // Transcode: H.264 video + AAC audio + loudnorm
      await execFileAsync('ffmpeg', [
        '-i', inputPath,
        '-c:v', 'libx264',
        '-preset', 'medium',
        '-crf', '23',
        '-c:a', 'aac',
        '-b:a', '128k',
        '-af', 'loudnorm=I=-16:TP=-1.5:LRA=11',
        '-movflags', '+faststart',
        '-y',
        outputPath,
      ], { timeout: 600000 }); // 10 min timeout

      if (!fs.existsSync(outputPath)) {
        this.logger.error(`[transcode] Output file not created for ${s3Key}`);
        return null;
      }

      const outputData = fs.readFileSync(outputPath);
      const newSize = outputData.length;

      // Replace original in S3
      await this.fileStorage.upload(s3Key, outputData, 'video/mp4');
      this.logger.log(`[transcode] ${s3Key} done: ${inputData.length} → ${newSize} bytes`);

      return { size: newSize };
    } catch (e) {
      this.logger.error(`[transcode] Failed for ${s3Key}:`, e);
      return null;
    } finally {
      try { fs.unlinkSync(inputPath); } catch {}
      try { fs.unlinkSync(outputPath); } catch {}
    }
  }
}
