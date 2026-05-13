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

      // Probe codec and determine transcoding strategy
      let codec = '';
      try {
        const { stdout } = await execFileAsync(
          'ffprobe',
          [
            '-v',
            'quiet',
            '-select_streams',
            'v:0',
            '-show_entries',
            'stream=codec_name',
            '-of',
            'csv=p=0',
            inputPath,
          ],
          { timeout: 10000 },
        );
        codec = stdout.trim().replace(/[,\s]+$/, '');
      } catch {
        this.logger.warn(
          `[transcode] ffprobe failed for ${s3Key}, attempting full transcode`,
        );
      }

      const isAlreadyMp4 = s3Key.toLowerCase().endsWith('.mp4');

      if (codec === 'h264' && isAlreadyMp4) {
        this.logger.log(`[transcode] ${s3Key} already H.264 MP4, skipping`);
        return null;
      }

      if (codec === 'h264') {
        // Already H.264 but in MOV container: remux (fast, no re-encode) + normalize audio
        this.logger.log(
          `[transcode] ${s3Key} H.264 in MOV, remuxing to MP4 + loudnorm`,
        );
        await execFileAsync(
          'ffmpeg',
          [
            '-i',
            inputPath,
            '-c:v',
            'copy',
            '-c:a',
            'aac',
            '-b:a',
            '128k',
            '-af',
            'loudnorm=I=-16:TP=-1.5:LRA=11',
            '-movflags',
            '+faststart',
            '-y',
            outputPath,
          ],
          { timeout: 300000 },
        );
      } else {
        // Full transcode: re-encode video + audio
        this.logger.log(
          `[transcode] ${s3Key} codec=${codec}, full transcode to H.264`,
        );
        await execFileAsync(
          'ffmpeg',
          [
            '-i',
            inputPath,
            '-c:v',
            'libx264',
            '-preset',
            'medium',
            '-crf',
            '23',
            '-c:a',
            'aac',
            '-b:a',
            '128k',
            '-af',
            'loudnorm=I=-16:TP=-1.5:LRA=11',
            '-movflags',
            '+faststart',
            '-y',
            outputPath,
          ],
          { timeout: 600000 },
        );
      }

      if (!fs.existsSync(outputPath)) {
        this.logger.error(`[transcode] Output file not created for ${s3Key}`);
        return null;
      }

      const outputData = fs.readFileSync(outputPath);
      const newSize = outputData.length;

      // Replace original in S3
      await this.fileStorage.upload(s3Key, outputData, 'video/mp4');
      this.logger.log(
        `[transcode] ${s3Key} done: ${inputData.length} → ${newSize} bytes`,
      );

      return { size: newSize };
    } catch (e) {
      this.logger.error(`[transcode] Failed for ${s3Key}:`, e);
      return null;
    } finally {
      try {
        fs.unlinkSync(inputPath);
      } catch {}
      try {
        fs.unlinkSync(outputPath);
      } catch {}
    }
  }
}
