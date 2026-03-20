import { Injectable, Logger } from '@nestjs/common';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadBucketCommand,
  CreateBucketCommand,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
} from '@aws-sdk/client-s3';
import { Readable } from 'stream';

@Injectable()
export class FileStorageService {
  private client: S3Client;
  private bucket: string;
  private readonly logger = new Logger(FileStorageService.name);

  constructor() {
    this.client = new S3Client({
      endpoint: process.env.S3_ENDPOINT ?? 'http://localhost:9000',
      region: process.env.S3_REGION ?? 'us-east-1',
      credentials: {
        accessKeyId: process.env.S3_ACCESS_KEY ?? 'minioadmin',
        secretAccessKey: process.env.S3_SECRET_KEY ?? 'minioadmin123',
      },
      forcePathStyle: true,
    });
    this.bucket = process.env.S3_FILES_BUCKET ?? 'taler-id-files';
    this.ensureBucket();
  }

  private async ensureBucket() {
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }));
    } catch {
      try {
        await this.client.send(new CreateBucketCommand({ Bucket: this.bucket }));
        this.logger.log(`Bucket "${this.bucket}" created`);
      } catch (e) {
        this.logger.error(`Failed to create bucket "${this.bucket}":`, e);
      }
    }
  }

  async upload(key: string, data: Buffer, contentType: string): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: data,
        ContentType: contentType,
      }),
    );
  }

  async getObject(key: string): Promise<{ stream: Readable; contentType: string }> {
    const resp = await this.client.send(
      new GetObjectCommand({ Bucket: this.bucket, Key: key }),
    );
    return {
      stream: resp.Body as Readable,
      contentType: resp.ContentType ?? 'application/octet-stream',
    };
  }

  /** Returns a public URL served through NestJS backend */
  getPublicUrl(key: string): string {
    const base = (process.env.BASE_URL ?? 'https://staging.id.taler.tirol').replace(/\/$/, '');
    return `${base}/messenger/files/download?key=${encodeURIComponent(key)}`;
  }

  async delete(key: string): Promise<void> {
    await this.client.send(
      new DeleteObjectCommand({ Bucket: this.bucket, Key: key }),
    );
  }

  // ─── S3 Multipart Upload ───

  async createMultipartUpload(key: string, contentType: string): Promise<string> {
    const resp = await this.client.send(
      new CreateMultipartUploadCommand({
        Bucket: this.bucket,
        Key: key,
        ContentType: contentType,
      }),
    );
    return resp.UploadId!;
  }

  async uploadPart(key: string, uploadId: string, partNumber: number, data: Buffer): Promise<string> {
    const resp = await this.client.send(
      new UploadPartCommand({
        Bucket: this.bucket,
        Key: key,
        UploadId: uploadId,
        PartNumber: partNumber,
        Body: data,
      }),
    );
    return resp.ETag!;
  }

  async completeMultipartUpload(
    key: string,
    uploadId: string,
    parts: { PartNumber: number; ETag: string }[],
  ): Promise<void> {
    await this.client.send(
      new CompleteMultipartUploadCommand({
        Bucket: this.bucket,
        Key: key,
        UploadId: uploadId,
        MultipartUpload: { Parts: parts },
      }),
    );
  }

  async abortMultipartUpload(key: string, uploadId: string): Promise<void> {
    await this.client.send(
      new AbortMultipartUploadCommand({
        Bucket: this.bucket,
        Key: key,
        UploadId: uploadId,
      }),
    );
  }
}
