import { IsISO8601, IsOptional, IsString } from 'class-validator';

/**
 * The route used to declare its body as an inline object type. That is only a
 * TypeScript annotation — the global ValidationPipe skips types it has no
 * class-validator metadata for, so `whitelist`/`forbidNonWhitelisted` never
 * applied and the whole body reached prisma.note.update().
 */
export class UpdateNoteDto {
  @IsOptional()
  @IsString()
  title?: string;

  @IsOptional()
  @IsString()
  content?: string;

  /** Optimistic-concurrency check against the row's updatedAt. */
  @IsOptional()
  @IsISO8601()
  expectedUpdatedAt?: string;
}
