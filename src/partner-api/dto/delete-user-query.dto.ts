import { IsIn, IsOptional } from 'class-validator';

export class DeleteUserQueryDto {
  /** Только 'true' или 'false': всё прочее — 400, а не молчаливое «не удалять». */
  @IsOptional()
  @IsIn(['true', 'false'], { message: 'invalid_delete_account' })
  deleteAccount?: 'true' | 'false';
}
