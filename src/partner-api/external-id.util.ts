import { BadRequestException } from '@nestjs/common';

/**
 * Стабильный id человека у партнёра (у nadi — id участника). Id из одних
 * точек (`.`, `..`, `...`) запрещён отдельно: их можно протащить через тело
 * запроса, но по URL до них не дойти (`/users/../token` нормализуется в
 * другой маршрут) — разночтение лучше не допускать вовсе.
 */
export const EXTERNAL_ID_RE = /^(?!\.+$)[A-Za-z0-9._:-]{1,128}$/;

export function assertExternalId(value: string): string {
  if (typeof value !== 'string' || !EXTERNAL_ID_RE.test(value)) {
    throw new BadRequestException('invalid_external_id');
  }
  return value;
}
