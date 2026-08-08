/**
 * Курсор «до какого пина скрыть плашку», пришедший из тела запроса.
 * Всё, что не разбирается в валидную дату, отбрасываем: сервис в этом случае
 * сам возьмёт максимальный pinnedAt беседы. Сюда нельзя передавать строку
 * дальше — dismissPins зовёт у аргумента getTime(), и строка уронит запрос
 * в необработанный 500.
 */
export function parseUpToCursor(raw: unknown): Date | undefined {
  if (typeof raw !== 'string' || raw.length === 0) return undefined;
  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}
