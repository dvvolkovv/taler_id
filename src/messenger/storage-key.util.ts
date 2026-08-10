/**
 * Достаёт ключ объекта из публичной ссылки на файл.
 *
 * Ссылки на вложения имеют вид
 * `https://<host>/messenger/files/download?key=<urlencoded>` — ключ лежит прямо
 * в параметре. Нужно это для сообщений, отправленных до того, как клиент начал
 * передавать `s3Key`: без восстановления вся старая переписка осталась бы без
 * доступа к самому файлу.
 *
 * Возвращает null для чего угодно другого — в том числе для внешних ссылок,
 * которые к нашему хранилищу отношения не имеют.
 */
export function storageKeyFromUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (!parsed.pathname.endsWith('/messenger/files/download')) return null;
    const key = parsed.searchParams.get('key');
    if (!key) return null;
    // Ключ не должен уводить за пределы бакета.
    if (key.includes('..')) return null;
    return key;
  } catch {
    return null;
  }
}
