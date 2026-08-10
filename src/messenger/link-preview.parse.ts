/** Что вытаскиваем со страницы для карточки. */
export interface ParsedPreview {
  title: string | null;
  description: string | null;
  imageUrl: string | null;
  siteName: string | null;
}

/** Потолки, чтобы карточка не превращалась в простыню, а база — в свалку. */
const MAX_TITLE = 200;
const MAX_DESCRIPTION = 400;

function decodeEntities(s: string): string {
  return s
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&'); // последним, иначе «&amp;lt;» схлопнется дважды
}

function clean(v: string | null, max: number): string | null {
  if (!v) return null;
  const out = decodeEntities(v).replace(/\s+/g, ' ').trim();
  if (!out) return null;
  return out.length > max ? out.slice(0, max) : out;
}

/**
 * Ищет `<meta>` с нужным property/name.
 *
 * Порядок атрибутов в разметке произвольный (`content` может стоять до
 * `property`), поэтому сначала выбираем сам тег, а внутри уже ищем `content`.
 */
function metaContent(html: string, keys: string[]): string | null {
  for (const key of keys) {
    const tagRe = new RegExp(
      `<meta\\b[^>]*\\b(?:property|name)\\s*=\\s*["']${key}["'][^>]*>`,
      'i',
    );
    const tag = html.match(tagRe)?.[0];
    if (!tag) continue;
    const content = tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)?.[1];
    if (content) return content;
  }
  return null;
}

/**
 * Разбирает HTML в карточку.
 *
 * Open Graph в приоритете, `<title>` и обычный `description` — запасной путь:
 * половина сайтов OG не размечает, и без запасного варианта карточка выходила
 * бы пустой у каждого второго.
 */
export function parsePreview(html: string, baseUrl: string): ParsedPreview {
  const title =
    clean(metaContent(html, ['og:title', 'twitter:title']), MAX_TITLE) ??
    clean(html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? null, MAX_TITLE);

  const description = clean(
    metaContent(html, ['og:description', 'twitter:description', 'description']),
    MAX_DESCRIPTION,
  );

  const rawImage = metaContent(html, ['og:image', 'og:image:url', 'twitter:image']);
  let imageUrl: string | null = null;
  if (rawImage) {
    try {
      // Картинку часто дают относительным путём — без базы она бесполезна.
      const abs = new URL(decodeEntities(rawImage.trim()), baseUrl);
      if (abs.protocol === 'http:' || abs.protocol === 'https:') {
        imageUrl = abs.toString();
      }
    } catch {
      imageUrl = null;
    }
  }

  const siteName =
    clean(metaContent(html, ['og:site_name']), MAX_TITLE) ??
    (() => {
      try {
        return new URL(baseUrl).hostname.replace(/^www\./, '');
      } catch {
        return null;
      }
    })();

  return { title, description, imageUrl, siteName };
}
