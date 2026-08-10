import { parsePreview } from './link-preview.parse';

const BASE = 'https://example.com/article';

describe('parsePreview', () => {
  it('reads Open Graph tags', () => {
    const html = `
      <meta property="og:title" content="Заголовок">
      <meta property="og:description" content="Описание страницы">
      <meta property="og:image" content="https://cdn.example.com/pic.png">
      <meta property="og:site_name" content="Example">
    `;
    expect(parsePreview(html, BASE)).toEqual({
      title: 'Заголовок',
      description: 'Описание страницы',
      imageUrl: 'https://cdn.example.com/pic.png',
      siteName: 'Example',
    });
  });

  it('falls back to <title> and plain description', () => {
    // Половина сайтов OG не размечает; без запасного пути карточка была бы пустой.
    const html = `<title>Обычный заголовок</title>
      <meta name="description" content="Обычное описание">`;
    const out = parsePreview(html, BASE);
    expect(out.title).toBe('Обычный заголовок');
    expect(out.description).toBe('Обычное описание');
  });

  it('falls back to the hostname as the site name', () => {
    expect(parsePreview('<title>x</title>', 'https://www.example.com/a').siteName)
      .toBe('example.com');
  });

  it('resolves a relative image against the page url', () => {
    const html = `<meta property="og:image" content="/img/pic.png">`;
    expect(parsePreview(html, BASE).imageUrl).toBe('https://example.com/img/pic.png');
  });

  it('drops an image with a non-http scheme', () => {
    const html = `<meta property="og:image" content="data:image/png;base64,AAAA">`;
    expect(parsePreview(html, BASE).imageUrl).toBeNull();
  });

  it('does not care about attribute order', () => {
    const html = `<meta content="Сначала контент" property="og:title">`;
    expect(parsePreview(html, BASE).title).toBe('Сначала контент');
  });

  it('decodes html entities', () => {
    const html = `<meta property="og:title" content="Тим &amp; Тома &quot;в кавычках&quot;">`;
    expect(parsePreview(html, BASE).title).toBe('Тим & Тома "в кавычках"');
  });

  it('collapses whitespace in a multiline title', () => {
    expect(parsePreview('<title>\n  Много\n  строк\n</title>', BASE).title)
      .toBe('Много строк');
  });

  it('truncates a huge description instead of storing a novel', () => {
    const html = `<meta property="og:description" content="${'я'.repeat(1000)}">`;
    expect(parsePreview(html, BASE).description).toHaveLength(400);
  });

  it('returns nulls for a page with nothing useful', () => {
    const out = parsePreview('<html><body>привет</body></html>', BASE);
    expect(out.title).toBeNull();
    expect(out.description).toBeNull();
    expect(out.imageUrl).toBeNull();
    expect(out.siteName).toBe('example.com');
  });

  it('ignores an empty title tag', () => {
    expect(parsePreview('<title>   </title>', BASE).title).toBeNull();
  });

  it('treats an odd image value as a relative path, the way a browser would', () => {
    // `new URL(x, base)` разрешает почти что угодно относительно страницы —
    // получается ссылка на её же origin. Это не дыра: качать картинку будет
    // клиент, и он просто ничего не покажет. Важно, что разбор не падает.
    const html = `<meta property="og:image" content=":://not a url">`;
    const out = parsePreview(html, BASE);
    expect(() => parsePreview(html, BASE)).not.toThrow();
    expect(out.imageUrl!.startsWith('https://example.com/')).toBe(true);
  });
});
