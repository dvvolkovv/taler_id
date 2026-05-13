# OAuth UI Kit — Phase 0: Brand Page

**Status:** Design approved 2026-04-29
**Decomposition parent:** `taler_id_mobile/docs/superpowers/specs/2026-04-28-oauth-ui-kit-decomposition.md`

## Goal

Publish a self-contained brand assets page at `https://id.taler.tirol/brand` so third-party OAuth integrators can copy-paste a "Sign in with Taler ID" button, download the logo, and reference the official color palette and font without contacting the maintainer.

## Scope

- **In scope:** Static HTML page, 4 sections (logo, colors, typography, buttons), 4 button variants with copy-paste HTML/CSS, link from `oauth-guide.html`.
- **Out of scope (future phases):** SVG logos (Phase 0 ships PNG-only), JS SDK / React component (Phase 2), do's & don'ts guidelines, social-card / favicon assets, additional logo sizes.

## Non-Goals

- No new design language. The page reuses the existing Taler ID mobile app design (blue `#167EF2`, Inter font, existing PNG logos).
- No backend logic. The page is pure static HTML served from `public/`.
- No theme switcher / live preview. Buttons are shown side-by-side on a neutral background; users choose by inspection.

## Architecture

Single static page `public/brand/index.html`, served via the existing `ServeStaticModule` (`rootPath: public/`, `serveRoot: '/'`). Putting the page inside a directory and naming it `index.html` gives a clean URL `/brand` (NestJS auto-redirects to `/brand/`, which serves `index.html`) — same pattern already used by `public/admin/index.html`. Logo PNGs sit alongside the HTML in the same directory so the page is self-contained.

```
public/
├── brand/
│   ├── index.html          # the page (all 4 sections, inline CSS)
│   ├── logo-light.png      # 1024×1024 — copy from mobile repo's app_icon_light.png
│   └── logo-dark.png       # 1024×1024 — copy from mobile repo's app_icon_dark.png
└── oauth-guide.html        # gains a "Brand assets →" link in header
```

No new CSS file: styles are inlined in `index.html` to keep the deliverable a single drop-in artifact.

## Page Structure

The page uses the same dark theme as `oauth-guide.html` (background `#0A0E1A`, foreground `#F5F7FA`) with the same Inter typography. Top bar mirrors `oauth-guide.html`. Page is a single column, max-width 960 px, centered.

### Section 1 — Logo

Two side-by-side preview cards (light logo on white background, dark logo on `#0A0E1A` background). Below each preview: a "Download PNG" anchor pointing to `/brand/logo-light.png` or `/brand/logo-dark.png` with `download` attribute. Logo dimensions noted underneath ("1024 × 1024 px, PNG").

### Section 2 — Colors

Five color cards in a responsive grid. Each card: a 64 px swatch, the hex value, and a human-readable name. Hex values are in a `<code>` element with a copy button (vanilla JS clipboard API).

| Hex       | Name                         |
| --------- | ---------------------------- |
| `#167EF2` | Taler Blue (primary)         |
| `#1570D6` | Taler Blue Dark (hover)      |
| `#FBBF24` | Taler Gold (accent)          |
| `#0A0E1A` | Background Dark              |
| `#F5F7FA` | Foreground Light             |

### Section 3 — Typography

One block per font family:

- **Inter** — UI text. Sample line at 32 / 16 / 14 px. Copy-paste block:
  ```html
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  ```
- **JetBrains Mono** — code samples. Single sample line at 14 px + Google Fonts link block.

### Section 4 — Buttons

Four "Sign in with Taler ID" variants. Each variant: visual rendering on a contrasting background panel, then a `<details>` block with the copy-paste HTML, then a `<details>` block with the copy-paste CSS. A copy button on each code block.

Variants:

| ID            | Theme | Height | Background  | Text color  | Use case                                  |
| ------------- | ----- | ------ | ----------- | ----------- | ----------------------------------------- |
| `light-regular` | Light | 44 px  | `#FFFFFF`   | `#167EF2`   | Default for light-themed sites            |
| `light-large`   | Light | 56 px  | `#FFFFFF`   | `#167EF2`   | Hero / landing page CTA on light bg       |
| `dark-regular`  | Dark  | 44 px  | `#167EF2`   | `#FFFFFF`   | Default for dark-themed sites             |
| `dark-large`    | Dark  | 56 px  | `#167EF2`   | `#FFFFFF`   | Hero / landing page CTA on dark bg        |

Common styles (all variants): Inter 600 weight, 8 px border-radius, 16 px horizontal padding (24 px on `large`), 1 px solid `#167EF2` border. Hover state: light variants get `#EFF6FF` bg (very light Taler-blue tint, visible against pure white); dark variants get `#1570D6` bg (Taler Blue Dark). Text content: "Sign in with Taler ID" — no logo glyph in Phase 0 (deferred until SVG exists).

## Linking from oauth-guide

`public/oauth-guide.html` gains a single anchor in its header navigation: `<a href="/brand">Brand assets →</a>`, placed next to the existing nav links in the same style.

## Testing

This is a static-asset deliverable — no unit tests. Manual acceptance checks:

1. `curl -fIL https://staging.id.taler.tirol/brand` returns 200 (after 301 → `/brand/`), content-type `text/html`.
2. `curl -fI https://staging.id.taler.tirol/brand/logo-light.png` returns 200, content-type `image/png`.
3. Open `/brand` in a browser; verify all 4 sections render, copy buttons work, "Download PNG" downloads (not opens) the file.
4. Open `/oauth-guide.html` and click "Brand assets →"; verify it lands on `/brand/`.
5. Visual smoke: two button variants displayed in the panel match the live mobile app's primary color (eyeball check; both are `#167EF2`).

## Deployment

Standard backend deploy flow (`git pull && npm run build && pm2 restart`). DEV first per [project rule](../../../CLAUDE.md). PROD only on explicit user instruction.

## Future Work

- **SVG logos** — when available, replace PNG previews and add an "SVG" download next to each PNG. Glyph then added to button variants.
- **Phase 2** (JS SDK) — will reference `/brand` as the canonical color/font source so the SDK and the standalone copy-paste stay in sync.
- **Phase 4** (Developer Portal) — a logged-in dashboard could embed a live preview of the buttons with the developer's selected theme.
