# OAuth UI Kit — Phase 0: Brand Page — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a self-contained brand page at `https://id.taler.tirol/brand` with logo downloads, color palette, typography, and 4 copy-paste "Sign in with Taler ID" buttons.

**Architecture:** Single static HTML file at `public/brand/index.html` with inline CSS. Logo PNGs copied from the mobile repo. Served by the existing `ServeStaticModule` (`/` → `public/`) — no backend code change. Linked from `oauth-guide.html`.

**Tech Stack:** Plain HTML5 + CSS3 + a tiny vanilla-JS clipboard helper. No frameworks, no build step. Page is dark-themed, matching `oauth-guide.html`.

**Spec:** `docs/superpowers/specs/2026-04-29-oauth-ui-kit-phase-0-brand.md`

**Working directory:** `~/taler-id` on `main` branch. Repository has many uncommitted parallel-development changes — every task in this plan must `git add` only the specific files it touches (never `git add -A` / `git add .`).

**Testing model:** This is a static-asset deliverable. No unit tests. Each task ends with a manual or `curl`-based verification that the just-added piece renders / serves correctly. Final task deploys to DEV and runs the smoke checklist from the spec.

---

## File Structure

```
~/taler-id/
├── public/
│   ├── brand/
│   │   ├── index.html          # NEW — the page (all 4 sections, inline CSS+JS)
│   │   ├── logo-light.png      # NEW — copy of mobile repo's app_icon_light.png
│   │   └── logo-dark.png       # NEW — copy of mobile repo's app_icon_dark.png
│   └── oauth-guide.html        # MODIFIED — adds "Brand assets →" nav link
└── docs/superpowers/
    ├── specs/2026-04-29-oauth-ui-kit-phase-0-brand.md   # spec (already committed)
    └── plans/2026-04-29-oauth-ui-kit-phase-0-brand.md   # this plan
```

Each task touches exactly one or two of these files. The HTML file grows section-by-section across Tasks 2-6.

---

## Task 1: Copy logo PNGs into public/brand/

**Files:**
- Create: `~/taler-id/public/brand/logo-light.png` (copy from `~/Downloads/taler_id_mobile/assets/app_icon_light.png`)
- Create: `~/taler-id/public/brand/logo-dark.png` (copy from `~/Downloads/taler_id_mobile/assets/app_icon_dark.png`)

- [ ] **Step 1: Create the brand directory and copy logos**

```bash
mkdir -p ~/taler-id/public/brand
cp ~/Downloads/taler_id_mobile/assets/app_icon_light.png ~/taler-id/public/brand/logo-light.png
cp ~/Downloads/taler_id_mobile/assets/app_icon_dark.png ~/taler-id/public/brand/logo-dark.png
```

- [ ] **Step 2: Verify the files**

```bash
file ~/taler-id/public/brand/logo-light.png ~/taler-id/public/brand/logo-dark.png
```

Expected output (both lines):
```
... PNG image data, 1024 x 1024, 8-bit/color ...
```

- [ ] **Step 3: Commit**

```bash
cd ~/taler-id
git add public/brand/logo-light.png public/brand/logo-dark.png
git commit -m "feat(brand): add light/dark logo PNGs to public/brand/"
```

---

## Task 2: Create page skeleton with Section 1 (Logo)

**Files:**
- Create: `~/taler-id/public/brand/index.html`

- [ ] **Step 1: Write the initial HTML file with skeleton + Logo section**

Create `~/taler-id/public/brand/index.html` with the following exact content:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Brand Assets — Taler ID</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #167EF2;
      --primary-dark: #1570D6;
      --accent: #FBBF24;
      --bg: #0A0E1A;
      --bg-elevated: #161B2C;
      --fg: #F5F7FA;
      --fg-muted: #8A92A6;
      --border: #232A40;
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--fg);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 16px;
      line-height: 1.6;
    }
    a { color: var(--primary); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code {
      font-family: 'JetBrains Mono', ui-monospace, monospace;
      font-size: 0.9em;
    }

    /* Top nav (mirrors oauth-guide.html) */
    .nav {
      background: var(--bg-elevated);
      border-bottom: 1px solid var(--border);
      padding: 16px 24px;
    }
    .nav-inner {
      max-width: 960px;
      margin: 0 auto;
      display: flex;
      gap: 24px;
      flex-wrap: wrap;
      align-items: center;
    }
    .nav-title {
      font-weight: 700;
      color: var(--fg);
    }

    /* Page container */
    .container {
      max-width: 960px;
      margin: 0 auto;
      padding: 48px 24px;
    }
    h1 { font-size: 36px; font-weight: 700; margin: 0 0 8px; }
    h2 { font-size: 24px; font-weight: 600; margin: 48px 0 16px; padding-top: 24px; border-top: 1px solid var(--border); }
    h2:first-of-type { border-top: none; padding-top: 0; }
    .lead { color: var(--fg-muted); font-size: 18px; margin: 0 0 32px; }

    /* Logo section */
    .logo-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
    }
    @media (max-width: 640px) {
      .logo-grid { grid-template-columns: 1fr; }
    }
    .logo-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      text-align: center;
    }
    .logo-preview {
      width: 100%;
      aspect-ratio: 1;
      max-width: 240px;
      margin: 0 auto 16px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }
    .logo-preview--light { background: #FFFFFF; }
    .logo-preview--dark { background: var(--bg); border: 1px solid var(--border); }
    .logo-preview img { max-width: 80%; max-height: 80%; }
    .logo-meta { color: var(--fg-muted); font-size: 14px; margin-bottom: 12px; }
    .download-btn {
      display: inline-block;
      padding: 8px 16px;
      background: var(--primary);
      color: #FFFFFF;
      border-radius: 6px;
      font-weight: 500;
      font-size: 14px;
    }
    .download-btn:hover { background: var(--primary-dark); text-decoration: none; }
  </style>
</head>
<body>
  <div class="nav">
    <div class="nav-inner">
      <span class="nav-title">Taler ID — Brand Assets</span>
      <a href="/oauth-guide.html">← Integration guide</a>
    </div>
  </div>

  <div class="container">
    <h1>Brand Assets</h1>
    <p class="lead">Logos, colors, typography, and ready-to-use buttons for integrating "Sign in with Taler ID".</p>

    <h2>Logo</h2>
    <div class="logo-grid">
      <div class="logo-card">
        <div class="logo-preview logo-preview--light">
          <img src="/brand/logo-light.png" alt="Taler ID logo (light)">
        </div>
        <div class="logo-meta">1024 × 1024 px, PNG · Use on dark backgrounds</div>
        <a class="download-btn" href="/brand/logo-light.png" download>Download PNG</a>
      </div>
      <div class="logo-card">
        <div class="logo-preview logo-preview--dark">
          <img src="/brand/logo-dark.png" alt="Taler ID logo (dark)">
        </div>
        <div class="logo-meta">1024 × 1024 px, PNG · Use on light backgrounds</div>
        <a class="download-btn" href="/brand/logo-dark.png" download>Download PNG</a>
      </div>
    </div>
  </div>
</body>
</html>
```

- [ ] **Step 2: Verify by opening in a browser**

```bash
open ~/taler-id/public/brand/index.html
```

Expected: Page loads with dark background, "Brand Assets" heading, lead paragraph, and two logo cards side-by-side. Light logo on a white card, dark logo on a dark card. Both "Download PNG" buttons are visible. Top nav shows "Taler ID — Brand Assets" and a link "← Integration guide".

- [ ] **Step 3: Commit**

```bash
cd ~/taler-id
git add public/brand/index.html
git commit -m "feat(brand): scaffold brand page with logo section"
```

---

## Task 3: Add Section 2 (Colors)

**Files:**
- Modify: `~/taler-id/public/brand/index.html` (add CSS for color cards + Colors section HTML)

- [ ] **Step 1: Add color-card CSS to the `<style>` block**

In `~/taler-id/public/brand/index.html`, locate the closing `}` of `.download-btn:hover { ... }` rule (just before `</style>`). Insert these rules immediately after that closing brace:

```css
    /* Colors section */
    .color-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 16px;
    }
    .color-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }
    .color-swatch {
      height: 96px;
      width: 100%;
    }
    .color-meta {
      padding: 12px 16px;
    }
    .color-name {
      font-weight: 600;
      font-size: 14px;
      margin-bottom: 4px;
    }
    .color-hex {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--fg-muted);
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
    }
    .copy-btn {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--fg-muted);
      border-radius: 4px;
      padding: 2px 8px;
      font-size: 11px;
      cursor: pointer;
      font-family: inherit;
    }
    .copy-btn:hover {
      color: var(--fg);
      border-color: var(--primary);
    }
    .copy-btn.copied {
      color: var(--accent);
      border-color: var(--accent);
    }
```

- [ ] **Step 2: Add the Colors section HTML**

Locate the closing `</div>` of the Logo section (after the second `.logo-card` closing div, just before `</div>` that closes `.container`). Insert this block immediately AFTER the `</div>` that closes `.logo-grid`:

```html

    <h2>Colors</h2>
    <div class="color-grid">
      <div class="color-card">
        <div class="color-swatch" style="background: #167EF2"></div>
        <div class="color-meta">
          <div class="color-name">Taler Blue</div>
          <div class="color-hex"><code>#167EF2</code><button class="copy-btn" data-copy="#167EF2">Copy</button></div>
        </div>
      </div>
      <div class="color-card">
        <div class="color-swatch" style="background: #1570D6"></div>
        <div class="color-meta">
          <div class="color-name">Taler Blue Dark</div>
          <div class="color-hex"><code>#1570D6</code><button class="copy-btn" data-copy="#1570D6">Copy</button></div>
        </div>
      </div>
      <div class="color-card">
        <div class="color-swatch" style="background: #FBBF24"></div>
        <div class="color-meta">
          <div class="color-name">Taler Gold</div>
          <div class="color-hex"><code>#FBBF24</code><button class="copy-btn" data-copy="#FBBF24">Copy</button></div>
        </div>
      </div>
      <div class="color-card">
        <div class="color-swatch" style="background: #0A0E1A; border-bottom: 1px solid #232A40"></div>
        <div class="color-meta">
          <div class="color-name">Background Dark</div>
          <div class="color-hex"><code>#0A0E1A</code><button class="copy-btn" data-copy="#0A0E1A">Copy</button></div>
        </div>
      </div>
      <div class="color-card">
        <div class="color-swatch" style="background: #F5F7FA"></div>
        <div class="color-meta">
          <div class="color-name">Foreground Light</div>
          <div class="color-hex"><code>#F5F7FA</code><button class="copy-btn" data-copy="#F5F7FA">Copy</button></div>
        </div>
      </div>
    </div>
```

- [ ] **Step 3: Reload the page in the browser**

```bash
open ~/taler-id/public/brand/index.html
```

Expected: After the Logo section, a "Colors" heading appears, followed by 5 color cards in a responsive grid (Taler Blue / Taler Blue Dark / Taler Gold / Background Dark / Foreground Light). Each card shows a colored swatch, name, hex, and a "Copy" button. Buttons don't work yet (JS comes in Task 6) — that's OK.

- [ ] **Step 4: Commit**

```bash
cd ~/taler-id
git add public/brand/index.html
git commit -m "feat(brand): add color palette section"
```

---

## Task 4: Add Section 3 (Typography)

**Files:**
- Modify: `~/taler-id/public/brand/index.html` (add CSS for typography + Typography section HTML)

- [ ] **Step 1: Add typography-section CSS**

Locate the closing `}` of the `.copy-btn.copied { ... }` rule. Insert immediately after:

```css
    /* Typography section */
    .type-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 16px;
    }
    .type-name {
      font-size: 14px;
      color: var(--fg-muted);
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-bottom: 12px;
    }
    .type-sample {
      margin-bottom: 24px;
    }
    .type-sample-32 { font-size: 32px; line-height: 1.2; font-weight: 600; }
    .type-sample-16 { font-size: 16px; line-height: 1.5; margin-top: 8px; }
    .type-sample-14 { font-size: 14px; line-height: 1.5; color: var(--fg-muted); margin-top: 4px; }
    .type-sample-mono { font-family: 'JetBrains Mono', monospace; font-size: 14px; }

    .code-block {
      position: relative;
      background: #05070D;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      padding-right: 80px;
      margin-top: 12px;
      overflow-x: auto;
    }
    .code-block pre {
      margin: 0;
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      color: var(--fg);
      white-space: pre;
    }
    .code-block .copy-btn {
      position: absolute;
      top: 12px;
      right: 12px;
    }
```

- [ ] **Step 2: Add the Typography section HTML**

Locate the closing `</div>` of `.color-grid`. Insert immediately AFTER it:

```html

    <h2>Typography</h2>
    <div class="type-card">
      <div class="type-name">Inter — UI text</div>
      <div class="type-sample">
        <div class="type-sample-32">Sign in with Taler ID</div>
        <div class="type-sample-16">Body text uses Inter at 16 px with 1.5 line-height for readability.</div>
        <div class="type-sample-14">Smaller hints and metadata sit at 14 px in muted color.</div>
      </div>
      <div class="code-block">
        <button class="copy-btn" data-copy-target="font-inter">Copy</button>
        <pre id="font-inter">&lt;link rel="preconnect" href="https://fonts.googleapis.com"&gt;
&lt;link rel="preconnect" href="https://fonts.gstatic.com" crossorigin&gt;
&lt;link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&amp;display=swap" rel="stylesheet"&gt;</pre>
      </div>
    </div>

    <div class="type-card">
      <div class="type-name">JetBrains Mono — Code</div>
      <div class="type-sample">
        <div class="type-sample-mono">curl -X POST https://id.taler.tirol/oauth/register</div>
      </div>
      <div class="code-block">
        <button class="copy-btn" data-copy-target="font-mono">Copy</button>
        <pre id="font-mono">&lt;link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet"&gt;</pre>
      </div>
    </div>
```

- [ ] **Step 3: Reload the page in the browser**

```bash
open ~/taler-id/public/brand/index.html
```

Expected: After Colors, a "Typography" heading appears, followed by two type cards. The Inter card shows three text samples (32 / 16 / 14 px) and a code block with the Google Fonts `<link>` snippet. The JetBrains Mono card shows a monospace sample line and its own snippet. A "Copy" button is in the top-right of each code block.

- [ ] **Step 4: Commit**

```bash
cd ~/taler-id
git add public/brand/index.html
git commit -m "feat(brand): add typography section"
```

---

## Task 5: Add Section 4 (Buttons)

**Files:**
- Modify: `~/taler-id/public/brand/index.html` (add button CSS, shared CSS snippet, 4 variant cards)

- [ ] **Step 1: Add `.signin-btn` CSS classes**

Locate the closing `}` of `.code-block .copy-btn { ... }` rule. Insert immediately after:

```css
    /* Sign-in button library (Phase 0 — Inter, no glyph yet) */
    .signin-btn {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      font-weight: 600;
      border-radius: 8px;
      border: 1px solid #167EF2;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      text-decoration: none;
      transition: background 120ms ease;
      user-select: none;
      box-sizing: border-box;
    }
    .signin-btn:hover { text-decoration: none; }
    .signin-btn--regular { height: 44px; padding: 0 16px; font-size: 14px; }
    .signin-btn--large { height: 56px; padding: 0 24px; font-size: 16px; }
    .signin-btn--light { background: #FFFFFF; color: #167EF2; }
    .signin-btn--light:hover { background: #EFF6FF; }
    .signin-btn--dark { background: #167EF2; color: #FFFFFF; }
    .signin-btn--dark:hover { background: #1570D6; border-color: #1570D6; }

    /* Button preview cards */
    .btn-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 16px;
    }
    .btn-card-title {
      font-size: 14px;
      color: var(--fg-muted);
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-bottom: 16px;
    }
    .btn-preview-light, .btn-preview-dark {
      padding: 32px;
      border-radius: 8px;
      text-align: center;
      margin-bottom: 12px;
    }
    .btn-preview-light { background: #F5F7FA; }
    .btn-preview-dark { background: #0A0E1A; border: 1px solid var(--border); }
```

- [ ] **Step 2: Add the Buttons section HTML**

Locate the closing `</div>` of the SECOND `.type-card` (JetBrains Mono card). Insert immediately AFTER it:

```html

    <h2>Buttons</h2>
    <p class="lead" style="font-size: 16px; margin-bottom: 24px;">Drop these "Sign in with Taler ID" buttons into your app. The CSS block below covers all four variants — paste it once, then use the per-variant HTML.</p>

    <div class="btn-card">
      <div class="btn-card-title">Shared CSS — paste once</div>
      <div class="code-block">
        <button class="copy-btn" data-copy-target="shared-css">Copy</button>
        <pre id="shared-css">.signin-btn {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  font-weight: 600;
  border-radius: 8px;
  border: 1px solid #167EF2;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  text-decoration: none;
  transition: background 120ms ease;
  user-select: none;
  box-sizing: border-box;
}
.signin-btn--regular { height: 44px; padding: 0 16px; font-size: 14px; }
.signin-btn--large   { height: 56px; padding: 0 24px; font-size: 16px; }
.signin-btn--light          { background: #FFFFFF; color: #167EF2; }
.signin-btn--light:hover    { background: #EFF6FF; }
.signin-btn--dark           { background: #167EF2; color: #FFFFFF; }
.signin-btn--dark:hover     { background: #1570D6; border-color: #1570D6; }</pre>
      </div>
    </div>

    <div class="btn-card">
      <div class="btn-card-title">Light · Regular (44 px)</div>
      <div class="btn-preview-light">
        <a href="#" class="signin-btn signin-btn--regular signin-btn--light">Sign in with Taler ID</a>
      </div>
      <div class="code-block">
        <button class="copy-btn" data-copy-target="btn-light-regular">Copy</button>
        <pre id="btn-light-regular">&lt;a href="https://id.taler.tirol/oauth/auth?..." class="signin-btn signin-btn--regular signin-btn--light"&gt;Sign in with Taler ID&lt;/a&gt;</pre>
      </div>
    </div>

    <div class="btn-card">
      <div class="btn-card-title">Light · Large (56 px)</div>
      <div class="btn-preview-light">
        <a href="#" class="signin-btn signin-btn--large signin-btn--light">Sign in with Taler ID</a>
      </div>
      <div class="code-block">
        <button class="copy-btn" data-copy-target="btn-light-large">Copy</button>
        <pre id="btn-light-large">&lt;a href="https://id.taler.tirol/oauth/auth?..." class="signin-btn signin-btn--large signin-btn--light"&gt;Sign in with Taler ID&lt;/a&gt;</pre>
      </div>
    </div>

    <div class="btn-card">
      <div class="btn-card-title">Dark · Regular (44 px)</div>
      <div class="btn-preview-dark">
        <a href="#" class="signin-btn signin-btn--regular signin-btn--dark">Sign in with Taler ID</a>
      </div>
      <div class="code-block">
        <button class="copy-btn" data-copy-target="btn-dark-regular">Copy</button>
        <pre id="btn-dark-regular">&lt;a href="https://id.taler.tirol/oauth/auth?..." class="signin-btn signin-btn--regular signin-btn--dark"&gt;Sign in with Taler ID&lt;/a&gt;</pre>
      </div>
    </div>

    <div class="btn-card">
      <div class="btn-card-title">Dark · Large (56 px)</div>
      <div class="btn-preview-dark">
        <a href="#" class="signin-btn signin-btn--large signin-btn--dark">Sign in with Taler ID</a>
      </div>
      <div class="code-block">
        <button class="copy-btn" data-copy-target="btn-dark-large">Copy</button>
        <pre id="btn-dark-large">&lt;a href="https://id.taler.tirol/oauth/auth?..." class="signin-btn signin-btn--large signin-btn--dark"&gt;Sign in with Taler ID&lt;/a&gt;</pre>
      </div>
    </div>
```

- [ ] **Step 3: Reload the page in the browser**

```bash
open ~/taler-id/public/brand/index.html
```

Expected: After Typography, a "Buttons" heading appears with intro text, then 5 cards: shared CSS, then 4 button variants. Each variant card shows the live button on a contrasting background (light variants on `#F5F7FA`, dark variants on `#0A0E1A`) and a code block with the copy-paste HTML. Hovering a light-variant button changes its bg to a faint blue tint; hovering a dark-variant button darkens to `#1570D6`.

- [ ] **Step 4: Commit**

```bash
cd ~/taler-id
git add public/brand/index.html
git commit -m "feat(brand): add 4 sign-in button variants with shared CSS"
```

---

## Task 6: Wire up the Copy buttons

**Files:**
- Modify: `~/taler-id/public/brand/index.html` (add a `<script>` block before `</body>`)

- [ ] **Step 1: Add the clipboard JS**

Locate `</body>` near the end of `~/taler-id/public/brand/index.html`. Insert this `<script>` block immediately BEFORE `</body>`:

```html
  <script>
    document.querySelectorAll('.copy-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const text = btn.dataset.copy
          ?? document.getElementById(btn.dataset.copyTarget)?.textContent
          ?? '';
        if (!text) return;
        try {
          await navigator.clipboard.writeText(text);
          const originalText = btn.textContent;
          btn.textContent = 'Copied!';
          btn.classList.add('copied');
          setTimeout(() => {
            btn.textContent = originalText;
            btn.classList.remove('copied');
          }, 1200);
        } catch (err) {
          console.error('Copy failed', err);
          btn.textContent = 'Press Ctrl+C';
        }
      });
    });
  </script>
```

The script supports both copy modes already used in earlier tasks:
- **Inline value** via `data-copy="..."` attribute (used by color cards and font-link snippets).
- **DOM-target lookup** via `data-copy-target="elementId"` (used by button code blocks where the snippet is also rendered as visible text in a `<pre id="...">`).

- [ ] **Step 2: Test all copy buttons in the browser**

```bash
open ~/taler-id/public/brand/index.html
```

Click each Copy button (5 colors + 2 typography snippets + 1 shared-CSS + 4 button variants = 12 total) and paste into a scratch buffer. Expected behaviour for each:
- Button text changes to "Copied!" briefly, then reverts.
- Button border/text turns gold (`#FBBF24`) during the "Copied!" state.
- Pasted clipboard contents match the visible code/value.

If `navigator.clipboard.writeText` is rejected because the file is opened via `file://` (browsers limit clipboard API on `file://` for security), the catch branch shows "Press Ctrl+C". That is acceptable — the buttons will work over HTTPS once deployed. Do NOT change the script to chase a `file://` workaround; the deployment smoke test (Task 8) re-verifies over HTTPS.

- [ ] **Step 3: Commit**

```bash
cd ~/taler-id
git add public/brand/index.html
git commit -m "feat(brand): wire up copy-to-clipboard buttons"
```

---

## Task 7: Link from oauth-guide.html

**Files:**
- Modify: `~/taler-id/public/oauth-guide.html` (one-line addition to the nav)

- [ ] **Step 1: Add the "Brand assets →" link to the oauth-guide top nav**

Open `~/taler-id/public/oauth-guide.html`. Locate the `.nav-inner` block (currently lines 124-135). It contains anchors `Overview`, `Quick Start`, `Registration`, `Example App`, `Auth Flow`, `Endpoints`, `Scopes & Claims`, `Code Examples`, `Error Handling`, `Security`. After the `Security` anchor and BEFORE the closing `</div>` of `.nav-inner`, insert:

```html
      <a href="/brand/" style="margin-left: auto;">Brand assets →</a>
```

The `margin-left: auto` pushes the link to the far right of the nav, visually separating it from the in-page anchor links. Apply this exact line — do not change indentation if the surrounding lines use the same (spaces, no tabs).

- [ ] **Step 2: Verify in browser**

```bash
open ~/taler-id/public/oauth-guide.html
```

Expected: Top nav now shows the existing 10 anchor links on the left, and "Brand assets →" pinned on the right. Clicking it navigates to `/brand/` (in `file://` mode this will 404 locally — that's fine; HTTPS deployment is verified in Task 8).

- [ ] **Step 3: Commit**

```bash
cd ~/taler-id
git add public/oauth-guide.html
git commit -m "feat(brand): link to /brand/ from oauth-guide nav"
```

---

## Task 8: Deploy to DEV and run smoke checklist

**Files:** none (deployment + verification only)

The DEV server is `dvolkov@89.169.55.217`. Deployment follows the standard backend flow from `CLAUDE.md`. **Important:** Inspect the DEV server's branch state before pulling — there may be parallel work on branches other than `main`.

- [ ] **Step 1: Push commits to origin/main**

```bash
cd ~/taler-id
git push origin main
```

Expected: Push succeeds and includes commits from Tasks 1-7 (7 commits in total).

- [ ] **Step 2: Check the DEV server branch state**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git status && git branch --show-current'
```

If the DEV server is on `main` with a clean tree, proceed to Step 3 with `git pull`. If it is on a feature branch (e.g. `feature/mesh-bridge`), use `git fetch origin main && git merge origin/main` to bring in the brand-page commits without switching branches.

- [ ] **Step 3: Pull on DEV and rebuild**

```bash
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && npm run build && pm2 restart taler-id-dev'
```

Expected: `git pull` reports the 7 new commits, `npm run build` finishes with no errors, `pm2 restart` shows status `online`. Static assets are served directly from `public/` — the rebuild is only required because PM2 needs to pick up the new files in the working tree.

- [ ] **Step 4: Smoke test — page loads, content-types are right**

```bash
curl -fIL -o /dev/null -w "BRAND %{http_code} %{content_type}\n"  https://staging.id.taler.tirol/brand
curl -fI  -o /dev/null -w "LIGHT %{http_code} %{content_type}\n" https://staging.id.taler.tirol/brand/logo-light.png
curl -fI  -o /dev/null -w "DARK  %{http_code} %{content_type}\n" https://staging.id.taler.tirol/brand/logo-dark.png
```

Expected output:
```
BRAND 200 text/html; charset=UTF-8
LIGHT 200 image/png
DARK  200 image/png
```

The `-L` on the brand request follows the 301 redirect from `/brand` → `/brand/` (NestJS auto-appends the trailing slash for directories with index files).

- [ ] **Step 5: Smoke test — visual check in browser**

```bash
open https://staging.id.taler.tirol/brand
```

Run through the spec's manual checklist (`docs/superpowers/specs/2026-04-29-oauth-ui-kit-phase-0-brand.md`, "Testing" section):

1. All 4 sections render: Logo, Colors, Typography, Buttons.
2. Click each Copy button — text changes to "Copied!" and the value lands in the clipboard. Test by pasting one color hex and one button HTML snippet into Notes / scratch buffer.
3. Click "Download PNG" on each logo card — browser downloads (does not display) the file.
4. Open `https://staging.id.taler.tirol/oauth-guide.html` and click "Brand assets →" in the top nav — it lands on `/brand/`.
5. Eyeball the Taler Blue swatch (`#167EF2`) against the live mobile app's primary blue. They should be visually identical.

If any step fails, fix and re-deploy via `ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && pm2 restart taler-id-dev'` (no rebuild needed for HTML/CSS-only fixes).

- [ ] **Step 6 (contingent): Re-deploy if Step 5 surfaced any issue**

Skip this step entirely if Step 5 passed. Otherwise, after editing `~/taler-id/public/brand/index.html` to fix the specific issue:

```bash
cd ~/taler-id
git add public/brand/index.html
git commit -m "fix(brand): correct <specific issue from smoke test>"
git push origin main
ssh dvolkov@89.169.55.217 'cd ~/taler-id && git pull && pm2 restart taler-id-dev'
```

Then re-run Step 5 against `https://staging.id.taler.tirol/brand` until all checks pass.

---

## Out of Scope — Do Not Do

These are explicitly NOT part of Phase 0 and must be deferred:

- **PROD deployment.** Phase 0 ships only to DEV. PROD deploy waits for explicit user instruction per the project's deploy rule (`CLAUDE.md` top section).
- **SVG logos.** PNG-only. Future SVG work belongs in a follow-up phase (will also be when the button design gains a glyph).
- **Logo glyph inside the button.** Buttons are text-only in Phase 0.
- **Favicon, Open Graph card, social-share images.** Not in spec.
- **A separate `styles.css`.** All CSS stays inline in `index.html`.
- **Restructuring `oauth-guide.html`** beyond adding the single nav link.
- **Touching any `src/` file.** This is a static-asset-only change.
