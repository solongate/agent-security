// SPDX-License-Identifier: Apache-2.0

// The diagrams, drawn in SolonGate's own design system.
//
// NOTHING HERE IS INVENTED. The mark is apps/onboarding/public/mark.svg from the
// product repository, copied path for path. The palette is that app's design
// tokens. The two status colours are the CLI's own, from
// packages/app/internal/term/color.go, which is the red and green a person
// actually sees when a call is refused or allowed.
//
//   node docs/assets/build.mjs
//
// THREE RULES OF THE DESIGN SYSTEM, inherited rather than chosen here:
//
//   1. ONE SURFACE. #1a1a1a is the whole thing: the page, every panel, every box.
//      Nothing is separated by being a different shade. Everything is separated
//      by a #383838 hairline, which is why that border has to be a real step
//      brighter than the surface rather than a near-invisible one.
//   2. NO RADIUS. --radius is 0rem. Every corner is square. The one exception is
//      the mark itself, whose own rounding is part of the artwork.
//   3. DARK, IN BOTH GITHUB THEMES. A single file per diagram rather than a
//      light and a dark one. The brand is one surface and it is this one, so a
//      derived light palette would be a second brand nobody approved, and the
//      pair would drift the first time one of them got a corrected label.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// The design tokens, verbatim.
const SURFACE = '#1a1a1a';
const TEXT = '#f2f2f2';
const LINE = '#383838';
const MUTED = '#8c8c8c';
const ACCENT = '#3ba9ee';

// The CLI's palette, converted from the ANSI triples it prints.
const ALLOW = '#50c878'; // term.Green, rgb(80 200 120)
const DENY = '#dc5050';  // term.Red,   rgb(220 80 80)

// Geist and Inter are the brand faces. No webfont loads inside an
// <img>-rendered SVG, so they are named first in case the renderer already has
// them, and the rest of the stack is what it falls back to.
const SANS = "Geist,Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO = "'Geist Mono',ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace";

const arrowDefs = `
  <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
    <path d="M0 0 10 5 0 10z" fill="${LINE}"/>
  </marker>
  <marker id="ard" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
    <path d="M0 0 10 5 0 10z" fill="${DENY}"/>
  </marker>`;

// A box is the surface with a hairline on it. Never a different fill.
const box = (x, y, w, h, stroke = LINE) =>
  `<rect x="${x + 0.5}" y="${y + 0.5}" width="${w - 1}" height="${h - 1}" fill="${SURFACE}" stroke="${stroke}"/>`;

// ── the five layers, in order ──────────────────────────────────────────────
const LAYERS = [
  ['1', 'Tamper protection', 'The guard state a tool call must never reach'],
  ['2', 'Rate limit', 'Reserve a slot, then count the window'],
  ['3', 'Policy rules', 'Your JSON, compiled to Rego and evaluated in process'],
  ['4', 'DLP', 'Three views, so a split or encoded secret still matches'],
  ['5', 'Egress', 'Read the files an upload command would actually send'],
];

const decisionPath = () => {
  const x = 250, w = 420, h = 58, cx = x + w / 2, right = x + w;
  const yFor = (i) => 32 + i * 80;
  const denyX = 742, denyW = 398;
  const denyTop = yFor(1), denyH = yFor(5) + h - denyTop;

  const connector = (i) =>
    `  <line x1="${cx}" y1="${yFor(i) + h}" x2="${cx}" y2="${yFor(i + 1) - 2}" stroke="${LINE}" stroke-width="2" marker-end="url(#ar)"/>`;

  const layer = ([n, title, sub], i) => {
    const y = yFor(i + 1);
    return `  ${box(x, y, w, h)}
  ${box(x + 15, y + 16, 26, 26, ACCENT)}
  <text x="${x + 28}" y="${y + 34}" text-anchor="middle" font-family="${SANS}" font-size="13" font-weight="600" fill="${ACCENT}">${n}</text>
  <text x="${x + 56}" y="${y + 25}" font-family="${SANS}" font-size="16" font-weight="600" fill="${TEXT}">${title}</text>
  <text x="${x + 56}" y="${y + 44}" font-family="${SANS}" font-size="12.5" fill="${MUTED}">${sub}</text>
  <line x1="${right}" y1="${y + 29}" x2="${denyX - 2}" y2="${y + 29}" stroke="${DENY}" stroke-width="1.5" stroke-opacity="0.65" marker-end="url(#ard)"/>`;
  };

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 616" width="1200" height="616" role="img" aria-label="The five layers a tool call passes through, and the denial branch">
  <title>The decision path</title>
  <defs>${arrowDefs}
  </defs>
  <rect width="1200" height="616" fill="${SURFACE}"/>

  ${box(denyX, denyTop, denyW, denyH, DENY)}
  <text x="${denyX + denyW / 2}" y="272" text-anchor="middle" font-family="${SANS}" font-size="20" font-weight="600" letter-spacing="1" fill="${DENY}">DENIED</text>
  <text x="${denyX + denyW / 2}" y="306" text-anchor="middle" font-family="${SANS}" font-size="13.5" fill="${TEXT}">Any layer can refuse, and the tool never runs.</text>
  <text x="${denyX + denyW / 2}" y="330" text-anchor="middle" font-family="${SANS}" font-size="13.5" fill="${MUTED}">The refusal is written to the audit trail</text>
  <text x="${denyX + denyW / 2}" y="350" text-anchor="middle" font-family="${SANS}" font-size="13.5" fill="${MUTED}">before the agent is answered.</text>

  ${box(x, yFor(0), w, h)}
  <text x="${x + 24}" y="${yFor(0) + 28}" font-family="${SANS}" font-size="16" font-weight="600" fill="${TEXT}">An agent asks to run a tool</text>
  <text x="${x + 24}" y="${yFor(0) + 46}" font-family="${SANS}" font-size="12.5" fill="${MUTED}">a shell command, a file read, a write</text>

${[0, 1, 2, 3, 4, 5].map(connector).join('\n')}

${LAYERS.map(layer).join('\n')}

  ${box(x, yFor(6), w, h, ALLOW)}
  <text x="${x + 24}" y="${yFor(6) + 28}" font-family="${SANS}" font-size="16" font-weight="600" fill="${ALLOW}">ALLOWED, the tool runs</text>
  <text x="${x + 24}" y="${yFor(6) + 46}" font-family="${SANS}" font-size="12.5" fill="${MUTED}">and the call is recorded</text>

  <text x="${x}" y="600" font-family="${SANS}" font-size="13" fill="${MUTED}">Every step is on this machine. Nothing is asked over a network on the decision path.</text>
</svg>
`;
};

// ── why there are two guards ───────────────────────────────────────────────
const twoImplementations = () => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 424" width="1200" height="424" role="img" aria-label="Two implementations of the guard reaching one verdict">
  <title>Two implementations, one verdict</title>
  <defs>${arrowDefs}
  </defs>
  <rect width="1200" height="424" fill="${SURFACE}"/>

  ${box(490, 28, 220, 50)}
  <text x="600" y="59" text-anchor="middle" font-family="${SANS}" font-size="16" font-weight="600" fill="${TEXT}">A tool call</text>
  <line x1="600" y1="78" x2="600" y2="102" stroke="${LINE}" stroke-width="2" marker-end="url(#ar)"/>

  ${box(390, 104, 420, 56, ACCENT)}
  <text x="600" y="139" text-anchor="middle" font-family="${SANS}" font-size="16" font-weight="600" fill="${ACCENT}">Does this machine have the Go binary?</text>

  <path d="M600 160 600 188 320 188 320 214" fill="none" stroke="${LINE}" stroke-width="2" marker-end="url(#ar)"/>
  <path d="M600 160 600 188 880 188 880 214" fill="none" stroke="${LINE}" stroke-width="2" marker-end="url(#ar)"/>
  <text x="332" y="182" font-family="${SANS}" font-size="13" font-weight="600" fill="${MUTED}">yes</text>
  <text x="868" y="182" text-anchor="end" font-family="${SANS}" font-size="13" font-weight="600" fill="${MUTED}">no</text>

  ${box(130, 216, 380, 72)}
  <text x="320" y="248" text-anchor="middle" font-family="${MONO}" font-size="15" fill="${TEXT}">packages/guard</text>
  <text x="320" y="270" text-anchor="middle" font-family="${SANS}" font-size="13" fill="${MUTED}">the Go binary decides</text>

  ${box(690, 216, 380, 72)}
  <text x="880" y="248" text-anchor="middle" font-family="${MONO}" font-size="15" fill="${TEXT}">guard.bundled.mjs</text>
  <text x="880" y="270" text-anchor="middle" font-family="${SANS}" font-size="13" fill="${MUTED}">the bundled Node hook decides</text>

  <path d="M320 288 320 314 600 314 600 328" fill="none" stroke="${LINE}" stroke-width="2" marker-end="url(#ar)"/>
  <path d="M880 288 880 314 600 314" fill="none" stroke="${LINE}" stroke-width="2"/>

  ${box(330, 330, 540, 56, ALLOW)}
  <text x="600" y="365" text-anchor="middle" font-family="${SANS}" font-size="16" font-weight="600" fill="${ALLOW}">The same verdict, for the same reason</text>

  <text x="600" y="410" text-anchor="middle" font-family="${SANS}" font-size="13" fill="${MUTED}">One conformance suite judges both, so a divergence between them is a bug by definition.</text>
</svg>
`;

// ── the OpenSSF badge ──────────────────────────────────────────────────────
//
// A STATIC COPY OF A LIVE CLAIM, and that is a trade worth naming.
// bestpractices.dev serves its own badge for project 15333 and it carries no
// logo at all: grey "openssf baseline v2026.08.28" against a blue "1". This one
// is drawn here from the foundation's own mark so the badge row has something
// recognisable in it.
//
// The cost is that the LEVEL IS FROZEN at the moment this ran. Change LEVEL
// below and re-run when it moves. The badge links to the project page, which is
// the authoritative answer and one click away, so a stale badge is checkable
// rather than merely wrong.
//
// TWO FILES FOR ONE PICTURE, which needs a reason. openssf-mark.png is the
// source: the foundation's logo with the wordmark cropped off, because the
// badge says OpenSSF in text already and the wordmark at 14 pixels tall is a
// grey smear. openssf-mark-14.png is that file scaled to the height the badge
// uses, scaled once and committed because node has no image resizer here and
// adding a dependency to draw two rectangles and some text would be a poor
// trade. Rescale it if the badge height ever changes.
const LEVEL = 'baseline-1';
const OPENSSF_NAVY = '#04335f'; // sampled from the wordmark in the source logo
const BADGE_GREY = '#555'; // the shields.io label colour, so the row matches

// Verdana advances, near enough for a badge and checked by eye. textLength
// pins the run to exactly this width afterwards, so a renderer with a slightly
// different Verdana cannot push the text out of its own section.
const advance = (text, px) => {
  const wide = new Set([...'MWmw@']);
  const narrow = new Set([...'iljtfr.,:;!|I ']);
  let total = 0;
  for (const ch of text) {
    if (wide.has(ch)) total += 0.82;
    else if (narrow.has(ch)) total += 0.36;
    else if (ch !== ch.toLowerCase()) total += 0.70;
    else total += 0.58;
  }
  return total * px;
};

const openssfBadge = () => {
  const H = 20, LOGO_H = 14, FS = 11, PAD = 6, GAP = 4;
  // The mark is 86x138 after cropping, so at 14 tall it is 9 wide.
  const LOGO_W = Math.max(1, Math.round((LOGO_H * 86) / 138));
  const b64 = readFileSync(join(here, 'openssf-mark-14.png')).toString('base64');

  const left = 'OpenSSF';
  const lw = advance(left, FS);
  const rw = advance(LEVEL, FS);
  const lSec = PAD + LOGO_W + GAP + lw + PAD;
  const rSec = PAD + rw + PAD;
  const total = lSec + rSec;

  const text = (x, body, width) =>
    `<text x="${(x * 10).toFixed(0)}" y="${((H / 2 + FS * 0.35) * 10).toFixed(0)}" transform="scale(.1)" fill="#fff" textLength="${(width * 10).toFixed(0)}">${body}</text>`;

  return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${total.toFixed(0)}" height="${H}" role="img" aria-label="OpenSSF: ${LEVEL}">
  <title>OpenSSF: ${LEVEL}</title>
  <linearGradient id="g" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${total.toFixed(0)}" height="${H}" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lSec.toFixed(0)}" height="${H}" fill="${BADGE_GREY}"/>
    <rect x="${lSec.toFixed(0)}" width="${rSec.toFixed(0)}" height="${H}" fill="${OPENSSF_NAVY}"/>
    <rect width="${total.toFixed(0)}" height="${H}" fill="url(#g)"/>
  </g>
  <image x="${PAD}" y="${(H - LOGO_H) / 2}" width="${LOGO_W}" height="${LOGO_H}" xlink:href="data:image/png;base64,${b64}"/>
  <g font-family="Verdana,DejaVu Sans,Geneva,sans-serif" font-size="${FS * 10}" text-rendering="geometricPrecision" text-anchor="middle">
    ${text(PAD + LOGO_W + GAP + lw / 2, left, lw)}
    ${text(lSec + rSec / 2, LEVEL, rw)}
  </g>
</svg>
`;
};

const DIAGRAMS = {
  'decision-path': decisionPath,
  'two-implementations': twoImplementations,
  'openssf-baseline': openssfBadge,
};

for (const [name, render] of Object.entries(DIAGRAMS)) {
  writeFileSync(join(here, `${name}.svg`), render());
  console.log('wrote', `docs/assets/${name}.svg`);
}
