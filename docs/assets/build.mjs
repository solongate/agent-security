// The diagrams, in both GitHub themes, from one geometry.
//
// WHY A GENERATOR RATHER THAN SIX HAND-WRITTEN FILES. GitHub picks between a
// light and a dark image with <picture> and prefers-color-scheme, which means
// every diagram exists twice. Hand-maintaining the pair is how the two drift:
// one gets a corrected label and the other keeps the old one, and nobody looking
// at their own theme ever sees it.
//
// So geometry is written once and the palette is substituted. The two files a
// reader sees differ in colour and in nothing else, by construction.
//
//   node docs/assets/build.mjs
//
// Palette values are GitHub's own, so the diagrams sit on the page rather than
// on top of it.

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const THEMES = {
  light: {
    BG: '#ffffff', SURFACE: '#f6f8fa', BORDER: '#d0d7de',
    TEXT: '#1f2328', MUTED: '#656d76',
    ACCENT: '#0969da', ACCENT_SOFT: '#ddf4ff',
    DENY: '#cf222e', DENY_SOFT: '#ffebe9',
    ALLOW: '#1a7f37', ALLOW_SOFT: '#dafbe1',
  },
  dark: {
    BG: '#0d1117', SURFACE: '#161b22', BORDER: '#30363d',
    TEXT: '#e6edf3', MUTED: '#8b949e',
    ACCENT: '#4493f8', ACCENT_SOFT: '#121d2f',
    DENY: '#f85149', DENY_SOFT: '#2a1416',
    ALLOW: '#3fb950', ALLOW_SOFT: '#0f2417',
  },
};

// No webfont loads inside an <img>-rendered SVG, so these are stacks the
// renderer already has.
const SANS = "ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace";

// The shield-and-barrier mark, at 48x48, ready to be transformed.
const mark = (c) => `
    <g>
      <path d="M24 3.5 41 11.2v14.6c0 9.2-7.3 16.1-17 19.2-9.7-3.1-17-10-17-19.2V11.2z"
            fill="none" stroke="${c.ACCENT}" stroke-width="2.6" stroke-linejoin="round"/>
      <path d="M19 13.5 24 19l5-5.5" fill="none" stroke="${c.ACCENT}" stroke-width="2.4"
            stroke-linecap="round" stroke-linejoin="round" opacity="0.55"/>
      <rect x="12.5" y="23" width="23" height="3.6" rx="1.8" fill="${c.ACCENT}"/>
      <path d="M24 31.5v5" fill="none" stroke="${c.ACCENT}" stroke-width="2.4"
            stroke-linecap="round" opacity="0.3"/>
    </g>`;

const arrowDefs = (c) => `
  <defs>
    <marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0 0 10 5 0 10z" fill="${c.BORDER}"/>
    </marker>
    <marker id="ad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0 0 10 5 0 10z" fill="${c.DENY}"/>
    </marker>
  </defs>`;

// ── the README hero ────────────────────────────────────────────────────────
//
// The two rows on the right are an illustration of the product's one sentence,
// not a screenshot: `git status` runs and `git push --force` does not.
const banner = (c) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 300" width="1200" height="300" role="img" aria-label="SolonGate: a policy gate for AI coding agents">
  <title>SolonGate</title>
  <rect x="0.75" y="0.75" width="1198.5" height="298.5" rx="18" fill="${c.SURFACE}" stroke="${c.BORDER}" stroke-width="1.5"/>

  <g transform="translate(68 104) scale(1.8333)">${mark(c)}
  </g>

  <text x="192" y="152" font-family="${SANS}" font-size="60" font-weight="700" letter-spacing="-1.2" fill="${c.TEXT}">SolonGate</text>
  <text x="195" y="193" font-family="${SANS}" font-size="22" fill="${c.MUTED}">A policy gate for AI coding agents</text>

  <g font-family="${SANS}" font-size="14" font-weight="500">
    <rect x="195" y="220" width="186" height="30" rx="15" fill="${c.ACCENT_SOFT}" stroke="${c.ACCENT}" stroke-width="1" stroke-opacity="0.35"/>
    <text x="288" y="240" text-anchor="middle" fill="${c.ACCENT}">Runs on your machine</text>
    <rect x="391" y="220" width="116" height="30" rx="15" fill="${c.ACCENT_SOFT}" stroke="${c.ACCENT}" stroke-width="1" stroke-opacity="0.35"/>
    <text x="449" y="240" text-anchor="middle" fill="${c.ACCENT}">No account</text>
    <rect x="517" y="220" width="132" height="30" rx="15" fill="${c.ACCENT_SOFT}" stroke="${c.ACCENT}" stroke-width="1" stroke-opacity="0.35"/>
    <text x="583" y="240" text-anchor="middle" fill="${c.ACCENT}">No telemetry</text>
    <rect x="659" y="220" width="66" height="30" rx="15" fill="${c.ACCENT_SOFT}" stroke="${c.ACCENT}" stroke-width="1" stroke-opacity="0.35"/>
    <text x="692" y="240" text-anchor="middle" fill="${c.ACCENT}">MIT</text>
  </g>

  <rect x="756.5" y="94.5" width="381" height="53" rx="10" fill="${c.BG}" stroke="${c.BORDER}"/>
  <circle cx="784" cy="121" r="5.5" fill="${c.ALLOW}"/>
  <text x="802" y="126" font-family="${MONO}" font-size="15" fill="${c.TEXT}">git status</text>
  <text x="1118" y="126" text-anchor="end" font-family="${SANS}" font-size="12.5" font-weight="600" fill="${c.ALLOW}">allowed</text>

  <rect x="756.5" y="160.5" width="381" height="53" rx="10" fill="${c.BG}" stroke="${c.BORDER}"/>
  <circle cx="784" cy="187" r="5.5" fill="${c.DENY}"/>
  <text x="802" y="192" font-family="${MONO}" font-size="15" fill="${c.TEXT}">git push --force</text>
  <text x="1118" y="192" text-anchor="end" font-family="${SANS}" font-size="12.5" font-weight="600" fill="${c.DENY}">denied</text>
</svg>
`;

// ── the five layers, in order ──────────────────────────────────────────────
const LAYERS = [
  ['1', 'Tamper protection', 'The guard state a tool call must never reach'],
  ['2', 'Rate limit', 'Reserve a slot, then count the window'],
  ['3', 'Policy rules', 'Your JSON, compiled to Rego and evaluated in process'],
  ['4', 'DLP', 'Three views of the call, so a split or encoded secret still matches'],
  ['5', 'Egress', 'Read the files an upload command would actually send'],
];

const decisionPath = (c) => {
  const x = 250, w = 420, h = 58, cx = x + w / 2, right = x + w;
  const yFor = (i) => 32 + i * 80;
  const denyX = 742, denyW = 398;
  const denyTop = yFor(1), denyBottom = yFor(5) + h;

  const connector = (i) => {
    const from = yFor(i) + h, to = yFor(i + 1);
    return `  <line x1="${cx}" y1="${from}" x2="${cx}" y2="${to - 2}" stroke="${c.BORDER}" stroke-width="2" marker-end="url(#a)"/>`;
  };

  const layer = ([n, title, sub], i) => {
    const y = yFor(i + 1);
    return `  <rect x="${x}.5" y="${y}.5" width="${w}" height="${h}" rx="10" fill="${c.BG}" stroke="${c.BORDER}"/>
  <circle cx="${x + 28}" cy="${y + 29}" r="13" fill="${c.ACCENT_SOFT}" stroke="${c.ACCENT}" stroke-opacity="0.4"/>
  <text x="${x + 28}" y="${y + 34}" text-anchor="middle" font-family="${SANS}" font-size="13" font-weight="700" fill="${c.ACCENT}">${n}</text>
  <text x="${x + 56}" y="${y + 25}" font-family="${SANS}" font-size="16" font-weight="600" fill="${c.TEXT}">${title}</text>
  <text x="${x + 56}" y="${y + 44}" font-family="${SANS}" font-size="12.5" fill="${c.MUTED}">${sub}</text>
  <line x1="${right}" y1="${y + 29}" x2="${denyX - 2}" y2="${y + 29}" stroke="${c.DENY}" stroke-width="1.75" stroke-opacity="0.55" marker-end="url(#ad)"/>`;
  };

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 616" width="1200" height="616" role="img" aria-label="The five layers a tool call passes through, and the denial branch">
  <title>The decision path</title>
${arrowDefs(c)}
  <rect width="1200" height="616" fill="none"/>

  <rect x="${denyX}.5" y="${denyTop}.5" width="${denyW}" height="${denyBottom - denyTop}" rx="12" fill="${c.DENY_SOFT}" stroke="${c.DENY}" stroke-opacity="0.5"/>
  <text x="${denyX + denyW / 2}" y="272" text-anchor="middle" font-family="${SANS}" font-size="20" font-weight="700" fill="${c.DENY}">DENIED</text>
  <text x="${denyX + denyW / 2}" y="304" text-anchor="middle" font-family="${SANS}" font-size="13.5" fill="${c.TEXT}">Any layer can refuse, and the tool never runs.</text>
  <text x="${denyX + denyW / 2}" y="328" text-anchor="middle" font-family="${SANS}" font-size="13.5" fill="${c.MUTED}">The refusal is written to the audit trail</text>
  <text x="${denyX + denyW / 2}" y="348" text-anchor="middle" font-family="${SANS}" font-size="13.5" fill="${c.MUTED}">before the agent is answered.</text>

  <rect x="${x}.5" y="${yFor(0)}.5" width="${w}" height="${h}" rx="10" fill="${c.SURFACE}" stroke="${c.BORDER}"/>
  <text x="${x + 24}" y="${yFor(0) + 28}" font-family="${SANS}" font-size="16" font-weight="600" fill="${c.TEXT}">An agent asks to run a tool</text>
  <text x="${x + 24}" y="${yFor(0) + 46}" font-family="${SANS}" font-size="12.5" fill="${c.MUTED}">a shell command, a file read, a write</text>

${[0, 1, 2, 3, 4, 5].map(connector).join('\n')}

${LAYERS.map(layer).join('\n')}

  <rect x="${x}.5" y="${yFor(6)}.5" width="${w}" height="${h}" rx="10" fill="${c.ALLOW_SOFT}" stroke="${c.ALLOW}" stroke-opacity="0.5"/>
  <text x="${x + 24}" y="${yFor(6) + 28}" font-family="${SANS}" font-size="16" font-weight="600" fill="${c.ALLOW}">ALLOWED, the tool runs</text>
  <text x="${x + 24}" y="${yFor(6) + 46}" font-family="${SANS}" font-size="12.5" fill="${c.MUTED}">and the call is recorded</text>

  <text x="${x}" y="600" font-family="${SANS}" font-size="13" fill="${c.MUTED}">Every step is on this machine. Nothing is asked over a network on the decision path.</text>
</svg>
`;
};

// ── why there are two guards ───────────────────────────────────────────────
const twoImplementations = (c) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 424" width="1200" height="424" role="img" aria-label="Two implementations of the guard reaching one verdict">
  <title>Two implementations, one verdict</title>
${arrowDefs(c)}

  <rect x="490.5" y="28.5" width="220" height="50" rx="10" fill="${c.SURFACE}" stroke="${c.BORDER}"/>
  <text x="600" y="59" text-anchor="middle" font-family="${SANS}" font-size="16" font-weight="600" fill="${c.TEXT}">A tool call</text>
  <line x1="600" y1="78" x2="600" y2="102" stroke="${c.BORDER}" stroke-width="2" marker-end="url(#a)"/>

  <rect x="390.5" y="104.5" width="420" height="56" rx="10" fill="${c.ACCENT_SOFT}" stroke="${c.ACCENT}" stroke-opacity="0.5"/>
  <text x="600" y="139" text-anchor="middle" font-family="${SANS}" font-size="16" font-weight="600" fill="${c.ACCENT}">Does this machine have the Go binary?</text>

  <path d="M600 160 600 188 320 188 320 214" fill="none" stroke="${c.BORDER}" stroke-width="2" marker-end="url(#a)"/>
  <path d="M600 160 600 188 880 188 880 214" fill="none" stroke="${c.BORDER}" stroke-width="2" marker-end="url(#a)"/>
  <text x="332" y="182" font-family="${SANS}" font-size="13" font-weight="600" fill="${c.MUTED}">yes</text>
  <text x="868" y="182" text-anchor="end" font-family="${SANS}" font-size="13" font-weight="600" fill="${c.MUTED}">no</text>

  <rect x="130.5" y="216.5" width="380" height="72" rx="10" fill="${c.BG}" stroke="${c.BORDER}"/>
  <text x="320" y="248" text-anchor="middle" font-family="${MONO}" font-size="15" fill="${c.TEXT}">packages/guard-go</text>
  <text x="320" y="270" text-anchor="middle" font-family="${SANS}" font-size="13" fill="${c.MUTED}">the Go binary decides</text>

  <rect x="690.5" y="216.5" width="380" height="72" rx="10" fill="${c.BG}" stroke="${c.BORDER}"/>
  <text x="880" y="248" text-anchor="middle" font-family="${MONO}" font-size="15" fill="${c.TEXT}">guard.bundled.mjs</text>
  <text x="880" y="270" text-anchor="middle" font-family="${SANS}" font-size="13" fill="${c.MUTED}">the bundled Node hook decides</text>

  <path d="M320 288 320 314 600 314 600 328" fill="none" stroke="${c.BORDER}" stroke-width="2" marker-end="url(#a)"/>
  <path d="M880 288 880 314 600 314 600 328" fill="none" stroke="${c.BORDER}" stroke-width="2"/>

  <rect x="330.5" y="330.5" width="540" height="56" rx="10" fill="${c.ALLOW_SOFT}" stroke="${c.ALLOW}" stroke-opacity="0.5"/>
  <text x="600" y="365" text-anchor="middle" font-family="${SANS}" font-size="16" font-weight="600" fill="${c.ALLOW}">The same verdict, for the same reason</text>

  <text x="600" y="410" text-anchor="middle" font-family="${SANS}" font-size="13" fill="${c.MUTED}">One conformance suite judges both, so a divergence between them is a bug by definition.</text>
</svg>
`;

const DIAGRAMS = { banner, 'decision-path': decisionPath, 'two-implementations': twoImplementations };

for (const [name, render] of Object.entries(DIAGRAMS)) {
  for (const [theme, palette] of Object.entries(THEMES)) {
    const file = join(here, `${name}-${theme}.svg`);
    writeFileSync(file, render(palette));
    console.log('wrote', `docs/assets/${name}-${theme}.svg`);
  }
}
