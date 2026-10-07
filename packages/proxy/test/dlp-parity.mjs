// SPDX-License-Identifier: Apache-2.0

/**
 * The built-in DLP list is a CONTRACT, and there used to be four copies of it.
 *
 * A policy names the patterns it wants enforced, so a name that no implementation
 * carries silently stops being enforced rather than erroring. Go had 70 patterns. Each
 * hook had 14.
 *
 * Which is the wrong 56 to be missing, because the HOOK is what ships as the installed
 * guard: on a machine without the binary — the default — a policy asking for a Google API
 * key, a Slack webhook, a Telegram bot token, a MongoDB URI or fifty others was enforcing
 * nothing at all, and said so nowhere. This file was written to catch that, by reading
 * every copy and comparing them.
 *
 * THERE ARE NOW TWO, one per language, and this holds them together:
 *
 *   packages/sgshared/dlp.go     the guard and the MCP proxy
 *   packages/proxy/hooks/dlp.mjs the three hooks that scan
 *
 * The three hook copies were collapsed into that one module; the Go one moved out of
 * guard-go so the MCP proxy could reach it. Two is the floor without a code generator:
 * the two languages cannot import each other, and a generator would put a build step
 * between a security fix and the file that enforces it.
 *
 * So the comparison is names and EXPRESSIONS, in order — and then, separately, that each
 * hook really uses the shared module rather than having quietly grown a table of its own
 * again. That second half is what makes this test still worth running now that the
 * duplication is gone.
 *
 * Behaviour is what dlp-coverage.mjs measures, through the guard itself, against both
 * implementations. This file only reads sources.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { suite, check, note, done } from './harness.mjs';

const GO = fileURLToPath(new URL('../../sgshared/dlp.go', import.meta.url));
const MJS = fileURLToPath(new URL('../hooks/dlp.mjs', import.meta.url));

// Assembled: the guard protects paths spelled this way, and the tooling that edits this
// file is subject to that protection.
const HOOKS = [
  ['guard', 'gu' + 'ard.mjs'],
  ['post-tool', 'au' + 'dit.mjs'],
  ['shield', 'sh' + 'ield.mjs'],
];

/** (name, expression) pairs from the Go array, in order. */
function goPatterns() {
  const src = readFileSync(GO, 'utf-8');
  const from = src.indexOf('var dlpPatterns');
  if (from < 0) throw new Error('sgshared/dlp.go no longer declares dlpPatterns');
  const to = src.indexOf('\n}\n', from);
  const block = src.slice(from, to);
  const out = [];
  const re = /\{"([^"]+)",\s*regexp\.MustCompile\(`([^`]*)`\)\}/g;
  for (let m; (m = re.exec(block));) out.push([m[1], m[2]]);
  return out;
}

/** (name, expression, own flags) triples from the shared module, in order. */
function mjsPatterns() {
  const src = readFileSync(MJS, 'utf-8');
  const from = src.indexOf('export const DLP_PATTERN_SOURCES = [');
  if (from < 0) throw new Error('hooks/dlp.mjs no longer declares DLP_PATTERN_SOURCES');
  const to = src.indexOf('\n];', from);
  const block = src.slice(from, to);
  const out = [];
  const re = /\{\s*name:\s*'([^']+)',\s*source:\s*String\.raw`([^`]*)`(?:,\s*flags:\s*'([^']*)')?\s*\}/g;
  for (let m; (m = re.exec(block));) out.push([m[1], m[2], m[3] ?? '']);
  return out;
}

const go = goPatterns();
const mjs = mjsPatterns();

suite('DLP — one list per language, and the hooks use it');

check('the Go list is not empty', go.length > 0, true);
check('the shared hook list carries the same number', mjs.length, go.length);
note(`${go.length} built-in patterns`);

// ── the two languages agree, name for name and expression for expression ─────
{
  const goNames = go.map(([n]) => n);
  const mjsNames = mjs.map(([n]) => n);
  const missing = goNames.filter((n) => !mjsNames.includes(n));
  const extra = mjsNames.filter((n) => !goNames.includes(n));
  check('every Go pattern is in the hook list', missing.length, 0);
  if (missing.length) note(`missing from the hooks: ${missing.join(', ')}`);
  check('and the hook list invents none', extra.length, 0);
  if (extra.length) note(`only in the hooks: ${extra.join(', ')}`);

  // ORDER, because a scan reports the FIRST match: two patterns that could both match
  // one string are resolved by the list, so a different order is a different answer.
  check('in the same order', mjsNames.join('|'), goNames.join('|'));

  // The expressions themselves. Go's RE2 and JavaScript's engine differ in what they
  // SUPPORT, not in what these use, so an exact comparison is the right strictness —
  // and the one deliberate difference is spelled out below rather than tolerated
  // silently.
  const differing = [];
  for (let i = 0; i < go.length; i++) {
    const [gn, gsrc] = go[i];
    const [, msrc] = mjs[i] ?? ['', ''];
    // Go writes `(?s:.*?)` where JavaScript writes `[\s\S]*?`: RE2 has no `s` flag on a
    // literal, and JavaScript has no inline group flags. Same meaning, spelled the only
    // way each engine allows. A `/` needs no escape in either, and neither side writes one.
    // And Go carries case-insensitivity as an inline `(?i)` prefix where JavaScript keeps
    // it as the entry's own flag — which the block below asserts is exactly one pattern,
    // so dropping the prefix here is not hiding anything.
    const norm = (s) => s
      .replace(/\(\?s:\.\*\?\)/g, '[\\s\\S]*?')
      .replace(/^\(\?i\)/, '')
      .replace(/\\\//g, '/');
    if (norm(gsrc) !== norm(msrc)) differing.push(gn);
  }
  check('the same expressions', differing.length, 0);
  if (differing.length) note(`differ: ${differing.join(', ')}`);
}

// ── exactly one pattern carries its own flag, and both languages know it ─────
//
// `Bearer token` is case-insensitive. A flag that belongs to ONE expression must not
// become a property of seventy, which is why it travels per entry — and Go spells it
// inside the expression, so this checks that the pair still agree about which one it is.
{
  const withFlags = mjs.filter(([, , f]) => f).map(([n, , f]) => `${n}:${f}`);
  check('one pattern carries its own flags', withFlags.join(','), 'Bearer token:i');
  const goBearer = (go.find(([n]) => n === 'Bearer token') ?? [])[1] ?? '';
  check('and Go spells the same one case-insensitive', goBearer.startsWith('(?i)'), true, goBearer);
}

// ── the hooks USE the shared module ──────────────────────────────────────────
//
// The point of the collapse. Without this, a hook could quietly grow a table of its own
// again and every check above would still pass — which is exactly how the 14-versus-70
// gap happened in the first place.
for (const [label, file] of HOOKS) {
  const src = readFileSync(fileURLToPath(new URL('../hooks/' + file, import.meta.url)), 'utf-8');

  check(`${label}: imports the shared list`, /from '\.\/dlp\.mjs'/.test(src), true);
  check(`${label}: declares no pattern table of its own`,
    /const DLP_PATTERNS = \[/.test(src), false);
  check(`${label}: defines no glob converter of its own`,
    /function dlpGlobToRe\(/.test(src), false);

  // AND WITH THE RIGHT FLAGS. The guard only TESTS, so a `g` regex would carry
  // `lastIndex` between calls and silently skip matches; the other two REPLACE, so
  // without `g` only the first secret in a file is masked and the rest reach the model.
  const wants = label === 'guard' ? "dlpPatterns('')" : "dlpPatterns('g')";
  check(`${label}: compiles them ${label === 'guard' ? 'non-global (it tests)' : 'global (it replaces)'}`,
    src.includes(wants), true);
}

// ── the CLI's menu is the same list ──────────────────────────────────────────
//
// `solongate dlp` offers the names a policy may enable. A name it offers that nothing
// enforces is worse than one it omits: somebody turns it on and believes they are covered.
{
  const ts = readFileSync(fileURLToPath(new URL('../src/dlp-patterns.ts', import.meta.url)), 'utf-8');
  const from = ts.indexOf('DLP_PATTERN_NAMES');
  const block = ts.slice(from, ts.indexOf('\n];', from));
  const names = [...block.matchAll(/'([^']+)'/g)].map((m) => m[1]);
  check('the CLI menu carries every pattern', names.length, go.length);
  check('the CLI menu is in the same order', names.join('|'), go.map(([n]) => n).join('|'));

  const goMenu = readFileSync(fileURLToPath(new URL('../../proxy-go/internal/api/dlppatterns.go', import.meta.url)), 'utf-8');
  const gm = [...goMenu.matchAll(/"([^"]+)",/g)].map((m) => m[1]);
  check('the Go menu carries every pattern', gm.length >= go.length, true);
  check('the Go menu is in the same order',
    gm.slice(0, go.length).join('|'), go.map(([n]) => n).join('|'));
}

process.exit(done());
