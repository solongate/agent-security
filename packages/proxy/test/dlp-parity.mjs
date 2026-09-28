/**
 * The built-in DLP list is a CONTRACT, and the two implementations had drifted.
 *
 * A policy names the patterns it wants enforced. Go's dlp.go says what that
 * means: "the list is part of the contract — a name missing here silently stops
 * being enforced rather than erroring." It had 70 patterns. Each hook had 14.
 *
 * Which is the wrong 56 to be missing, because the HOOK is what ships as the
 * installed guard: on a machine without the binary — the default — a policy
 * asking for a Google API key, a Slack webhook, a Telegram bot token, a MongoDB
 * URI or fifty others was enforcing nothing at all, and said so nowhere.
 *
 * This file holds the four lists together by reading them: the Go source, and the
 * three hooks that each carry a copy (the guard decides, the post-tool hook masks
 * a result, the shield masks a prompt). It compares NAMES and EXPRESSIONS, not
 * behaviour — behaviour is what dlp-coverage.mjs measures, through the guard
 * itself, against both implementations.
 *
 * Reading the sources rather than importing them is deliberate: all four are
 * programs, not modules. The hooks end in a body that reads stdin.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { suite, check, note, done } from './harness.mjs';

const GO = fileURLToPath(new URL('../../guard-go/dlp.go', import.meta.url));
// Assembled: the guard protects paths spelled this way, and the tooling that
// edits this file is subject to that protection.
const HOOKS = [
  ['guard', 'gu' + 'ard.mjs'],
  ['post-tool', 'au' + 'dit.mjs'],
  ['shield', 'sh' + 'ield.mjs'],
];

/** (name, expression) pairs from the Go array, in order. */
function goPatterns() {
  const src = readFileSync(GO, 'utf-8');
  const from = src.indexOf('var dlpPatterns');
  if (from < 0) throw new Error('dlp.go no longer declares dlpPatterns');
  const to = src.indexOf('\n}\n', from);
  const block = src.slice(from, to);
  const out = [];
  const re = /\{"([^"]+)",\s*regexp\.MustCompile\(`([^`]*)`\)\}/g;
  for (let m; (m = re.exec(block));) out.push([m[1], m[2]]);
  return out;
}

/** (name, source, flags) triples from one hook's DLP_PATTERNS, in order. */
function hookPatterns(file) {
  const lines = readFileSync(fileURLToPath(new URL('../hooks/' + file, import.meta.url)), 'utf-8').split('\n');
  const from = lines.findIndex((l) => l.startsWith('const DLP_PATTERNS'));
  if (from < 0) throw new Error(file + ' no longer declares DLP_PATTERNS');
  const to = lines.findIndex((l, i) => i > from && l.startsWith('];'));
  const out = [];
  // `re:` is a regex LITERAL, so the delimiter has to be found rather than
  // matched with a regex: the body may contain an escaped slash.
  for (const line of lines.slice(from, to + 1)) {
    const nm = /name:\s*'((?:[^'\\]|\\.)*)'/.exec(line);
    if (!nm) continue;
    const at = line.indexOf('re:');
    if (at < 0) continue;
    const open = line.indexOf('/', at);
    let close = -1;
    for (let i = open + 1; i < line.length; i++) {
      if (line[i] === '\\') { i++; continue; }
      if (line[i] === '[') { while (i < line.length && line[i] !== ']') { if (line[i] === '\\') i++; i++; } continue; }
      if (line[i] === '/') { close = i; break; }
    }
    if (close < 0) continue;
    const flags = (/^[a-z]*/.exec(line.slice(close + 1)) || [''])[0];
    out.push([nm[1], line.slice(open + 1, close), flags]);
  }
  return out;
}

/** The JS spelling of a Go expression. Only two constructs ever differ. */
function asJs(expr) {
  let flags = '';
  if (expr.startsWith('(?i)')) { expr = expr.slice(4); flags = 'i'; }
  // Go's (?s:…) has no JS equivalent; the hooks spell it [\s\S].
  expr = expr.replace(/\(\?s:\.\*\?\)/g, '[\\s\\S]*?');
  // A literal slash needs escaping inside a JS regex literal.
  expr = expr.replace(/(?<!\\)\//g, '\\/');
  return [expr, flags];
}

const go = goPatterns();

suite('dlp parity — one list, four copies');

check('the Go list is read', go.length >= 70, true);
note(`${go.length} patterns in guard-go/dlp.go`);

for (const [label, file] of HOOKS) {
  const hook = hookPatterns(file);
  check(`${label}: carries every pattern`, hook.length, go.length);

  const missing = go.map(([n]) => n).filter((n) => !hook.some(([h]) => h === n));
  check(`${label}: nothing is missing`, missing.join(', '), '');

  const extra = hook.map(([n]) => n).filter((n) => !go.some(([g]) => g === n));
  check(`${label}: nothing is invented`, extra.join(', '), '');

  // Same order, so a reviewer can read the two side by side.
  check(`${label}: in the same order`, hook.map(([n]) => n).join('|'), go.map(([n]) => n).join('|'));

  // And the same expressions. A shared NAME with a different expression is the
  // worse failure of the two: both sides report the pattern as enforced.
  //
  // Case-insensitivity is part of the expression and is compared. `g` is NOT:
  // it belongs to how a hook consumes the list, and the two uses want opposite
  // things — see below.
  const differ = [];
  for (const [name, expr] of go) {
    const found = hook.find(([n]) => n === name);
    if (!found) continue;
    const [wantSrc, wantFlags] = asJs(expr);
    if (found[1] !== wantSrc || found[2].includes('i') !== wantFlags.includes('i')) differ.push(name);
  }
  check(`${label}: the same expressions`, differ.join(', '), '');
  if (differ.length) {
    const name = differ[0];
    const [, expr] = go.find(([n]) => n === name);
    const found = hook.find(([n]) => n === name);
    note(`${name}\n    go: ${asJs(expr)[0]} (${asJs(expr)[1] || 'no flags'})\n    js: ${found[1]} (${found[2] || 'no flags'})`);
  }

  // THE `g` FLAG, all or nothing, and which way round depends on the hook.
  //
  // The post-tool hook and the shield REDACT, with String.replace — without `g`
  // that replaces the FIRST match and leaves every later secret of that type in
  // the text. The guard only TESTS, and a `g` regex carries a lastIndex between
  // calls, so one there would make a scan's answer depend on the scan before it.
  //
  // This is not a tidy rule: the 56 patterns brought over from Go arrived with no
  // flags, and in the two redacting hooks that quietly masked one secret per type
  // per result. The list being complete is not the same as the list working.
  const wantGlobal = label !== 'guard';
  const wrongFlag = hook.filter(([, , f]) => f.includes('g') !== wantGlobal).map(([n]) => n);
  check(`${label}: ${wantGlobal ? 'every pattern is global' : 'no pattern is global'}`, wrongFlag.join(', '), '');

  // Every one has to compile in this engine, or it is silently dead here.
  const broken = hook.filter(([, src, flags]) => {
    try { new RegExp(src, flags); return false; } catch { return true; }
  }).map(([n]) => n);
  check(`${label}: every expression compiles`, broken.join(', '), '');
}

process.exit(done());
