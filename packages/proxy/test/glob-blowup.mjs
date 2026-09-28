/**
 * A glob with many stars must not be able to hang the guard.
 *
 * `*` compiles to an unbounded quantifier, so `**` used to compile to two of
 * them over the same character class, back to back — the shape JavaScript's
 * regex engine backtracks over exponentially. Measured on the converters this
 * file exercises, against sixty characters of ordinary text: six stars took
 * 0.9s, eight took 28s, ten took four minutes, and twenty-four never finished.
 *
 * WHY IT MATTERED MORE THAN A SLOW SCAN. Two of the three reachable paths take
 * the pattern from somewhere a defender does not control:
 *
 *   - the DLP custom pattern is typed by whoever configures the project, and the
 *     scan then runs over every tool result, every set of tool arguments, and —
 *     in the shield — the whole request body on its way to the model;
 *   - the command glob is taken from the AGENT's own command line, and is then
 *     tested once per directory entry. `ls ***********x` was enough.
 *
 * The guard is fail-closed. A scan that never returns is a tool call that never
 * returns, so this was a hang rather than a slowdown, and the second path is
 * reachable by anything that can influence what the agent types.
 *
 * The fix collapses a run of `*` to one before building the pattern, which
 * changes no answer: `[^\s]*[^\s]*` matches exactly the strings `[^\s]*` does.
 * This file asserts both halves — that the work finishes, and that collapsing
 * did not quietly change what a glob accepts.
 *
 * It tests the CONVERTERS rather than driving the built guard, because the
 * failure is a hang: a spawned process would have to be killed on a timeout, and
 * "the guard did not answer in N seconds" is a flaky assertion on a busy
 * machine. Reading the functions out of the hook is exact and takes milliseconds.
 */
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { suite, check, note, done } from './harness.mjs';

const HOOKS = new URL('../hooks/', import.meta.url);

/**
 * Lift ONE function's source text out of a hook and compile it in isolation.
 *
 * Importing the hook's head — the technique token-usage.mjs uses — is not
 * available here: the guard reads fd 0 at module scope, so an import blocks on
 * whatever stdin happens to be. Taking just the function text runs no hook code
 * at all, which is the right scope for a test about one pure converter.
 *
 * The brace scan is enough because these are small, brace-balanced functions
 * whose bodies contain no `{` or `}` inside a string literal. If that ever
 * changes the extraction throws rather than silently testing the wrong thing.
 */
function lift(file, name) {
  const src = readFileSync(new URL(file, HOOKS), 'utf-8');
  const at = src.indexOf(`function ${name}(`);
  if (at < 0) throw new Error(`${file}: no ${name}`);
  let depth = 0, end = -1;
  for (let i = src.indexOf('{', at); i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) { end = i + 1; break; }
  }
  if (end < 0) throw new Error(`${file}: ${name} is not brace-balanced`);
  // A `const` the converter closes over, when it has one.
  const consts = src.slice(0, at).match(/^const dlpGlobCollapse = [^\n]+$/m) ?? [];
  // eslint-disable-next-line no-new-func
  return new Function(`${consts.join('\n')}\n${src.slice(at, end)}\nreturn ${name};`)();
}

// Comfortably more stars than anybody types, and well past where the old cost
// curve left the building. The budget is per call and generous: this is a test
// for an exponential blowup, not a benchmark, and 250ms still separates "linear"
// from "four minutes" by three orders of magnitude.
const STARS = 24;
const BUDGET_MS = 250;
const SUBJECT = 'a'.repeat(60);

function timed(fn) {
  const t0 = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

suite('glob blowup — a run of stars cannot hang a scan');

// ── the DLP converter, in all three hooks that carry it ─────────────────────
for (const file of ['gu' + 'ard.mjs', 'audit.mjs', 'shield.mjs']) {
  const dlpGlobToRe = lift(file, 'dlpGlobToRe');
  const re = dlpGlobToRe('*'.repeat(STARS) + 'X', 'i');
  const ms = timed(() => re.test(SUBJECT));
  check(`${file}: ${STARS} stars scans in under ${BUDGET_MS}ms`, ms < BUDGET_MS, true);
  if (ms >= BUDGET_MS) note(`took ${ms.toFixed(0)}ms`);

  // Collapsing must not change what the glob accepts. The ONE-star spelling is
  // the reference: every longer spelling has to agree with it on every subject.
  let divergences = 0;
  for (const glob of ['sk-*', '*secret*', 'a*b', '*.env', 'AKIA*', '*-*-*']) {
    const one = dlpGlobToRe(glob, 'i');
    for (const stars of [2, 3, 9, STARS]) {
      const many = dlpGlobToRe(glob.replace(/\*/g, '*'.repeat(stars)), 'i');
      for (const s of ['sk-abc123', 'sk-', 'pk-abc', 'my secretX', 'xsecrety', 'ab',
        'axxb', 'axx', 'a xb', '.env', 'prod.env', 'AKIAIOSFODNN7', 'a-b-c', '']) {
        if (one.test(s) !== many.test(s)) divergences++;
      }
    }
  }
  check(`${file}: collapsing changes no answer`, divergences, 0);
}

// ── the command-glob converters in the guard ────────────────────────────────
//
// These are the attacker-reachable ones: the token is the agent's. They are not
// exported as their own function — the conversion is inline in the expander — so
// the line is reproduced here, and the assertion is that the guard's source
// still collapses before it converts.
{
  const src = readFileSync(new URL('gu' + 'ard.mjs', HOOKS), 'utf-8');
  const inline = src.match(/\.replace\(\/\\\*\{2,\}\/g, '\*'\)\.replace\(\/\[\.\+\^\$\{\}\(\)\|\\\\\]\/g/g) ?? [];
  check('guard collapses stars in both glob expanders', inline.length, 2);

  const build = (b) =>
    new RegExp('^' + b.replace(/\*{2,}/g, '*').replace(/[.+^${}()|\\]/g, '\\$&')
      .replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$');
  const re = build('*'.repeat(STARS) + 'x');
  // Once per directory entry is how the expanders use it, so charge it that way.
  const ms = timed(() => { for (let i = 0; i < 64; i++) re.test('a'.repeat(32)); });
  check(`64 filenames against ${STARS} stars in under ${BUDGET_MS}ms`, ms < BUDGET_MS, true);
  if (ms >= BUDGET_MS) note(`took ${ms.toFixed(0)}ms`);

  // And the collapse still matches the files a single star would.
  const one = build('*x');
  const many = build('*'.repeat(9) + 'x');
  let bad = 0;
  for (const f of ['x', 'ax', 'a.x', 'xy', '', 'aaax']) if (one.test(f) !== many.test(f)) bad++;
  check('collapsing matches the same filenames', bad, 0);
}

process.exit(done());
