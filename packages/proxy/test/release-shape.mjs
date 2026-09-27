/**
 * The published package can only pull its OWN binaries.
 *
 * This exists because of a release that looked perfect from every angle and
 * shipped the previous version's CLI. @solongate/proxy went out at 0.83.53 with
 * optionalDependencies still pinned to 0.83.52, so npm installed the new
 * JavaScript beside the OLD executables — and the launcher runs the executable.
 *
 * Every observable signal said it had worked. npm installed cleanly. `update`
 * printed "✓ updated to 0.83.53". `repair` reported every hook registered. Then
 * `solongate --version` answered 0.83.52 and the dataroom drew the previous
 * release's sections, because that is what was actually on disk. There is no
 * point in that chain where anything reports a failure, which is exactly why it
 * needs a test rather than more care.
 *
 * These six entries are not a choice anybody makes: they are this package's own
 * version, six times. The build script writes them now, and this is what says so
 * before a publish rather than after one.
 */
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { suite, check, note, done } from './harness.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(resolve(here, '..'), 'package.json'), 'utf-8'));

suite('release shape — the platform packages track the version');

{
  const deps = pkg.optionalDependencies || {};
  const names = Object.keys(deps);

  check('there are six platform packages', names.length, 6);

  const wrong = names.filter((n) => deps[n] !== pkg.version);
  check('every one is pinned to this package version', wrong, []);
  if (wrong.length) {
    note(`package is ${pkg.version}; ${wrong.map((n) => `${n}@${deps[n]}`).join(', ')}`);
    note('run `pnpm build:go` — it rewrites this block — then republish the platform packages first');
  }

  // Exact versions, not ranges. A caret here would let a machine hold a proxy
  // and a binary from two different releases, which is the same failure with a
  // longer fuse: it would appear only once a later version was published.
  const ranged = names.filter((n) => /[\^~*x]|\s-\s/.test(deps[n]));
  check('none of them is a range', ranged, []);
}

process.exitCode = done();
