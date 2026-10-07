// SPDX-License-Identifier: Apache-2.0

/**
 * THE LOCKFILE AND THE MANIFESTS AGREE, so `--frozen-lockfile` can pass.
 *
 * CI and the release workflow both open with `pnpm install --frozen-lockfile`.
 * That flag compares the dependency SPECIFIERS a package.json declares against
 * the ones the lockfile recorded, and refuses the install when they differ. So
 * a manifest edit that never reached the lockfile does not fail slowly or
 * partially: it fails the first step of every job, before a single test runs.
 *
 * WHICH IS EXACTLY WHAT HAPPENED, for an unknown number of weeks. This package
 * declared six optionalDependencies, one per platform package, each pinned to
 * its own version. Those versions were never published, and pnpm cannot record
 * a dependency it cannot resolve, so the lockfile never held them and the two
 * sets could not be reconciled by any amount of reinstalling.
 *
 * The cost was not only a red badge. The release workflow runs the same install,
 * so five tags were pushed and produced no releases at all, and nothing anywhere
 * said why: the repository looked like one that simply had not cut a release.
 *
 * This file used to assert the opposite property, that those six entries existed
 * and tracked the version. It was correct when written and became a
 * specification for a package this repository does not publish. It is replaced
 * rather than deleted, because the failure it guarded against is real and the
 * one below is what that failure turned into here.
 *
 * WHAT IS CHECKED. Every specifier in every workspace manifest appears in the
 * lockfile for that importer, with the same value, and the reverse. The lockfile
 * is read with a small targeted parser rather than a YAML dependency: this suite
 * imports nothing the product does not already ship with, and the two nested
 * levels it needs are not worth a parser that can read the other forty.
 */
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { suite, check, note, done } from './harness.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..', '..');

// The importers block, as {importer: {name: specifier}}. Indentation is the
// structure: two spaces is an importer, four a dependency kind, six a package
// name, eight its fields.
function lockfileSpecifiers(text) {
  const out = {};
  let importer = null;
  let name = null;
  let inImporters = false;

  for (const line of text.split('\n')) {
    if (/^importers:/.test(line)) { inImporters = true; continue; }
    if (!inImporters) continue;
    // A top-level key ends the block.
    if (/^\S/.test(line)) break;
    if (!line.trim()) continue;

    const indent = line.length - line.trimStart().length;
    const trimmed = line.trim();

    if (indent === 2 && trimmed.endsWith(':')) {
      importer = trimmed.slice(0, -1).replace(/^'|'$/g, '');
      out[importer] = {};
      name = null;
    } else if (indent === 4 && trimmed.endsWith(':')) {
      name = null; // dependencies / devDependencies / optionalDependencies
    } else if (indent === 6 && trimmed.endsWith(':')) {
      name = trimmed.slice(0, -1).replace(/^'|'$/g, '');
    } else if (indent === 8 && name && trimmed.startsWith('specifier:')) {
      out[importer][name] = trimmed.slice('specifier:'.length).trim().replace(/^'|'$/g, '');
    }
  }
  return out;
}

// The workspace is `packages/*` plus the root, and the root is `.` in a lockfile.
const MANIFESTS = {
  '.': 'package.json',
  'packages/proxy': 'packages/proxy/package.json',
  'packages/tsconfig': 'packages/tsconfig/package.json',
};

const KINDS = ['dependencies', 'devDependencies', 'optionalDependencies'];

suite('release shape — the lockfile matches every manifest');

const locked = lockfileSpecifiers(readFileSync(join(repo, 'pnpm-lock.yaml'), 'utf-8'));

check('the lockfile declares importers', Object.keys(locked).length > 0, true);

for (const [importer, file] of Object.entries(MANIFESTS)) {
  const pkg = JSON.parse(readFileSync(join(repo, file), 'utf-8'));

  const declared = {};
  for (const kind of KINDS) {
    for (const [name, spec] of Object.entries(pkg[kind] || {})) declared[name] = spec;
  }

  const inLock = locked[importer] || {};

  // MISSING is the direction that breaks the install, and it is the one that
  // produced the outage described above: a manifest that asks for something the
  // lockfile never recorded.
  const missing = Object.keys(declared).filter((n) => !(n in inLock));
  check(`${importer}: every declared dependency is in the lockfile`, missing, []);
  if (missing.length) {
    note(`${missing.join(', ')} — if these are unpublished, they cannot be locked, and`);
    note('`pnpm install --frozen-lockfile` will fail on every machine until they go or get published');
  }

  // And the reverse, which breaks it just as completely: a dependency removed
  // from the manifest while the lockfile still carries it.
  const stale = Object.keys(inLock).filter((n) => !(n in declared));
  check(`${importer}: the lockfile carries nothing the manifest dropped`, stale, []);

  const drifted = Object.keys(declared).filter((n) => n in inLock && inLock[n] !== declared[n]);
  check(`${importer}: every specifier matches`, drifted, []);
  if (drifted.length) {
    note(drifted.map((n) => `${n}: manifest ${declared[n]}, lockfile ${inLock[n]}`).join('; '));
  }
}

// A RANGE ON A PLATFORM BINARY IS THE LONGER-FUSE VERSION OF THE SAME BUG, and
// the reason is worth keeping even though nothing here declares one today: a
// caret would let a machine hold a proxy and a binary from two different
// releases, and the launcher runs the binary. `solongate --version` would then
// answer with a release the user had already left, with nothing reporting a
// failure anywhere in the chain. If platform packages come back, they come back
// pinned.
{
  const pkg = JSON.parse(readFileSync(join(repo, 'packages/proxy/package.json'), 'utf-8'));
  const optional = pkg.optionalDependencies || {};
  const ranged = Object.keys(optional).filter((n) => /[\^~*x]|\s-\s/.test(optional[n]));
  check('no platform binary is pinned to a range', ranged, []);
}

process.exitCode = done();
