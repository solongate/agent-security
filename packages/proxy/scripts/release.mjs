#!/usr/bin/env node
// release.mjs — the whole of cutting a release, in the order the pieces have to
// happen in.
//
// WHY THIS EXISTS. The steps are five, three of them are order-dependent in ways
// that fail silently, and the failure is always the same shape: a release that
// looks published and is missing a browser.
//
//   1. build.mjs regenerates the extension from packages/shadowdom, and it
//      CLEARS the signed add-on on its way past. Signing before it is signing a
//      file that is about to be deleted.
//   2. sign.mjs sends the packed XPI to addons.mozilla.org and writes the signed
//      copy back into the tree. It needs credentials and a network round trip,
//      and an AMO version number is spent whether the upload is accepted or
//      refused - so this runs before anything is published, never after.
//   3. build:go compiles the binaries, which is what EMBEDS the signed add-on.
//      Running it before signing produces a binary that carries nothing for
//      Firefox, and the symptom is a machine where Chrome installs itself and
//      Firefox quietly does not.
//   4. the platform packages publish BEFORE the main one, or an install
//      resolves optionalDependencies that do not exist yet.
//   5. the main package last.
//
// Every one of those was a separate thing to remember, and each has been
// forgotten at least once. What that cost was never a build error: it was a
// published version with a browser missing from it, found days later.
//
//	pnpm release                 cut whatever version package.json says
//	pnpm release 0.90.0          set the version first
//	pnpm release --no-publish    everything up to and including the binaries
//
// AMO_JWT_ISSUER and AMO_JWT_SECRET have to be in the environment. Without them
// this stops at the signing step rather than continuing, because a release that
// treated signing as optional is exactly how a build with no Firefox add-on gets
// published - see sign.mjs, which refuses for the same reason.

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { goBin } from '../../../scripts/gobin.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const proxy = join(here, '..');
const repo = join(proxy, '..', '..');
const web = join(repo, 'packages', 'shadowext-web');

const args = process.argv.slice(2);
const publish = !args.includes('--no-publish');
const version = args.find((a) => /^\d+\.\d+\.\d+$/.test(a));

const step = (n, what) => console.log('\n\x1b[1m[' + n + '/6] ' + what + '\x1b[0m');

// THE TOOLCHAIN IS RESOLVED ONCE AND HANDED DOWN.
//
// Two of the steps below shell out to Go, and on a machine whose toolchain came
// down through the module cache there is nothing called `go` on PATH at all -
// which is not an unusual machine, it is what `go` itself produces when a go.mod
// asks for a newer toolchain than the one installed. That failed the release at
// step one, after it had already deleted the signed add-on. Both GO_BIN and PATH
// are set because the two scripts read it differently, and a person running
// either of them on its own gets the same answer from scripts/gobin.mjs.
const go = goBin();
const env = { ...process.env, GO_BIN: go };
if (go !== 'go') {
  env.PATH = dirname(go) + ':' + (process.env.PATH || '');
}

const run = (cmd, cmdArgs, cwd) => execFileSync(cmd, cmdArgs, { cwd, stdio: 'inherit', env });

// ── the version ─────────────────────────────────────────────────────────────
//
// Written into package.json before anything reads it, because build.mjs stamps
// the extension manifests from this file and build:go stamps the binaries from
// it. A version set halfway through is a release whose extension and binaries
// disagree, which the tests catch and which is a wasted signing round.
const manifestPath = join(proxy, 'package.json');
const pkg = JSON.parse(readFileSync(manifestPath, 'utf8'));
if (version && version !== pkg.version) {
  pkg.version = version;
  writeFileSync(manifestPath, JSON.stringify(pkg, null, 2) + '\n');
  console.log('version set to ' + version);
}
const releasing = pkg.version;
console.log('releasing ' + releasing);

// THE CREDENTIALS ARE CHECKED FIRST, before anything is built.
//
// Signing is in the middle of this sequence and it is the only step that can
// fail for a reason outside the repository. Finding that out after two minutes
// of compiling, with the signed add-on already deleted by step one, leaves the
// tree in a state where the only way forward is to sign - which is the thing
// that just turned out to be impossible.
if (!process.env.AMO_JWT_ISSUER || !process.env.AMO_JWT_SECRET) {
  console.error('\nrelease.mjs: AMO_JWT_ISSUER and AMO_JWT_SECRET are not set.');
  console.error('  Firefox installs an add-on Mozilla signed and nothing else, so a release');
  console.error('  cut without them is one where Firefox gets nothing. The keys are at');
  console.error('  https://addons.mozilla.org/developers/addon/api/key/ and they are read');
  console.error('  from the environment, never written anywhere.');
  process.exit(1);
}

step(1, 'the extension, from packages/shadowdom');
run('node', [join(web, 'build.mjs')], repo);

step(2, 'the Mozilla signature');
run('node', [join(web, 'sign.mjs')], repo);

step(3, 'the binaries, with the signed add-on inside them');
run('pnpm', ['build:go'], proxy);

step(4, 'the workspace');
run('pnpm', ['build'], repo);

if (!publish) {
  console.log('\nStopping before publish, as asked. The tree is ready.');
  process.exit(0);
}

// ── the two publishes, in the one order that works ──────────────────────────
step(5, 'the platform packages');
const platforms = join(proxy, 'platforms');
if (!existsSync(platforms)) {
  console.error('release.mjs: there is no platforms directory, so build:go did not lay one out.');
  process.exit(1);
}
for (const name of readdirSync(platforms)) {
  const dir = join(platforms, name);
  process.stdout.write('  ' + name + ' ... ');
  try {
    execFileSync('npm', ['publish', '--access', 'public'], { cwd: dir, stdio: 'pipe' });
    console.log('published');
  } catch (err) {
    // A version already on the registry is the one failure worth continuing
    // past: it means this platform published on an earlier attempt of the same
    // release, and stopping would leave the other five behind it.
    const said = String((err.stderr || err.stdout || '') + '');
    if (said.includes('cannot publish over') || said.includes('previously published')) {
      console.log('already there');
      continue;
    }
    console.log('FAILED');
    console.error(said.trim());
    process.exit(1);
  }
}

step(6, 'the main package');
run('npm', ['publish', '--access', 'public'], proxy);

// It used to end "the dashboard and the API deploy from main", which is what a push
// did in the monorepo this was carved out of. Nothing deploys from this repository:
// the npm package IS the release, and it has just been published.
console.log('\n' + releasing + ' is out on npm. Commit and push so the tag and the published version agree.');
