#!/usr/bin/env node
/**
 * Builds the guard for every platform we ship, and lays out the npm packages
 * that carry them.
 *
 * The shape is the one the migration plan commits to: each platform binary is
 * its own tiny npm package, and @solongate/proxy lists them as
 * optionalDependencies. npm installs only the one matching the host, so a user
 * downloads ~21MB rather than the ~125MB all six come to, and the main package
 * stays small for anyone who never resolves a binary at all.
 *
 * The rule this exists to serve: a failed or missing binary must mean SLOW BUT
 * GUARDED. optionalDependencies is what makes that structural rather than
 * hopeful — npm does not fail an install when an optional dependency will not
 * install, so the Node hook is still there and still registered, and the
 * resolver simply does not find a binary and says so.
 *
 * Usage:
 *   node scripts/build-platforms.mjs            # build into dist-platforms/
 *   node scripts/build-platforms.mjs --version 0.84.0
 *   node scripts/build-platforms.mjs --check    # compile only, no packages
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync, statSync, readFileSync, copyFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const goDir = resolve(here, '..');
const outDir = join(goDir, 'dist-platforms');

// The six the plan commits to. Cross-compiling all of them is one `go build`
// each with GOOS/GOARCH set, which is most of why this is Go and not Rust:
// there is no per-target toolchain to install anywhere.
const TARGETS = [
  { os: 'linux', arch: 'amd64', npmOs: 'linux', npmCpu: 'x64' },
  { os: 'linux', arch: 'arm64', npmOs: 'linux', npmCpu: 'arm64' },
  { os: 'darwin', arch: 'amd64', npmOs: 'darwin', npmCpu: 'x64' },
  { os: 'darwin', arch: 'arm64', npmOs: 'darwin', npmCpu: 'arm64' },
  { os: 'windows', arch: 'amd64', npmOs: 'win32', npmCpu: 'x64' },
  { os: 'windows', arch: 'arm64', npmOs: 'win32', npmCpu: 'arm64' },
];

const argv = process.argv.slice(2);
const checkOnly = argv.includes('--check');
const versionArg = argv.indexOf('--version');
const version = versionArg !== -1
  ? argv[versionArg + 1]
  : JSON.parse(readFileSync(resolve(goDir, '..', 'proxy', 'package.json'), 'utf-8')).version;

// The binary carries the version it was built at, and the resolver refuses a
// binary whose version does not match the package that is asking. Without that
// a self-updated Node hook and a stale npm-installed binary are two different
// decision engines on one machine, and which one answers is down to install
// order.
const ldflags = `-s -w -X main.buildVersion=${version}`;

const pkgName = (t) => `@solongate/guard-${t.npmOs}-${t.npmCpu}`;
const binName = (t) => (t.os === 'windows' ? 'solongate-guard.exe' : 'solongate-guard');

function build(t) {
  const dest = join(outDir, `${t.npmOs}-${t.npmCpu}`);
  mkdirSync(dest, { recursive: true });
  const bin = join(dest, binName(t));
  execFileSync('go', ['build', '-trimpath', '-ldflags', ldflags, '-o', bin, '.'], {
    cwd: goDir,
    env: { ...process.env, CGO_ENABLED: '0', GOOS: t.os, GOARCH: t.arch },
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  return { dest, bin, size: statSync(bin).size };
}

function writePackage(t, dest) {
  // `os` and `cpu` are what make npm skip the five packages that do not apply.
  // Without them every user downloads every platform.
  writeFileSync(join(dest, 'package.json'), JSON.stringify({
    name: pkgName(t),
    version,
    description: `SolonGate guard binary for ${t.npmOs} ${t.npmCpu}`,
    os: [t.npmOs],
    cpu: [t.npmCpu],
    files: [binName(t)],
    license: 'SEE LICENSE IN LICENSE',
    repository: { type: 'git', url: 'git+https://github.com/codeyevsky/solongate.git' },
  }, null, 2) + '\n');

  const license = resolve(goDir, '..', '..', 'LICENSE');
  try { copyFileSync(license, join(dest, 'LICENSE')); } catch { /* not fatal */ }

  writeFileSync(join(dest, 'README.md'),
    `# ${pkgName(t)}\n\n` +
    `The SolonGate guard, compiled for ${t.npmOs} ${t.npmCpu}.\n\n` +
    `You do not install this yourself. \`@solongate/proxy\` lists it as an\n` +
    `optional dependency and npm picks the one matching your machine.\n\n` +
    `If it fails to install, nothing breaks: the guard falls back to its Node\n` +
    `implementation, which is slower and enforces exactly the same policy.\n`);
}

if (!checkOnly) {
  try { rmSync(outDir, { recursive: true, force: true }); } catch { /* fresh anyway */ }
}

const mb = (n) => (n / 1048576).toFixed(1).padStart(5);
const built = [];
for (const t of TARGETS) {
  const { dest, size } = build(t);
  if (!checkOnly) writePackage(t, dest);
  built.push({ t, size });
  console.log(`  ${`${t.npmOs}-${t.npmCpu}`.padEnd(14)} ${mb(size)} MB  ${checkOnly ? 'compiled' : pkgName(t)}`);
}

const total = built.reduce((n, b) => n + b.size, 0);
console.log(`\n${built.length} targets, ${mb(total)} MB total, ${mb(total / built.length)} MB per user (one platform each).`);

if (!checkOnly) {
  // The block to paste into @solongate/proxy's package.json. Written out rather
  // than edited in, because publishing order matters: the platform packages have
  // to exist on the registry before the package that declares them.
  const optional = Object.fromEntries(TARGETS.map((t) => [pkgName(t), version]));
  writeFileSync(join(outDir, 'optional-dependencies.json'), JSON.stringify({ optionalDependencies: optional }, null, 2) + '\n');
  console.log(`\nLayout in ${outDir}`);
  console.log('Publish the platform packages FIRST, then @solongate/proxy — a package');
  console.log('that declares an optionalDependency the registry does not have yet installs');
  console.log('with no binary, which is safe but pointlessly slow for everyone who updates.');
}
