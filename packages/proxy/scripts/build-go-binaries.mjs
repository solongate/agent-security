#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

/**
 * Cross-compile the Go guard and CLI, and lay them out as npm platform packages.
 *
 *   node scripts/build-go-binaries.mjs            # build every target
 *   node scripts/build-go-binaries.mjs linux-x64  # just one, for a quick loop
 *
 * WHY PLATFORM PACKAGES rather than a postinstall download: npm installs only
 * the optionalDependency whose `os`/`cpu` match the host, so a user downloads
 * one binary rather than six, and it arrives through the same registry, lockfile
 * and integrity hash as everything else. A postinstall that fetches from a
 * release URL is a second supply chain, and for a security tool that is the
 * wrong trade even when it is smaller.
 *
 * Both binaries go in ONE platform package. They are separate programs — the
 * guard runs per tool call, the CLI is what a human types — but they ship and
 * version together, and two packages would let a machine hold one of each from
 * different releases.
 *
 * The guard's version is NOT the npm version. It prints the HOOK_VERSION it
 * implements, because that is what the Node hook compares against before handing
 * over a call; see the comment on hookVersion in packages/guard-go/main.go. The
 * npm version is stamped separately and is diagnostic only.
 */
import { execFileSync } from 'node:child_process';

import { goBin } from '../../../scripts/gobin.mjs';
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const proxyDir = resolve(here, '..');
const repo = resolve(proxyDir, '..', '..');
const outRoot = join(proxyDir, 'platforms');

const pkgPath = join(proxyDir, 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));

// npm's own names for a host, which are also each package's name and the values
// of its `os` and `cpu` fields. Go spells two of them differently.
const TARGETS = [
  { tag: 'linux-x64', os: 'linux', cpu: 'x64', GOOS: 'linux', GOARCH: 'amd64' },
  { tag: 'linux-arm64', os: 'linux', cpu: 'arm64', GOOS: 'linux', GOARCH: 'arm64' },
  { tag: 'darwin-x64', os: 'darwin', cpu: 'x64', GOOS: 'darwin', GOARCH: 'amd64' },
  { tag: 'darwin-arm64', os: 'darwin', cpu: 'arm64', GOOS: 'darwin', GOARCH: 'arm64' },
  { tag: 'win32-x64', os: 'win32', cpu: 'x64', GOOS: 'windows', GOARCH: 'amd64' },
  { tag: 'win32-arm64', os: 'win32', cpu: 'arm64', GOOS: 'windows', GOARCH: 'arm64' },
];

const only = process.argv[2];
const targets = only ? TARGETS.filter((t) => t.tag === only) : TARGETS;
if (targets.length === 0) {
  console.error(`unknown target ${only}; known: ${TARGETS.map((t) => t.tag).join(', ')}`);
  process.exit(1);
}

const go = process.env.GO_BIN || goBin();
try {
  execFileSync(go, ['version'], { stdio: 'ignore' });
} catch {
  console.error(`no Go toolchain on PATH (looked for \`${go}\`). Set GO_BIN, or add it:`);
  console.error('  export PATH="$HOME/.local/opt/go/bin:$PATH"');
  process.exit(1);
}

/**
 * The two programs, and where each one's module lives.
 *
 * `bin` is the name the hook and the launcher look for, so it is part of the
 * contract rather than a build detail — packages/proxy/hooks/guard.mjs resolves
 * exactly `solongate-guard` inside the platform package.
 */
const PROGRAMS = [
  { bin: 'solongate-guard', module: join(repo, 'packages', 'guard-go') },
  { bin: 'solongate', module: join(repo, 'packages', 'proxy-go') },
];

// A THIRD PROGRAM USED TO BE HERE and it broke this script outright. It built
// `./cmd/solongate-browser` from `packages/shadowbridge` — a browser-side agent
// that is not part of this release and whose module is not in this repository.
//
// The failure was worth more than the missing feature, because it named the wrong
// cause. spawnSync reports a missing `cwd` as ENOENT on the COMMAND, so a build
// run in a directory that does not exist came back as:
//
//     Error: spawnSync go ENOENT   path: 'go'
//
// on a machine with a perfectly good Go toolchain on PATH — and gobin.mjs next
// door exists entirely to make that message mean what it says. Anyone reading it
// would have gone looking for their Go install.
//
// `pkg` — the package to build inside a module, defaulting to its root — is kept
// even though both programs now build from theirs. It is what lets a module ship
// more than one command, and packages/proxy-go/cmd/solongate-audit is one such
// command sitting unbuilt: a Go main package reaches nobody by existing, and a
// build script that could only build a module root is why.

function build(target, program) {
  const exe = program.bin + (target.os === 'win32' ? '.exe' : '');
  const dest = join(outRoot, target.tag, exe);
  mkdirSync(dirname(dest), { recursive: true });
  execFileSync(go, [
    'build',
    // -trimpath keeps the building machine's directory layout out of the binary,
    // which is both smaller and one less thing published to a registry.
    '-trimpath',
    '-ldflags', `-s -w -X main.buildVersion=${pkg.version}`,
    '-o', dest,
    program.pkg || '.',
  ], {
    cwd: program.module,
    env: { ...process.env, GOOS: target.GOOS, GOARCH: target.GOARCH, CGO_ENABLED: '0' },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  if (target.os !== 'win32') chmodSync(dest, 0o755);
  return { exe, bytes: statSync(dest).size };
}

console.log(`building ${targets.length} target(s) at version ${pkg.version}\n`);

for (const t of targets) {
  const dir = join(outRoot, t.tag);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  const built = PROGRAMS.map((p) => build(t, p));

  // `os` and `cpu` are what make this an optionalDependency npm can decline:
  // on a host that does not match, install skips it without failing, which is
  // exactly the "no binary here, use Node" case the hook already handles.
  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: `@solongate/guard-${t.tag}`,
    version: pkg.version,
    description: `SolonGate guard and CLI binaries for ${t.tag}`,
    license: pkg.license,
    repository: pkg.repository,
    os: [t.os],
    cpu: [t.cpu],
    files: built.map((b) => b.exe),
    // No main, no exports: there is no JavaScript in here. The hook resolves
    // this package.json and reads the binary beside it.
    preferUnplugged: true,
  }, null, 2) + '\n');

  writeFileSync(join(dir, 'README.md'),
    `# @solongate/guard-${t.tag}\n\n`
    + `Prebuilt SolonGate binaries for \`${t.os}\`/\`${t.cpu}\`.\n\n`
    + 'Installed automatically as an optional dependency of\n'
    + '[`@solongate/proxy`](https://www.npmjs.com/package/@solongate/proxy). There is no\n'
    + 'reason to depend on it directly, and nothing in it to import: it contains two\n'
    + 'executables and this file.\n\n'
    + 'If npm skipped it — an unsupported platform, `--no-optional`, a restricted\n'
    + 'registry — SolonGate still works. The guard falls back to its Node\n'
    + 'implementation, which enforces the same policy more slowly. A missing binary\n'
    + 'costs speed and never protection.\n');

  const total = built.reduce((n, b) => n + b.bytes, 0);
  console.log(`  ${t.tag.padEnd(14)} ${built.map((b) => b.exe).join(', ').padEnd(34)} ${(total / 1048576).toFixed(1)} MB`);
}

// THIS SCRIPT NO LONGER TOUCHES packages/proxy/package.json.
//
// It used to write six optionalDependencies, one per platform package, each
// pinned to pkg.version. That was right while this package was published to a
// registry: npm installs only the entry whose os and cpu match the host, so a
// user downloaded one binary rather than six, through the same lockfile and
// integrity hash as everything else.
//
// This repository does not publish to a registry. It is distributed over git,
// `solongate update` builds from source, and the layout below is what
// install.sh and `repair` copy from. The six entries therefore named versions
// that were never published, and that is not a dormant inconsistency: pnpm
// cannot record an optional dependency it cannot resolve, so the lockfile never
// held them, and `pnpm install --frozen-lockfile` could not pass on any machine.
// It failed every CI run and every release job, which is why five pushed tags
// produced no releases at all.
//
// If this package is ever published again, the entries come back WITH a
// publishing step that puts the platform packages on the registry first. One
// without the other is the state this comment is describing.

console.log(`\nlaid out under ${outRoot}`);
console.log('these are what install.sh and `repair` copy from; nothing here is published.');
