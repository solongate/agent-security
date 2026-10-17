#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

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

const PROGRAMS = [
  { bin: 'solongate-guard', module: join(repo, 'packages', 'guard') },
  { bin: 'solongate', module: join(repo, 'packages', 'app') },
];


function build(target, program) {
  const exe = program.bin + (target.os === 'win32' ? '.exe' : '');
  const dest = join(outRoot, target.tag, exe);
  mkdirSync(dirname(dest), { recursive: true });
  execFileSync(go, [
    'build',
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

  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: `@solongate/guard-${t.tag}`,
    version: pkg.version,
    description: `SolonGate guard and CLI binaries for ${t.tag}`,
    license: pkg.license,
    repository: pkg.repository,
    os: [t.os],
    cpu: [t.cpu],
    files: built.map((b) => b.exe),
  }, null, 2) + '\n');

  writeFileSync(join(dir, 'README.md'),
    `# @solongate/guard-${t.tag}\n\n`
    + `Prebuilt SolonGate binaries for \`${t.os}\`/\`${t.cpu}\`.\n\n`
    + 'There is nothing in it to import: it contains two executables and this\n'
    + 'file. This layout is what install.sh and `solongate repair` copy from, and\n'
    + 'what a release archive is made of.\n\n'
    + 'Without the binary, SolonGate still enforces. The guard falls back to its\n'
    + 'bundled Node implementation, which applies the same policy more slowly. A\n'
    + 'missing binary costs speed and never protection.\n');

  const total = built.reduce((n, b) => n + b.bytes, 0);
  console.log(`  ${t.tag.padEnd(14)} ${built.map((b) => b.exe).join(', ').padEnd(34)} ${(total / 1048576).toFixed(1)} MB`);
}


console.log(`\nlaid out under ${outRoot}`);
console.log('these are what install.sh and `repair` copy from; nothing here is published.');