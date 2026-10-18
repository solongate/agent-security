// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors


import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

let cached = null;

export function goBin() {
  if (cached) return cached;
  cached = find();
  return cached;
}

function find() {
  if (process.env.GO_BIN) return process.env.GO_BIN;

  const home = homedir();
  const fixed = [
    join(home, 'go', 'bin', 'go'),
    '/usr/local/go/bin/go',
    '/usr/lib/go/bin/go',
    '/opt/homebrew/bin/go',
    '/usr/local/bin/go',
  ];
  for (const path of fixed) {
    if (existsSync(path)) return path;
  }

  const cache = join(home, 'go', 'pkg', 'mod', 'golang.org');
  try {
    const found = readdirSync(cache)
      .filter((name) => name.startsWith('toolchain@'))
      .sort()
      .reverse()
      .map((name) => join(cache, name, 'bin', 'go'))
      .filter((path) => existsSync(path));
    if (found.length) return found[0];
  } catch {}

  return 'go';
}