// SPDX-License-Identifier: Apache-2.0

// gobin.mjs — where the Go toolchain actually is on this machine.
//
// WHY THIS IS NOT JUST "go". Go installs itself in half a dozen shapes and only
// one of them puts a binary on PATH by default. A machine that got its toolchain
// through a module download - which is what `go` itself does when a go.mod names
// a newer toolchain than the one installed - keeps it under the module cache,
// with no symlink anywhere and nothing on PATH. Homebrew, the tarball, the
// distribution package and a version manager each pick a different directory.
//
// The failure this exists for is a build that stops on "spawnSync go ENOENT" in
// the middle of a release, on a machine that has a perfectly good Go toolchain
// two directories away. Nothing about a release should require a person to have
// arranged their shell a particular way.
//
// GO_BIN overrides everything, for the machine where none of this is true.

import { execFileSync } from 'node:child_process';
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

  // PATH first, because a machine that has it there has chosen it there.
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return 'go';
  } catch {}

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

  // AND THE MODULE CACHE, which is where `go` puts a toolchain it downloaded
  // for a go.mod that asked for a newer one than the machine has. The directory
  // is named for the version and the platform, so the newest is picked by
  // sorting the names - a machine that has fetched three of them should build
  // with the one the newest module would have asked for.
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

  // Nothing found. Answered as the bare name so the caller's own error is the
  // familiar one, rather than this file inventing a path that does not exist.
  return 'go';
}
