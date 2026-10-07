// SPDX-License-Identifier: Apache-2.0

/**
 * The launcher that stands between an agent client and a hook script.
 *
 * WHY THIS EXISTS
 *
 * A hook is registered as a command string in somebody else's config file, and
 * that string used to name a node binary by absolute path — `process.execPath`
 * at install time. The absolute path was deliberate and is still right: Claude
 * Code runs hooks in a non-interactive environment whose PATH frequently has no
 * `node` on it, and bare `node` there fails with "command not found" while the
 * client reports nothing at all.
 *
 * What was wrong is that `process.execPath` RESOLVES SYMLINKS. On the machines
 * where this bit, that is the whole story:
 *
 *   Homebrew  /opt/homebrew/bin/node is a symlink into
 *             /opt/homebrew/Cellar/node/<version>/bin/node, so execPath records
 *             the VERSIONED path — and `brew upgrade` moves it and `brew
 *             cleanup` deletes it. The stable symlink was right there and we
 *             wrote down the thing it pointed at.
 *   nvm/fnm   ~/.nvm/versions/node/v22.11.0/bin/node, and the version directory
 *   /volta    goes away the moment that version is uninstalled or pruned.
 *
 * Linux distro node is /usr/bin/node and Windows node is under Program Files;
 * neither moves. macOS is where node is nearly always under a version manager,
 * which is why "it works everywhere except on the Mac" is the shape this took.
 *
 * When the recorded path is gone, the client spawns a command that cannot start.
 * Nothing enforces, nothing is logged, and every status this CLI printed still
 * said "guard registered" — because it was registered. It just could not run.
 *
 * WHAT THIS DOES
 *
 * Resolve node at RUN time, from a list that starts with the recorded path and
 * falls through every place a Mac actually keeps one. Then exec the hook, so no
 * extra process is left behind.
 *
 * And leave a mark. The launcher touches a beat file before it does anything
 * else, which is the one fact nothing else in this product could establish: that
 * the client invoked the hook at all. "Registered but never fired" and "fired
 * but enforcing nothing" are different faults with different fixes and they
 * looked identical from the outside.
 */

/**
 * Candidate node locations, in the order they are tried.
 *
 * `$SOLONGATE_NODE` first so a machine with an unusual layout can be told the
 * answer once rather than waiting for this list to grow. Then the path recorded
 * at install, which is the version this was installed with and is right until it
 * is not. Then PATH — populated when the client runs hooks through a login
 * shell, which Codex does. Then the fixed locations, then the version managers.
 *
 * The version-manager entries are globs and the glob order is lexicographic, so
 * `v9` sorts after `v10`. That is not worth correcting: any node that runs the
 * hook is the right answer here, and PATH has usually already produced the
 * current one by this point.
 */
const NODE_CANDIDATES = [
  // Homebrew, by the STABLE symlink rather than the Cellar path behind it —
  // the exact distinction this file exists for. Apple Silicon then Intel.
  '/opt/homebrew/bin/node',
  '/usr/local/bin/node',
  // Homebrew's keg-only layout, both prefixes.
  '/opt/homebrew/opt/node/bin/node',
  '/usr/local/opt/node/bin/node',
  // Distro and hand-built.
  '/usr/bin/node',
  '/usr/local/n/versions/node/*/bin/node',
  '/snap/bin/node',
];

/**
 * The version managers, as globs against $home.
 *
 * Every expansion here is `${VAR:-}` rather than `$VAR`, and that is load
 * bearing: the launcher runs under `set -u`, so a bare `$NVM_DIR` on a machine
 * without nvm aborts the whole script — which is every machine this was meant
 * to help. Caught by the test that runs it with an empty environment.
 */
const NODE_GLOBS = [
  // nvm. NVM_DIR is exported by its own shell hook, which a non-interactive
  // hook environment does not run, so the default location is tried too.
  '"${NVM_DIR:-}"/versions/node/*/bin/node',
  '"$home"/.nvm/versions/node/*/bin/node',
  // fnm, both the XDG location and the macOS Application Support one.
  '"$home"/.local/share/fnm/node-versions/*/installation/bin/node',
  '"$home"/Library/Application Support/fnm/node-versions/*/installation/bin/node',
  // Volta.
  '"$home"/.volta/tools/image/node/*/bin/node',
  // asdf, old layout and the current plugin one.
  '"$home"/.asdf/installs/nodejs/*/bin/node',
  '"$home"/.asdf/installs/node/*/bin/node',
];

/** Where the launcher lives, relative to the hooks directory. */
export const LAUNCHER_NAME = 'sg-run.sh';

/** Where the beat files live, relative to ~/.solongate. */
export const BEAT_DIR = '.beat';

/**
 * The launcher, with the install-time node baked in.
 *
 * POSIX sh, because /bin/sh is the one interpreter every macOS and Linux has at
 * a fixed path. It runs before every single tool call, so it forks nothing on
 * the happy path: the candidate tests are builtins, the beat file is written by
 * a redirect whose MTIME is the timestamp, and the hook is `exec`d rather than
 * spawned.
 */
export function launcherScript(pinnedNode: string): string {
  const pinned = pinnedNode.replace(/'/g, `'\\''`);
  return `#!/bin/sh
# SolonGate hook launcher — generated by \`solongate init --global\` / \`repair\`.
#
# Finds a working node and execs the hook with it. Do not edit: a reinstall
# overwrites this file, and on macOS it is chflags-locked besides.
#
# The reason it exists rather than the hook naming a node directly: an absolute
# node path recorded at install time is a Homebrew Cellar path or an nvm version
# directory, and both are deleted by a routine upgrade. The hook then could not
# start, nothing was enforced, nothing was logged, and every check still said
# the guard was registered — because it was.

set -u

script="\${1:-}"
[ -n "\$script" ] || { echo "solongate: launcher called with no hook script" >&2; exit 1; }
shift

hook=\${script##*/}
home=\${HOME:-~}
beatdir="\$home/.solongate/${BEAT_DIR}"

# The beat. Written BEFORE node is resolved, because its whole job is to record
# that the client invoked us — which is true even when everything after this
# line fails. The file's modification time is the timestamp; nothing is forked
# to produce one, and the directory test is a builtin.
#
# The braces matter. A redirect into a missing directory is reported by the
# SHELL, before the command runs, so a \`2>/dev/null\` on the printf alone does
# not suppress it — it lands on the hook's stderr, and Claude Code shows a
# hook's stderr to the person using it. Redirecting the group catches both.
beat() {
  [ -d "\$beatdir" ] || mkdir -p "\$beatdir" 2>/dev/null || return 0
  { printf '%s\\n' "\$1" > "\$beatdir/\$hook"; } 2>/dev/null || true
}

try() {
  [ -n "\${1:-}" ] && [ -x "\$1" ]
}

resolve_node() {
  # Told explicitly.
  if try "\${SOLONGATE_NODE:-}"; then echo "\$SOLONGATE_NODE"; return 0; fi
  # The node this was installed with.
  if try '${pinned}'; then echo '${pinned}'; return 0; fi
  # PATH, when the client gave us one worth having.
  p=\$(command -v node 2>/dev/null) || p=
  if try "\$p"; then echo "\$p"; return 0; fi
  # The fixed locations.
  for c in ${NODE_CANDIDATES.map((c) => `"${c}"`).join(' ')}; do
    for g in \$c; do
      if try "\$g"; then echo "\$g"; return 0; fi
    done
  done
  # The version managers.
  for c in ${NODE_GLOBS.join(' ')}; do
    for g in \$c; do
      if try "\$g"; then echo "\$g"; return 0; fi
    done
  done
  return 1
}

node_bin=\$(resolve_node) || node_bin=

# --sg-doctor: report what would be used and leave. This is what \`solongate
# doctor\` runs, so the health check exercises the REAL resolution rather than a
# copy of it that can drift.
if [ "\$script" = "--sg-doctor" ] || [ "\${1:-}" = "--sg-doctor" ]; then
  [ -n "\$node_bin" ] && { echo "\$node_bin"; exit 0; }
  echo "no node found" >&2
  exit 1
fi

if [ -z "\$node_bin" ]; then
  beat "no-node"
  # Nothing can be enforced without node, and which way to fail is not a
  # judgement call: the guard is fail-closed, so it refuses the call and says
  # why. Everything else here only records what already happened, and refusing
  # a tool call because the log could not be written would be a worse product
  # than a gap in the log.
  echo "solongate: no node runtime found, so \$hook did not run." >&2
  echo "solongate: run \\\`solongate repair\\\` in a terminal, or set SOLONGATE_NODE to your node binary." >&2
  case "\$hook" in
    guard.mjs) echo "solongate: this tool call is REFUSED — the guard is fail-closed." >&2; exit 2 ;;
    *) exit 0 ;;
  esac
fi

beat "\$node_bin"
exec "\$node_bin" "\$script" "\$@"
`;
}
