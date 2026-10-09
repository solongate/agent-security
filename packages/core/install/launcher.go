// SPDX-License-Identifier: Apache-2.0

package install

import (
	"path/filepath"
	"runtime"
)

// The launcher that stands between a client and a hook program.
//
// WHY IT EXISTS
//
// A hook is registered as a command string in somebody else's config file, and
// that string used to name a node binary by absolute path. Absolute was and is
// right: clients run hooks in a non-interactive environment whose PATH often has
// no node on it, and a bare `node` there fails with "command not found" while
// the client reports nothing at all.
//
// What was wrong is WHICH absolute path. Both implementations resolved the
// symlink first — resolveNode calls filepath.EvalSymlinks and the npm package
// gets the same effect for free, because process.execPath is already resolved —
// so on the machines where this bit:
//
//	Homebrew  /opt/homebrew/bin/node is a symlink into
//	          /opt/homebrew/Cellar/node/<version>/bin/node, and what got written
//	          down was the versioned path. `brew upgrade` moves it and `brew
//	          cleanup` deletes it. The stable symlink was right there and we
//	          recorded the thing it pointed at instead.
//	nvm/fnm   ~/.nvm/versions/node/v22.11.0/bin/node, and the version directory
//	volta     goes the moment that version is uninstalled or pruned.
//
// Linux distro node is /usr/bin/node and Windows node is under Program Files;
// neither moves. macOS is where node is nearly always under a version manager,
// which is why this arrived as "it works everywhere except on the Mac".
//
// When the recorded path is gone the client spawns a command that cannot start.
// Nothing is enforced, nothing is logged, and every check this CLI had still
// said "guard registered" — because it was registered. It could not run.
//
// WHAT IT DOES
//
// Resolves node at RUN time, starting from the recorded path and falling
// through everywhere a Mac actually keeps one, then execs the hook so no extra
// process is left behind.
//
// And leaves a mark. The launcher touches a beat file before anything else,
// which is the one fact nothing in this product could previously establish:
// that the client invoked the hook at all. "Registered but never fired" and
// "fired but enforcing nothing" are different faults with different fixes, and
// from the outside they looked identical.
//
// This file used to be the twin of a TypeScript installer that wrote the same
// script, and the two had to agree byte for byte or each would rewrite the
// other's copy on every run. That installer has been removed. This is the only
// one left.

// LauncherName is the launcher, under HooksDir.
const LauncherName = "sg-run.sh"

// BeatDirName is where the launcher records that a hook was invoked, under the
// solongate directory.
const BeatDirName = ".beat"

// hookCommand is the command string one client's config gets for one hook.
//
// POSIX goes through the launcher. Windows keeps naming node directly: its node
// lives at a fixed location under Program Files rather than in a versioned
// directory a package manager deletes, and there is no /bin/sh to launch from.
//
// `/bin/sh <script>` rather than executing the launcher directly, so the file
// never needs its executable bit — which also means an install that could not
// chmod still produces a launcher that runs.
func hookCommand(p Paths, node, script, client, label string) string {
	target := filepath.ToSlash(filepath.Join(p.HooksDir, script))
	if runtime.GOOS == "windows" {
		return callPrefix() + `"` + filepath.ToSlash(node) + `" "` + target + `" ` + client + ` "` + label + `"`
	}
	launcher := filepath.ToSlash(filepath.Join(p.HooksDir, LauncherName))
	return `/bin/sh "` + launcher + `" "` + target + `" ` + client + ` "` + label + `"`
}
