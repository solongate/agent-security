package install

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Put the Go binaries where the installed hook can find them.
//
// THE PROBLEM THIS SOLVES, and it made the whole fast path unreachable for the
// commonest install: a global install writes guard.mjs as a LONE FILE under
// ~/.solongate/hooks, and a client launches it from whatever directory the agent
// happens to be in. From there the hook's package lookup —
// require.resolve("@solongate/guard-<platform>") — finds nothing, because there
// is no node_modules anywhere above it. So the hook fell back to its Node
// implementation on every call, on every machine, and nothing said so: a
// fallback looks exactly like a fast path that is merely slow.
//
// The hook's last candidate is ~/.solongate/bin, which is what this fills.
//
// WHERE THE BINARIES COME FROM is the part worth reading. Not a package lookup —
// this program IS one of them. The CLI and the guard ship in the same platform
// package, side by side, so the guard is the file next to this executable. That
// needs no resolver, works the same for npm, pnpm, yarn and bun, and cannot pick
// up a copy from a different version.
//
// BEST EFFORT, ALWAYS. A platform with no published binary, an install with
// --no-optional, a read-only home: none of them is an install failure. The hook
// enforces the same policy in Node, more slowly. A missing binary costs speed
// and never protection, and an installer that refused to continue without one
// would turn a performance feature into an outage.

// goBinaryNames are the two programs a platform package carries. The names are
// part of the contract: the installed hook looks for exactly `solongate-guard`
// in this directory.
//
// A THIRD NAME USED TO BE HERE, `solongate-browser`, for a browser-side agent
// that is not part of this release — nothing in this repository builds it. The
// copy loop below skips a name it cannot stat, so the only cost was a file that
// never arrived and a comment explaining why it was everywhere. Both are better
// gone than explained.
func goBinaryNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"solongate-guard.exe", "solongate.exe"}
	}
	return []string{"solongate-guard", "solongate"}
}

// BinDir is where the installed hook looks for a binary.
func BinDir() string { return filepath.Join(GlobalPaths().SGDir, "bin") }

// InstallGoBinaries copies the platform package's binaries beside the installed
// hook. It returns the names it placed, for the install report.
func InstallGoBinaries() []string {
	self, err := os.Executable()
	if err != nil {
		return nil
	}
	// Symlinks matter here: a global npm install links the bin into a directory
	// on PATH, and the link's directory has no binaries next to it.
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	return copyFrom(filepath.Dir(self))
}

// copyFrom is the copy itself, with the source named rather than discovered, so
// a test can drive it without pretending to be a different executable.
func copyFrom(src string) []string {
	dst := BinDir()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return nil
	}

	var placed []string
	for _, name := range goBinaryNames() {
		from := filepath.Join(src, name)
		info, err := os.Stat(from)
		if err != nil || info.IsDir() {
			continue
		}
		to := filepath.Join(dst, name)
		if sameFile(from, to) {
			placed = append(placed, name)
			continue
		}
		if err := copyExecutable(from, to); err != nil {
			continue
		}
		placed = append(placed, name)
	}
	return placed
}

func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// copyExecutable writes to a temporary name and renames.
//
// A hook that fires mid-install must not be handed a half-written binary. It
// would be refused — the version probe fails on a truncated file — and fall back
// to Node, which is safe but slow for no reason. A rename is atomic within a
// directory, so the hook sees either the old binary or the new one.
func copyExecutable(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := to + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// Windows refuses to rename over an existing file that is open; removing
	// first is the portable order and the window it opens is the same one the
	// atomic rename was protecting, only shorter.
	if runtime.GOOS == "windows" {
		_ = os.Remove(to)
	}
	if err := os.Rename(tmp, to); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Chmod(to, 0o755)
}
