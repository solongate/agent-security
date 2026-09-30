package sgshared

import (
	"os"
	"runtime"
	"testing"
)

// ~/.solongate holds credentials and the policy cache, so it is owner-only — and
// the mode has to be the same whichever program creates it.
//
// IT WAS NOT. Two packages created this same directory: the CLI's internal/config
// at 0700 and this one at 0755. MkdirAll applies a mode only when it CREATES, so
// the mode a machine ended up with was decided by whichever program ran first —
// and the guard, which goes through this package, runs on every tool call. The
// 0700 the CLI asked for was routinely undone before anybody could rely on it.
//
// Both halves are asserted, because the second is the one that bites an existing
// install: a directory already on disk at 0755 has to be corrected, not accepted.
func TestTheConfigDirectoryIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}

	t.Run("when this package creates it", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		if err := EnsureSGDir(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(SGDir())
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != DirMode {
			t.Errorf("mode = %04o, want %04o", got, DirMode)
		}
	})

	t.Run("and when it is already there, wide open", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		// The state an existing install is in.
		if err := os.MkdirAll(SGDir(), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := EnsureSGDir(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(SGDir())
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != DirMode {
			t.Errorf("mode = %04o, want %04o — MkdirAll does not narrow a directory that exists", got, DirMode)
		}
	})

	// A second case stood here: the guard reached the directory through SaveFleet, which
	// was the path that used to create it at 0755. SaveFleet and the fleet marker are
	// gone — nothing wrote the file, and a stale one made the Go guard enforce nothing
	// (see guard-go/localmode_test.go). EnsureSGDir above is the one creator left, and
	// it is what every writer goes through.

}
