package selfupdate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// THE UPDATE ARRANGES THE MACHINE WITH THE BINARY IT JUST INSTALLED.
//
// Everything else an update does runs the code of the version being replaced,
// which is fine for copying files and wrong for anything the new version knows
// how to do and the old one does not. The release that taught this product to
// install the Firefox add-on could not install it during its own update: the
// process doing the updating was the version from before, so it took a second,
// unrelated command afterwards that nothing on screen asked for.
//
// What is pinned here is that the path names the binary ON DISK rather than
// whatever `solongate` resolves to on PATH - which is the npm launcher, and on
// some installs the launcher belonging to the version being replaced.
func TestAnUpdateArrangesWithTheNewBinary(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Nothing installed: no path, and nothing is run.
	if got := freshCLI(); got != "" {
		t.Errorf("a machine with no installed binary answered %q", got)
	}

	name := "solongate"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(config.Dir(), "bin", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := freshCLI(); got != path {
		t.Errorf("the update would arrange with %q rather than the binary it installed at %q", got, path)
	}

	// A directory where the binary should be is not a binary, and trying to run
	// one would be an error on every update from then on.
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(filepath.Join(config.Dir(), "bin", name), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := freshCLI(); got != "" {
		t.Errorf("a directory was mistaken for the installed binary: %q", got)
	}
}
