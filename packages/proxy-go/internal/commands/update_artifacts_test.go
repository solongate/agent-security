// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A checkout an install has already run in, which is the state every update
// after the first one starts from.
func repoWithCommit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	for _, p := range []string{"pnpm-lock.yaml", "packages/proxy/package.json", "packages/proxy/hooks/guard.bundled.mjs", "README.md"} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("committed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "-A")
	run("commit", "-qm", "base")
	return dir
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// THE UPDATE THAT BLOCKS THE NEXT UPDATE.
//
// install.sh runs `pnpm install`, which rewrites the lockfile whenever it has
// anything to resolve differently. Nobody typed that, and until this existed the
// next `solongate update` died on `git pull --ff-only` before reaching any work.
func TestAnInstallsOwnRewritesDoNotBlockThePull(t *testing.T) {
	root := repoWithCommit(t)
	write(t, root, "pnpm-lock.yaml", "rewritten by pnpm\n")
	write(t, root, "packages/proxy/package.json", "rewritten by the build\n")

	if code := restoreInstallArtifacts(root); code != 0 {
		t.Fatalf("returned %d — the update stops on changes it made itself", code)
	}
	if got := read(t, root, "pnpm-lock.yaml"); got != "committed\n" {
		t.Errorf("lockfile is %q, want it restored", got)
	}
	if got := read(t, root, "packages/proxy/package.json"); got != "committed\n" {
		t.Errorf("manifest is %q, want it restored", got)
	}
}

// AND THE HALF THAT MATTERS MORE: somebody's own edit is not the install's to
// throw away. A command that resets everything to get itself unstuck would be
// the worse bug.
func TestARealLocalEditStopsTheUpdateAndSurvivesIt(t *testing.T) {
	root := repoWithCommit(t)
	write(t, root, "pnpm-lock.yaml", "rewritten by pnpm\n")
	write(t, root, "README.md", "my own work\n")

	if code := restoreInstallArtifacts(root); code == 0 {
		t.Fatal("the update carried on over an edit that was not its own")
	}
	if got := read(t, root, "README.md"); got != "my own work\n" {
		t.Fatalf("the edit was destroyed: %q", got)
	}
	if got := read(t, root, "pnpm-lock.yaml"); got != "rewritten by pnpm\n" {
		t.Error("it reset half the tree on its way to refusing, which is the worst of both")
	}
}

// An untracked file does not block a fast-forward, so it is not this command's
// business — and deleting one on the way past would be a surprise with no upside.
func TestUntrackedFilesAreLeftAlone(t *testing.T) {
	root := repoWithCommit(t)
	write(t, root, "notes.txt", "scratch\n")

	if code := restoreInstallArtifacts(root); code != 0 {
		t.Fatalf("returned %d — an untracked file stopped an update it cannot block", code)
	}
	if _, err := os.Stat(filepath.Join(root, "notes.txt")); err != nil {
		t.Error("the untracked file was removed")
	}
}

func TestACleanCheckoutIsLeftExactlyAsItIs(t *testing.T) {
	root := repoWithCommit(t)
	if code := restoreInstallArtifacts(root); code != 0 {
		t.Fatalf("returned %d on a clean checkout", code)
	}
}
