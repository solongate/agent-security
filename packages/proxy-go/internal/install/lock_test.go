// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Self-protection pins the protection files read-only, which means every writer
// of those files has to lift the lock, write, and put it back. Forgetting that
// is not a visible failure: the write returns EPERM, a caller that swallows the
// error reports success, and the OLD guard stays on disk. That is exactly how a
// device revoked in the dashboard once stayed stuck on an invalid key.
//
// So this test installs with the lock ON, checks the files really are pinned,
// and then installs again — which can only work if the second install unlocks
// what the first one locked.
func TestAReinstallSurvivesItsOwnLocks(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the lock is a permission bit only on POSIX; Windows uses ACLs")
	}
	home := sandbox(t)
	haveHookSources(t)
	t.Setenv("SOLONGATE_NO_OS_LOCK", "") // locks ON, the shipped default
	t.Setenv("SOLONGATE_API_KEY", "sg_live_0123456789abcdef")
	// Leave nothing pinned behind: on a machine where chattr +i actually takes
	// (a privileged container), the temp directory could not be cleaned up.
	t.Cleanup(UnlockProtected)

	if r := Install(); !r.OK {
		t.Fatalf("first install: %s", r.Message)
	}
	guard := filepath.Join(home, ".solongate", "hooks", GuardHookName)
	info, err := os.Stat(guard)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("the guard was left writable by any process: %v", info.Mode().Perm())
	}
	if err := os.WriteFile(guard, []byte("disarmed"), 0o644); err == nil {
		t.Fatal("a plain write to the locked guard succeeded — the lock is not doing anything")
	}

	if r := Install(); !r.OK {
		t.Fatalf("a reinstall could not rewrite its own locked files: %s", r.Message)
	}
	if body, err := os.ReadFile(guard); err != nil || string(body) == "disarmed" {
		t.Fatalf("the reinstall did not replace the guard: %v", err)
	}
}

// An install lifts the locks before it writes, so a failure in the middle must
// put them back. Returning with them off would leave the machine LESS protected
// than if the install had never been run — the one outcome worse than failing.
func TestAFailedInstallPutsTheLocksBack(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the lock is a permission bit only on POSIX; Windows uses ACLs")
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory, so the failure cannot be staged")
	}
	home := sandbox(t)
	haveHookSources(t)
	t.Setenv("SOLONGATE_NO_OS_LOCK", "")
	t.Setenv("SOLONGATE_API_KEY", "sg_live_0123456789abcdef")
	t.Cleanup(UnlockProtected)

	if r := Install(); !r.OK {
		t.Fatalf("first install: %s", r.Message)
	}

	// A hooks directory nothing can create a file in: the atomic write fails
	// after the locks have already been lifted.
	hooks := filepath.Join(home, ".solongate", "hooks")
	if err := os.Chmod(hooks, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hooks, 0o755) })

	if r := Install(); r.OK {
		t.Fatal("an install that could not write the hooks reported success")
	}
	info, err := os.Stat(filepath.Join(hooks, GuardHookName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("the failed install left the guard writable by any process: %v", info.Mode().Perm())
	}
}
