package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The accounts file holds live API keys in cleartext, and it was written 0644 —
// world-readable. On the machines this tool actually runs on (shared build boxes,
// CI runners, containers with more than one account in them) that hands every
// other user a working credential for the project.
//
// Both halves are asserted: the mode on a file this code CREATES, and the mode on
// one that was already there. Go's WriteFile only applies a mode on creation, so a
// fix that only passed 0600 would leave every existing install exactly as exposed
// as before — which is most of them.
func TestTheAccountsFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	acct := SavedAccount{APIKey: "sg_live_" + "0123456789abcdef0123456789abcdef", APIURL: "http://127.0.0.1:9"}

	t.Run("a file this code creates", func(t *testing.T) {
		SaveAccount(acct)
		info, err := os.Stat(AccountsPath())
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("accounts.json mode = %04o, want 0600 — it holds a live key", got)
		}
	})

	t.Run("and one already on disk, written before the fix", func(t *testing.T) {
		// The state an existing install is in.
		if err := os.Chmod(AccountsPath(), 0o644); err != nil {
			t.Fatal(err)
		}
		SaveAccount(acct)
		info, err := os.Stat(AccountsPath())
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("mode = %04o, want 0600 — an existing file keeps its mode unless something narrows it", got)
		}
	})

	t.Run("and the directory is not listable either", func(t *testing.T) {
		if err := os.Chmod(Dir(), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := EnsureDir(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(Dir())
		if err != nil {
			t.Fatal(err)
		}
		// 0600 files inside a 0755 directory are still ENUMERABLE, which names the
		// projects, the accounts and every agent that has run here.
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s mode = %04o, want 0700", filepath.Base(Dir()), got)
		}
	})
}
