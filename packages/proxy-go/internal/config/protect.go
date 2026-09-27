package config

import (
	"os"
	"os/exec"
	"runtime"
)

// Self-protection puts an OS-level lock on the files that keep the guard armed
// — the installed hooks, the client settings, and cloud-guard.json. The lock
// exists to stop PROGRAMS (an agent, an editor, a stray script) from disarming
// the guard; it is not aimed at the person at the terminal, and the CLI is
// human-only, so the CLI is allowed to lift it around its own writes.
//
// Each mechanism works for the current user with no sudo or admin:
//
//	macOS:   chflags uchg — user-immutable, blocks delete and overwrite even by
//	         the owner.
//	Windows: an icacls deny to Everyone plus an OWNER_RIGHTS (S-1-3-4) ACE
//	         pinned to read/execute, so the owner cannot rewrite the ACL back
//	         and then delete. Plus the read-only attribute.
//	Linux:   chattr +i is the only true immutability and needs privilege (a
//	         harmless no-op without it). chmod a-w always works and blocks the
//	         overwrite-disarm; a plain unlink still gets through, which is an OS
//	         limit, not a missing feature.
func lockFile(file string) {
	if _, err := os.Stat(file); err != nil {
		return
	}
	switch runtime.GOOS {
	case "windows":
		run("icacls", file, "/deny", "*S-1-1-0:(WD,AD,DC,DE,WDAC,WO)")
		run("icacls", file, "/grant", "*S-1-3-4:(RX)")
		run("attrib", "+R", file)
	case "darwin":
		run("chflags", "uchg", file)
	default:
		run("chattr", "+i", file)
		_ = os.Chmod(file, 0o444)
	}
}

func unlockFile(file string) {
	if _, err := os.Stat(file); err != nil {
		return
	}
	switch runtime.GOOS {
	case "windows":
		run("icacls", file, "/remove:g", "*S-1-3-4")
		run("icacls", file, "/remove:d", "*S-1-1-0")
		run("icacls", file, "/reset")
		run("attrib", "-R", file)
	case "darwin":
		run("chflags", "nouchg", file)
	default:
		run("chattr", "-i", file)
		_ = os.Chmod(file, 0o644)
	}
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Run()
}

// WriteProtectedFile rewrites one locked file, clearing and restoring its lock
// around the write.
//
// The credential writers need this. cloud-guard.json is locked, so a plain
// write fails with EPERM and a caller that swallows the error leaves the OLD
// key on disk. That is how a device revoked in the dashboard got stuck showing
// "Invalid API key": removing or switching the account reported success while
// the dead key was still there.
//
// The lock is only lifted when the direct write actually fails, so a device
// that has the lock disabled is left untouched, and only what was unlocked is
// locked again. SOLONGATE_NO_OS_LOCK=1 is the developer opt-out and is honoured
// here too — re-locking a file on a machine that asked for no locks would arm
// something the user turned off.
func WriteProtectedFile(file string, contents []byte) bool {
	if os.WriteFile(file, contents, 0o644) == nil {
		return true
	}
	unlockFile(file)
	ok := os.WriteFile(file, contents, 0o644) == nil
	if os.Getenv("SOLONGATE_NO_OS_LOCK") != "1" {
		lockFile(file)
	}
	return ok
}
