// SPDX-License-Identifier: Apache-2.0

// Locking a path the USER named, as opposed to one of SolonGate's own files.
//
// The mechanisms are the same three as protect.go and the reporting is not,
// which is the entire reason this is a separate file. Locking our own hooks is
// best effort by design: a machine where it does not take still has a guard,
// and saying so on every run would be noise. Locking somebody's source file is
// a promise, and a promise that quietly did not happen is worse than no promise
// at all. So every call here returns what actually took, and the caller prints
// it.
//
// WHAT EACH PLATFORM CAN ACTUALLY DO, with nothing rounded up:
//
//	macOS    chflags uchg. Unprivileged, and the owner cannot delete or
//	         overwrite the file either. This is the complete answer.
//	Windows  An icacls deny to Everyone plus an OWNER_RIGHTS (S-1-3-4) ACE
//	         pinned to read and execute. Unprivileged, and the OWNER_RIGHTS ACE
//	         is what stops the owner from rewriting the ACL back and then
//	         deleting. Also the complete answer.
//	Linux    chattr +i is the only true immutability and it needs
//	         CAP_LINUX_IMMUTABLE, which an ordinary user does not have. With
//	         sudo it is complete. Without it the best available is chmod 0444,
//	         which stops the overwrite and does NOT stop rm, because unlink
//	         checks the DIRECTORY's permission bits and not the file's.
//
// Linux is the odd one out and this file does not pretend otherwise: it asks,
// in the CLI, in words, before it runs anything as root.
package config

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Lock is what happened when a path was locked, in enough detail to print.
type Lock struct {
	// Path, cleaned and absolute.
	Path string

	// How is the mechanism that took, named the way a person could verify it
	// themselves: "chflags uchg", "chattr +i", "icacls deny + OWNER_RIGHTS",
	// "chmod 0444", or "" when nothing took.
	How string

	// Immutable is whether DELETION is blocked, not just writing. It is the
	// difference between a promise kept and a promise half kept, and it is the
	// one thing a caller must not infer from How.
	Immutable bool

	// Err is why nothing took, empty on success.
	Err string
}

// Held reports whether anything at all is in force.
func (l Lock) Held() bool { return l.How != "" }

// Summary is one line for `protect list`, written so that the weak case reads
// as weak.
func (l Lock) Summary() string {
	switch {
	case l.Err != "":
		return "not locked · " + l.Err
	case !l.Held():
		return "not locked"
	case l.Immutable:
		return l.How + " · cannot be written or deleted"
	default:
		return l.How + " · cannot be written, CAN still be deleted"
	}
}

// NeedsRootOnLinux reports whether locking this path properly would require
// one sudo. It is a question, not an action: the CLI asks it before it prints
// the explanation, so a machine that is already root never sees the prompt.
func NeedsRootOnLinux() bool {
	return runtime.GOOS == "linux" && os.Geteuid() != 0 && !hasImmutableCap()
}

// hasImmutableCap tries the cheapest possible probe: set and clear the flag on
// a file we own in our own directory. Reading /proc/self/status and parsing
// CapEff would be guessing at a bitmask; actually doing it is the answer.
func hasImmutableCap() bool {
	if EnsureDir() != nil {
		return false
	}
	probe := filepath.Join(Dir(), ".immutable-probe")
	if os.WriteFile(probe, []byte("x"), FileMode) != nil {
		return false
	}
	defer func() {
		_ = exec.Command("chattr", "-i", probe).Run()
		_ = os.Remove(probe)
	}()
	return exec.Command("chattr", "+i", probe).Run() == nil
}

// LockPath puts the strongest lock this machine can on one path.
//
// withSudo is the user's answer to the question NeedsRootOnLinux asks, and it
// is only ever true because a person typed y. Nothing here escalates on its
// own.
func LockPath(path string, withSudo bool) Lock {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Lock{Path: path, Err: err.Error()}
	}
	abs = filepath.Clean(abs)
	l := Lock{Path: abs}
	if _, err := os.Stat(abs); err != nil {
		l.Err = "no such path"
		return l
	}

	switch runtime.GOOS {
	case "darwin":
		if err := runReport("chflags", "uchg", abs); err != nil {
			l.Err = err.Error()
			return l
		}
		l.How, l.Immutable = "chflags uchg", true

	case "windows":
		// Three commands, and the second is the one that matters. Without the
		// OWNER_RIGHTS ACE the owner can rewrite the ACL the first command
		// wrote and then delete the file, which makes the whole thing theatre.
		if err := runReport("icacls", abs, "/deny", "*S-1-1-0:(WD,AD,DC,DE,WDAC,WO)"); err != nil {
			l.Err = err.Error()
			return l
		}
		if err := runReport("icacls", abs, "/grant", "*S-1-3-4:(RX)"); err != nil {
			l.Err = err.Error()
			return l
		}
		_ = runReport("attrib", "+R", abs)
		l.How, l.Immutable = "icacls deny + OWNER_RIGHTS", true

	default:
		if err := chattrSet(abs, "+i", withSudo); err == nil {
			l.How, l.Immutable = "chattr +i", true
			return l
		}
		// The fallback, and it is a real downgrade rather than a near miss.
		if err := os.Chmod(abs, 0o444); err != nil {
			l.Err = err.Error()
			return l
		}
		l.How, l.Immutable = "chmod 0444", false
	}
	return l
}

// UnlockPath lifts whatever LockPath put on.
//
// It runs every mechanism rather than only the one that took: a path locked by
// an older build, or on a machine that has since gained or lost privilege,
// should still come free. Each one is allowed to fail.
func UnlockPath(path string, withSudo bool) Lock {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Lock{Path: path, Err: err.Error()}
	}
	abs = filepath.Clean(abs)
	l := Lock{Path: abs}
	if _, err := os.Stat(abs); err != nil {
		l.Err = "no such path"
		return l
	}

	switch runtime.GOOS {
	case "darwin":
		if err := runReport("chflags", "nouchg", abs); err != nil {
			l.Err = err.Error()
		}
	case "windows":
		_ = runReport("icacls", abs, "/remove:g", "*S-1-3-4")
		_ = runReport("icacls", abs, "/remove:d", "*S-1-1-0")
		_ = runReport("icacls", abs, "/reset")
		_ = runReport("attrib", "-R", abs)
	default:
		if err := chattrSet(abs, "-i", withSudo); err != nil {
			// Not fatal on its own: the flag may never have been set.
			_ = err
		}
		if err := os.Chmod(abs, 0o644); err != nil {
			l.Err = err.Error()
		}
	}
	return l
}

// CheckLock reports what is in force on a path right now, without changing
// anything. `protect list` is only worth printing if it reads the machine
// rather than the config file.
func CheckLock(path string) Lock {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Lock{Path: path, Err: err.Error()}
	}
	abs = filepath.Clean(abs)
	l := Lock{Path: abs}
	info, err := os.Stat(abs)
	if err != nil {
		l.Err = "no such path"
		return l
	}

	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("ls", "-lO", abs).Output()
		if err == nil && strings.Contains(string(out), "uchg") {
			l.How, l.Immutable = "chflags uchg", true
		}
	case "windows":
		out, err := exec.Command("icacls", abs).Output()
		if err == nil && strings.Contains(string(out), "S-1-3-4") {
			l.How, l.Immutable = "icacls deny + OWNER_RIGHTS", true
		}
	default:
		out, err := exec.Command("lsattr", "-d", abs).Output()
		if err == nil && len(out) > 0 && strings.ContainsRune(strings.Fields(string(out))[0], 'i') {
			l.How, l.Immutable = "chattr +i", true
		} else if info.Mode().Perm()&0o222 == 0 {
			l.How, l.Immutable = "chmod 0444", false
		}
	}
	return l
}

// chattrSet is the one place that may run sudo, and only when told to.
func chattrSet(path, flag string, withSudo bool) error {
	if err := runReport("chattr", flag, path); err == nil {
		return nil
	}
	if !withSudo {
		return errors.New("chattr needs CAP_LINUX_IMMUTABLE")
	}
	// -n so sudo never silently waits on a password prompt the caller did not
	// expect. The CLI primes the credential itself, with the user watching.
	return runReport("sudo", "-n", "chattr", flag, path)
}

// runReport is run() with the exit status kept.
//
// protect.go's run() discards it, which is defensible for our own hooks and is
// not defensible here: a lock that did not take, reported as one that did, is
// the exact shape of the problem this whole feature exists to remove.
func runReport(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(name + ": " + firstLine(msg))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
