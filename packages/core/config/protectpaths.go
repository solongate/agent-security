// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Lock struct {
	Path string

	How string

	Immutable bool

	Err string
}

func (l Lock) Held() bool { return l.How != "" }

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

func NeedsRootOnLinux() bool {
	return runtime.GOOS == "linux" && os.Geteuid() != 0 && !hasImmutableCap()
}

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

		if err := os.Chmod(abs, 0o400); err != nil {
			l.Err = err.Error()
			return l
		}
		l.How, l.Immutable = "chmod 0400", false
	}
	return l
}

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

			_ = err
		}
		if err := os.Chmod(abs, 0o600); err != nil {
			l.Err = err.Error()
		}
	}
	return l
}

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
		out, err := exec.Command(windowsSystemBinary("icacls"), abs).Output()
		if err == nil && strings.Contains(string(out), "S-1-3-4") {
			l.How, l.Immutable = "icacls deny + OWNER_RIGHTS", true
		}
	default:
		out, err := exec.Command("lsattr", "-d", abs).Output()
		if err == nil && len(out) > 0 && strings.ContainsRune(strings.Fields(string(out))[0], 'i') {
			l.How, l.Immutable = "chattr +i", true
		} else if info.Mode().Perm()&0o222 == 0 {
			l.How, l.Immutable = "chmod 0400", false
		}
	}
	return l
}

// windowsSystemBinary resolves a Windows system utility to its fixed,
// unwriteable System32 location instead of trusting a PATH lookup, falling
// back to the bare name only if that location doesn't exist on this machine.
func windowsSystemBinary(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	p := root + `\System32\` + name + `.exe`
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return name
}

func chattrSet(path, flag string, withSudo bool) error {
	if err := runReport("chattr", flag, path); err == nil {
		return nil
	}
	if !withSudo {
		return errors.New("chattr needs CAP_LINUX_IMMUTABLE")
	}

	return runReport("sudo", "-n", "chattr", flag, path)
}

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