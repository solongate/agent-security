// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"os"
	"os/exec"
	"runtime"
)

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
		// 0o500, not 0o400: protectedTargets() includes the guard binary, and
		// chattr commonly fails without CAP_LINUX_IMMUTABLE (containers,
		// rootless), so this chmod is the fallback that actually runs. Keeping
		// the execute bit matches the windows ACL above (grants RX) and the
		// directory mode in protectpaths.go's LockPath.
		_ = os.Chmod(file, 0o500)
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
		_ = os.Chmod(file, 0o600)
	}
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Run()
}

func WriteProtectedFile(file string, contents []byte) bool {
	if os.WriteFile(file, contents, 0o600) == nil {
		return true
	}
	unlockFile(file)
	ok := os.WriteFile(file, contents, 0o600) == nil
	if os.Getenv("SOLONGATE_NO_OS_LOCK") != "1" {
		lockFile(file)
	}
	return ok
}