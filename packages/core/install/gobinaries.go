// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
)

func goBinaryNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"solongate-guard.exe", "solongate.exe"}
	}
	return []string{"solongate-guard", "solongate"}
}

func BinDir() string { return filepath.Join(GlobalPaths().SGDir, "bin") }

func InstallGoBinaries() []string {
	dir, ok := selfBinDir()
	if !ok {
		return nil
	}
	return copyFrom(dir)
}

func selfBinDir() (string, bool) {
	self, err := os.Executable()
	if err != nil {
		return "", false
	}

	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	return filepath.Dir(self), true
}

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

	if runtime.GOOS == "windows" {
		_ = os.Remove(to)
	}
	if err := os.Rename(tmp, to); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Chmod(to, 0o755)
}