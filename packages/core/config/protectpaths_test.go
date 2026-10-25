// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLockHeld(t *testing.T) {
	cases := []struct {
		name string
		l    Lock
		want bool
	}{
		{"zero value", Lock{}, false},
		{"error only", Lock{Err: "no such path"}, false},
		{"locked", Lock{How: "chmod 0400"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.l.Held(); got != tc.want {
				t.Errorf("Held() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLockSummary(t *testing.T) {
	cases := []struct {
		name string
		l    Lock
		want string
	}{
		{"error", Lock{Err: "no such path"}, "not locked · no such path"},
		{"not held", Lock{}, "not locked"},
		{"immutable", Lock{How: "chattr +i", Immutable: true}, "chattr +i · cannot be written or deleted"},
		{"chmod only", Lock{How: "chmod 0400", Immutable: false}, "chmod 0400 · cannot be written, CAN still be deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.l.Summary(); got != tc.want {
				t.Errorf("Summary() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLockPathCheckLockUnlockPathOnFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("chattr", "-i", file).Run() })

	before := CheckLock(file)
	if before.Held() {
		t.Errorf("CheckLock() on a fresh file = %+v, want not held", before)
	}

	locked := LockPath(file, false)
	if locked.Err != "" {
		t.Fatalf("LockPath() failed: %s", locked.Err)
	}
	if !locked.Held() {
		t.Fatal("LockPath() did not report the lock as held")
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if !locked.Immutable {
		if locked.How != "chmod 0400" {
			t.Errorf("How = %q, want %q", locked.How, "chmod 0400")
		}
		if info.Mode().Perm() != 0o400 {
			t.Errorf("perm after LockPath = %v, want 0400", info.Mode().Perm())
		}
	}

	checked := CheckLock(file)
	if checked.How != locked.How || checked.Immutable != locked.Immutable {
		t.Errorf("CheckLock() = %+v, want it to agree with LockPath() = %+v", checked, locked)
	}

	unlocked := UnlockPath(file, false)
	if unlocked.Err != "" {
		t.Fatalf("UnlockPath() failed: %s", unlocked.Err)
	}
	info, err = os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm after UnlockPath = %v, want 0600", info.Mode().Perm())
	}
}

func TestLockPathAndUnlockPathOnDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = chmodTree(dir, 0o600, 0o700) })
	t.Cleanup(func() { _ = exec.Command("chattr", "-R", "-i", dir).Run() })

	locked := LockPath(dir, false)
	if locked.Err != "" {
		t.Fatalf("LockPath(dir) failed: %s", locked.Err)
	}
	if !locked.Held() {
		t.Fatal("LockPath(dir) did not report the lock as held")
	}

	if !locked.Immutable {
		fi, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o400 {
			t.Errorf("file perm after LockPath(dir) = %v, want 0400", fi.Mode().Perm())
		}
		di, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if di.Mode().Perm() != 0o500 {
			t.Errorf("dir perm after LockPath(dir) = %v, want 0500", di.Mode().Perm())
		}
	}

	unlocked := UnlockPath(dir, false)
	if unlocked.Err != "" {
		t.Fatalf("UnlockPath(dir) failed: %s", unlocked.Err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file perm after UnlockPath(dir) = %v, want 0600", fi.Mode().Perm())
	}
}

func TestLockPathMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	l := LockPath(missing, false)
	if l.Err != "no such path" {
		t.Errorf("Err = %q, want %q", l.Err, "no such path")
	}
	if l.Held() {
		t.Error("a missing path must not be reported as locked")
	}
}

func TestUnlockPathMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	l := UnlockPath(missing, false)
	if l.Err != "no such path" {
		t.Errorf("Err = %q, want %q", l.Err, "no such path")
	}
}

func TestCheckLockMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	l := CheckLock(missing)
	if l.Err != "no such path" {
		t.Errorf("Err = %q, want %q", l.Err, "no such path")
	}
}

func TestNeedsRootOnLinuxAsRoot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-specific")
	}
	if os.Geteuid() != 0 {
		t.Skip("only meaningful when running as root")
	}
	t.Setenv("HOME", t.TempDir())
	if NeedsRootOnLinux() {
		t.Error("root never needs root")
	}
}

func TestHasImmutableCapCleansUpItsProbeFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = hasImmutableCap()
	probe := filepath.Join(home, ".solongate", ".immutable-probe")
	if _, err := os.Stat(probe); err == nil {
		t.Error("expected the immutable probe file to be removed after hasImmutableCap()")
	}
}

func TestChmodTreeSetsFileAndDirModesRecursively(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sub, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = chmodTree(root, 0o600, 0o700) })

	if err := chmodTree(root, 0o400, 0o500); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o400 {
		t.Errorf("file perm = %v, want 0400", fi.Mode().Perm())
	}
	di, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o500 {
		t.Errorf("dir perm = %v, want 0500", di.Mode().Perm())
	}
}

func TestChflagsArgs(t *testing.T) {
	cases := []struct {
		name      string
		recursive bool
		want      []string
	}{
		{"file", false, []string{"uchg", "/p"}},
		{"dir", true, []string{"-R", "uchg", "/p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := chflagsArgs("uchg", "/p", tc.recursive)
			if !equalStrings(got, tc.want) {
				t.Errorf("chflagsArgs() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIcaclsArgs(t *testing.T) {
	cases := []struct {
		name      string
		recursive bool
		want      []string
	}{
		{"file", false, []string{"/p", "/deny", "x"}},
		{"dir", true, []string{"/p", "/t", "/deny", "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := icaclsArgs("/p", tc.recursive, "/deny", "x")
			if !equalStrings(got, tc.want) {
				t.Errorf("icaclsArgs() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAttribArgs(t *testing.T) {
	cases := []struct {
		name      string
		recursive bool
		want      []string
	}{
		{"file", false, []string{"+R", "/p"}},
		{"dir", true, []string{"+R", "/p", "/s", "/d"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := attribArgs("+R", "/p", tc.recursive)
			if !equalStrings(got, tc.want) {
				t.Errorf("attribArgs() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestChattrArgs(t *testing.T) {
	cases := []struct {
		name      string
		recursive bool
		want      []string
	}{
		{"file", false, []string{"+i", "/p"}},
		{"dir", true, []string{"-R", "+i", "/p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := chattrArgs("+i", "/p", tc.recursive)
			if !equalStrings(got, tc.want) {
				t.Errorf("chattrArgs() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestChattrSetWithoutSudoFailsWithoutCapability(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("CAP_LINUX_IMMUTABLE is expected to be present as root")
	}
	file := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := chattrSet(file, "+i", false, false); err == nil {
		t.Error("expected chattrSet without sudo to fail for a non-root caller")
	}
}

func TestRunReportSuccess(t *testing.T) {
	if err := runReport("true"); err != nil {
		t.Errorf("runReport(true) = %v, want nil", err)
	}
}

func TestRunReportFailureWrapsNameAndFirstLineOfOutput(t *testing.T) {
	err := runReport("sh", "-c", "echo boom >&2; exit 3")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.HasPrefix(err.Error(), "sh: ") {
		t.Errorf("error = %q, want it prefixed with %q", err.Error(), "sh: ")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %q, want it to contain the command's output", err.Error())
	}
}

func TestRunReportFailureWithNoOutputFallsBackToErrError(t *testing.T) {
	err := runReport("sh", "-c", "exit 1")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.HasPrefix(err.Error(), "sh: ") {
		t.Errorf("error = %q, want it prefixed with %q", err.Error(), "sh: ")
	}
}

func TestFirstLine(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"single", "single"},
		{"line1\nline2", "line1"},
		{"", ""},
		{"\nsecond", ""},
	}
	for _, tc := range cases {
		if got := firstLine(tc.in); got != tc.want {
			t.Errorf("firstLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWindowsSystemBinaryFallsBackWhenMissing(t *testing.T) {
	t.Setenv("SystemRoot", t.TempDir())
	if got := windowsSystemBinary("icacls"); got != "icacls" {
		t.Errorf("windowsSystemBinary() = %q, want the bare name %q", got, "icacls")
	}
}

func TestWindowsSystemBinaryResolvesWhenPresent(t *testing.T) {
	root := t.TempDir()
	// windowsSystemBinary joins with a literal backslash rather than
	// filepath.Join, which Linux treats as an ordinary filename byte, not
	// a separator - so the fixture must be created at that exact string.
	want := root + `\System32\icacls.exe`
	if err := os.WriteFile(want, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(want) })
	t.Setenv("SystemRoot", root)
	if got := windowsSystemBinary("icacls"); got != want {
		t.Errorf("windowsSystemBinary() = %q, want %q", got, want)
	}
}

func TestWindowsSystemBinaryDefaultsSystemRootWhenUnset(t *testing.T) {
	t.Setenv("SystemRoot", "")
	if got := windowsSystemBinary("icacls"); got != "icacls" {
		t.Errorf("windowsSystemBinary() = %q, want the bare name %q", got, "icacls")
	}
}

func TestUnixSystemBinaryFallsBackWhenMissing(t *testing.T) {
	const name = "definitely-not-a-real-binary-xyz"
	if got := unixSystemBinary(name); got != name {
		t.Errorf("unixSystemBinary(%q) = %q, want the bare name back", name, got)
	}
}

func TestUnixSystemBinaryResolvesKnownBinary(t *testing.T) {
	found := ""
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		p := filepath.Join(dir, "sh")
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			found = p
			break
		}
	}
	if found == "" {
		t.Skip("sh not found in any standard system directory")
	}
	if got := unixSystemBinary("sh"); got != found {
		t.Errorf("unixSystemBinary(sh) = %q, want %q", got, found)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}