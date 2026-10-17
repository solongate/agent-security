// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSandboxMarkerRoundTrips(t *testing.T) {

	if got := SandboxMarker(SandboxModeRun, "1.2.3"); got != "run:1.2.3" {
		t.Errorf("SandboxMarker=%q, want run:1.2.3", got)
	}
	t.Setenv(SandboxEnv, SandboxMarker(SandboxModeBox, "1.2.3"))
	if got := SandboxMode(); got != SandboxModeBox {
		t.Errorf("SandboxMode=%q, want %q", got, SandboxModeBox)
	}
}

func TestSandboxModeReadsTheWeakerModeWhenItCannotTell(t *testing.T) {
	cases := []struct{ env, want string }{
		{"", ""},
		{"run:1.0.0", SandboxModeRun},
		{"box:1.0.0", SandboxModeBox},

		{"1.0.0", SandboxModeRun},
		{"run", SandboxModeRun},

		{"anything-at-all", SandboxModeRun},
	}
	for _, c := range cases {
		if c.env == "" {
			t.Setenv(SandboxEnv, "x")
			os.Unsetenv(SandboxEnv)
		} else {
			t.Setenv(SandboxEnv, c.env)
		}
		if got := SandboxMode(); got != c.want {
			t.Errorf("with %s=%q, SandboxMode()=%q, want %q", SandboxEnv, c.env, got, c.want)
		}
	}
}

func TestInSandboxIsTheUnverifiedAnswer(t *testing.T) {

	t.Setenv(SandboxEnv, "run:0.0.0-forged")
	if !InSandbox() {
		t.Error("InSandbox ignored a marker that is present")
	}
	confined, _ := VerifiedInSandbox(nil)
	if confined {
		t.Error("VerifiedInSandbox agreed with a forged marker with nothing to probe")
	}
}

func TestVerifiedInSandboxWithNoMarker(t *testing.T) {
	t.Setenv(SandboxEnv, "x")
	os.Unsetenv(SandboxEnv)

	confined, conclusive := VerifiedInSandbox([]string{"/etc/hosts"})
	if confined {
		t.Error("a process with no marker was reported as confined")
	}
	if !conclusive {
		t.Error("the absence of a marker is a conclusive answer and was reported as inconclusive")
	}
}

func TestVerifiedInSandboxCatchesAForgedRunMarker(t *testing.T) {
	dir := t.TempDir()
	readable := filepath.Join(dir, "protected.txt")
	if err := os.WriteFile(readable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SandboxEnv, SandboxMarker(SandboxModeRun, "9.9.9"))

	confined, conclusive := VerifiedInSandbox([]string{readable})
	if confined {
		t.Error("a protected path opened for reading and the probe still said confined")
	}
	if !conclusive {
		t.Error("a successful read is proof; it must be conclusive")
	}
}

func TestVerifiedInSandboxIsInconclusiveWithNothingToProbe(t *testing.T) {
	t.Setenv(SandboxEnv, SandboxMarker(SandboxModeRun, "1.0.0"))

	for _, paths := range [][]string{
		nil,
		{},
		{"", "   "},
		{filepath.Join(t.TempDir(), "never-created")},
	} {
		confined, conclusive := VerifiedInSandbox(paths)
		if confined {
			t.Errorf("with %v to probe, the probe claimed confinement", paths)
		}
		if conclusive {
			t.Errorf("with %v to probe, there is nothing to learn and it claimed to know", paths)
		}
	}
}

func TestVerifiedInSandboxAcceptsAnUnreadablePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not deny the owner on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file, so there is nothing to deny here")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(locked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

	t.Setenv(SandboxEnv, SandboxMarker(SandboxModeRun, "1.0.0"))
	confined, conclusive := VerifiedInSandbox([]string{locked})
	if !confined || !conclusive {
		t.Errorf("an unreadable protected path gave confined=%v conclusive=%v, want true true", confined, conclusive)
	}
}

func TestVerifiedInSandboxStopsAtTheFirstPathThatAnswers(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "not-there")
	readable := filepath.Join(dir, "readable.txt")
	if err := os.WriteFile(readable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SandboxEnv, SandboxMarker(SandboxModeRun, "1.0.0"))

	confined, conclusive := VerifiedInSandbox([]string{missing, readable})
	if confined || !conclusive {
		t.Errorf("got confined=%v conclusive=%v, want false true: the readable path proves it", confined, conclusive)
	}
}

func TestVerifiedInSandboxBoxProbeReadsPidOne(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("there is no /proc/1/comm to read")
	}
	b, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		t.Skip("no /proc on this machine")
	}
	t.Setenv(SandboxEnv, SandboxMarker(SandboxModeBox, "1.0.0"))

	confined, conclusive := VerifiedInSandbox(nil)
	init := string(b)
	hostInit := init == "systemd\n" || init == "init\n" || init == "launchd\n"
	if hostInit {

		if confined || !conclusive {
			t.Errorf("PID 1 is %q, so no box was built; got confined=%v conclusive=%v", init, confined, conclusive)
		}
		return
	}

	if !confined {
		t.Errorf("PID 1 is %q, which is not a host init, so the probe should accept it", init)
	}
}