// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// THE TEST FOR A FAIL-CLOSED SWITCH IS THAT IT FAILS CLOSED.
//
// VerifiedInSandbox returns two booleans and the second one is the whole point.
// A caller that reads only the first gets "false" for both "I checked and it is
// not confined" and "I could not check", which are different sentences. The bug
// this replaced read the environment variable alone, so an agent that exported
// SOLONGATE_SANDBOX was not confined and was not refused either: one line in a
// shell profile and require-sandbox fails open.
//
// So these cases are written from the attacker's side. Every one of them is an
// agent setting a variable it can set, and the assertion is that doing so wins
// it nothing.

func TestSandboxMarkerRoundTrips(t *testing.T) {
	// Mode and version travel in one variable because a machine running two
	// builds has to be able to tell which one a call came through.
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
		// A marker from an older build that wrote only a version. It must read
		// as `run`, the weaker of the two: `box` is verified against /proc/1 and
		// `run` against a protected path, and guessing the stronger mode would
		// verify the wrong fact.
		{"1.0.0", SandboxModeRun},
		{"run", SandboxModeRun},
		// Something an agent made up. It is not `box`, which is all that
		// matters: the default branch probes the filesystem.
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
	// It reports the claim and nothing else. Two callers want exactly that and
	// neither refuses a call on it; this pins the difference so a future caller
	// has to choose deliberately rather than pick the shorter name.
	t.Setenv(SandboxEnv, "run:0.0.0-forged")
	if !InSandbox() {
		t.Error("InSandbox ignored a marker that is present")
	}
	confined, _ := VerifiedInSandbox(nil)
	if confined {
		t.Error("VerifiedInSandbox agreed with a forged marker with nothing to probe")
	}
}

// NO MARKER IS A CONCLUSIVE NO.
//
// Both launchers set it, so its absence means neither ran. This has to be
// conclusive or require-sandbox would refuse every call on an ordinary machine
// and the switch would be unusable rather than strict.
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

// A FORGED MARKER WITH A READABLE PROTECTED PATH IS CAUGHT.
//
// This is the attack. The agent exports the variable; the probe opens a path
// somebody protected; it opens, so nothing is standing between this process and
// that file, so the marker is a lie and the answer is a conclusive no.
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

// NOTHING TO PROBE AGAINST IS INCONCLUSIVE, NOT A YES.
//
// `run` with no protected paths, or with paths that are not on disk, has no
// fact to check. The caller fails closed on this, which is require-sandbox
// doing what its name says rather than guessing.
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

// AN UNREADABLE PATH IS THE ONLY YES THIS PROBE GIVES.
//
// And it is a yes only in combination with the marker: the path's own
// permissions could produce the same EACCES. That is stated in the source and
// pinned here, because it is the one place the answer rests on something an
// agent could arrange rather than on something it could not.
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

// THE FIRST ANSWERABLE PATH DECIDES, which means a readable one anywhere in the
// list is a no even when a later one would have said yes. That ordering is the
// safe one: it takes a single opened file to prove the confinement is off.
func TestVerifiedInSandboxStopsAtTheFirstPathThatAnswers(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "not-there")
	readable := filepath.Join(dir, "readable.txt")
	if err := os.WriteFile(readable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(SandboxEnv, SandboxMarker(SandboxModeRun, "1.0.0"))

	// The missing path is skipped rather than ending the walk, or a protected
	// path that happens not to exist would hide every path after it.
	confined, conclusive := VerifiedInSandbox([]string{missing, readable})
	if confined || !conclusive {
		t.Errorf("got confined=%v conclusive=%v, want false true: the readable path proves it", confined, conclusive)
	}
}

// THE BOX PROBE ASKS WHO PID 1 IS.
//
// A mount namespace gives the process its own /proc, in which PID 1 is bwrap
// rather than the host's systemd. On a host, PID 1 is the host's init, and a
// `box` marker on a host is therefore a forged one.
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
		// The test machine is a host, so this is the forged case and the probe
		// must catch it. Note that it does so WITHOUT any protected path: the
		// box answer does not depend on the caller passing anything.
		if confined || !conclusive {
			t.Errorf("PID 1 is %q, so no box was built; got confined=%v conclusive=%v", init, confined, conclusive)
		}
		return
	}
	// Already inside something: a container, a namespace, a CI runner. The
	// probe cannot distinguish our box from any other namespace, which is
	// stated rather than hidden: a namespace an agent built for itself grants
	// it nothing it did not already have.
	if !confined {
		t.Errorf("PID 1 is %q, which is not a host init, so the probe should accept it", init)
	}
}