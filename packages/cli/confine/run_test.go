// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package confine

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/solongate/agent-security/packages/sandbox"
)

// newHome isolates the local-file client store behind a throwaway $HOME so
// tests never touch the real machine's SolonGate state.
func newHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// captureStderr redirects the process's real stderr file descriptor for the
// duration of fn and returns what was written. cliutil.Errln writes through
// an unexported io.Writer that was bound to os.Stderr at package init, so
// merely reassigning the os.Stderr variable does not intercept it; the
// underlying fd must be swapped instead.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origFd, err := syscall.Dup(int(os.Stderr.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(int(w.Fd()), int(os.Stderr.Fd())); err != nil {
		t.Fatal(err)
	}

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(origFd, int(os.Stderr.Fd())); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(origFd); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestRunUsage(t *testing.T) {
	u := runUsage()
	if !strings.Contains(u, "solongate run") {
		t.Errorf("runUsage() should mention solongate run, got: %s", u)
	}
	if !strings.Contains(u, "--explain") {
		t.Errorf("runUsage() should mention --explain, got: %s", u)
	}
}

func TestRunAgentEmptyArgvShowsUsage(t *testing.T) {
	var code int
	out := captureStderr(t, func() {
		code = RunAgent(nil)
	})
	if code != 1 {
		t.Errorf("RunAgent(nil) = %d, want 1", code)
	}
	if !strings.Contains(out, "solongate run") {
		t.Errorf("RunAgent(nil) output=%q, want usage mentioning solongate run", out)
	}
}

func TestRunAgentExplainDelegatesWithoutLaunching(t *testing.T) {
	for _, arg := range []string{"--explain", "explain"} {
		t.Run(arg, func(t *testing.T) {
			newHome(t)
			var code int
			out := captureStderr(t, func() {
				code = RunAgent([]string{arg})
			})
			if code != 0 {
				t.Errorf("RunAgent([%q]) = %d, want 0, output=%q", arg, code, out)
			}
			if out == "" {
				t.Errorf("RunAgent([%q]) produced no output", arg)
			}
		})
	}
}

func TestPrintBannerUnconfinedPrintsNothing(t *testing.T) {
	out := captureStderr(t, func() {
		printBanner("Landlock", sandbox.Plan{})
	})
	if out != "" {
		t.Errorf("printBanner(unconfined) output=%q, want empty", out)
	}
}

func TestPrintBannerAllowlist(t *testing.T) {
	plan := sandbox.Plan{Workspace: "/some/workspace"}
	out := captureStderr(t, func() {
		printBanner("Landlock", plan)
	})
	if !strings.Contains(out, "workspace only") {
		t.Errorf("printBanner(allowlist) output=%q, want it to mention workspace only", out)
	}
	if !strings.Contains(out, "/some/workspace") {
		t.Errorf("printBanner(allowlist) output=%q, want it to mention the workspace path", out)
	}
	if !strings.Contains(out, "Landlock") {
		t.Errorf("printBanner(allowlist) output=%q, want it to mention the mechanism", out)
	}
}

func TestPrintBannerDenylist(t *testing.T) {
	plan := sandbox.Plan{Deny: []string{"/etc/does-not-exist-secret", "/home/does-not-exist/.ssh"}}
	out := captureStderr(t, func() {
		printBanner("Landlock", plan)
	})
	if !strings.Contains(out, "Landlock") {
		t.Errorf("printBanner(denylist) output=%q, want it to mention the mechanism", out)
	}
	if !strings.Contains(out, "out of reach") {
		t.Errorf("printBanner(denylist) output=%q, want it to mention paths out of reach", out)
	}
	for _, d := range plan.Deny {
		if !strings.Contains(out, d) {
			t.Errorf("printBanner(denylist) output=%q, want it to list %q", out, d)
		}
	}
}

func TestHomeDirMatchesUserHomeDir(t *testing.T) {
	want, err := os.UserHomeDir()
	got := homeDir()
	if err != nil {
		if got != "" {
			t.Errorf("homeDir() = %q, want empty string when os.UserHomeDir errors", got)
		}
		return
	}
	if got != want {
		t.Errorf("homeDir() = %q, want %q", got, want)
	}
}

func TestExplainSandboxReturnsZero(t *testing.T) {
	newHome(t)

	mech, _ := sandbox.Describe()
	var code int
	out := captureStderr(t, func() {
		code = explainSandbox()
	})
	if code != 0 {
		t.Errorf("explainSandbox() = %d, want 0", code)
	}
	if mech == "" {
		if !strings.Contains(out, "No OS-level confinement") {
			t.Errorf("explainSandbox() output=%q, want it to mention no confinement", out)
		}
	} else if !strings.Contains(out, mech) {
		t.Errorf("explainSandbox() output=%q, want it to mention mechanism %q", out, mech)
	}
}

func TestIndexOf(t *testing.T) {
	cases := []struct {
		name string
		ss   []string
		want string
		idx  int
	}{
		{"found first", []string{"a", "b", "c"}, "a", 0},
		{"found middle", []string{"a", "b", "c"}, "b", 1},
		{"found last", []string{"a", "b", "c"}, "c", 2},
		{"not found", []string{"a", "b", "c"}, "z", -1},
		{"empty slice", nil, "a", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := indexOf(tc.ss, tc.want); got != tc.idx {
				t.Errorf("indexOf(%v, %q) = %d, want %d", tc.ss, tc.want, got, tc.idx)
			}
		})
	}
}

func TestExitCodeOf(t *testing.T) {
	t.Run("real exit error", func(t *testing.T) {
		err := exec.Command("sh", "-c", "exit 3").Run()
		if err == nil {
			t.Fatal("expected sh -c 'exit 3' to fail")
		}
		code, ok := exitCodeOf(err)
		if !ok {
			t.Fatalf("exitCodeOf(%v) ok=false, want true", err)
		}
		if code != 3 {
			t.Errorf("exitCodeOf(%v) = %d, want 3", err, code)
		}
	})

	t.Run("non exit error", func(t *testing.T) {
		code, ok := exitCodeOf(errors.New("not an exit error"))
		if ok {
			t.Errorf("exitCodeOf(plain error) ok=true, want false")
		}
		if code != 0 {
			t.Errorf("exitCodeOf(plain error) = %d, want 0", code)
		}
	})
}

func TestBuildTag(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		t.Setenv("SOLONGATE_VERSION", "  2.3.4  ")
		if got := buildTag(); got != "2.3.4" {
			t.Errorf("buildTag() = %q, want %q", got, "2.3.4")
		}
	})

	t.Run("unset", func(t *testing.T) {
		t.Setenv("SOLONGATE_VERSION", "")
		if got := buildTag(); got != "1" {
			t.Errorf("buildTag() = %q, want %q", got, "1")
		}
	})
}