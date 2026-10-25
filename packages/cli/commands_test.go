// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/solongate/agent-security/packages/core/client"
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

func TestHandlersReturnsExpectedCommands(t *testing.T) {
	want := []string{"policy", "ratelimit", "dlp", "stats", "audit", "doctor", "trace", "watch", "range"}

	h := handlers()
	if len(h) != len(want) {
		t.Fatalf("handlers() returned %d entries, want %d: %v", len(h), len(want), h)
	}
	for _, name := range want {
		fn, ok := h[name]
		if !ok {
			t.Errorf("handlers() is missing %q", name)
			continue
		}
		if fn == nil {
			t.Errorf("handlers()[%q] is nil", name)
		}
	}
}

func TestRunUnknownCommand(t *testing.T) {
	newHome(t)

	var code int
	out := captureStderr(t, func() {
		code = Run("not-a-real-command", nil)
	})

	if code != 1 {
		t.Errorf("Run(unknown) code=%d, want 1", code)
	}
	if !strings.Contains(out, "Unknown command") {
		t.Errorf("Run(unknown) output=%q, want it to mention Unknown command", out)
	}
	if !strings.Contains(out, "not-a-real-command") {
		t.Errorf("Run(unknown) output=%q, want it to name the command", out)
	}
}

func TestRunDoctorHelpSucceeds(t *testing.T) {
	newHome(t)

	var code int
	captureStderr(t, func() {
		code = Run("doctor", []string{"help"})
	})

	if code != 0 {
		t.Errorf("Run(doctor help) code=%d, want 0", code)
	}
}

func TestRunRangeShowSucceeds(t *testing.T) {
	newHome(t)

	var code int
	out := captureStderr(t, func() {
		code = Run("range", nil)
	})

	if code != 0 {
		t.Errorf("Run(range) code=%d, want 0, output=%q", code, out)
	}
}

func TestRunPolicyShowNonexistentSurfacesError(t *testing.T) {
	newHome(t)

	var code int
	out := captureStderr(t, func() {
		code = Run("policy", []string{"show", "nonexistent-id"})
	})

	if code != 1 {
		t.Errorf("Run(policy show nonexistent-id) code=%d, want 1, output=%q", code, out)
	}
	if !strings.Contains(out, "this machine has no policy") {
		t.Errorf("Run(policy show nonexistent-id) output=%q, want it to mention the machine has no policy", out)
	}
}

func TestRunnerDelegatesToRun(t *testing.T) {
	newHome(t)

	var runnerCode, runCode int
	captureStderr(t, func() {
		runnerCode = Runner("doctor")([]string{"help"})
	})
	captureStderr(t, func() {
		runCode = Run("doctor", []string{"help"})
	})
	if runnerCode != runCode {
		t.Errorf("Runner(doctor)([help])=%d, Run(doctor,[help])=%d, want equal", runnerCode, runCode)
	}

	captureStderr(t, func() {
		runnerCode = Runner("bogus")(nil)
	})
	captureStderr(t, func() {
		runCode = Run("bogus", nil)
	})
	if runnerCode != runCode {
		t.Errorf("Runner(bogus)(nil)=%d, Run(bogus,nil)=%d, want equal", runnerCode, runCode)
	}
}

func TestReport(t *testing.T) {
	t.Run("context canceled", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", context.Canceled)
		if got := report(err); got != 130 {
			t.Errorf("report(context.Canceled) = %d, want 130", got)
		}
	})

	t.Run("client error", func(t *testing.T) {
		ae := &client.Error{Message: "boom", Status: 404}
		var code int
		out := captureStderr(t, func() {
			code = report(ae)
		})
		if code != 1 {
			t.Errorf("report(*client.Error) = %d, want 1", code)
		}
		if !strings.Contains(out, "boom") {
			t.Errorf("report(*client.Error) output=%q, want it to contain the message", out)
		}
		if !strings.Contains(out, "404") {
			t.Errorf("report(*client.Error) output=%q, want it to contain the status", out)
		}
	})

	t.Run("plain error", func(t *testing.T) {
		err := errors.New("plain failure")
		var code int
		out := captureStderr(t, func() {
			code = report(err)
		})
		if code != 1 {
			t.Errorf("report(plain error) = %d, want 1", code)
		}
		if !strings.Contains(out, "plain failure") {
			t.Errorf("report(plain error) output=%q, want it to contain the message", out)
		}
	})
}

func TestEsc(t *testing.T) {
	cases := []string{"a b", "a/b", "plain", ""}
	for _, s := range cases {
		if got, want := esc(s), url.PathEscape(s); got != want {
			t.Errorf("esc(%q) = %q, want %q", s, got, want)
		}
	}
}