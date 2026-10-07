// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// EVERY INSTALLED HOOK RUNS FROM THE DIRECTORY IT WAS INSTALLED INTO.
//
// A hook is copied into ~/.solongate/hooks as a LONE FILE, and it runs from an arbitrary
// working directory with no node_modules anywhere near it. So anything a hook imports has
// to be copied beside it, and the list of files the installer copies is the only thing
// that makes that true.
//
// Nothing tested it. The conformance suite runs the hooks from the CHECKOUT, where every
// sibling is present because the repository has them — so a hook could import a file the
// installer does not copy, pass every test, and fail on the first tool call of a real
// install with a module-resolution error. The guard's exit code on a crash is not 2, and
// every client reads a non-2 exit as "allowed": the failure mode is an unguarded machine,
// reported as nothing at all.
//
// This runs each installed hook as a subprocess, the way a client does, and fails on the
// one error that means "the installer left something behind".
func TestEveryInstalledHookCanActuallyRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the launcher and the shim differ on Windows; the POSIX layout is the one this checks")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH")
	}

	home := sandbox(t)
	haveHookSources(t)
	if r := Install(); !r.OK {
		t.Fatalf("install failed: %+v", r)
	}

	hooksDir := filepath.Join(home, ".solongate", "hooks")

	// The PostToolUse payload shape, which is the least a hook needs to get past its own
	// argument handling and into whatever it imports.
	const payload = `{"hook_event_name":"PostToolUse","session_id":"s","cwd":"/tmp",` +
		`"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"tool_response":{"stdout":"hi"}}`

	// shield.mjs is not in this list: it WRAPS a command and only returns when the
	// wrapped process does, so running it bare would hang rather than answer. Its imports
	// are covered by the same copy list, and test/shield-config.mjs drives its reader
	// directly.
	for _, name := range []string{GuardHookName, auditHookName, stopHookName, tokensHookName} {
		path := filepath.Join(hooksDir, name)
		if !Exists(path) {
			t.Errorf("%s was not installed", name)
			continue
		}

		cmd := exec.Command(node, path, "claude-code", "Claude Code")
		cmd.Stdin = strings.NewReader(payload)
		cmd.Env = append(os.Environ(), "HOME="+home, "SOLONGATE_NO_GO_GUARD=1")
		out, err := combinedWithTimeout(cmd, 20*time.Second)

		// The exit CODE is not what this checks — a guard that blocks exits 2, and that is
		// a correct answer. What it checks is that the process got far enough to answer at
		// all, rather than dying on an import.
		text := string(out)
		for _, fatal := range []string{
			"ERR_MODULE_NOT_FOUND",
			"Cannot find module",
			"Cannot find package",
			"SyntaxError",
			"ReferenceError",
		} {
			if strings.Contains(text, fatal) {
				t.Errorf("%s cannot run from its installed directory (%s):\n%s", name, fatal, text)
			}
		}
		if err != nil && strings.Contains(err.Error(), "timed out") {
			t.Errorf("%s hung when run from its installed directory", name)
		}
	}
}

// combinedWithTimeout runs a command and returns its combined output, killing it if it
// outlives the deadline — a hook that hangs is as broken as one that crashes, and a test
// that waits forever for it is worse than either.
func combinedWithTimeout(cmd *exec.Cmd, d time.Duration) ([]byte, error) {
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return []byte(buf.String()), err
	case <-time.After(d):
		_ = cmd.Process.Kill()
		<-done
		return []byte(buf.String()), errTimedOut
	}
}

var errTimedOut = timeoutError{}

type timeoutError struct{}

func (timeoutError) Error() string { return "timed out" }
