// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Windows confinement is a DENY ACE for this user on each protected path, put
// on for the lifetime of the child and taken off when it exits.
//
// WHY NOT A RESTRICTED TOKEN, which is the textbook answer. CreateRestrictedToken
// with restricting SIDs gives a genuine default-deny: the access check runs
// twice, and a file whose DACL names none of the restricting SIDs is refused
// without any deny ACE at all. It is also the heavier thing by a wide margin.
// It needs a per-run grant on every path the agent legitimately uses, plus the
// window station and the desktop, or the child fails to start with 0xC0000142
// before it prints anything; and `WRITE_RESTRICTED`, the flag that looks like
// the safe middle, leaves reads unconfined, which is the half that matters
// here. Shipping that untested on a platform I cannot run would be shipping a
// claim rather than a feature.
//
// So this does the thing that is verifiable from its own output: the same
// icacls deny the file lock uses, scoped to the run. It is weaker in one
// specific way and the CLI says so: it is per-path rather than default-deny,
// so it protects what was named and nothing else, and a path added to the list
// while an agent is running is not covered until the agent restarts.
//
// `solongate protect` already puts a PERMANENT lock on these paths with the
// same mechanism, and that one does not depend on how the agent was started.
// On Windows that permanent lock is the stronger of the two.

// Launch applies the deny, runs the command, and lifts the deny afterwards.
//
// It waits rather than execs because Windows has no execve: the deny has to be
// taken off when the child finishes, and that needs somebody still alive to do
// it.
func Launch(p Plan, argv []string, env []string) (Report, error) {
	rep := Report{Mechanism: "icacls deny (per run)"}
	if len(argv) == 0 {
		rep.Err = errors.New("nothing to run")
		return rep, rep.Err
	}

	var applied []string
	for _, d := range p.Deny {
		abs, err := filepath.Abs(d)
		if err != nil {
			continue
		}
		abs = filepath.Clean(abs)
		if _, err := os.Stat(abs); err != nil {
			continue
		}
		if err := icacls(abs, "/deny", `*S-1-1-0:(F)`); err == nil {
			applied = append(applied, abs)
		}
	}
	rep.Enforced = len(applied) > 0 || len(p.Deny) == 0
	if len(applied) < len(p.Deny) {
		rep.Notes = append(rep.Notes, "not every path could be denied; `solongate protect list` says which")
	}
	rep.Notes = append(rep.Notes,
		"per-path rather than default-deny: it covers the protected list and",
		"nothing else, and a path added while this agent runs is not covered")

	defer func() {
		for _, abs := range applied {
			_ = icacls(abs, "/remove:d", `*S-1-1-0`)
		}
	}()

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// The agent's own exit code is not this function's failure.
			rep.Err = nil
			return rep, ee
		}
		rep.Err = err
	}
	return rep, err
}

func icacls(path string, args ...string) error {
	full := append([]string{path}, args...)
	cmd := exec.Command("icacls", full...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return errors.New("icacls: " + strings.TrimSpace(out.String()))
	}
	return nil
}

// Preview is what Launch would cost.
func Preview(p Plan) []string {
	if len(p.Deny) == 0 {
		return nil
	}
	return []string{
		"the deny ACEs go on for the lifetime of this run and come off when it",
		"ends, so an agent killed with the machine may leave them behind;",
		"`solongate protect list` shows what is actually on each path",
	}
}

func Describe() (string, []string) {
	return "icacls deny (per run)", []string{
		"weaker than the Landlock and Seatbelt paths: per-path rather than",
		"default-deny, and written rather than verified on a real Windows machine",
		"the permanent lock from `solongate protect` is the stronger one here",
	}
}
