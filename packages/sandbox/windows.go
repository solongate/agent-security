// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build windows

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func Launch(p Plan, argv []string, env []string) (Report, error) {
	rep := Report{Mechanism: "icacls deny (per run)"}

	if p.Allowlist() {
		rep.Mechanism = ""
		rep.Err = errors.New("workspace confinement is not implemented on Windows: " +
			"it needs a restricted token with a default-deny ACL, not the per-path deny this uses. " +
			"Use `solongate policy protect` for the paths that matter, which applies a permanent lock " +
			"independent of how the agent was started")
		return rep, rep.Err
	}
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
		rep.Notes = append(rep.Notes, "not every path could be denied; `solongate policy protect list` says which")
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

			rep.Err = nil
			return rep, ee
		}
		rep.Err = err
	}
	return rep, err
}

func icacls(path string, args ...string) error {
	full := append([]string{path}, args...)
	cmd := exec.Command(systemBinary("icacls"), full...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return errors.New("icacls: " + strings.TrimSpace(out.String()))
	}
	return nil
}

func Preview(p Plan) []string {
	if len(p.Deny) == 0 {
		return nil
	}
	return []string{
		"the deny ACEs go on for the lifetime of this run and come off when it",
		"ends, so an agent killed with the machine may leave them behind;",
		"`solongate policy protect list` shows what is actually on each path",
	}
}

func Describe() (string, []string) {
	return "icacls deny (per run)", []string{
		"weaker than the Landlock and Seatbelt paths: per-path rather than",
		"default-deny, and written rather than verified on a real Windows machine",
		"the permanent lock from `solongate policy protect` is the stronger one here",
	}
}

// systemBinary resolves a Windows system utility to its fixed, unwriteable
// System32 location instead of trusting a PATH lookup, falling back to the
// bare name only if that location doesn't exist on this machine.
func systemBinary(name string) string {
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