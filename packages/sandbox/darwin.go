// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build darwin

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func Launch(p Plan, argv []string, env []string) (Report, error) {
	rep := Report{Mechanism: "Seatbelt"}
	if len(argv) == 0 {
		rep.Err = errors.New("nothing to run")
		return rep, rep.Err
	}

	exe, err := exec.LookPath("sandbox-exec")
	if err != nil {
		rep.Err = errors.New("sandbox-exec is not on PATH, so nothing was confined")
		return rep, rep.Err
	}

	var profile string
	if p.Allowlist() {
		profile, err = seatbeltWorkspaceProfile(p)
		if err != nil {
			rep.Err = err
			return rep, err
		}
		rep.Notes = append(rep.Notes,
			"writable: "+p.Workspace,
			"writable outside it: "+strings.Join(p.RuntimeWrite, " "),
			"readable, never writable: "+strings.Join(p.RuntimeRead, " "),
			"everything else is denied by default, including $HOME itself,",
			"so ~/.ssh, ~/.aws and every other project are unreachable")
	} else {
		var denied []string
		profile, denied = seatbeltProfile(p.Deny)
		if len(denied) == 0 {
			rep.Notes = append(rep.Notes, "nothing to deny, so the profile only blocks nothing")
		}
	}
	rep.Enforced = true

	if os.Getenv("SG_DEBUG_PROFILE") != "" {
		os.Stderr.WriteString("--- SG_DEBUG_PROFILE ---\n" + profile + "--- end profile ---\n")
	}

	full := append([]string{"sandbox-exec", "-p", profile, "--"}, argv...)
	err = syscall.Exec(exe, full, env)
	rep.Err = err
	return rep, err
}

func Preview(p Plan) []string {
	_, got := seatbeltProfile(p.Deny)
	if len(got) == len(p.Deny) {
		return nil
	}
	return []string{"one or more paths do not exist and were not written into the profile"}
}

func Describe() (string, []string) {
	notes := []string{
		"a real deny rule, so a file created after launch behaves normally",
		"inherited by every process the agent starts",
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		notes = append(notes, "sandbox-exec is NOT on PATH on this machine")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err == nil {
		notes = append(notes, "deprecated by Apple, with no removal date announced")
	}
	return "Seatbelt", notes
}