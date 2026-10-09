// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// macOS confinement is Seatbelt, through sandbox-exec.
//
// DEPRECATED AND STILL THE ONLY OPTION. Apple marked sandbox-exec deprecated
// and has announced no removal date; it remains the one mechanism that applies
// a sandbox to an arbitrary command without App Store enrolment or an Apple
// entitlement, and it is what Bazel, Homebrew and Claude Code's own sandbox
// use today. The warning it prints on stderr is filtered, because it would
// otherwise land in the agent's output on every launch.
//
// Unlike Landlock, Seatbelt HAS a real deny rule and deny wins, so the profile
// is the straightforward one: allow everything, then deny the protected paths.
// That means none of Landlock's enumeration cost applies here: a file created
// after launch behaves normally.
//
// THREE THINGS THAT BREAK A NAIVE PROFILE, all of them handled below:
//
//   - Seatbelt matches CANONICAL paths. A literal that has not been through
//     realpath can be walked around with a symlink, so both forms are denied.
//   - Resolving a path stats every component, so denying a tree without
//     re-allowing file-read-metadata on its ancestors makes paths NEXT TO it
//     unreachable too.
//   - The profile is passed with -p rather than written to a file, so there is
//     no temporary file holding the list of what somebody wanted hidden.

// Launch confines the command and becomes it.
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

	profile, denied := seatbeltProfile(p.Deny)
	if len(denied) == 0 {
		rep.Notes = append(rep.Notes, "nothing to deny, so the profile only blocks nothing")
	}
	rep.Enforced = true

	full := append([]string{"sandbox-exec", "-p", profile, "--"}, argv...)
	err = syscall.Exec(exe, full, env)
	rep.Err = err
	return rep, err
}

// seatbeltProfile writes the SBPL. It returns the profile and the paths that
// made it in, which is not always every path asked for: one that does not
// exist cannot be canonicalised and is reported rather than silently dropped.
func seatbeltProfile(deny []string) (string, []string) {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")

	var got []string
	ancestors := map[string]bool{}

	for _, d := range deny {
		abs, err := filepath.Abs(d)
		if err != nil {
			continue
		}
		abs = filepath.Clean(abs)
		forms := map[string]bool{abs: true}
		// The canonical form as well as the literal one. Seatbelt matches what
		// the kernel resolves, so a symlink to the file is a way past a rule
		// written against the name the user typed.
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			forms[real] = true
		}
		for f := range forms {
			b.WriteString("(deny file-read* (literal " + sbplString(f) + "))\n")
			b.WriteString("(deny file-write* (literal " + sbplString(f) + "))\n")
			b.WriteString("(deny file-read* (subpath " + sbplString(f) + "))\n")
			b.WriteString("(deny file-write* (subpath " + sbplString(f) + "))\n")
			for dir := filepath.Dir(f); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
				ancestors[dir] = true
			}
		}
		got = append(got, abs)
	}

	// Resolving any path stats every directory above it, so the ancestors of a
	// denied path keep their metadata readable. Without this, denying
	// ~/game/game.c makes ~/game/readme.md unreachable as well, and the symptom
	// is an agent that cannot see files nobody protected.
	for dir := range ancestors {
		b.WriteString("(allow file-read-metadata (literal " + sbplString(dir) + "))\n")
	}
	return b.String(), got
}

// sbplString quotes a path for SBPL, which is a Scheme dialect.
func sbplString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Preview is what Launch would cost. Seatbelt has real deny rules, so there
// is no enumeration and no cost to report; the only thing worth saying is
// which paths could not be canonicalised.
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
