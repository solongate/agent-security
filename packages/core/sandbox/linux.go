// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

// Linux confinement is Landlock: unprivileged, inherited by every descendant,
// and impossible for the confined process to remove.
//
// THE ONE THING THAT SHAPES ALL OF THIS: Landlock is an ALLOW-LIST and it has
// no deny rule. A rule on a subdirectory cannot grant fewer rights than its
// parent, so "allow everything except this one file" cannot be written down.
// The kernel patch that would fix it, LANDLOCK_ADD_RULE_NO_INHERIT, is at v7
// on the mailing list and is not upstream.
//
// So the policy is built the way the kernel documentation recommends:
// enumerate what IS allowed. Walk from the root down to each denied path, and
// at every level grant that directory's children except the one leading
// onward. The denied path is simply never granted, and with nothing granting
// it, nothing can open it.
//
// WHAT THAT COSTS, stated rather than discovered: an entry created DIRECTLY in
// one of those walked-through directories after the sandbox starts has no rule
// of its own, so the agent cannot reach it until it is restarted. Entries
// inside a sibling directory are unaffected, because the sibling was granted
// whole. For `/home/me/game/game.c` the walked-through directories are `/`,
// `/home`, `/home/me` and `/home/me/game`, and `solongate run` prints that list
// on the way in.

// Launch confines this process and then becomes the command.
//
// It execs rather than forking. The Landlock domain survives execve, so the
// agent IS this process with the restriction already on it: there is no parent
// left to go wrong, and the exit code is the agent's because it is the same
// process. On success this function does not return.
func Launch(p Plan, argv []string, env []string) (Report, error) {
	rep := Report{Mechanism: "Landlock"}
	if len(argv) == 0 {
		rep.Err = errors.New("nothing to run")
		return rep, rep.Err
	}

	rules, walked, err := allowRules(p.Deny)
	if err != nil {
		rep.Err = err
		return rep, err
	}

	// BestEffort so an older kernel gets the strongest subset it supports
	// rather than an error. Refer is granted because without it Landlock
	// refuses every rename across directories, which breaks ordinary tools in
	// a way that reads as the sandbox being broken.
	cfg := landlock.V5.BestEffort()
	if err := cfg.RestrictPaths(rules...); err != nil {
		rep.Err = err
		return rep, err
	}
	rep.Enforced = true

	if len(walked) > 0 {
		rep.Notes = append(rep.Notes,
			"a file created directly in "+strings.Join(walked, " ")+" from now on",
			"is not reachable by the agent until it restarts")
	}

	// no_new_privs is required by Landlock and the library sets it, but it is
	// also what stops a setuid binary washing the restriction off, so it is
	// asserted here rather than assumed.
	if err := setNoNewPrivs(); err != nil {
		rep.Notes = append(rep.Notes, "could not set no_new_privs: "+err.Error())
	}

	bin, err := exec.LookPath(argv[0])
	if err != nil {
		rep.Err = err
		return rep, err
	}
	err = syscall.Exec(bin, argv, env)
	rep.Err = err
	return rep, err
}

// allowRules turns a deny list into the allow list Landlock needs, and reports
// which directories had to be walked through rather than granted whole.
func allowRules(deny []string) ([]landlock.Rule, []string, error) {
	denied := map[string]bool{}
	for _, d := range deny {
		abs, err := filepath.Abs(d)
		if err != nil {
			return nil, nil, err
		}
		abs = filepath.Clean(abs)
		if abs == "/" {
			return nil, nil, errors.New(`refusing to deny "/": that is not a sandbox, it is a brick`)
		}
		denied[abs] = true
	}
	if len(denied) == 0 {
		// Nothing to deny, but still a real Landlock domain: entering one
		// blocks arbitrary mounts, which is worth having on its own.
		return []landlock.Rule{landlock.RWDirs("/").WithRefer()}, nil, nil
	}

	// Every directory on the way to something denied. These cannot be granted
	// wholesale, because a grant on a parent cannot be narrowed below it.
	onPath := map[string]bool{"/": true}
	for d := range denied {
		for dir := filepath.Dir(d); ; dir = filepath.Dir(dir) {
			onPath[dir] = true
			if dir == "/" {
				break
			}
		}
	}

	var rules []landlock.Rule
	var walked []string
	for dir := range onPath {
		walked = append(walked, dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			// An unreadable directory on the way grants nothing below it, which
			// is the safe direction to fail in.
			continue
		}
		for _, e := range entries {
			child := filepath.Join(dir, e.Name())
			if denied[child] || onPath[child] {
				continue // denied outright, or walked through one level down
			}
			// Directory and file rights are different sets and the kernel
			// rejects a directory right applied to a file, so the two are not
			// interchangeable even though both mean "as before".
			if e.IsDir() {
				rules = append(rules, landlock.RWDirs(child).WithRefer().IgnoreIfMissing())
			} else {
				rules = append(rules, landlock.RWFiles(child).IgnoreIfMissing())
			}
		}
	}
	sort.Strings(walked)
	return rules, walked, nil
}

// setNoNewPrivs is PR_SET_NO_NEW_PRIVS: execve may not grant this process, or
// anything it starts, a privilege it does not already have.
func setNoNewPrivs() error {
	const prSetNoNewPrivs = 38
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// Preview is what Launch would cost, computed before anything is applied.
//
// IT EXISTS BECAUSE Launch EXECS. Report.Notes are filled in after the domain
// is in force and a moment before the process becomes the agent, so nothing
// ever gets to print them. A limit the user is not told about is a limit they
// discover as a bug, so the enumeration runs twice: once to report, once to
// apply. It is one ReadDir per ancestor directory.
func Preview(p Plan) []string {
	_, walked, err := allowRules(p.Deny)
	if err != nil {
		return []string{"could not read the filesystem: " + err.Error()}
	}
	if len(walked) == 0 {
		return nil
	}
	return []string{
		"Landlock has no deny rule, so these directories are granted entry by",
		"entry rather than whole: " + strings.Join(walked, " "),
		"A file created directly in one of them from now on is out of the agent's",
		"reach too, until it restarts. Anything inside a subdirectory is fine.",
	}
}

// Describe says what this platform does, without doing it.
func Describe() (string, []string) {
	return "Landlock", []string{
		"unprivileged, inherited by every process the agent starts, and it cannot",
		"be removed by the confined process",
	}
}
