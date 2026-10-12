// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
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

// A SECOND THING LANDLOCK SEPARATES OUT, and it is not about files at all.
//
// ABI 5 split `ioctl` on device files into its own right, and go-landlock
// leaves it out of RWDirs and RWFiles on purpose: you ask for it by name or
// you do not get it. We did not ask, so inside the sandbox every ioctl on
// /dev/pts/N failed with EACCES, and an agent is a full-screen terminal
// program: it could not read the window size, could not put the terminal in
// raw mode, and crashed the moment the window was resized or the mouse moved.
// Mouse reports arrived as literal text in its input box.
//
// So every rule carries WithIoctlDev. This gives nothing away. The right
// governs ioctl on character and block devices; it has no bearing on reading
// or deleting the file somebody asked us to protect, which is the whole of
// what this sandbox is for. BestEffort strips it below ABI 5, where the right
// does not exist and ioctl was never restricted in the first place.

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

	// THE ABI IS PROBED RATHER THAN ASSUMED, and this is a correctness fix as
	// much as a feature. BestEffort().RestrictPaths returns nil on a kernel with
	// no Landlock at all, the library's own documented behaviour, and this
	// function used to set Enforced = true unconditionally after it. On a 5.12
	// kernel, WSL1, or a distribution that leaves landlock out of CONFIG_LSM,
	// `solongate run` printed its banner, reported "Landlock", and ran the agent
	// with nothing applied. The one case other.go says must never happen.
	//
	// It matters more in workspace mode than it ever did for a deny list. A
	// denylist that silently does nothing loses the files somebody named; an
	// allowlist that silently does nothing hands over the whole machine while
	// reporting that it did not.
	abi, abiErr := llsys.LandlockGetABIVersion()
	if abiErr != nil || abi < 1 {
		rep.Mechanism = ""
		rep.Err = errors.New("this kernel has no Landlock (ABI " + strconv.Itoa(abi) +
			"), so nothing can be confined; 5.13 or newer with landlock in CONFIG_LSM is required")
		return rep, rep.Err
	}

	var rules []landlock.Rule
	var walked []string
	var err error
	if p.Allowlist() {
		rules, err = workspaceRules(p)
	} else {
		rules, walked, err = allowRules(p.Deny)
	}
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
	rep.ABI = abi

	if p.Allowlist() {
		rep.Notes = append(rep.Notes,
			"writable: "+p.Workspace,
			"writable outside it: "+strings.Join(p.RuntimeWrite, " "),
			"readable, never writable: "+strings.Join(p.RuntimeRead, " "),
			"everything else does not exist to the agent, including $HOME itself,",
			"so ~/.ssh, ~/.aws, ~/.gnupg and every other project are unreachable")
		if abi < 3 {
			rep.Notes = append(rep.Notes,
				"ABI "+strconv.Itoa(abi)+": this kernel cannot restrict truncate(), so a file",
				"the agent can read it can also shorten to nothing. ABI 3 (kernel 6.2) fixes it")
		}
	}

	if len(walked) > 0 {
		rep.Notes = append(rep.Notes,
			"these directories are listable: "+strings.Join(walked, " "),
			"nothing in them can be deleted, and a file created in one cannot then",
			"be written, granting that would grant it on the protected file too.",
			"`solongate sandbox` has none of these costs; see its --explain")
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
		return []landlock.Rule{landlock.RWDirs("/").WithRefer().WithIoctlDev()}, nil, nil
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

	// THE WALKED DIRECTORY ITSELF GETS A RULE, and it did not before.
	//
	// Only its children were granted, so the directory had no rights of its own
	// and `ls /home/you` and `mkdir /home/you/anything` were refused for as long
	// as the agent ran. Measured and then written in the README as though it
	// worked. Protecting one file in a home directory made the home directory
	// unusable, which is not a trade anybody agreed to.
	//
	// What it gets is listing and creating, and NOT removing. The remove bits
	// are the ones that matter here: REMOVE_FILE on a parent is exactly what
	// `rm` needs to delete the child, so granting them would hand over the file
	// this whole layer exists to keep. The denied child still has no rule of its
	// own, so it cannot be opened, read, written or truncated either, the
	// directory being listable does not make its contents reachable.
	//
	// EXECUTE IS NOT GRANTED EITHER, for a smaller reason: a directory does not
	// need it and including it would let a file created here be run, which is
	// one of the routes the string-matching layers cannot see.
	//
	// WHAT THIS STILL CANNOT DO, and it is a limit of the model rather than of
	// this list: a file CREATED in a walked directory cannot then be written.
	// Creating needs MAKE_REG on the directory, which is granted; writing needs
	// WRITE_FILE on the new file, which has no rule of its own, and the only
	// way to give it one is to grant WRITE_FILE on the directory, which Landlock
	// applies to everything beneath it INCLUDING the protected child. So the
	// choice is "list and create but not author" or "read and write everything,
	// protected file included", and the first is the one that keeps the promise.
	//
	// `solongate sandbox` does not have this shape at all: an allow-list grants
	// the project read-write as one rule and never walks an ancestor.
	const walkedAccess = landlock.AccessFSSet(llsys.AccessFSReadDir |
		llsys.AccessFSMakeDir | llsys.AccessFSMakeReg |
		llsys.AccessFSMakeSym | llsys.AccessFSMakeFifo |
		llsys.AccessFSMakeSock)

	var rules []landlock.Rule
	var walked []string
	for dir := range onPath {
		walked = append(walked, dir)
		rules = append(rules, landlock.PathAccess(walkedAccess, dir).IgnoreIfMissing())
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
				rules = append(rules, landlock.RWDirs(child).WithRefer().WithIoctlDev().IgnoreIfMissing())
			} else {
				rules = append(rules, landlock.RWFiles(child).WithIoctlDev().IgnoreIfMissing())
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

// workspaceRules is the allowlist, and it is the simple direction for Landlock.
//
// Landlock has no deny rule, which made the denylist above an enumeration of
// everything on the way to each protected path. An allowlist is what the kernel
// interface actually is, so this is three grants and nothing else: the
// workspace read-write, the runtime-write set read-write, the runtime-read set
// read-only. Anything not named gets no rule, and with no rule there is no
// handle, open() returns EACCES whether the agent spells the path, globs it,
// assembles it at runtime or compiles a program to call unlink on it.
//
// NO ANCESTOR WALK, and so none of the denylist's cost: a file created after
// launch inside the workspace is reachable immediately, because the grant is on
// the directory rather than on the children that existed when it started.
//
// IgnoreIfMissing throughout. The runtime sets are written for a range of
// distributions, /lib64 does not exist on some, ~/.codex only after that
// client is installed, and Landlock rejects a rule naming a path that is not
// there, which would turn an absent optional directory into a refusal to start.
func workspaceRules(p Plan) ([]landlock.Rule, error) {
	ws := filepath.Clean(p.Workspace)
	if !filepath.IsAbs(ws) {
		return nil, errors.New("workspace must be an absolute path, got " + p.Workspace)
	}
	if ws == "/" {
		return nil, errors.New(`refusing to use "/" as a workspace: that confines nothing`)
	}
	// A workspace of $HOME would put ~/.ssh back inside the sandbox and quietly
	// undo the entire point, so it is refused rather than honoured.
	if home, err := os.UserHomeDir(); err == nil && filepath.Clean(home) == ws {
		return nil, errors.New("refusing to use the home directory as a workspace: " +
			"it contains ~/.ssh and every other project, which is what this mode exists to keep out")
	}
	st, err := os.Stat(ws)
	if err != nil {
		return nil, errors.New("workspace " + ws + " cannot be read: " + err.Error())
	}
	if !st.IsDir() {
		return nil, errors.New("workspace " + ws + " is not a directory")
	}

	rules := []landlock.Rule{
		landlock.RWDirs(ws).WithRefer().WithIoctlDev(),
	}
	// Writable, and stat decides whether it is a directory rule or a file one:
	// the kernel rejects a directory right applied to a file, so /dev/null and
	// ~/.cache cannot share a rule shape.
	for _, d := range append(p.RuntimeWrite, DefaultRuntimeDevices()...) {
		if d == "" {
			continue
		}
		st, err := os.Stat(d)
		if err != nil {
			continue // absent is skipped; IgnoreIfMissing cannot fix a wrong KIND
		}
		if st.IsDir() {
			rules = append(rules, landlock.RWDirs(d).WithRefer().WithIoctlDev().IgnoreIfMissing())
		} else {
			rules = append(rules, landlock.RWFiles(d).WithIoctlDev().IgnoreIfMissing())
		}
	}
	for _, d := range p.RuntimeRead {
		if d == "" {
			continue
		}
		// Directory and file rights are different sets and the kernel rejects a
		// directory right applied to a file, so /dev/null and /usr cannot share
		// a rule. Stat decides which; a missing path is skipped rather than
		// guessed at, since IgnoreIfMissing cannot save a wrong KIND of rule.
		st, err := os.Stat(d)
		if err != nil {
			continue
		}
		if st.IsDir() {
			rules = append(rules, landlock.RODirs(d).WithIoctlDev().IgnoreIfMissing())
		} else {
			rules = append(rules, landlock.ROFiles(d).WithIoctlDev().IgnoreIfMissing())
		}
	}
	return rules, nil
}
