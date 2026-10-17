// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

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

func Launch(p Plan, argv []string, env []string) (Report, error) {
	rep := Report{Mechanism: "Landlock"}
	if len(argv) == 0 {
		rep.Err = errors.New("nothing to run")
		return rep, rep.Err
	}

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
		rules, walked, _, err = allowRules(p.Deny, p.Immutable)
	}
	if err != nil {
		rep.Err = err
		return rep, err
	}

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

func allowRules(deny, immutable []string) ([]landlock.Rule, []string, []string, error) {
	denied := map[string]bool{}
	for _, d := range deny {
		abs, err := filepath.Abs(d)
		if err != nil {
			return nil, nil, nil, err
		}
		abs = filepath.Clean(abs)
		if abs == "/" {
			return nil, nil, nil, errors.New(`refusing to deny "/": that is not a sandbox, it is a brick`)
		}
		denied[abs] = true
	}
	if len(denied) == 0 {

		return []landlock.Rule{landlock.RWDirs("/").WithRefer().WithIoctlDev()}, nil, nil, nil
	}

	frozen := map[string]bool{}
	for _, d := range immutable {
		abs, err := filepath.Abs(d)
		if err != nil {
			continue
		}
		abs = filepath.Clean(abs)
		if denied[abs] {
			frozen[abs] = true
		}
	}

	onPath := map[string]bool{"/": true}
	for d := range denied {
		for dir := filepath.Dir(d); ; dir = filepath.Dir(dir) {
			onPath[dir] = true
			if dir == "/" {
				break
			}
		}
	}

	const walkedAccess = landlock.AccessFSSet(llsys.AccessFSReadDir |
		llsys.AccessFSMakeDir | llsys.AccessFSMakeReg |
		llsys.AccessFSMakeSym | llsys.AccessFSMakeFifo |
		llsys.AccessFSMakeSock)

	var rules []landlock.Rule
	var walked []string
	var narrow []string
	for dir := range onPath {
		walked = append(walked, dir)

		if frozenBelow(dir, denied, frozen) {
			rules = append(rules, landlock.RWDirs(dir).WithRefer().WithIoctlDev().IgnoreIfMissing())
			continue
		}

		narrow = append(narrow, dir)
		rules = append(rules, landlock.PathAccess(walkedAccess, dir).IgnoreIfMissing())
		entries, err := os.ReadDir(dir)
		if err != nil {

			continue
		}
		for _, e := range entries {
			child := filepath.Join(dir, e.Name())
			if denied[child] || onPath[child] {
				continue
			}

			if e.IsDir() {
				rules = append(rules, landlock.RWDirs(child).WithRefer().WithIoctlDev().IgnoreIfMissing())
			} else {
				rules = append(rules, landlock.RWFiles(child).WithIoctlDev().IgnoreIfMissing())
			}
		}
	}
	sort.Strings(walked)
	sort.Strings(narrow)
	return rules, walked, narrow, nil
}

func frozenBelow(dir string, denied, frozen map[string]bool) bool {
	prefix := dir
	if prefix != "/" {
		prefix += "/"
	}
	found := false
	for d := range denied {
		if d != dir && !strings.HasPrefix(d, prefix) {
			continue
		}
		found = true
		if !frozen[d] {
			return false
		}
	}
	return found
}

func setNoNewPrivs() error {
	const prSetNoNewPrivs = 38
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

func Preview(p Plan) []string {
	_, walked, narrow, err := allowRules(p.Deny, p.Immutable)
	if err != nil {
		return []string{"could not read the filesystem: " + err.Error()}
	}
	if len(walked) == 0 {
		return nil
	}

	if len(narrow) == 0 {
		return []string{
			"Every protected path is immutable in the inode, so the directories on",
			"the way to them are granted whole: " + strings.Join(walked, " "),
			"A file created in one of them is writable immediately. The protected",
			"paths stay out of reach through the OS lock, which Landlock does not",
			"mediate and the agent cannot remove.",
		}
	}
	return []string{
		"Landlock has no deny rule, so these directories are granted entry by",
		"entry rather than whole: " + strings.Join(narrow, " "),
		"A file created directly in one of them from now on is out of the agent's",
		"reach too, until it restarts. Anything inside a subdirectory is fine.",
		"This applies to a protected path that is not immutable in the inode. Run",
		"`solongate protect` again with sudo and the directory is granted whole.",
	}
}

func Describe() (string, []string) {
	return "Landlock", []string{
		"unprivileged, inherited by every process the agent starts, and it cannot",
		"be removed by the confined process",
	}
}

func workspaceRules(p Plan) ([]landlock.Rule, error) {
	ws := filepath.Clean(p.Workspace)
	if !filepath.IsAbs(ws) {
		return nil, errors.New("workspace must be an absolute path, got " + p.Workspace)
	}
	if ws == "/" {
		return nil, errors.New(`refusing to use "/" as a workspace: that confines nothing`)
	}

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

	for _, d := range append(p.RuntimeWrite, DefaultRuntimeDevices()...) {
		if d == "" {
			continue
		}
		st, err := os.Stat(d)
		if err != nil {
			continue
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