// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func DefaultBoxRuntime() []string {
	return []string{

		"/usr", "/bin", "/lib", "/lib64", "/sbin",

		"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/localtime",
		"/etc/ssl", "/etc/ca-certificates",
	}
}

func BoxAvailable() error {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return errors.New("bwrap is not installed, and the closed box is built with it. " +
			"Install bubblewrap (Debian/Ubuntu: apt install bubblewrap, Fedora: dnf install bubblewrap, " +
			"Arch: pacman -S bubblewrap). There is no weaker fallback on purpose: a box that " +
			"quietly became a permission layer would claim more than it does")
	}

	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		if strings.TrimSpace(string(b)) == "0" {
			return errors.New("unprivileged user namespaces are disabled on this kernel " +
				"(/proc/sys/kernel/unprivileged_userns_clone is 0), so no box can be built. " +
				"Enable them, or use `solongate run` for the weaker path-permission confinement")
		}
	}
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil {
		if strings.TrimSpace(string(b)) == "0" {
			return errors.New("this kernel allows no user namespaces " +
				"(/proc/sys/user/max_user_namespaces is 0), so no box can be built")
		}
	}
	return nil
}

func BoxLaunch(p BoxPlan, env []string) (Report, error) {
	rep := Report{Mechanism: "mount namespace (bubblewrap)"}

	if err := BoxAvailable(); err != nil {
		rep.Mechanism = ""
		rep.Err = err
		return rep, err
	}
	if len(p.AgentExec) == 0 {
		rep.Err = errors.New("nothing to run")
		return rep, rep.Err
	}
	ws := filepath.Clean(p.Workspace)
	if !filepath.IsAbs(ws) {
		rep.Err = errors.New("workspace must be an absolute path, got " + p.Workspace)
		return rep, rep.Err
	}
	if st, err := os.Stat(ws); err != nil || !st.IsDir() {
		rep.Err = errors.New("workspace " + ws + " is not a readable directory")
		return rep, rep.Err
	}

	bw, err := exec.LookPath("bwrap")
	if err != nil {
		rep.Mechanism = ""
		rep.Err = err
		return rep, err
	}

	args := []string{
		"bwrap",

		"--unshare-all",

		"--die-with-parent",

		"--new-session",

		"--cap-drop", "ALL",

		"--tmpfs", "/",
	}

	if p.Network {
		args = append(args, "--share-net")
	}

	var bound []string
	for _, d := range p.Runtime {
		if d == "" {
			continue
		}
		if _, err := os.Stat(d); err != nil {
			continue
		}
		args = append(args, "--ro-bind", d, d)
		bound = append(bound, d)
	}

	args = append(args, "--bind", ws, "/workspace")

	if p.AgentTree != "" {
		args = append(args, "--ro-bind", p.AgentTree, "/opt/agent")
	}

	args = append(args,

		"--proc", "/proc",

		"--dev", "/dev",

		"--tmpfs", "/tmp",
		"--chdir", "/workspace",
	)
	args = append(args, "--", p.AgentExec[0])
	args = append(args, p.AgentExec[1:]...)

	rep.Enforced = true
	rep.Notes = append(rep.Notes,
		"the agent's root is a tmpfs; these are the only things in it:",
		"  /workspace   "+ws+"   read-write",
		"  /opt/agent   the agent's own program   read-only",
		"  "+strings.Join(bound, " ")+"   read-only",
		"  /proc        this box's processes only",
		"  /dev         null, zero, full, random, urandom, tty",
		"  /tmp         empty, and gone when the box exits",
		"$HOME, /etc/passwd and every other project are ABSENT, not forbidden:",
		"there is no path to them from inside.",
	)

	if p.Network {
		rep.Notes = append(rep.Notes,
			"the network IS reachable, so the agent can talk to its model; what",
			"leaves over it is the DLP and egress layers' job, not the box's.")
	} else {
		rep.Notes = append(rep.Notes,
			"the network is unreachable too, so nothing can leave this box at all, ",
			"and an agent that cannot reach its model can only do offline work.")
	}

	if err := syscall.Exec(bw, args, env); err != nil {
		rep.Enforced = false
		rep.Err = err
		return rep, err
	}
	return rep, nil
}

func BoxAgent(name string, argv []string) (tree string, exec_ []string, err error) {
	resolved, err := exec.LookPath(name)
	if err != nil {
		return "", nil, errors.New(name + " is not on PATH")
	}
	real, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		real = resolved
	}
	tree = packageRoot(filepath.Dir(real))

	rel, err := filepath.Rel(tree, real)
	if err != nil {
		return "", nil, err
	}
	inside := filepath.Join("/opt/agent", rel)

	switch filepath.Ext(real) {
	case ".js", ".mjs", ".cjs":
		node, nerr := exec.LookPath("node")
		if nerr != nil {
			return "", nil, errors.New("the agent is a Node program and node is not on PATH")
		}
		exec_ = append([]string{node, inside}, argv...)
	default:
		exec_ = append([]string{inside}, argv...)
	}
	return tree, exec_, nil
}