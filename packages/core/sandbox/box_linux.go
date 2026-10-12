// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

// The closed box: a new root, and nothing in it that was not put there.
//
// WHY THIS EXISTS BESIDE Launch. Landlock, which Launch uses, is a permission
// layer over the host's one filesystem view. It can refuse a path; it cannot
// remove it. So /usr and /etc stay visible, $HOME stays a directory that exists
// and returns EACCES, and "the agent cannot touch anything outside the project"
// is true only in the sense that every attempt fails. Somebody reading `ls /`
// inside it still sees the whole machine.
//
// A MOUNT NAMESPACE CHANGES THE VIEW INSTEAD OF THE PERMISSIONS. The agent gets
// its own root: an empty tmpfs with the project bound into it, a read-only copy
// of the runtime it needs to execute, a fresh /proc that shows only its own
// processes, and a /dev with five device nodes. $HOME is not denied, /etc/passwd
// is not denied, the sibling project is not denied — none of them is there.
// `ls /` returns nine entries and every one of them was chosen.
//
// This is what Docker, Flatpak, Firejail and bubblewrap all are. It needs no
// privilege: unprivileged user namespaces have been the default on mainstream
// distributions for years, and the box is built inside one.
//
// IT SHELLS OUT TO bwrap RATHER THAN CALLING pivot_root DIRECTLY, and that is a
// deliberate refusal to write this by hand. The sequence — unshare the user and
// mount namespaces, map the uid, make the old root private, bind what belongs
// in the new one, pivot, unmount the old, drop the remaining capabilities, set
// no_new_privs, seccomp the rest — is about four hundred lines of ordering
// where a single wrong step is a sandbox escape rather than a bug. bubblewrap
// is the implementation Flatpak ships to hundreds of millions of desktops and
// it has had that ordering reviewed by people who do this for a living. A
// hand-rolled copy in this file would be a worse version of it with no reviewers.
//
// WHAT THAT COSTS: bwrap has to be installed. There is no fallback to a weaker
// mode — a closed box that quietly became a permission layer would be the most
// expensive kind of wrong, so a missing bwrap is a refusal with the package name
// in it.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// DefaultBoxRuntime is the read-only runtime, and every entry is here because
// a process does not start without it.
//
// NOT /etc. The whole directory used to be granted by the Landlock mode, which
// made /etc/passwd and every service's configuration readable. A box binds four
// files and two directories instead: enough to resolve a name and verify a
// certificate, and nothing that describes the machine or the people on it.
//
// NOT $HOME, not /home at all, not /root, not /var, not /mnt, not /media, not
// /opt beyond the agent's own tree. They are absent rather than forbidden.
func DefaultBoxRuntime() []string {
	return []string{
		// The interpreter, the libraries, the tools.
		"/usr", "/bin", "/lib", "/lib64", "/sbin",
		// Name resolution and TLS. Four files and two directories.
		"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/localtime",
		"/etc/ssl", "/etc/ca-certificates",
	}
}

// BoxAvailable reports whether a closed box can be built here, and says why not
// when it cannot. Checked before anything is printed, so a refusal arrives
// before the banner rather than after it.
func BoxAvailable() error {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return errors.New("bwrap is not installed, and the closed box is built with it. " +
			"Install bubblewrap (Debian/Ubuntu: apt install bubblewrap, Fedora: dnf install bubblewrap, " +
			"Arch: pacman -S bubblewrap). There is no weaker fallback on purpose: a box that " +
			"quietly became a permission layer would claim more than it does")
	}
	// Unprivileged user namespaces, which the box is built inside. Absent on a
	// few hardened kernels and on some container runtimes.
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

// BoxLaunch builds the box and becomes the agent inside it.
//
// It execs bwrap rather than forking it, so there is no parent left to go wrong
// and the exit code is the agent's. On success this does not return.
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

	// THE BOX, ARGUMENT BY ARGUMENT. Order matters to bwrap: binds are applied
	// in sequence onto a root that starts empty.
	args := []string{
		"bwrap",
		// Unshare the user, mount, pid, ipc, uts and cgroup namespaces. This is
		// what makes the box a box: its own root, its own process list, no way
		// to see or signal anything outside.
		"--unshare-all",
		// Die when this process dies, so a killed launcher cannot leave an
		// agent running in a box nobody is watching.
		"--die-with-parent",
		// Its own session, so the agent cannot send signals to the terminal's
		// other processes or steal the controlling tty.
		"--new-session",
		// No capabilities and no way to gain one through a setuid binary.
		"--cap-drop", "ALL",
		// The root is a tmpfs that exists only while the box does.
		"--tmpfs", "/",
	}

	// THE NETWORK IS THE ONE HOLE THAT IS NOT A FILESYSTEM HOLE, and it is the
	// box's own choice rather than this file's. --unshare-all took the network
	// too, which made every box airtight and unusable: an agent that cannot
	// reach its model does nothing, so a box nobody turns on protects nothing.
	//
	// Giving it back is a decision per box, recorded in the policy file. With
	// the network on, nothing outside the project is readable, writable or
	// visible, and what leaves over the wire is the DLP and egress layers' job
	// — they read content, which a mount namespace cannot. With it off the box
	// is sealed and the agent is useful only for work that needs no model.
	if p.Network {
		args = append(args, "--share-net")
	}

	var bound []string
	for _, d := range p.Runtime {
		if d == "" {
			continue
		}
		if _, err := os.Stat(d); err != nil {
			continue // absent on this distribution; /lib64 commonly is
		}
		args = append(args, "--ro-bind", d, d)
		bound = append(bound, d)
	}

	// The project, read-write, at a fixed path. /workspace rather than its host
	// path, so the box contains no trace of where it came from: an agent
	// confined to /home/you/projects/x can still read the names "home", "you"
	// and "projects" off its own cwd, and those are three facts about a machine
	// it is not supposed to know anything about.
	args = append(args, "--bind", ws, "/workspace")

	// The agent's own install tree, read-only, at /opt/agent. Not at its host
	// path: that would put /home/<user>/.local inside the box.
	if p.AgentTree != "" {
		args = append(args, "--ro-bind", p.AgentTree, "/opt/agent")
	}

	args = append(args,
		// A fresh /proc shows the box's own processes and nothing else, so the
		// agent cannot read another process's command line or environment.
		"--proc", "/proc",
		// Five device nodes, not the host's /dev. --dev gives null, zero, full,
		// random, urandom and tty and nothing that leads to a disk.
		"--dev", "/dev",
		// Scratch that vanishes with the box. A script the agent writes to /tmp
		// and runs still works, and is gone afterwards, and was never on the
		// host's filesystem.
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
			"the network is unreachable too, so nothing can leave this box at all —",
			"and an agent that cannot reach its model can only do offline work.")
	}

	if err := syscall.Exec(bw, args, env); err != nil {
		rep.Enforced = false
		rep.Err = err
		return rep, err
	}
	return rep, nil // unreachable
}

// BoxAgent resolves a command into the tree to bind and the path to run it at
// inside the box.
//
// An agent installed through npm is a symlink on PATH pointing into a package
// directory, and the package needs its whole tree: granting only the entry file
// gets MODULE_NOT_FOUND. The tree goes to /opt/agent and the entry file's path
// is rewritten to sit under it, so the box never contains the host path.
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

	// A .js or .mjs entry is run through the interpreter, which lives in the
	// read-only runtime at its own path. A native binary is exec'd directly.
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
