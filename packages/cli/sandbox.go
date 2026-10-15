// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

// `solongate sandbox <agent>`, the closed box.
//
// THE DIFFERENCE FROM `run`, because two commands that both say "confined" have
// to be told apart in one line each:
//
//	run      a permission layer over this machine's filesystem. Paths are
//	         refused. $HOME exists and returns EACCES; `ls /` shows the whole
//	         machine. It is what macOS and Windows can do, and what Linux can
//	         do without bubblewrap.
//	sandbox  a new root. The project, a read-only runtime, a private /proc and
//	         a /dev with five nodes. $HOME is not refused, it is not there.
//	         The network stays, so the agent can reach its model. Linux only.
//
// `run` protects what the protected-paths list names. `sandbox` protects
// everything nobody named, which is the set that matters: nobody adds ~/.ssh,
// a sibling customer's repository, or the credentials of a tool they installed
// last month to a deny list.

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/sandbox"
	"github.com/solongate/agent-security/packages/shared"
)

func sandboxUsage() string {
	return usage("solongate sandbox", "start an agent in a closed box", []usageRow{
		row("sandbox <id> <agent> [args...]", "the box's directory is all it can see"),
		row("sandbox list", "the boxes this machine has, and their ids"),
		row("sandbox --explain [id]", "everything that is inside a box"),
		line(""),
		line("  Boxes are made in the TUI's Sandbox section, which gives each one"),
		line("  an id from 001 and decides whether it keeps the network."),
		line(""),
		line("  solongate sandbox 001 claude"),
		line("  solongate sandbox 2 codex"),
	})
}

// SandboxAgent is wired directly rather than through the handler table, for the
// same reason RunAgent is: everything after the agent's name belongs to the
// agent, including flags this CLI also uses.
func SandboxAgent(argv []string) int {
	if len(argv) == 0 {
		errln(sandboxUsage())
		return 1
	}
	if argv[0] == "--explain" || argv[0] == "explain" {
		return explainBox(argv[1:])
	}

	// `sandbox list` before anything else, so somebody who has forgotten the
	// numbers can find them without starting an agent.
	if argv[0] == "list" || argv[0] == "ls" {
		return listBoxes()
	}

	// CHECKED BEFORE ANYTHING IS PRINTED. A banner followed by a refusal reads
	// as the box having been built and then failed, which is the opposite of
	// what happened.
	if err := sandbox.BoxAvailable(); err != nil {
		errln("")
		errln("  " + red("No closed box on this machine."))
		errln("  " + dim(err.Error()))
		errln("")
		return 1
	}

	// THE ID COMES FIRST AND THE AGENT SECOND: `solongate sandbox 001 claude`.
	// Everything after the agent's name belongs to the agent, including flags
	// this CLI also understands.
	id := argv[0]
	rest := argv[1:]
	if i := indexOf(rest, "--"); i >= 0 {
		rest = rest[i+1:]
	}
	if len(rest) == 0 {
		errln(sandboxUsage())
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	box, err := client.New().Settings.Sandbox(ctx, id)
	if err != nil {
		errln("")
		errln("  " + red(err.Error()))
		errln("")
		return 1
	}
	ws := box.Dir

	tree, inside, err := sandbox.BoxAgent(rest[0], rest[1:])
	if err != nil {
		errln("")
		errln("  " + red("Could not resolve the agent: ") + err.Error())
		errln("")
		return 1
	}

	// HOME POINTS INSIDE THE PROJECT, because the box has no home directory and
	// an agent without one writes its session state nowhere and usually exits.
	// Pointing it at the project means everything the agent keeps is somewhere
	// the person can see, next to the code it was keeping it about.
	home := "/workspace/.sandbox-home"
	_ = os.MkdirAll(filepath.Join(ws, ".sandbox-home"), 0o755)

	env := append(os.Environ(),
		shared.SandboxEnv+"="+shared.SandboxMarker(shared.SandboxModeBox, buildTag()),
		"HOME="+home,
		"TMPDIR=/tmp",
		"XDG_CACHE_HOME="+home+"/.cache",
		"XDG_CONFIG_HOME="+home+"/.config",
		"PWD=/workspace",
	)

	plan := sandbox.BoxPlan{
		Workspace: ws,
		Runtime:   sandbox.DefaultBoxRuntime(),
		AgentTree: tree,
		AgentExec: inside,
		Network:   box.Network,
	}

	errln("")
	net := "no network"
	if box.Network {
		net = "network on"
	}
	errln("  " + bold("SolonGate") + dim(" · box "+box.ID+" · "+net+" · "+ws))
	errln("  " + dim("  the project is /workspace inside; nothing else on this machine is there"))
	errln("  " + dim("  `solongate sandbox --explain` for everything that is in the box"))
	errln("")

	rep, err := sandbox.BoxLaunch(plan, env)
	// BoxLaunch execs, so reaching here means it failed before the agent ran.
	if err != nil {
		if code, ok := exitCodeOf(err); ok {
			return code
		}
		errln("")
		errln("  " + red("Could not build the box: ") + err.Error())
		errln("")
		return 1
	}
	if !rep.Enforced {
		errln("  " + red("Nothing was confined.") + dim(" Refusing to continue."))
		return 1
	}
	return 0
}

// listBoxes is the column somebody reads when they have forgotten the numbers.
func listBoxes() int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	boxes, err := client.New().Settings.Sandboxes(ctx)
	if err != nil {
		errln("")
		errln("  " + red("Could not read the sandboxes: ") + err.Error())
		errln("")
		return 1
	}
	errln("")
	if len(boxes) == 0 {
		errln("  " + dim("No sandboxes. The TUI's Sandbox section is where they are made."))
		errln("")
		return 0
	}
	for _, b := range boxes {
		net := red("no network")
		if b.Network {
			net = dim("network on ")
		}
		label := ""
		if b.Label != "" {
			label = dim("  " + b.Label)
		}
		errln("  " + bold(b.ID) + "  " + net + "  " + b.Dir + label)
	}
	errln("")
	errln("  " + dim("solongate sandbox "+boxes[0].ID+" claude"))
	errln("")
	return 0
}

// explainBox says what is in a box. With an id it describes that box; without
// one it describes the shape every box has.
func explainBox(argv []string) int {
	errln("")
	if err := sandbox.BoxAvailable(); err != nil {
		errln("  " + red("No closed box on this machine."))
		errln("  " + dim(err.Error()))
		errln("")
		return 1
	}

	var box shared.Sandbox
	var have bool
	if len(argv) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		b, err := client.New().Settings.Sandbox(ctx, argv[0])
		if err != nil {
			errln("  " + red(err.Error()))
			errln("")
			return 1
		}
		box, have = b, true
	}

	errln("  " + bold("The closed box") + dim(" · mount namespace (bubblewrap)"))
	errln("")
	if have {
		net := "off, nothing can leave this box at all"
		if box.Network {
			net = "on, the agent can reach its model"
		}
		errln("  " + dim("box "+box.ID+": ") + box.Dir)
		errln("  " + dim("network: ") + net)
	} else {
		errln("  " + dim("No id given, so this is the shape every box has."))
		errln("  " + dim("`solongate sandbox list` shows the ones that exist."))
	}
	errln("")
	errln("  " + dim("Inside a box, the agent's root is a tmpfs holding only:"))
	errln("")
	errln("  " + dim("  /workspace    the box's directory, read-write"))
	errln("  " + dim("  /opt/agent    the agent's own program, read-only"))
	for _, d := range sandbox.DefaultBoxRuntime() {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		errln("  " + dim("  "+padRight(d, 13)+" read-only"))
	}
	errln("  " + dim("  /proc         this box's processes only"))
	errln("  " + dim("  /dev          null, zero, full, random, urandom, tty"))
	errln("  " + dim("  /tmp          empty, and gone when the box exits"))
	errln("")
	errln("  " + dim("ABSENT, not forbidden: $HOME, /etc/passwd, /root, /var, /mnt and"))
	errln("  " + dim("every other project. There is no path to any of them from inside,"))
	errln("  " + dim("so no rule is needed to refuse one."))
	errln("")
	errln("  " + dim("HOME is /workspace/.sandbox-home, so whatever the agent keeps is"))
	errln("  " + dim("in the project rather than in a directory that does not exist."))
	errln("")
	errln("  " + dim("THE NETWORK IS THE ONE HOLE THAT IS NOT A FILESYSTEM HOLE, and it is"))
	errln("  " + dim("each box's own choice. Off, nothing leaves and an agent that cannot"))
	errln("  " + dim("reach its model can only do offline work. On, the agent works and"))
	errln("  " + dim("what leaves is the DLP and egress layers' job, they read content,"))
	errln("  " + dim("which a mount namespace cannot."))
	errln("")
	return 0
}