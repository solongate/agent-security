// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func parseSandboxArgs(argv []string) (id string, rest []string, ok bool) {
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) < 2 {
		return "", nil, false
	}
	id = argv[0]
	rest = argv[1:]
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return "", nil, false
	}
	return id, rest, true
}

func SandboxAgent(argv []string) int {
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		errln(sandboxUsage())
		return 1
	}
	if argv[0] == "--explain" || argv[0] == "explain" {
		return explainBox(argv[1:])
	}

	if argv[0] == "list" || argv[0] == "ls" {
		return listBoxes()
	}

	if err := sandbox.BoxAvailable(); err != nil {
		errln("")
		errln("  " + red("No closed box on this machine."))
		errln("  " + dim(err.Error()))
		errln("")
		return 1
	}

	id, rest, ok := parseSandboxArgs(argv)
	if !ok {
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
	ws := filepath.Clean(box.Dir)
	if !filepath.IsAbs(ws) {
		errln("")
		errln("  " + red("Workspace must be an absolute path, got: ") + box.Dir)
		errln("")
		return 1
	}
	if st, err := os.Stat(ws); err != nil || !st.IsDir() {
		errln("")
		errln("  " + red("Workspace "+ws+" is not a readable directory"))
		errln("")
		return 1
	}

	tree, inside, err := sandbox.BoxAgent(rest[0], rest[1:])
	if err != nil {
		errln("")
		errln("  " + red("Could not resolve the agent: ") + err.Error())
		errln("")
		return 1
	}

	home := "/workspace/.sandbox-home"
	if err := os.MkdirAll(filepath.Join(ws, ".sandbox-home"), 0o755); err != nil {
		errln("")
		errln("  " + red("Could not create sandbox home directory: ") + err.Error())
		errln("")
		return 1
	}

	env := buildSandboxEnv(home)

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

	_, err = sandbox.BoxLaunch(plan, env)
	// BoxLaunch execs with bwrap, so reaching here means it failed before the agent ran.
	errln("")
	errln("  " + red("Could not build the box: ") + err.Error())
	errln("")
	return 1
}

func buildSandboxEnv(home string) []string {
	overrides := map[string]string{
		shared.SandboxEnv: shared.SandboxMarker(shared.SandboxModeBox, buildTag()),
		"HOME":            home,
		"TMPDIR":          "/tmp",
		"XDG_CACHE_HOME":  home + "/.cache",
		"XDG_CONFIG_HOME": home + "/.config",
		"PWD":             "/workspace", // NOSONAR go:S2068 -- PWD is the working-directory env var, not a credential
	}

	// Host-specific sockets that cannot be reached inside the isolated namespace.
	drop := map[string]bool{
		"SSH_AUTH_SOCK":            true,
		"DBUS_SESSION_BUS_ADDRESS": true,
	}

	var env []string
	seen := make(map[string]bool)
	for _, kv := range os.Environ() {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		k := kv[:idx]
		if _, ok := overrides[k]; ok || drop[k] || seen[k] {
			continue
		}
		seen[k] = true
		env = append(env, kv)
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	return env
}

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
			net = dim("network on")
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
	errln("  " + dim("  "+padRight("/workspace", 22)+"  the box's directory, read-write"))
	errln("  " + dim("  "+padRight("/opt/agent", 22)+"  the agent's own program, read-only"))
	for _, d := range sandbox.DefaultBoxRuntime() {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		errln("  " + dim("  "+padRight(d, 22)+"  read-only"))
	}
	errln("  " + dim("  "+padRight("/proc", 22)+"  this box's processes only"))
	errln("  " + dim("  "+padRight("/dev", 22)+"  null, zero, full, random, urandom, tty"))
	errln("  " + dim("  "+padRight("/tmp", 22)+"  empty, and gone when the box exits"))
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