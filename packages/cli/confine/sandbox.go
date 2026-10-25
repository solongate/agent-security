// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package confine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/sandbox"
	"github.com/solongate/agent-security/packages/shared"
)

func sandboxUsage() string {
	return cliutil.Usage("solongate sandbox", "start an agent in a closed box", []cliutil.UsageRow{
		cliutil.Row("sandbox <id> <agent> [args...]", "the box's directory is all it can see"),
		cliutil.Row("sandbox list", "the boxes this machine has, and their ids"),
		cliutil.Row("sandbox --explain [id]", "everything that is inside a box"),
		cliutil.Line(""),
		cliutil.Line("  Boxes are made in the TUI's Sandbox section, which gives each one"),
		cliutil.Line("  an id from 001 and decides whether it keeps the network."),
		cliutil.Line(""),
		cliutil.Line("  solongate sandbox 001 claude"),
		cliutil.Line("  solongate sandbox 2 codex"),
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
		cliutil.Errln(sandboxUsage())
		return 1
	}
	if argv[0] == "--explain" || argv[0] == "explain" {
		return explainBox(argv[1:])
	}

	if argv[0] == "list" || argv[0] == "ls" {
		return listBoxes()
	}

	if err := sandbox.BoxAvailable(); err != nil {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("No closed box on this machine."))
		cliutil.Errln("  " + cliutil.Dim(err.Error()))
		cliutil.Errln("")
		return 1
	}

	id, rest, ok := parseSandboxArgs(argv)
	if !ok {
		cliutil.Errln(sandboxUsage())
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	box, err := client.New().Settings.Sandbox(ctx, id)
	if err != nil {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red(err.Error()))
		cliutil.Errln("")
		return 1
	}
	ws := filepath.Clean(box.Dir)
	if !filepath.IsAbs(ws) {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("Workspace must be an absolute path, got: ") + box.Dir)
		cliutil.Errln("")
		return 1
	}
	if st, err := os.Stat(ws); err != nil || !st.IsDir() {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("Workspace "+ws+" is not a readable directory"))
		cliutil.Errln("")
		return 1
	}

	tree, inside, err := sandbox.BoxAgent(rest[0], rest[1:])
	if err != nil {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("Could not resolve the agent: ") + err.Error())
		cliutil.Errln("")
		return 1
	}

	home := "/workspace/.sandbox-home"
	if err := os.MkdirAll(filepath.Join(ws, ".sandbox-home"), 0o755); err != nil {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("Could not create sandbox home directory: ") + err.Error())
		cliutil.Errln("")
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

	cliutil.Errln("")
	net := "no network"
	if box.Network {
		net = "network on"
	}
	cliutil.Errln("  " + cliutil.Bold("SolonGate") + cliutil.Dim(" · box "+box.ID+" · "+net+" · "+ws))
	cliutil.Errln("  " + cliutil.Dim("  the project is /workspace inside; nothing else on this machine is there"))
	cliutil.Errln("  " + cliutil.Dim("  `solongate sandbox --explain` for everything that is in the box"))
	cliutil.Errln("")

	_, err = sandbox.BoxLaunch(plan, env)
	// BoxLaunch execs with bwrap, so reaching here means it failed before the agent ran.
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Red("Could not build the box: ") + err.Error())
	cliutil.Errln("")
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
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("Could not read the sandboxes: ") + err.Error())
		cliutil.Errln("")
		return 1
	}
	cliutil.Errln("")
	if len(boxes) == 0 {
		cliutil.Errln("  " + cliutil.Dim("No sandboxes. The TUI's Sandbox section is where they are made."))
		cliutil.Errln("")
		return 0
	}
	for _, b := range boxes {
		net := cliutil.Red("no network")
		if b.Network {
			net = cliutil.Dim("network on")
		}
		label := ""
		if b.Label != "" {
			label = cliutil.Dim("  " + b.Label)
		}
		cliutil.Errln("  " + cliutil.Bold(b.ID) + "  " + net + "  " + b.Dir + label)
	}
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("solongate sandbox "+boxes[0].ID+" claude"))
	cliutil.Errln("")
	return 0
}

func explainBox(argv []string) int {
	cliutil.Errln("")
	if err := sandbox.BoxAvailable(); err != nil {
		cliutil.Errln("  " + cliutil.Red("No closed box on this machine."))
		cliutil.Errln("  " + cliutil.Dim(err.Error()))
		cliutil.Errln("")
		return 1
	}

	var box shared.Sandbox
	var have bool
	if len(argv) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		b, err := client.New().Settings.Sandbox(ctx, argv[0])
		if err != nil {
			cliutil.Errln("  " + cliutil.Red(err.Error()))
			cliutil.Errln("")
			return 1
		}
		box, have = b, true
	}

	cliutil.Errln("  " + cliutil.Bold("The closed box") + cliutil.Dim(" · mount namespace (bubblewrap)"))
	cliutil.Errln("")
	if have {
		net := "off, nothing can leave this box at all"
		if box.Network {
			net = "on, the agent can reach its model"
		}
		cliutil.Errln("  " + cliutil.Dim("box "+box.ID+": ") + box.Dir)
		cliutil.Errln("  " + cliutil.Dim("network: ") + net)
	} else {
		cliutil.Errln("  " + cliutil.Dim("No id given, so this is the shape every box has."))
		cliutil.Errln("  " + cliutil.Dim("`solongate sandbox list` shows the ones that exist."))
	}
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("Inside a box, the agent's root is a tmpfs holding only:"))
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("  "+cliutil.PadRight("/workspace", 22)+"  the box's directory, read-write"))
	cliutil.Errln("  " + cliutil.Dim("  "+cliutil.PadRight("/opt/agent", 22)+"  the agent's own program, read-only"))
	for _, d := range sandbox.DefaultBoxRuntime() {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		cliutil.Errln("  " + cliutil.Dim("  "+cliutil.PadRight(d, 22)+"  read-only"))
	}
	cliutil.Errln("  " + cliutil.Dim("  "+cliutil.PadRight("/proc", 22)+"  this box's processes only"))
	cliutil.Errln("  " + cliutil.Dim("  "+cliutil.PadRight("/dev", 22)+"  null, zero, full, random, urandom, tty"))
	cliutil.Errln("  " + cliutil.Dim("  "+cliutil.PadRight("/tmp", 22)+"  empty, and gone when the box exits"))
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("ABSENT, not forbidden: $HOME, /etc/passwd, /root, /var, /mnt and"))
	cliutil.Errln("  " + cliutil.Dim("every other project. There is no path to any of them from inside,"))
	cliutil.Errln("  " + cliutil.Dim("so no rule is needed to refuse one."))
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("HOME is /workspace/.sandbox-home, so whatever the agent keeps is"))
	cliutil.Errln("  " + cliutil.Dim("in the project rather than in a directory that does not exist."))
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Dim("THE NETWORK IS THE ONE HOLE THAT IS NOT A FILESYSTEM HOLE, and it is"))
	cliutil.Errln("  " + cliutil.Dim("each box's own choice. Off, nothing leaves and an agent that cannot"))
	cliutil.Errln("  " + cliutil.Dim("reach its model can only do offline work. On, the agent works and"))
	cliutil.Errln("  " + cliutil.Dim("what leaves is the DLP and egress layers' job, they read content,"))
	cliutil.Errln("  " + cliutil.Dim("which a mount namespace cannot."))
	cliutil.Errln("")
	return 0
}
