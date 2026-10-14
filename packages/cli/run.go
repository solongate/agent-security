// SPDX-License-Identifier: Apache-2.0

// `solongate run -- <agent>` starts an agent inside OS-level confinement.
//
// THIS IS THE ONLY COMMAND THAT CHANGES WHAT SOLONGATE *IS*. Everywhere else
// SolonGate is a child of the agent: the client spawns the guard, the guard
// reads a JSON description of what the agent says it is about to do, and
// answers yes or no. Everything downstream of that answer is the agent's own
// process, doing whatever it does, with no SolonGate anywhere near it. That is
// why a protected path can be reached by a script the agent writes, or a
// program it compiles: the guard was never asked.
//
// Started this way, the order is reversed. The confinement goes on before the
// agent's first instruction, every process it starts inherits it, and nothing
// it runs can take it off. The agent does not get refused by SolonGate; it
// gets refused by the kernel, with SolonGate not in the path at all.
package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/sandbox"
	"github.com/solongate/agent-security/packages/shared"
)

func runUsage() string {
	return usage("solongate run", "start an agent inside OS-level confinement", []usageRow{
		row("run -- <command> [args...]", "run it with the protected paths out of reach"),
		row("run --explain", "what this machine's confinement can and cannot do"),
		line(""),
		line("  solongate run -- claude"),
		line("  solongate run -- codex"),
	})
}

// RunAgent is wired directly rather than through the handler table, because it
// must NOT have its arguments parsed: everything after `--` belongs to the
// agent, including flags this CLI also uses.
func RunAgent(argv []string) int {
	if len(argv) > 0 && (argv[0] == "--explain" || argv[0] == "explain") {
		return explainSandbox()
	}

	rest := argv
	if i := indexOf(argv, "--"); i >= 0 {
		rest = argv[i+1:]
	}
	if len(rest) == 0 {
		errln(runUsage())
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := client.New()
	deny, err := client.Settings.ProtectedPaths(ctx)
	if err != nil {
		errln("")
		errln("  " + red("Could not read the protected paths: ") + err.Error())
		errln("  " + dim("Refusing to start unconfined. That is the whole point of this command."))
		errln("")
		return 1
	}

	// `run` IS THE DENY LIST, and the closed box is a separate command.
	//
	// They were briefly one thing with a setting deciding which, and that was
	// wrong: `run` is a permission layer over this machine, paths are refused,
	// $HOME still exists, `ls /` still shows everything, and it works on three
	// platforms. The box builds a new root and needs a Linux mount namespace.
	// One flag standing for both would have hidden that difference behind a
	// word, and the difference is the whole of what somebody is choosing.
	//
	// See `solongate sandbox`.
	// AND WHICH OF THEM THE OS HAS ALREADY FROZEN, probed here rather than read
	// out of the config file.
	//
	// `solongate protect` sets an immutable flag as well as recording the path,
	// and the two can disagree: a file restored from a backup, moved to another
	// filesystem, or locked on a machine where the user had no
	// CAP_LINUX_IMMUTABLE and got chmod 0444 instead. CheckLock asks the live
	// filesystem, and only Immutable counts, which is the field that means
	// deletion is blocked and not merely writing. chmod 0444 is not enough: it
	// stops a write until the agent runs chmod, and does not stop rm at all.
	//
	// What the sandbox does with it is widen the grant on the ancestor
	// directories of frozen paths, which is what lets a file created next to a
	// protected one actually be written. See Plan.Immutable.
	var frozen []string
	for _, d := range deny {
		if config.CheckLock(d).Immutable {
			frozen = append(frozen, d)
		}
	}

	plan := sandbox.Plan{Deny: deny, Immutable: frozen}

	mech, _ := sandbox.Describe()
	if mech == "" {
		errln("")
		errln("  " + red("No OS-level confinement is implemented for this platform."))
		errln("  " + dim("Refusing to start the agent rather than starting it loose."))
		errln("")
		return 1
	}

	// The marker the guard reads. It reports the fact; it does not create it.
	// See shared.SandboxEnv for why an agent setting it gains nothing.
	env := append(os.Environ(), shared.SandboxEnv+"="+shared.SandboxMarker(shared.SandboxModeRun, buildTag()))

	printBanner(mech, plan)

	rep, err := sandbox.Launch(plan, rest, env)
	// On Linux and macOS Launch execs and never returns, so reaching here at
	// all means something failed before the agent started.
	if err != nil {
		if code, ok := exitCodeOf(err); ok {
			return code
		}
		errln("")
		errln("  " + red("Could not start the agent: ") + err.Error())
		errln("")
		return 1
	}
	if !rep.Enforced {
		errln("  " + red("Nothing was confined.") + dim(" Refusing to continue."))
		return 1
	}
	return 0
}

// printBanner is deliberately small.
//
// THIS RUNS ON EVERY AGENT LAUNCH once the shim is in place, so it is three
// lines at most. The full account of what the confinement does and does not
// cover is `solongate run --explain`, which a person reads once rather than
// scrolling past every time. With nothing protected it says nothing at all:
// a banner that appears before there is anything to report trains people to
// stop reading it, and then the one that matters goes past unread too.
// printBanner says which of the two postures this launch is, because they are
// not degrees of each other and somebody reading one line should not have to
// guess. A workspace line names what the agent CAN reach; a deny line names
// what it cannot, and the difference is everything else on the disk.
func printBanner(mech string, p sandbox.Plan) {
	if !p.Confined() {
		return
	}
	errln("")
	if p.Allowlist() {
		errln("  " + bold("SolonGate") + dim(" · "+mech+" · workspace only"))
		errln("  " + dim("  ") + p.Workspace)
		errln("  " + dim("  nothing else on this machine is reachable, including $HOME"))
		errln("  " + dim("  `solongate run --explain` for the runtime set this keeps open"))
		errln("")
		return
	}
	errln("  " + bold("SolonGate") + dim(" · "+mech+" · "+
		plural(len(p.Deny), "path", "paths")+" out of reach"))
	for _, d := range p.Deny {
		errln("  " + dim("  ") + d)
	}
	if len(sandbox.Preview(p)) > 0 {
		errln("  " + dim("  `solongate run --explain` for what this does not cover"))
	}
	errln("")
}

// homeDir is the user's home, empty when it cannot be resolved. An empty one
// narrows the runtime-write set to /tmp rather than guessing a path, because a
// wrong guess here grants the agent a directory somebody did not intend.
func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func explainSandbox() int {
	mech, notes := sandbox.Describe()
	errln("")
	if mech == "" {
		errln("  " + red("No OS-level confinement on this platform."))
	} else {
		errln("  " + bold(mech))
	}
	for _, n := range notes {
		errln("  " + dim(n))
	}
	errln("")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deny, err := client.New().Settings.ProtectedPaths(ctx)
	if err == nil && len(deny) > 0 {
		errln("  " + bold("Would be put out of reach"))
		// The same probe the launch path runs, and it is printed next to each
		// path because the two answers are connected: a frozen path is the one
		// whose directory gets the full grant, so what the preview says about
		// walked directories depends on this column.
		var frozen []string
		for _, d := range deny {
			lock := config.CheckLock(d)
			if lock.Immutable {
				frozen = append(frozen, d)
			}
			errln("  " + dim("  ") + d + dim("   os lock: "+lock.Summary()))
		}
		for _, n := range sandbox.Preview(sandbox.Plan{Deny: deny, Immutable: frozen}) {
			errln("  " + dim(n))
		}
		errln("")
	}

	errln("  " + dim("What this does NOT cover: an agent started any other way. The OS lock"))
	errln("  " + dim("from `solongate protect` still applies to it, and the guard still reads"))
	errln("  " + dim("its tool calls, but neither is the kernel refusing to open the file."))
	errln("  " + dim("`solongate protect require-sandbox on` refuses those agents outright."))
	errln("")
	return 0
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// exitCodeOf pulls the agent's own exit code out of a wait error, so
// `solongate run -- cmd` exits the way `cmd` did. Only Windows reaches it: the
// other two platforms exec, so the agent's exit IS this process's exit.
func exitCodeOf(err error) (int, bool) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	return 0, false
}

// buildTag is what goes in the marker: enough to tell two builds apart on one
// machine, and nothing that would be worth an agent forging.
func buildTag() string {
	v := strings.TrimSpace(os.Getenv("SOLONGATE_VERSION"))
	if v == "" {
		v = "1"
	}
	return v
}