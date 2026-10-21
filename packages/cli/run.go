// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

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
		row("run <command> [args...]", "run it with the protected paths out of reach"),
		row("run --explain", "what this machine's confinement can and cannot do"),
		line(""),
		line("  solongate run claude"),
		line("  solongate run codex"),
	})
}

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

	env := append(os.Environ(), shared.SandboxEnv+"="+shared.SandboxMarker(shared.SandboxModeRun, buildTag()))

	printBanner(mech, plan)

	rep, err := sandbox.Launch(plan, rest, env)

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
	errln("  " + dim("from `solongate policy protect` still applies to it, and the guard still reads"))
	errln("  " + dim("its tool calls, but neither is the kernel refusing to open the file."))
	errln("  " + dim("`solongate policy protect require-sandbox on` refuses those agents outright."))
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

func exitCodeOf(err error) (int, bool) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	return 0, false
}

func buildTag() string {
	v := strings.TrimSpace(os.Getenv("SOLONGATE_VERSION"))
	if v == "" {
		v = "1"
	}
	return v
}