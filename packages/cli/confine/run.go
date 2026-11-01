// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package confine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/sandbox"
	"github.com/solongate/agent-security/packages/shared"
)

func runUsage() string {
	return cliutil.Usage("solongate run", "start an agent inside OS-level confinement", []cliutil.UsageRow{
		cliutil.Row("run <command> [args...]", "run it with the protected paths out of reach"),
		cliutil.Row("run --explain", "what this machine's confinement can and cannot do"),
		cliutil.Line(""),
		cliutil.Line("  solongate run claude"),
		cliutil.Line("  solongate run codex"),
	})
}

func RunAgent(argv []string) int {
	if len(argv) > 0 && (argv[0] == "--explain" || argv[0] == "explain") {
		return explainSandbox()
	}

	rest := agentArgv(argv)
	if len(rest) == 0 {
		cliutil.Errln(runUsage())
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := client.New()
	deny, err := client.Settings.ProtectedPaths(ctx)
	if err != nil {
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("Could not read the protected paths: ") + err.Error())
		cliutil.Errln("  " + cliutil.Dim("Refusing to start unconfined. That is the whole point of this command."))
		cliutil.Errln("")
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
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("No OS-level confinement is implemented for this platform."))
		cliutil.Errln("  " + cliutil.Dim("Refusing to start the agent rather than starting it loose."))
		cliutil.Errln("")
		return 1
	}

	env := append(os.Environ(), shared.SandboxEnv+"="+shared.SandboxMarker(shared.SandboxModeRun, buildTag()))

	printBanner(mech, plan)

	rep, err := sandbox.Launch(plan, rest, env)

	if err != nil {
		if code, ok := exitCodeOf(err); ok {
			return code
		}
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Red("Could not start the agent: ") + err.Error())
		cliutil.Errln("")
		return 1
	}
	if !rep.Enforced {
		cliutil.Errln("  " + cliutil.Red("Nothing was confined.") + cliutil.Dim(" Refusing to continue."))
		return 1
	}
	return 0
}

func printBanner(mech string, p sandbox.Plan) {
	if !p.Confined() {
		return
	}
	cliutil.Errln("")
	if p.Allowlist() {
		cliutil.Errln("  " + cliutil.Bold("SolonGate") + cliutil.Dim(" · "+mech+" · workspace only"))
		cliutil.Errln("  " + cliutil.Dim("  ") + p.Workspace)
		cliutil.Errln("  " + cliutil.Dim("  nothing else on this machine is reachable, including $HOME"))
		cliutil.Errln("  " + cliutil.Dim("  `solongate run --explain` for the runtime set this keeps open"))
		cliutil.Errln("")
		return
	}
	cliutil.Errln("  " + cliutil.Bold("SolonGate") + cliutil.Dim(" · "+mech+" · "+
		cliutil.Plural(len(p.Deny), "path", "paths")+" out of reach"))
	for _, d := range p.Deny {
		cliutil.Errln("  " + cliutil.Dim("  ") + d)
	}
	if len(sandbox.Preview(p)) > 0 {
		cliutil.Errln("  " + cliutil.Dim("  `solongate run --explain` for what this does not cover"))
	}
	cliutil.Errln("")
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

func explainSandbox() int {
	mech, notes := sandbox.Describe()
	cliutil.Errln("")
	if mech == "" {
		cliutil.Errln("  " + cliutil.Red("No OS-level confinement on this platform."))
	} else {
		cliutil.Errln("  " + cliutil.Bold(mech))
	}
	for _, n := range notes {
		cliutil.Errln("  " + cliutil.Dim(n))
	}
	cliutil.Errln("")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deny, err := client.New().Settings.ProtectedPaths(ctx)
	if err == nil && len(deny) > 0 {
		cliutil.Errln("  " + cliutil.Bold("Would be put out of reach"))

		var frozen []string
		for _, d := range deny {
			lock := config.CheckLock(d)
			if lock.Immutable {
				frozen = append(frozen, d)
			}
			cliutil.Errln("  " + cliutil.Dim("  ") + d + cliutil.Dim("   os lock: "+lock.Summary()))
		}
		for _, n := range sandbox.Preview(sandbox.Plan{Deny: deny, Immutable: frozen}) {
			cliutil.Errln("  " + cliutil.Dim(n))
		}
		cliutil.Errln("")
	}

	cliutil.Errln("  " + cliutil.Dim("What this does NOT cover: an agent started any other way. The OS lock"))
	cliutil.Errln("  " + cliutil.Dim("from `solongate policy protect` still applies to it, and the guard still reads"))
	cliutil.Errln("  " + cliutil.Dim("its tool calls, but neither is the kernel refusing to open the file."))
	cliutil.Errln("  " + cliutil.Dim("`solongate policy protect require-sandbox on` refuses those agents outright."))
	cliutil.Errln("")
	return 0
}

// agentArgv returns the command and arguments handed to the agent. Only a
// leading `--` separates confine's own arguments from the agent command; a
// `--` further along belongs to the agent's own command line, where tools use
// it to end their option parsing, so it is passed through untouched.
func agentArgv(argv []string) []string {
	if len(argv) > 0 && argv[0] == "--" {
		return argv[1:]
	}
	return argv
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
