// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-isatty"

	"github.com/solongate/agent-security/packages/cli"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/install"
	"github.com/solongate/agent-security/packages/core/term"
	"github.com/solongate/agent-security/packages/sandbox"
	"github.com/solongate/agent-security/packages/tui"
	_ "github.com/solongate/agent-security/packages/tui/audit"
	_ "github.com/solongate/agent-security/packages/tui/live"
	"github.com/solongate/agent-security/packages/tui/panels"
)

var buildVersion = "dev"

var cliSubcommands = map[string]bool{
	"repair": true,
	"policy": true, "ratelimit": true, "dlp": true, "stats": true, "audit": true,
	"doctor": true, "trace": true, "watch": true, "range": true,
	"tui": true,
}

var runExplainArgs = map[string]bool{"--explain": true, "explain": true}

var cliInfoArgs = map[string]bool{
	"help": true, "--help": true, "-h": true,
	"--version": true, "-v": true, "version": true,
}

var policyFileName = "poli" + "cy.json"

func main() { os.Exit(run(os.Args[1:])) }

func wireGuardVersions() {
	client.GuardVersions = func() (int, *int) {
		latest := 0
		if v := install.ShippedGuardVersion(); v != nil {
			latest = *v
		}
		return latest, install.InstalledGuardVersion()
	}
}

func run(args []string) int {
	wireGuardVersions()

	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "arrange":
		install.InstallGoBinaries()
		return 0
	case "--help", "-h", "help":
		printHelp()
		return 0
	case "--version", "-v", "version":
		fmt.Println(buildVersion)
		return 0
	}

	isHumanCLI := len(args) == 0 || cliSubcommands[sub]
	hasJSON := hasFlag(args, "--json")

	if isHumanCLI && len(args) > 0 {
		assertHumanTerminal(hasJSON)
	}
	if sub == "run" && len(args) > 1 && runExplainArgs[args[1]] {
		assertHumanTerminal(false)
	}

	if isHumanCLI {
		install.InstallGoBinaries()
	}

	if len(args) == 0 {
		if isInteractive(false) {
			return launchTUI()
		}
		printWelcome()
		return 0
	}

	if cmd, ok := lookup(sub); ok {
		return cmd.run(args[1:])
	}

	fmt.Printf("\n  Unknown command: %s\n", sub)
	fmt.Print("  Run `solongate --help` to see every command, or `solongate` for the TUI.\n\n")
	return 1
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

func isInteractive(allowNonTTYStdout bool) bool {
	if allowNonTTYStdout {
		return isatty.IsTerminal(os.Stdin.Fd())
	}
	return isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
}

func assertHumanTerminal(allowNonTTYStdout bool) {
	if os.Getenv("SOLONGATE_INTERNAL") == "1" || isInteractive(allowNonTTYStdout) {
		return
	}
	w := func(s string) { fmt.Fprintln(os.Stderr, s) }
	w("")
	w("  SolonGate is human-only.")
	w("  These commands control your security policy, so they cannot be run by an AI")
	w("  agent or any non-interactive process. Run them yourself, in a terminal.")
	w("  (refused: no interactive terminal, stdin and stdout are not both a tty)")
	w("")
	os.Exit(1)
}

type command struct {
	name    string
	summary string
	run     func(args []string) int
}

func table() []command {
	return []command{
		{"tui", "open the terminal UI (policies, audit, settings)",
			func([]string) int { return launchTUI() }},

		{"policy", "list, create, edit and activate policies; also locks paths with the OS", cli.Runner("policy")},
		{"ratelimit", "show and edit rate limits", cli.Runner("ratelimit")},
		{"dlp", "show and edit secret detection", cli.Runner("dlp")},

		{"run", "start an agent with the protected paths out of its reach", cli.RunAgent},

		{"sandbox", "start an agent in a closed box: the project, and nothing else", cli.SandboxAgent},
		{"stats", "traffic and security statistics", cli.Runner("stats")},
		{"audit", "browse the audit log", cli.Runner("audit")},
		{"doctor", "health check: policy, guard, hooks, local logs", cli.Runner("doctor")},
		{"trace", "what the guard saw in this directory", cli.Runner("trace")},
		{"watch", "live-tail tool calls", cli.Runner("watch")},

		{"repair", "restore the guard, hooks and settings files", cli.RunRepair},
		{"update", "pull the newest version and reinstall it", cli.RunUpdate},
		{"range", "how far an update may move: releases only, or every commit", cli.Runner("range")},
	}
}

func lookup(name string) (command, bool) {
	for _, c := range table() {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

func launchTUI() int {
	panels.Version = buildVersion

	mech, _ := sandbox.Describe()
	if err := tui.Run(tui.Confinement{Mechanism: mech, BoxUnavailable: sandbox.BoxAvailable()}); err != nil {
		fmt.Fprintf(os.Stderr, "\n  %sThe TUI could not start:%s %s\n\n", term.Yellow, term.Reset, err)
		return 1
	}
	return 0
}

func printWelcome() {
	fmt.Println("")
	fmt.Printf("  %s%sSolonGate%s %ssecure gateway for your AI agents%s\n",
		term.Bold, term.Blue4, term.Reset, term.Dim, term.Reset)
	fmt.Println("")
	fmt.Println("  Get started with one command:")
	fmt.Println("")
	fmt.Printf("    %ssolongate%s             %sopen the TUI (policies, audit, settings)%s\n",
		term.Cyan, term.Reset, term.Dim, term.Reset)
	fmt.Printf("    %ssolongate --help%s      %slist every command%s\n",
		term.Cyan, term.Reset, term.Dim, term.Reset)
	fmt.Println("")
	fmt.Printf("  %sRunning it in a terminal walks you through three things: that the%s\n", term.Dim, term.Reset)
	fmt.Printf("  %sguard is registered, that this machine has a policy, and that the%s\n", term.Dim, term.Reset)
	fmt.Printf("  %sguard has judged a real tool call. The last one is the only proof%s\n", term.Dim, term.Reset)
	fmt.Printf("  %sany of it works here, so it waits for one.%s\n", term.Dim, term.Reset)
	fmt.Println("")
	fmt.Printf("  %sThe policy is a file on this machine: %s%s~/.solongate/%s%s\n",
		term.Dim, term.Reset, term.Cyan, policyFileName, term.Reset)
	fmt.Println("")
	fmt.Printf("  %sWith no policy file the guard allows every call and records it.%s\n", term.Dim, term.Reset)
	fmt.Printf("  %s`solongate doctor` says which of those this machine is doing.%s\n", term.Dim, term.Reset)
	fmt.Println("")
}

func printHelp() {
	const w = 46
	head := func(t string) { fmt.Printf("\n  %s%s%s\n", term.Bold, t, term.Reset) }

	cmd := func(syntax string, desc ...string) {
		d := ""
		if len(desc) > 0 {
			d = desc[0]
		}
		if d == "" {
			fmt.Printf("    %s%s%s\n", term.Cyan, syntax, term.Reset)
			return
		}
		if len(syntax) <= w {
			fmt.Printf("    %s%s%s%s%s%s%s\n",
				term.Cyan, syntax, term.Reset, strings.Repeat(" ", w-len(syntax)), term.Dim, d, term.Reset)
			return
		}
		fmt.Printf("    %s%s%s\n", term.Cyan, syntax, term.Reset)
		fmt.Printf("    %s%s%s%s\n", strings.Repeat(" ", w), term.Dim, d, term.Reset)
	}

	fmt.Println("")
	fmt.Printf("  %s%sSolonGate%s %ssecure gateway for your AI agents%s  %sv%s%s\n",
		term.Bold, term.Blue4, term.Reset, term.Dim, term.Reset, term.Dim, buildVersion, term.Reset)
	fmt.Println("")
	fmt.Printf("  %sUsage:%s %ssolongate%s %s[command]%s   %s(no command opens the TUI: all of this in a terminal UI)%s\n",
		term.Dim, term.Reset, term.Cyan, term.Reset, term.Dim, term.Reset, term.Dim, term.Reset)

	head("Setup & status")
	cmd("solongate", "open the terminal UI: policies, audit, settings")
	cmd("update", "pull the newest version and reinstall it")
	cmd("range [long|short]", "how far an update may move: releases only, or every commit")
	cmd("repair", "restore the guard + hook + settings files if they were deleted or disarmed")
	cmd("doctor", "health check: policy, guard, hooks, local logs")
	cmd("doctor --json", "the same health check as machine-readable JSON")
	cmd("trace [--limit N]", "what the guard saw in this directory, allows included")

	head("Policies")
	cmd("policy list", "list all policies")
	cmd("policy create <name>", "create a new empty policy")
	cmd("policy delete <id>", "delete a policy")
	cmd("policy show <id>", "show one policy (rules, mode)")
	cmd("policy allow <id> [--command|--path|--filename|--url <val>]", "add an ALLOW rule")
	cmd("policy deny <id> [--command|--path|--filename|--url <val>]", "add a DENY rule")
	cmd("  --permission READ,WRITE,EXECUTE,NETWORK", "scope an allow/deny to a class of call")
	cmd("policy mode <id> <denylist|whitelist>", "switch deny-by-default / allow-by-default")
	cmd("policy rule <id> <ruleId> <enable|disable>", "turn one rule on or off without deleting it")
	cmd("policy revoke <id> <ruleId>", "remove a rule")
	cmd("policy activate <id> | --off", "pin the active policy, or enforce nothing")
	cmd("policy active", "show the resolved active policy")

	head("Protected paths")
	cmd("policy protect <path>", "put a path out of the agent's reach, with the OS")
	cmd("policy protect list", "every protected path, and what is actually holding it")
	cmd("policy protect remove <path>", "drop a path and lift its lock")
	cmd("policy protect require-sandbox on|off", "refuse calls from agents not started by `solongate run`")
	cmd("run -- <agent>", "start an agent inside OS-level confinement")
	cmd("run --explain", "what this machine's confinement can and cannot do")
	cmd("sandbox <id> <agent>", "start an agent in a closed box: the project, and nothing else")
	cmd("sandbox --explain [id]", "everything that is inside the box")

	head("Rate limits")
	cmd("ratelimit show", "current limits + change history")
	cmd("ratelimit set --minute N [--hour N] [--day N] [--mode off|detect|block]", "edit limits (unset fields kept)")
	cmd("ratelimit history", "recent limit changes")

	head("DLP (secrets)")
	cmd("dlp show", "current mode + enabled patterns")
	cmd("dlp mode <off|detect|redact|block>", "detect records, redact masks, block refuses")
	cmd("dlp enable <pattern>", "enable a built-in pattern")
	cmd("dlp disable <pattern>", "disable a built-in pattern")
	cmd("dlp add-custom --name X --re <regex>", "add a custom pattern")
	cmd("dlp remove-custom <name>", "remove a custom pattern")

	head("Monitoring")
	cmd("audit [--filter ALLOW|DENY] [--tool <s>] [--signal dlp|ratelimit] [--limit N]", "browse the audit log")
	cmd("stats", "traffic & security statistics")
	cmd("watch [--filter DENY] [--tool <s>]", "live-tail tool calls (Ctrl+C to stop)")

	fmt.Println("")
	fmt.Printf("  %sAdd %s%s--json%s%s to most read commands for machine output.%s\n",
		term.Dim, term.Reset, term.Cyan, term.Reset, term.Dim, term.Reset)
	fmt.Printf("  %sDetails for a command: %s%ssolongate <command> help%s\n",
		term.Dim, term.Reset, term.Cyan, term.Reset)
	fmt.Println("")
}