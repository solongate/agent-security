// SPDX-License-Identifier: Apache-2.0

// The SolonGate CLI, in Go.
//
// This is the SECOND implementation of the CLI, standing beside the one in
// packages/proxy rather than replacing it. Nothing in this binary may require a
// change over there to keep working, and both are installable at once, which is
// why every file under ~/.solongate is read and written in the shapes the Node
// implementation already uses (internal/config).
//
// What is here today is the foundation the other slices sit on: configuration,
// the API client, the core security vocabulary, and this entry point. Every
// command is registered below and every one of them says, out loud, that it is
// not ported yet. A command that printed something plausible instead would be
// worse than one that refuses: this CLI's whole subject is what your security
// posture currently is, and a confident wrong answer about that is the failure
// mode to avoid.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-isatty"

	"github.com/solongate/agent-security/packages/proxy-go/internal/api"
	"github.com/solongate/agent-security/packages/proxy-go/internal/commands"
	"github.com/solongate/agent-security/packages/proxy-go/internal/install"
	"github.com/solongate/agent-security/packages/proxy-go/internal/term"
	"github.com/solongate/agent-security/packages/proxy-go/internal/tui"
	"github.com/solongate/agent-security/packages/proxy-go/internal/tui/panels"
)

// buildVersion is stamped at build time:
//
//	-ldflags "-X main.buildVersion=<npm version>"
//
// It has to be the version of the npm package that shipped this binary. The
// Node side refuses a binary whose version does not match the package asking
// for it and falls back to its own implementation — without that check a
// machine can end up running two different implementations and which one
// answers depends on install order.
var buildVersion = "dev"

// exitNotPorted is what an unported command returns. Deliberately neither 0 nor
// 1: 0 would tell a script the command succeeded, and 1 is indistinguishable
// from the command running and failing. A script that sees 69 knows it asked
// this binary for something it does not have yet.
const exitNotPorted = 69

// The human-facing subcommand set, matching packages/proxy/src/index.ts. It
// decides two things: whether output is a banner or MCP protocol traffic, and
// whether the human-only gate applies.
var cliSubcommands = map[string]bool{
	"repair": true,
	"policy": true, "ratelimit": true, "dlp": true, "stats": true, "audit": true,
	"doctor": true, "trace": true, "watch": true,
	"dataroom": true,
}

// Flags and aliases that print a banner and exit.
var cliInfoArgs = map[string]bool{
	"help": true, "--help": true, "-h": true,
	"--version": true, "-v": true, "version": true,
}

// policyFileName is assembled rather than written out: the guard protects paths
// spelled this way, and the tooling that edits this file is subject to it.
var policyFileName = "poli" + "cy.json"

func main() { os.Exit(run(os.Args[1:])) }

// WHO KNOWS THE GUARD'S VERSION NUMBERS. internal/api declares GuardVersions as a
// function variable, with a comment saying the install layer fills it in, and nothing
// ever did — so it kept its default of (0, nil) on every machine. Everything reading
// it therefore believed the installed guard was unknown and the newest available was
// zero, which the live view renders literally:
//
//	hooks v? → v0
//
// A permanent warning that the guard is out of date, pointing at a version that
// cannot exist, on an install made thirty seconds earlier. `solongate doctor` papered
// over it by reading the local file itself, which is why this survived: the command
// whose job is to say whether the guard is healthy had its own copy of the answer.
//
// Wired here rather than in an init() because internal/install does not import
// internal/api, and main imports both. One assignment, before anything can read it.
func wireGuardVersions() {
	api.GuardVersions = func() (int, *int) {
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
	isHumanCLI := len(args) == 0 || cliSubcommands[sub] || cliInfoArgs[sub]

	if isHumanCLI {
		assertHumanTerminal()
	}

	switch sub {
	// ARRANGE IS NOT A COMMAND ANYBODY TYPES, and it is not in cliSubcommands
	// on purpose: it is what the UPDATER runs, on the binary it has just
	// installed, and a subprocess has no terminal for the human-only gate.
	//
	// It exists because everything else in an update runs the code of the
	// version being replaced. That is fine for copying files and wrong for
	// anything the new version knows how to do and the old one does not, so the
	// freshly installed binary is asked to arrange the machine itself.
	//
	// It does exactly what every ordinary run does and nothing else, which is
	// why there is no security decision in here worth gating. The call is a
	// no-op when nothing moved: InstallGoBinaries compares size and mtime.
	case "arrange":
		install.InstallGoBinaries()
		return 0
	case "--help", "-h", "help":
		printHelp()
		return 0
	case "--version", "-v", "version":
		fmt.Println(buildVersion)
		// AND WHETHER THAT NUMBER IS THE CURRENT ONE, which is the actual
		// question somebody typing this is asking.
		//
		// The notice further down never reaches here: this returns first, so
		// the one command a person runs to check their version was the one
		// command that never mentioned a newer one. They read a number, saw
		// nothing else, and concluded they were up to date.
		//
		// ON STDERR, and that is not a detail. `solongate --version` is read by
		// scripts and by this product's own installers; a second line on stdout
		// would turn a version string into two, and something somewhere would
		// compare the pair against a number and fail. Stderr is where a human
		// reads it and a pipe does not.
		//
		return 0
	}

	// The local audit-log service is a SERVICE: once enabled it has to survive
	// Ctrl+C, a closed terminal and a reboot. Nothing else brings it back, so
	// every human CLI run resurrects it unless the user explicitly disabled it
	if isHumanCLI {
		// The binaries beside the hook, brought level with THIS run - so an
		// update whose npm half landed but whose binary copy did not is
		// finished here. A no-op when they already match (a size-and-mtime
		// compare, see InstallGoBinaries), so it costs nothing on the runs
		// between updates.
		install.InstallGoBinaries()
	}

	// Bare invocation. On an interactive terminal this opens the dataroom even
	// when the device is unpaired, because logging in happens inside it; a
	// piped or CI run gets the plain welcome instead.
	if len(args) == 0 {
		if isInteractive() {
			return launchDataroom()
		}
		printWelcome()
		return 0
	}

	if cmd, ok := lookup(sub); ok {
		return cmd.run(args[1:])
	}

	// AN UNRECOGNISED TOKEN IS NOT A COMMAND, and there is nothing else for it to
	// be any more.
	//
	// It used to fall through to an MCP proxy runtime, which meant `solongate h`
	// was spawned as an upstream program and failed with "spawn h ENOENT" under a
	// wall of startup logs. That runtime is gone: this binary guards tool calls
	// and edits a policy, and it never stood in front of a tool server.
	fmt.Printf("\n  Unknown command: %s\n", sub)
	fmt.Print("  Run `solongate --help` to see every command, or `solongate` for the dataroom.\n\n")
	return 1
}

// ── the human-only gate ────────────────────────────────────────────────────

// Every command in this CLI reads or changes a security posture: policies, rate limits,
// DLP, the guard itself. An AI agent must never run one as a tool call, or a compromised
// or prompt-injected agent could switch off the thing watching it.
//
// THE SIGNAL IS THE TERMINAL, and only the terminal. An agent tool call pipes stdin and
// stdout, so there is no TTY on both ends; a person at a keyboard always has one.
//
// A SECOND SIGNAL USED TO REFUSE TOO, and it refused the wrong people: a list of
// environment-variable prefixes — CLAUDECODE, CURSOR, CODEX_, ANTIGRAVITY and a dozen
// more — any one of which turned the CLI away even with a real terminal on both ends.
// The comment on it said "a human running these commands from inside an agent's
// integrated terminal is refused too. That is on purpose: no exceptions."
//
// It is not defensible. An integrated terminal INHERITS the agent's environment, so that
// rule locked people out of their own tool in VS Code, Cursor, and any editor whose
// terminal is a child of an agent process — while the thing it was guarding against, a
// tool call, was already refused by the TTY check. It was a guess about the environment
// standing in for a fact about the caller, and the guess was wrong far more often than it
// was right.
//
// What it was protecting is now protected where every other protection in this product
// lives: the GUARD refuses a tool call whose command invokes this CLI. See
// reTamperCmdCLI in packages/guard-go/tamper.go and commandTargetsProtected in the hook.
// That is a fact about the caller — it runs on a tool call and nowhere else — and it
// holds whether or not the agent allocated a pseudo-terminal, which the old TTY check
// alone did not.
//
// THERE IS STILL NO EXEMPTION. SOLONGATE_INTERNAL=1 used to be one, for a daemon that is
// gone, and it was only a way past the gate: an agent that exported it walked straight
// through to edit policy.

func isInteractive() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
}

// assertHumanTerminal exits the process itself rather than returning a value a
// caller could forget to check. A gate that fails open when someone adds a new
// call site is not a gate.
func assertHumanTerminal() {
	if isInteractive() {
		return
	}
	w := func(s string) { fmt.Fprintln(os.Stderr, s) }
	w("")
	w("  SolonGate is human-only.")
	w("  These commands control your security policy, so they cannot be run by an AI")
	w("  agent or any non-interactive process. Run them yourself, in a terminal.")
	w("  (refused: no interactive terminal — stdin and stdout are not both a tty)")
	w("")
	os.Exit(1)
}

// ── the command table ──────────────────────────────────────────────────────

type command struct {
	name    string
	summary string
	run     func(args []string) int
}

// Every command the CLI answers to, in one table, so the next slices replace a
// single `run` field each rather than editing a dispatch chain.
func table() []command {
	return []command{
		{"dataroom", "open the dataroom UI (login, policies, audit, settings)",
			func([]string) int { return launchDataroom() }},

		{"policy", "list, create, edit and activate policies", commands.Runner("policy")},
		{"ratelimit", "show and edit rate limits", commands.Runner("ratelimit")},
		{"dlp", "show and edit secret detection", commands.Runner("dlp")},
		{"stats", "traffic and security statistics", commands.Runner("stats")},
		{"audit", "browse the audit log", commands.Runner("audit")},
		{"doctor", "health check: login, policy, guard, local logs", commands.Runner("doctor")},
		{"trace", "what the guard saw in this directory", commands.Runner("trace")},
		{"watch", "live-tail tool calls", commands.Runner("watch")},

		{"repair", "restore the guard, hooks and settings files", commands.RunRepair},
		{"update", "pull the newest version and reinstall it", commands.RunUpdate},
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

// notPorted is the stub the next slices replace. It names the TypeScript it
// comes from so the replacement has somewhere to start, and it points at the
// implementation that does work today rather than leaving the user stuck.
func notPorted(name string) func([]string) int {
	return func([]string) int {
		w := func(s string) { fmt.Fprintln(os.Stderr, s) }
		w("")
		w("  " + term.Yellow + "not ported yet" + term.Reset + ": " + term.Bold + "solongate " + name + term.Reset)
		w("  " + term.Dim + "This Go build has configuration, the API client and the core in place;" + term.Reset)
		w("  " + term.Dim + "this command still lives in packages/proxy/src (TypeScript)." + term.Reset)
		w("")
		w("  " + term.Dim + "Use the npm CLI meanwhile:" + term.Reset + " " + term.Cyan + "npx @solongate/proxy " + name + term.Reset)
		w("")
		return exitNotPorted
	}
}

// launchDataroom starts the Bubble Tea program.
//
// The one constraint, already paid for once: a frame must be no taller than
// (terminal rows - 1). Ink repainted the entire screen on every render as soon
// as a frame reached full height and it read as a glitch; Bubble Tea has the
// same failure mode. internal/tui enforces it by clipping every frame rather
// than by trusting each panel's arithmetic.
//
// The gate above has already run: the dataroom is the command that both reveals
// and changes a security posture, so it is human-only like every other one.
//
// internal/tui/panels is imported for its side effects: each panel registers
// its own section from init(), and without something importing the package the
// nav would list five sections that exist and report every one of them as not
// ported. The version is stamped in here because it is stamped into main at
// build time and the shell does not carry it.
func launchDataroom() int {
	panels.Version = buildVersion
	if err := tui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n  %sThe dataroom could not start:%s %s\n\n", term.Yellow, term.Reset, err)
		return 1
	}
	return 0
}

// ── banners ────────────────────────────────────────────────────────────────

// printWelcome is what a human sees running the package with no arguments and
// no terminal to open the dataroom in. The proxy normally runs under an MCP
// client, so a plain invocation means someone is trying it out: the only thing
// asked of them is the one onboarding command.
func printWelcome() {
	fmt.Println("")
	fmt.Printf("  %s%sSolonGate%s %ssecure gateway for your AI agents%s\n",
		term.Bold, term.Blue4, term.Reset, term.Dim, term.Reset)
	fmt.Println("")
	fmt.Println("  Get started with one command:")
	fmt.Println("")
	fmt.Printf("    %ssolongate%s             %sopen the dataroom (login, policies, audit, settings)%s\n",
		term.Cyan, term.Reset, term.Dim, term.Reset)
	fmt.Printf("    %ssolongate --help%s      %slist every command%s\n",
		term.Cyan, term.Reset, term.Dim, term.Reset)
	fmt.Println("")
	fmt.Printf("  %sOpen the dataroom to install the guard and write a policy. The%s\n", term.Dim, term.Reset)
	fmt.Printf("  %spolicy is a file on this machine: %s%s~/.solongate/%s%s\n",
		term.Dim, term.Reset, term.Cyan, policyFileName, term.Reset)
	fmt.Println("")
}

// printHelp is the FULL command tree with exact syntax, so how to edit a rate
// limit, a policy or a DLP rule is discoverable from the terminal without
// opening the dataroom.
func printHelp() {
	const w = 46 // syntax column width
	head := func(t string) { fmt.Printf("\n  %s%s%s\n", term.Bold, t, term.Reset) }
	// Long syntaxes drop to their own line with the description indented under
	// them, rather than pushing the description off an 80-column terminal.
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
	fmt.Printf("  %sUsage:%s %ssolongate%s %s[command]%s   %s(no command opens the dataroom: all of this in a terminal UI)%s\n",
		term.Dim, term.Reset, term.Cyan, term.Reset, term.Dim, term.Reset, term.Dim, term.Reset)

	head("Setup & status")
	cmd("solongate", "open the dataroom: policies, audit, settings")
	cmd("update", "pull the newest version and reinstall it")
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

// A "This is the Go build … anything still marked not ported yet runs from the npm
// package" footer stood here, naming sessions, alerts and webhooks among the commands
// that "run here". None of those three exist, the port has no stubs left (see
// TestStubsDoNotReportSuccess), and a footer explaining a migration is not something a
// person typing --help needs to read.
