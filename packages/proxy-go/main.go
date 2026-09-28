// The SolonGate CLI, in Go.
//
// This is the SECOND implementation of the CLI, standing beside the npm package
// rather than replacing it. @solongate/proxy keeps its name, its install command
// and its update path; nothing in this binary may require a change over there to
// keep working, and both are installable at once, which is why every file under
// ~/.solongate is read and written in the shapes the Node implementation already
// uses (internal/config).
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

	"github.com/codeyevsky/solongate/proxy/internal/commands"
	"github.com/codeyevsky/solongate/proxy/internal/install"
	"github.com/codeyevsky/solongate/proxy/internal/logsserver"
	"github.com/codeyevsky/solongate/proxy/internal/proxy"
	"github.com/codeyevsky/solongate/proxy/internal/term"
	"github.com/codeyevsky/solongate/proxy/internal/tui"
	"github.com/codeyevsky/solongate/proxy/internal/tui/panels"
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
	"repair": true, "logs-server": true, "local-logs": true,
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

func run(args []string) int {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	isHumanCLI := len(args) == 0 || cliSubcommands[sub] || cliInfoArgs[sub]

	// The MCP proxy runtime is NOT gated: it is launched by a client, it never
	// edits security configuration, and gating it would mean the guard cannot
	// run under the agent it is guarding.
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
	// — without this a machine that rebooted quietly stops recording and
	// nothing says why. Skipped for the command that manages it,
	// which would otherwise start a server on its way to stopping one.
	if isHumanCLI && sub != "logs-server" && sub != "local-logs" {
		logsserver.Ensure()
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

	// An unrecognised token must NOT be spawned as an upstream program. It used
	// to be: `solongate h` failed with "spawn h ENOENT" under a wall of proxy
	// startup logs. Only an explicit `--` separator or a proxy flag enters the
	// runtime below.
	hasSeparator := false
	for _, a := range args {
		if a == "--" {
			hasSeparator = true
			break
		}
	}
	if !hasSeparator && !strings.HasPrefix(sub, "-") {
		fmt.Printf("\n  Unknown command: %s\n", sub)
		fmt.Print("  Run `solongate --help` to see every command, or `solongate` for the dataroom.\n\n")
		return 1
	}

	return runProxyRuntime(args)
}

// ── the human-only gate ────────────────────────────────────────────────────

// Every command in this CLI reads or changes a security posture: policies, rate
// limits, DLP, the guard itself. An AI agent must never be able to run them as
// a tool call, or a compromised or prompt-injected agent could simply switch
// off the thing watching it.
//
// Two independent signals, and either one refuses:
//
//  1. No interactive terminal. An agent tool call pipes stdin and stdout, so
//     there is no TTY on both ends. A person at a terminal always has one.
//  2. A known agent marker in the environment, even if a TTY somehow exists.
//
// The one exemption is our own detached logs-server daemon, which sets
// SOLONGATE_INTERNAL=1 and is spawned by this CLI rather than by an agent.
//
// A consequence worth stating: whoever is porting this cannot run these
// commands end to end from an agent session. That is the feature working.
var agentEnvPrefixes = []string{
	"CLAUDECODE", "CLAUDE_CODE", "CLAUDE_AGENT",
	"ANTIGRAVITY", "CORTEX_", "CASCADE_", "WINDSURF", "JETSKI", "EXA_",
	"GEMINI_CLI", "GEMINI_SESSION", "GEMINI_PROJECT", "GEMINI_CWD",
	"CURSOR", "AIDER", "OPENAI_CODEX", "CODEX_", "OPENCLAW", "REPLIT", "DEVIN",
}

// agentMarker prefix-matches rather than comparing exactly, so the specific
// variable a given agent leaks into a tool subprocess does not have to be known
// — only the family. Antigravity leaks many ANTIGRAVITY_/CORTEX_/GEMINI_ names
// and which one arrives varies by version.
//
// A human running these commands from inside an agent's integrated terminal is
// refused too. That is on purpose: no exceptions.
func agentMarker() string { return agentMarkerIn(os.Environ()) }

// Split from agentMarker so the matching can be tested. A test cannot unset the
// agent variables of the process running it, and this gate is the last thing
// that should be verified only by reading it.
func agentMarkerIn(env []string) string {
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		k := kv[:eq]
		for _, p := range agentEnvPrefixes {
			if k == p || strings.HasPrefix(k, p) {
				return k
			}
		}
	}
	return ""
}

func isInteractive() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd())
}

// assertHumanTerminal exits the process itself rather than returning a value a
// caller could forget to check. A gate that fails open when someone adds a new
// call site is not a gate.
func assertHumanTerminal() {
	if os.Getenv("SOLONGATE_INTERNAL") == "1" {
		return
	}
	marker := agentMarker()
	if isInteractive() && marker == "" {
		return
	}
	w := func(s string) { fmt.Fprintln(os.Stderr, s) }
	w("")
	w("  SolonGate is human-only.")
	w("  These commands control your security policy, so they cannot be run by an AI")
	w("  agent or any non-interactive process. Run them yourself, in a terminal.")
	if marker != "" {
		w("  (refused: agent environment detected via " + marker + ")")
	} else {
		w("  (refused: no interactive terminal)")
	}
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
		// Two names for one service, as the npm package has them. `local-logs`
		// is the older spelling and is kept because instructions carrying it are
		// still in circulation.
		{"logs-server", "the local audit-log service", logsserver.Run},
		{"local-logs", "the local audit-log service", logsserver.Run},
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

// runProxyRuntime is entered only for a genuine proxy invocation: an upstream
// command after `--`, or proxy flags.
//
// internal/proxy is the port of packages/proxy/src/proxy.ts: both MCP ends, the
// interception pipeline, the audit trail and the bidirectional policy sync. The
// one thing it does not carry is the engine that decides ALLOW or DENY, which
// lives in packages/guard-go and cannot be imported from this module yet — so
// proxy.DefaultEvaluator returns nil, and the runtime refuses to start rather
// than starting and denying everything. Replacing that one function is what
// turns this on; see the comment on it.
func runProxyRuntime(args []string) int {
	return proxy.Run(args, proxy.DefaultEvaluator())
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
	cmd("solongate", "open the dataroom UI (login, policies, audit, settings)")
	cmd("update auto on|off", "background auto-update (default off — on macOS npm -g often needs sudo)")
	cmd("repair", "restore the guard + hook + settings files if they were deleted or disarmed")
	cmd("doctor", "health check: login, policy, guard, local logs")
	cmd("trace [--limit N]", "what the guard saw in this directory, allows included")
	cmd("doctor --json", "the same health check as machine-readable JSON")
	cmd("browser status", "the Shadow AI agent, and which browsers ask it")
	cmd("browser start|stop", "run or stop the agent that answers a browser")
	cmd("browser enable firefox|edge|chrome", "point a browser at the agent")
	cmd("logs-server start", "start the local audit-log service for the dashboard (background)")
	cmd("logs-server stop", "stop AND disable it (only this makes it stay down)")
	cmd("logs-server status", "show the local audit-log service status")

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
	cmd("policy dry-run <id|file.json> [--mode denylist|whitelist]", "replay recent traffic against rules")

	head("Rate limits")
	cmd("ratelimit show", "current limits + change history")
	cmd("ratelimit set --minute N [--hour N] [--day N] [--mode off|detect|block]", "edit limits (unset fields kept)")
	cmd("ratelimit history", "recent limit changes")

	head("DLP (secrets)")
	cmd("dlp show", "current mode + enabled patterns")
	cmd("dlp mode <off|detect|block>", "set enforcement mode")
	cmd("dlp enable <pattern>", "enable a built-in pattern")
	cmd("dlp disable <pattern>", "disable a built-in pattern")
	cmd("dlp add-custom --name X --re <regex>", "add a custom pattern")
	cmd("dlp remove-custom <name>", "remove a custom pattern")

	head("Monitoring")
	cmd("audit [--filter ALLOW|DENY] [--tool <s>] [--signal dlp|ratelimit] [--limit N]", "browse the audit log")
	cmd("audit whitelist <logId> [--scope exact|tool]", "turn a denial into an ALLOW rule")
	cmd("audit block <logId> [--scope exact|tool]", "turn a call into a DENY rule")
	cmd("stats [timeseries|drift]", "traffic & security statistics")
	cmd("watch [--filter DENY] [--tool <s>]", "live-tail tool calls (Ctrl+C to stop)")
	cmd("sessions [--all]", "live agent-session feed (calls, denies, trust)")
	cmd("session <id>", "one session's detail")

	printPortStatus()

	fmt.Println("")
	fmt.Printf("  %sAdd %s%s--json%s%s to most read commands for machine output.%s\n",
		term.Dim, term.Reset, term.Cyan, term.Reset, term.Dim, term.Reset)
	fmt.Printf("  %sDetails for a command: %s%ssolongate <command> help%s\n",
		term.Dim, term.Reset, term.Cyan, term.Reset)
	fmt.Println("")
}

// printPortStatus is temporary and goes away with the last stub. While this
// build still has stubs in it, the help text above must not read as a list of
// things that work.
func printPortStatus() {
	fmt.Println("")
	fmt.Printf("  %sThis is the Go build. The management commands (policy, ratelimit, dlp,%s\n", term.Dim, term.Reset)
	fmt.Printf("  %sstats, audit, sessions, session, doctor, watch, alerts, webhooks) run%s\n", term.Dim, term.Reset)
	fmt.Printf("  %shere. Anything still marked \"not ported yet\" runs from the npm package:%s\n", term.Dim, term.Reset)
	fmt.Printf("  %s%snpx @solongate/proxy <command>%s\n", term.Reset, term.Cyan, term.Reset)
}
