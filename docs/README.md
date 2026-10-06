<p align="center">
  <img src="assets/banner.svg" alt="SolonGate: a policy gate for AI coding agents" width="760">
</p>

# SolonGate documentation

SolonGate decides whether an AI coding agent's tool call runs. The decision
happens on your machine, against a policy file you wrote, before the tool acts.

New here? Read these two, in order:

1. **[Install](install.md)**: get it on the machine, and understand what it
   wrote.
2. **[Quickstart](quickstart.md)**: a first rule, and proof that it is enforced.
   A policy gate is silent when it works, so the proof matters.

## Reference

| | |
| --- | --- |
| [Policy reference](policy.md) | Modes, every rule field, every constraint, and what each pattern actually matches. |
| [DLP and egress](dlp.md) | The 70 built in patterns, the four modes, custom expressions, the upload check, the prompt shim. |
| [Rate limits](rate-limits.md) | Caps per minute, hour and day, and the observing mode. |
| [Audit trail](audit.md) | Every field of a recorded line, where it goes, and the tools that read it. |
| [CLI reference](cli.md) | Every command, every flag, and why none of them run without a terminal. |
| [Clients](clients.md) | Claude Code, Codex, OpenCode, Antigravity: what each one supports and where its registration is written. |
| [MCP proxy](mcp-proxy.md) | The same policy in front of an MCP server, and the one layer that is not there. |
| [Architecture](architecture.md) | What runs when, which process decides, and the on disk layout. |
| [Troubleshooting](troubleshooting.md) | Nothing is blocked. Everything is blocked. The rule that reads correctly and matches nothing. |

## Answers to the questions people actually ask first

**Does anything leave my machine?** No. There is no account, no API key, no
telemetry and no service. The policy is a file, the audit trail is a file, and
the guard contains no code that can open a socket. `solongate doctor` shows you
the whole posture.

**Nothing is being blocked. Is it working?** Hooks load when a session starts, so
a terminal that was already open before you installed is not guarded. Open a new
one. If that was not it, [troubleshooting.md](troubleshooting.md) is next.

**Can the agent turn it off?** No. Every CLI command requires a terminal on both
stdin and stdout, which a tool call does not have, and the guard refuses a tool
call that invokes the CLI. The guard's own files are unreachable from a tool call
by any path spelling. A policy file inside a repository can add rules and nothing
else, because the agent can write to that file.

**Which agents does it support?** Claude Code, Codex, OpenCode and Antigravity,
plus a conservative generic adapter for anything that speaks a similar hook
protocol, and the MCP proxy for anything that speaks MCP. See
[clients.md](clients.md).

**Why two implementations?** A machine with the Go binary is decided by Go, a
machine without it by a bundled JavaScript hook. Nothing else chooses, so they
have to agree, and one conformance suite judges both. See
[architecture.md](architecture.md) and [ENGINEERING.md](../ENGINEERING.md).

## For contributors

- [CONTRIBUTING.md](../CONTRIBUTING.md): setup, the testing rules, how a change
  lands.
- [ENGINEERING.md](../ENGINEERING.md): why it is built this way, and the failure
  modes that cost somebody a day.
- [TESTING.md](../TESTING.md): the manual run sheet, for the parts only a person
  can test.
- [RELEASING.md](../RELEASING.md): how a version becomes installable.
- [SECURITY.md](../SECURITY.md): what is in scope, and how to report a bypass.
