# Design

What decides, what it decides about, and the path a tool call takes between
an agent reaching for something and that thing happening or not.

## Actors

| Actor | What it is |
| --- | --- |
| **Operator** | The person who installed SolonGate and owns the machine's policy. Runs the CLI and TUI, reads the audit trail, chooses the update channel. |
| **AI coding agent** | Claude Code, Codex, OpenCode, Antigravity, or any client that calls SolonGate's hook before a tool call. Never has standing access to SolonGate's own state. |
| **The guard** | The decision point. Two implementations (a Go binary, a bundled Node hook) that must agree; the hook delegates to the binary when a compatible one is present and falls back to itself otherwise. |
| **Policy engine** | Compiles the operator's `policy.json` rules to Rego and evaluates each call against them: allow or deny, scoped by path, command, filename, URL and action kind (READ/WRITE/EXECUTE/NETWORK). |
| **DLP** | Scans call arguments and, in block mode, file content on egress, against 70 built-in secret patterns plus operator-defined ones. |
| **Sandbox** | OS-level confinement invoked explicitly (`solongate run`, `solongate sandbox`): Landlock on Linux, Seatbelt on macOS, a deny list on Windows, and a closed-box mode (bubblewrap) that removes everything but the project directory. |
| **Audit store** | The append-only local log every decision is written to. |

No actor other than the operator, acting through the CLI/TUI on a real
terminal, can change policy, rate limits, protected paths or the audit
trail's own integrity; this is what tamper protection and the CLI's
terminal-gating exist to hold.

## The decision path

A tool call from the agent reaches the hook before it runs, not after:

1. **Protected paths** — if the OS itself refuses the path (a Landlock rule,
   a Seatbelt deny, an ACL), the call never reaches the layers below; this is
   enforcement the agent cannot route around by rephrasing the call.
2. **Policy evaluation** — the compiled rules decide allow/deny for this
   path, command, filename or URL, scoped to the action kind.
3. **DLP** — the call's arguments (and, for uploads in block mode, the file
   content) are scanned for secret patterns.
4. **Rate limit** — the call is checked against the per-minute/hour/day cap.
5. **Tamper check** — if the call targets SolonGate's own state (policy
   file, audit log, rate-limit counters), it is refused regardless of what
   the policy says, unless `selfProtect: false` was set from the machine's
   own file.
6. **Decision + audit** — the verdict is returned to the hook, which allows
   or blocks the call, and one entry is appended to the audit log
   regardless of outcome.

The Go guard and the Node hook run this same sequence independently; the CI
parity and layers checks exist to catch the two implementations diverging on
any step.

## Two tool-call paths, two threat models

- **In-process (the guard above)**: every tool call from a client that
  installed the hook. Catches the call before it executes, sees its
  arguments, can mask or block.
- **Out-of-process (`solongate run` / `solongate sandbox`)**: the agent
  process itself runs inside OS-level confinement. Catches what the guard
  cannot see — a script the agent writes and then executes, a path built at
  runtime — at the cost of not knowing which specific call did it.

[SECURITY.md](../SECURITY.md) states which bypasses of this path are
in scope as vulnerabilities and which classes of behaviour are not claims
this project makes.
