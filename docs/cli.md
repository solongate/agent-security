# CLI reference

```
solongate [command]
```

No command opens the dataroom: all of this in a terminal UI.

`solongate <command> help` prints the syntax for one command.
`--json` works on most read commands.

## It will not run without a terminal

Every command here reads or changes a security posture: policies, rate limits,
DLP, the guard itself. So:

- The CLI requires a terminal on **both** stdin and stdout. An agent tool call
  pipes both, so it has no terminal on either end. A person at a keyboard always
  does.
- The **guard** refuses a tool call whose command invokes this CLI, which is a
  fact about the caller rather than a guess about the environment.

A prompt injected agent must not be able to switch off the thing watching it, and
**there is no environment variable that exempts anything from this.** There was
one once, for a daemon that no longer exists, and all it did was give an agent
that exported it a clear path to editing the policy.

A second check used to refuse too, and it refused the wrong people: a list of
environment variable prefixes (`CLAUDECODE`, `CURSOR`, `CODEX_`, `ANTIGRAVITY`
and a dozen more), any one of which turned the CLI away even with a real terminal
on both ends. An integrated terminal inherits the agent's environment, so that
rule locked people out of their own tool inside VS Code and Cursor, while the
thing it was guarding against was already refused by the terminal check. It is
gone.

The refusal says so plainly:

```
  SolonGate is human-only.
  These commands control your security policy, so they cannot be run by an AI
  agent or any non-interactive process. Run them yourself, in a terminal.
  (refused: no interactive terminal, stdin and stdout are not both a tty)
```

The one exception is `solongate-audit`, a separate binary that only reads
transcripts and writes a report. See [audit.md](audit.md).

## Setup and status

| | |
| --- | --- |
| `solongate` | Open the dataroom: policies, audit, settings. |
| `solongate update` | Pull the newest version and reinstall it. |
| `solongate repair` | Restore the guard, the hooks and the settings files if they were deleted or disarmed. |
| `solongate doctor` | Health check: policy, guard, hooks, local logs. |
| `solongate doctor --json` | The same check, machine readable. |
| `solongate trace [--limit N]` | What the guard saw in this directory, allows included. Default 20. |
| `solongate trace --json` | The raw records. |
| `solongate --version` | The version. A newer one, if there is one, is reported on stderr, so a pipe still gets exactly one line. |
| `solongate --help` | The full command tree. |

### `update`

Runs `git pull --ff-only` in the checkout the install was made from, then
rebuilds and reinstalls from it. The install writes that path down, so there is
no directory to remember.

It refuses to run with uncommitted changes in that checkout rather than
overwriting them.

### `repair`

Idempotent. Reinstalls the guard binaries, rewrites every client registration and
restores the settings files. This is the command for "doctor says a hook is
missing" and for "I deleted something in `~/.solongate`".

## Policies

| | |
| --- | --- |
| `policy list` | List all policies. |
| `policy create <name>` | Create a new empty policy. |
| `policy delete <id>` | Delete a policy. |
| `policy show <id>` | Show one policy: its rules, its mode, and what each rule matches. |
| `policy allow <id> [--command\|--path\|--filename\|--url <val>]` | Append an ALLOW rule. |
| `policy deny <id> [--command\|--path\|--filename\|--url <val>]` | Append a DENY rule. |
| `  --permission READ,WRITE,EXECUTE,NETWORK` | Scope an allow or deny to a class of call. |
| `policy mode <id> <denylist\|whitelist>` | Switch deny by default and allow by default. |
| `policy rule <id> <ruleId> <enable\|disable>` | Turn one rule on or off without deleting it. |
| `policy revoke <id> <ruleId>` | Remove a rule. |
| `policy activate <id>` | Pin the active policy. |
| `policy activate --off` | Enforce nothing. |
| `policy active` | Show the resolved active policy. |

`local` works as `<id>` for the machine's own policy.

```bash
solongate policy deny local --command '*push --force*'
solongate policy allow local --path 'src*' --permission WRITE
solongate policy mode local whitelist
solongate policy show local
```

Patterns are trimmed before they are stored, and a pattern of nothing but spaces
is refused rather than kept. A trailing space is invisible in the editor that
made it and produces the worst kind of rule: one that reads correctly everywhere
and enforces nothing.

`--permission` only belongs on a rule about files or commands, and a typo in it
is refused rather than stored.

Full semantics: [policy.md](policy.md).

## Rate limits

| | |
| --- | --- |
| `ratelimit show` | Current limits, and the change history. |
| `ratelimit set --minute N [--hour N] [--day N] [--mode off\|detect\|block]` | Edit the limits. Unset fields keep their value. |
| `ratelimit history` | Recent limit changes. |

See [rate-limits.md](rate-limits.md).

## DLP

| | |
| --- | --- |
| `dlp show` | Current mode, and which patterns are enabled. |
| `dlp mode <off\|detect\|redact\|block>` | `detect` records, `redact` masks, `block` refuses. |
| `dlp enable <pattern>` | Enable a built in pattern, by name. |
| `dlp disable <pattern>` | Disable one. |
| `dlp add-custom --name X --re <glob>` | Add a custom pattern. |
| `dlp remove-custom <name>` | Remove one. |

Custom patterns are globs, not regular expressions, despite the flag name. See
[dlp.md](dlp.md).

## Monitoring

| | |
| --- | --- |
| `audit [--filter ALLOW\|DENY] [--tool <substr>] [--signal dlp\|ratelimit]` | Browse the audit trail. |
| `audit [--search <text>] [--agent-name <name>] [--limit N]` | The same, narrowed. |
| `audit whitelist <logId> [--scope exact\|tool]` | Turn a denied call into an ALLOW rule. |
| `audit block <logId> [--scope exact\|tool]` | Turn a call into a DENY rule. |
| `watch [--filter DENY] [--tool <substr>] [--json]` | Live tail tool calls. Ctrl+C to stop. |
| `stats` | Overview: totals and recent activity. |
| `stats timeseries [--period 24h\|7d\|30d\|all]` | Calls over time. |
| `stats drift [--days N]` | Denials rising or falling against the previous window. |
| `trace [--limit N] [--json]` | What the guard saw in this directory. |

`--scope` defaults to `exact`. A whitelist that widened to the whole tool by
default would be a very quiet way to disarm a policy.

`--filter DENY` also matches rows spelled `DENIED`: the guard writes one
spelling and the audit trail the other, and a filter that dropped either would
show half the denials.

See [audit.md](audit.md).

## The MCP proxy

```bash
solongate -- <upstream command>
```

Not a subcommand: anything after `--` is the upstream MCP server to wrap. This
path is **not** gated to humans, because it is launched by a client and never
edits security configuration. Gating it would mean the guard cannot run under the
agent it is guarding.

An unrecognised token is not treated as a program to run. `solongate h` says
"Unknown command" rather than failing with `spawn h ENOENT` under a wall of proxy
startup logs. Only an explicit `--` or a proxy flag enters that runtime.

See [mcp-proxy.md](mcp-proxy.md).

## The audit report

A separate binary, documented in [audit.md](audit.md):

```bash
solongate-audit [--detailed] [--logs N] [--watch] [--json]
solongate-audit --export json|csv|html|pdf|all
solongate-audit --search | --list-dirs | --add-dir <path> | --remove-dir <path>
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | The command ran and failed, including a usage error, and the refusal when there is no terminal. |
| 69 | This binary does not have that command yet. Deliberately neither 0 nor 1: a script that sees 69 knows it asked for something unported rather than something broken. |

## Why some commands exist at all

Three of them answer questions that were previously unanswerable without reading
source:

- **`doctor`** exists because every signal a user could see was indirect. It
  reports the policy file, the guard binary and its version, the hook
  registration per client, and the log folder, each with a verdict.
- **`trace`** exists because a rule can read correctly and match nothing. It
  shows the call as the guard saw it, after path resolution and glob expansion.
- **`update`** exists because `doctor` kept recommending an update and there was
  no command to perform one.
