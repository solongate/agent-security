# External interfaces

What something outside this repository can call, read or write, and what it
can expect back.

## CLI

`solongate <subcommand>`, documented in full in the [README](../README.md#the-cli)
and in `solongate --help`. Most subcommands require a real terminal on both
stdin and stdout and are refused if a tool call invokes them; `run` and
`update` are the documented exceptions, for the reasons given there.

## Hook (agent integration)

Each supported agent (Claude Code, Codex, OpenCode, Antigravity) registers
SolonGate as a pre-tool-call hook through that agent's own hook mechanism.
The hook receives the pending call, asks the guard for a verdict, and allows
or blocks accordingly; an agent cannot reach the guard's decision logic by
any route other than this hook (a guard bypass through any other route is a
vulnerability — see [SECURITY.md](../SECURITY.md)).

## Policy file

`policy.json`, local to the machine (or a project, for a project-local
override). Rules are scoped by path, command, filename or URL, and by action
kind (`READ`, `WRITE`, `EXECUTE`, `NETWORK`). A project-local file may only
add rules; it cannot loosen or disarm machine-level ones (tamper protection),
and a policy that fails to compile does not disarm the guard — it falls back
to a deterministic evaluator (see SECURITY.md "Known limits").

## Audit trail

`~/.solongate/local-logs/solongate-audit.jsonl`, owner-only, one JSON object
per line, append-only. Current fields (`packages/core/client/types.go`,
`AuditEntry`):

| Field | Type | Meaning |
| --- | --- | --- |
| `id`, `request_id` | string | Identifiers for the entry and the originating call. |
| `session_id`, `agent_id`, `agent_name` | string or null | Which agent session made the call, where known. |
| `tool_name`, `server_name` | string | What was called and through which MCP/tool server. |
| `permission`, `trust_level` | string | The scope and trust level the call was evaluated under. |
| `decision` | string | The verdict: allow, deny, etc. |
| `matched_rule_id`, `reason` | string or null | Which policy rule decided it, and why. |
| `evaluation_time_ms` | number or null | How long the decision took. |
| `arguments_summary` | JSON | A summary of the call's arguments (not necessarily the raw arguments — see SECURITY.md on secret handling). |
| `dlp_matches` | array of string | Which DLP patterns matched, if any. |
| `rate_limit_burst` | bool | Whether this call tripped the rate limit. |
| `created_at` | string | Timestamp. |

This is a local, read-only interface for the operator (via `solongate audit`,
`watch`, `trace`, or by reading the file directly); nothing external writes
to it, and nothing in SolonGate reads it back into a decision.

## Prompt shim (Claude Code only)

A shim that masks secrets in the outbound request body on Claude Code, which
no tool-call hook can reach because it never becomes a tool call. It carries
the agent's own model credential, not SolonGate's — there is no SolonGate
account or server anywhere in this project. The hop is TLS-encrypted, scoped
by a per-run token, and fails open: a request it cannot parse is forwarded
unmasked rather than breaking the agent. Full detail in SECURITY.md.

## What is explicitly not an interface

SolonGate makes no network calls of its own (the policy engine links OPA,
which brings `net/http` along, but nothing in SolonGate calls it — see the
README). There is no remote API, no telemetry, and no account.
