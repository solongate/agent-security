# SolonGate

A policy gate for AI coding agents. It sits in front of every tool call an agent
makes — every shell command, every file read, every write — and decides whether
it runs, against rules you wrote.

Everything is on the machine. The policy is a file, the audit trail is a file, and
nothing leaves: there is no service to sign in to, no account, and no code left in
the guard that can open a socket.

Supported agents: **Claude Code**, **Codex**, **OpenCode**, **Antigravity**.

## What is here

| | |
| --- | --- |
| `packages/guard-go` | The guard, in Go. Runs on every tool call and decides. |
| `packages/proxy` | The CLI, the TUI and the hooks (npm `@solongate/proxy`, command `solongate`). |
| `packages/proxy-go` | The same CLI in Go, which is what ships as the binary. |
| `packages/sgpolicy` | The Go policy engine: JSON rules → Rego, evaluated in process. |
| `packages/sgshared` | Shapes more than one program has to agree about. |

Two implementations of everything, deliberately. Which one decides a call depends
only on whether a machine has the Go binary, so they have to agree — and the
conformance suite runs against both to make sure they do.

## Getting started

```bash
npm i -g @solongate/proxy
solongate                    # the dataroom; install the guard from Settings
```

Start a new terminal afterwards. Hooks load when a session starts, so
already-open terminals are not guarded yet.

## Write a policy

`~/.solongate/policy.json`:

```json
{
  "mode": "denylist",
  "rules": [
    {
      "id": "no-force-push",
      "description": "Rewriting shared history is not an agent's decision",
      "effect": "DENY",
      "priority": 10,
      "enabled": true,
      "toolPattern": "*",
      "minimumTrustLevel": "UNTRUSTED",
      "commandConstraints": { "denied": ["*push --force*", "*push -f*"] }
    }
  ]
}
```

The next tool call is decided against it: `git push --force` and `git push -f` are
refused from that point, `git push` is not. `solongate policy deny local --command '*push --force*'` writes the same thing
without the JSON.

**`denylist` allows what no rule forbids. `whitelist` refuses what no ALLOW rule
matches.** A DENY always wins over an ALLOW, whatever the priorities say — the
priority orders rules of the same effect.

A `policy.json` beside your working directory is read when the machine has no file
of its own. It may add **rules and nothing else**: it lives in a repository the
agent can write to, so `selfProtect` and `security` are ignored there.

## The other three layers

They live in the same file. Wrap the policy and add `security`:

```json
{
  "policy": { "mode": "denylist", "rules": [] },
  "security": {
    "rateLimit": { "perMinute": 60, "perHour": 900, "perDay": 5000 },
    "dlpBlock": { "patterns": ["AWS access key", "Anthropic key"], "custom": [] },
    "localLogs": { "path": "/where/the/audit/trail/goes" }
  }
}
```

- **Rate limiting** — a cap per minute, hour or day. `rateLimitObserve` instead of
  `rateLimit` counts without blocking.
- **DLP** — when a call carries a secret, refuse it. `dlpBlock` refuses and masks;
  `dlpRedact` alone masks without refusing. 70 built-in patterns, and `custom`
  takes globs of your own. `solongate dlp` lists the names.
- **Tamper protection** — the guard's own state is unreachable from a tool call, by
  every route, and cannot be switched off by a policy in a repository. On by
  default; `"selfProtect": false` beside `policy` turns it off.

## Where the record goes

`~/.solongate/local-logs/solongate-audit.jsonl`, owner-only, one JSON object per
line. The guard writes a denial before it answers the agent; the post-tool hook
writes the rest.

Recording is not optional — there is nowhere else for an entry to go — so
`localLogs.path` chooses the folder and nothing more. `solongate audit` reads the
file, and `solongate audit whitelist <id>` turns a line of it into a rule.

## The CLI

```
solongate                    the dataroom (policies, audit, settings)
solongate policy             list, create and edit the policy
solongate ratelimit          show and edit the rate limit
solongate dlp                show and edit secret detection
solongate audit              browse the audit trail
solongate watch              live-tail tool calls
solongate trace              what the guard saw in this directory
solongate stats              what has been recorded
solongate doctor             health check: policy file, guard, local logs
solongate repair             restore the guard, hooks and settings files
```

Every one of these reads or changes a security posture, so they refuse to run
without an interactive terminal and refuse when an agent marker is in the
environment. A prompt-injected agent must not be able to switch off the thing
watching it — and there is no environment variable that exempts anything from that
check.

## The MCP proxy

`solongate -- <upstream command>` puts the same policy in front of an MCP server's
tool calls, for an agent that speaks MCP rather than running hooks. It decides with
the same evaluator the guard uses (`packages/proxy/hooks/policy-eval.mjs`), so a
policy means one thing in both places.

## Developing

Go 1.25 and Node 20+.

```bash
pnpm install

cd packages/guard-go && go test ./...
cd packages/proxy-go && go test ./...
cd packages/sgpolicy && go test ./...
cd packages/proxy    && npx tsc --noEmit -p tsconfig.json
```

**The conformance suite is the contract.** It runs the guard as a subprocess, feeds
it a client payload, and asserts on the exit code, the files touched and what a
stub server does NOT receive — without importing any implementation's internals.

```bash
cd packages/proxy
npx tsc -p tsconfig.json      # once, or after a change: the suite imports dist/
npm run build:hooks           # and the bundled hook it drives

node test/run-all.mjs                                   # the Node hook
SG_HOOK=$PWD/../guard-go/solongate-guard \
  node test/run-all.mjs                                 # and the Go binary
```

Both, every time. The two implementations are meant to be indistinguishable, and
every divergence found so far was found by running the same suite against each:
the tamper globs disagreeing about `*`, the DLP list running 14 patterns against
70, and an ALLOW beating a DENY in the Rego chain.

A change to the guard is correct exactly when this passes unchanged, against both.
Every case in it exists because the behaviour it pins was once wrong, and the
comments say which.

[ENGINEERING.md](ENGINEERING.md) is the rest: why Go, where the guard stands, and
the failure modes that cost somebody a day.

## Licence

MIT. See [LICENSE](LICENSE).
