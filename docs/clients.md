# Clients

Four agents are supported, plus a conservative fallback for anything else, plus
the MCP proxy for anything that speaks MCP instead of running hooks.

The clients differ in what they can do, and the differences are not cosmetic:
they decide whether a secret can be masked or has to be blocked, and whether an
allowed call gets recorded at all. This page is the table to check before you
conclude something is broken.

## Capabilities

| Client | Decides calls | Post tool stage | Can mask tool output |
| --- | --- | --- | --- |
| Claude Code | yes | yes | **yes** |
| Codex | yes | yes | no |
| OpenCode | yes | yes | no |
| Antigravity | yes | **no** | no |
| Anything else (generic) | yes | no | no |

### What "can mask tool output" changes

Masking a secret that lives inside a file the agent reads needs somewhere to
rewrite the result.

- **Yes**: the post tool stage rewrites the tool's output, and `redact` mode
  masks there.
- **No**: the file is redacted into a temporary copy before the tool runs, with
  the read pointed at the copy. Any masking that cannot be applied becomes a
  **block** instead. The safe direction, and a different experience.

In `block` mode none of this matters: the pre tool scan runs on every client, and
a file holding a secret is refused everywhere. That was not always true, and it
is the most recent behaviour fix in this project: the scan was gated on the
client lacking output rewriting, so on Claude Code `block` mode quietly behaved
like `redact`.

### What "post tool stage" changes

It is what files the audit row for a call that was **allowed**.

- **Yes**: the post tool hook writes the allow rows.
- **No**: the only records are the ones the guard writes itself, so anything
  meant to be observed rather than blocked is recorded by the guard or it is
  recorded nowhere.

Capabilities are asked about as capabilities. No layer in the guard branches on
which client is running: there are exactly two vendor neutral shapes, and one
adapter per client translates both ways.

## Claude Code

| | |
| --- | --- |
| Registration | `~/.claude/settings.json` |
| Backup | `~/.claude/settings.solongate.bak` |
| Events | `PreToolUse` (the guard), `PostToolUse` (the audit hook), `Stop` (token usage) |
| Prompt shim | **yes**, see below |

The fullest integration: it decides calls, records allows, and can mask a
secret inside a file the agent read.

### The prompt shim

The guard sees tool calls. It does not see your typed prompt, or what the client
sweeps into context on its own.

So the installer adds a marked block to your shell configuration that redefines
`claude` as a function routing through a local proxy, which masks the request
body on its way out. The response comes back untouched. It uses the same
patterns as everything else, your custom ones included.

- The block is marked, so installing twice cannot leave two definitions.
- An install that cannot find `claude` on `PATH` is not a failed install: the
  shim is simply not written.
- It is a shell function, so it applies to new shells. Open a new terminal.

This is the only client with a prompt path integration.

## Codex

| | |
| --- | --- |
| Registration | `~/.codex/hooks.json`, honouring `CODEX_HOME` |
| Backup | `~/.codex/hooks.solongate.bak` |
| Also read | `~/.codex/config.toml`, which carries the hook **trust** state Codex manages itself |
| Decision dialect | the same as Claude Code |

Codex sends **every file edit as one tool call named `apply_patch`**, with the
target paths inside the patch text rather than in a field. Two consequences:

- The permission classifier maps `apply_patch` to `WRITE` explicitly, because no
  substring in the tool name says so. Without that, every Codex file edit would
  classify as a READ and every WRITE scoped rule would miss it.
- The adapter lifts the paths out of the patch text onto the neutral fields, so
  path and filename rules apply to them.

`config.toml` is read and not rewritten. It is the user's file and it holds state
Codex owns.

## OpenCode

| | |
| --- | --- |
| Registration | `~/.config/opencode/plugins/solongate.js`, honouring `XDG_CONFIG_HOME` |
| Install | dropping the file **is** the installation. Deleting it is the uninstall. |

OpenCode has no subprocess hook contract at all. A plugin runs in process and
refuses a call by throwing. The plugin SolonGate installs spawns the guard with a
Claude shaped payload and reads the Claude dialect back, so both halves are
reused as is and only the identity differs.

`tool.execute.after` does run, and it runs the audit hook, so allow rows are
recorded. Whether writing to the result there changes what the model sees is
**untested**, so the output masking capability is declared false: claiming a
capability that has not been proven would let a secret through masked in name
only.

Measured on 1.18.10, both `plugin/` and `plugins/` are scanned. The installer
writes the documented one.

## Antigravity

| | |
| --- | --- |
| Registration | `~/.gemini/config/hooks.json` |
| Backup | `~/.gemini/config/hooks.solongate.bak` |
| Group key | `solongate-guard`, one named group that SolonGate owns |
| Payload | nested, and a decision dialect of its own |

**No post tool stage.** Its output is ignored, so:

- Allow rows are written by the guard itself, including detect mode hits that
  would otherwise be recorded nowhere.
- `redact` mode works through the pre tool temporary copy, and masking that
  cannot be applied is a block.

Its edit tool is `replace_file_content`, which is why `replace`, `patch` and
`modify` are in the WRITE list of the permission classifier. Before they were,
that tool classified as a READ, so `deny writes under config/` left the agent
free to rewrite `config/` all day.

## Anything else

An unknown client gets the `generic` adapter, which:

- Parses by payload **shape** rather than adopting another client's rules.
- Denies with the most widely enforced signal available: a JSON refusal and exit
  code 2.
- Assumes the **weaker** capability on both counts, so masking fails closed and
  the guard records its own rows.

A client that needs anything else gets its own entry. Adding one is adding a
single table entry with two functions: `Parse` maps the client's raw payload onto
the neutral call, `Emit` maps the neutral decision onto that client's wire format
and returns the process exit code.

`Emit` returns the exit code rather than exiting, so the process controls its own
teardown. That is not a style preference: exiting inside a settling network call
on Windows replaced exit code 2 with an abort, and Claude Code then ran the tool.

## MCP servers

For an agent that speaks MCP rather than running hooks:

```bash
solongate -- <upstream command>
```

Same evaluator, same policy, and all the layers except egress. See
[mcp-proxy.md](mcp-proxy.md).

## Checking your own machine

```bash
solongate doctor
```

It reports the registration per client, with the version. `solongate repair`
rewrites any that are missing or disarmed.

And the thing that is almost always the answer when nothing is being blocked:
**hooks load when a session starts.** A client that was already running is
operating under whatever was registered when it launched. Quit it and start
again.
