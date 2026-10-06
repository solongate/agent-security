# Quickstart

Five minutes, and at the end you will have seen a tool call refused rather than
assumed it would be.

That last part is the point. A policy gate is silent when it works, so "nothing
was blocked" is never evidence on its own.

Before you start: [install it](install.md), and **open a new terminal.** Hooks
load when a session starts.

## 1. Write one rule

The whole policy, in `~/.solongate/policy.json`:

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
      "commandConstraints": { "denied": ["*push --force*", "*push -f*"] }
    }
  ]
}
```

Or the same thing without the JSON:

```bash
solongate policy deny local --command '*push --force*'
solongate policy deny local --command '*push -f*'
```

`denylist` means: allow anything no rule forbids. So this policy refuses two
command shapes and nothing else.

Two things about that rule that are worth knowing now rather than later:

- **`"enabled": true` is explicit on purpose.** A rule with the field missing is
  treated as disabled by the compiled evaluator. Always write it.
- **The patterns are globs**, matched against the whole command. `*push -f*`
  catches `git push -f origin main` because of the trailing `*`.

## 2. Check that the guard agrees with you

```bash
solongate policy active
```

That prints the resolved policy, which is what will actually decide calls. If
your file has a syntax error, this is where you find out, rather than on the
first call.

```bash
solongate doctor
```

The guard, the hooks per client, the policy file and the log folder, each with a
verdict. Everything should be healthy before you go on.

## 3. Watch, in a second terminal

```bash
solongate watch
```

It live tails tool calls as they are decided. Leave it running.

## 4. Ask an agent to do the thing

In your agent (Claude Code, Codex, OpenCode or Antigravity), in a **newly
started** session:

> Run `git push --force origin main` in this repository.

What should happen:

- The agent reports that the command was refused, and names the reason.
- `solongate watch` shows the call with a DENY and the rule id
  `no-force-push`.
- The push did not happen.

Then the other half of the test, which matters just as much:

> Run `git status`.

That should run normally. A gate that refuses everything is as broken as one
that refuses nothing, and you have now seen both answers.

## 5. Read the record

```bash
solongate audit --filter DENY
```

One line per decision, with the tool, the arguments, the decision, the reason and
how long the evaluation took. The denial was written before the agent was
answered, so it is there even if the agent crashed afterwards.

```bash
solongate trace
```

What the guard saw in this directory, allows included. When a call is decided in
a way you did not expect, this is the command that usually explains it in one
line.

## 6. Turn on secret detection

Policy rules decide calls by shape. DLP decides them by content.

```bash
solongate dlp mode block
solongate dlp enable "AWS access key"
solongate dlp enable "Anthropic key"
solongate dlp show
```

Then, in the agent:

> Read the file `.env`

If that file holds something matching an enabled pattern, the read is refused in
`block` mode. There are four modes and the difference between them is not
cosmetic:

| Mode | What it does |
| --- | --- |
| `off` | Nothing. |
| `detect` | Records the hit. Changes nothing about the call. |
| `redact` | Masks the secret so the model does not see it. The call runs. |
| `block` | Refuses the call. |

`block` is strict by design: a read of any file holding a secret is refused
outright, so the agent cannot work with that file at all. `redact` is the mode
for letting the call through with the value hidden. The full list of 70 patterns
and how to add your own is in [dlp.md](dlp.md).

## 7. Put a ceiling on the volume

```bash
solongate ratelimit set --minute 60 --hour 900 --mode block
solongate ratelimit show
```

A runaway loop stops at the cap instead of making four thousand calls.
`--mode detect` counts without blocking, which is the right first setting if you
do not yet know what your normal volume looks like. See
[rate-limits.md](rate-limits.md).

## Where to go next

- **Write the policy you actually want**: [policy.md](policy.md) has every field,
  and the matching semantics that are the usual surprise. Path patterns name
  directories, command patterns are globs, and the difference matters.
- **Lock it to a whitelist**: `solongate policy mode local whitelist` flips the
  default so that only what an ALLOW rule matches can run. Do this once you know
  what your agent legitimately needs, and expect to add rules for a while.
- **Check the record periodically**: `solongate stats`, and
  `solongate-audit` for a graded report against the OWASP Agentic Top 10. See
  [audit.md](audit.md).
- **Turn a denial into a rule**: `solongate audit whitelist <id>` takes a line
  from the audit trail and writes the rule that would have allowed it.

## If nothing was blocked

In order of how often it is the answer:

1. The session was already open when you installed. Open a new terminal.
2. `solongate doctor` reports a hook that is not registered for your client.
   `solongate repair` fixes that.
3. The pattern did not match what you thought it did. `solongate trace` shows
   the command as the guard saw it, which is the fastest way to see why.

[troubleshooting.md](troubleshooting.md) is the long version.
