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
  or keep it from the model.
- **Rate limiting** — cap tool calls per minute, hour or day.
- **Tamper protection** — the guard's own state cannot be edited by a tool call,
  by any route.

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
owner-only. With no service configured there is nothing to send anywhere and no
attempt is made.

## A service, if a team needs one

Optional. What it adds is one place to keep the policy and the audit log for many
machines, and sign-in against your own identity provider so it knows who is
asking. `SOLONGATE_API_URL` points a machine at it; it defaults to
`http://127.0.0.1:3002`. The decision still happens on each machine.

The server is in this repository (`apps/system`) and runs on infrastructure you
operate. There is no hosted service.

## The CLI

```
solongate                    the dataroom (policies, audit, settings)
solongate doctor             what is installed, and whether it is enforcing
solongate trace              watch decisions as they happen
```

## Licence

See the repository root.
