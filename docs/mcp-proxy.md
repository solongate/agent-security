# The MCP proxy

For an agent that speaks MCP rather than running hooks, the same policy goes in
front of an MCP server's tool calls:

```bash
solongate -- <upstream command>
```

Anything after `--` is the upstream server. It decides with the same evaluator
the guard uses, so a policy means one thing in both places.

This path is **not** gated to humans. It is launched by a client, it never edits
security configuration, and gating it would mean the guard cannot run under the
agent it is guarding.

## Registering it

Wherever your client declares MCP servers, wrap the command it was going to run:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "solongate",
      "args": ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/work"]
    }
  }
}
```

The upstream keeps its own arguments. SolonGate adds nothing to them and does not
rewrite the protocol.

## Which layers are in force

It prints them, every time it starts:

```
Layer: rate limit 60/min (from the policy file)
Layer: DLP on, arguments scanned for secrets
```

| Layer | On this path |
| --- | --- |
| Policy rules | **yes**, the same evaluator and the same policy file |
| Rate limiting | **yes**, from `--global-rate-limit` or from the policy file |
| DLP | **yes**, the same scanner and the same pattern list, including the de-obfuscating views |
| Egress, the upload check | **no**, see below |

The rate limit reads from the policy file now. It used to come only from
`--rate-limit` and `--global-rate-limit`, so a machine that had set one in its
policy got none here.

DLP uses the same scanner as the guard, which means a secret split across string
literals or base64 encoded does not walk past it either. See [dlp.md](dlp.md).

## Why egress is not here

The egress check reads the files a transfer command would upload and scans their
contents. To do that it resolves the paths in the command against the **agent's**
working directory.

A proxy in front of a tool server has no such directory. The paths in a call
belong to whatever machine the upstream runs on, so a check that read them here
would be reading the wrong machine's files.

So it is a decision rather than an omission, and the proxy says it out loud when
your policy configures egress:

```
NOTE: egress protection is configured and applies to the guard hooks, not to
this path: the files a transfer command would upload live on the agent's
machine, and a proxy in front of a tool server has no agent working directory
to resolve them against.
```

Somebody can configure `dlpBlock`, watch it work on their agent's tool calls, put
an MCP server behind this proxy and reasonably assume the same protection is
there. A difference a person cannot see is the kind that gets found the expensive
way, so it is named at startup rather than left to whoever reads the README.

## Flags

| Flag | What it does |
| --- | --- |
| `--policy <path>` | A policy file for this proxy, instead of the machine's. |
| `--policy-id <id>`, `--id <id>` | Which policy to use. |
| `--name <name>`, `--agent-name <name>` | What this proxy calls itself in the audit trail. |
| `--rate-limit <n>` | Per client rate limit. |
| `--global-rate-limit <n>` | Across all clients. |
| `--upstream-url <url>` | An HTTP upstream instead of a command. |
| `--upstream-transport <t>` | Which transport to speak to it. |
| `--port <n>` | Listen port, when serving over HTTP. |
| `--config <path>` | A configuration file. |
| `--verbose` | More startup and decision logging. |

An unrecognised token is **not** spawned as an upstream program. `solongate h`
answers "Unknown command" rather than failing with `spawn h ENOENT` under a wall
of proxy startup logs. Only an explicit `--` or a proxy flag enters this runtime.

## Failing closed

With no policy loaded, the evaluator **denies**.

An evaluator that allowed until something remembered to load a policy would make
"the policy failed to load" indistinguishable from "the policy permits this",
which is the one failure direction this project does not accept.

A policy whose mode is `whitelist` keeps that mode here. The MCP lineage carried
no mode field of its own, so it is read back out of the rules payload rather than
defaulting to `denylist`, which would enforce a whitelist policy as a denylist.

## Parity with the guard

There is a conformance case, `proxy-parity`, asserting that the proxy and the
guard reach the same verdict case for case, and `reason-parity` asserting that
one policy explains itself the same way in both. They exist because the two
paths once shared no evaluator: the proxy enforced the policy rules and the rate
limit and scanned nothing for secrets, while the same machine's hooks did both.

If you find a call the guard refuses and the proxy allows, outside the documented
egress gap, that is a bug worth reporting. If it leaks a secret, report it
privately: [SECURITY.md](../SECURITY.md).
