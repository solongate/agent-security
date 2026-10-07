<div align="center">
  <img src="docs/assets/hero.png" alt="SolonGate. For AI agents to execute tools safely. Make agents secure again." width="900">
</div>

<p align="center">
  <a href="https://github.com/codeyevsky/solongate-oss/actions/workflows/ci.yml"><img src="https://github.com/codeyevsky/solongate-oss/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/codeyevsky/solongate-oss/releases"><img src="https://img.shields.io/github/v/release/codeyevsky/solongate-oss?color=3ba9ee&label=release" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="license: Apache 2.0"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/go-1.25-00ADD8.svg" alt="Go 1.25"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-20%2B-339933.svg" alt="Node 20+"></a>
</p>

<p align="center">
  <a href="CONTRIBUTING.md"><b>Contributing</b></a> ·
  <a href="SECURITY.md"><b>Security</b></a>
</p>

---

SolonGate sits in front of every tool call an AI coding agent makes, every shell
command, every file read and every write, and decides whether it runs against
rules you wrote.

Everything stays on the machine. The policy is a file, the audit trail is a
file, and the guard contains no code that can open a socket. No account, no
telemetry.

Agents: **Claude Code**, **Codex**, **OpenCode**, **Antigravity**.

<div align="center">
  <img src="docs/assets/flow.gif" alt="A tool call from an AI agent passes through SolonGate, which runs a policy check, DLP scan, rate limit and logging, then allows or blocks it before the tool runs" width="900">
</div>

## Install

```bash
git clone https://github.com/codeyevsky/solongate-oss.git
cd solongate-oss
./install.sh
```

Then open a new terminal: hooks load when a session starts, so an already open
one is not guarded yet. `solongate update` pulls and reinstalls later.

The installer refuses to run from an agent, by design.

## What it looks like when it fires

A real Claude Code session: the agent reaches for a `.env`, the guard refuses it,
and the agent says so rather than quietly working around it.

<div align="center">
  <img src="docs/assets/claudecode.gif" alt="A Claude Code session in which SolonGate blocks access to a .env file and Claude reports the refusal instead of working around it" width="900">
</div>

## What it enforces

| Layer | What it does |
| --- | --- |
| **Policy rules** | Allow or deny by path, command, filename or URL, scoped to READ, WRITE, EXECUTE or NETWORK. |
| **DLP** | 70 built in secret patterns plus your own, in four modes: observe, detect, redact, block. |
| **Egress** | Refuses an upload whose file holds a secret, which pattern matching alone cannot see. |
| **Rate limits** | A cap per minute, hour or day. |
| **The prompt** | A shim masks the outbound request body on Claude Code, which no tool call hook can reach. |
| **Tamper protection** | The guard's own state is unreachable from a tool call, and a policy in a repository cannot switch it off. |

Every decision lands in `~/.solongate/local-logs/solongate-audit.jsonl`, owner
only, one JSON object per line.

## The CLI

```
solongate              the dataroom: policies, audit, settings
solongate policy       list, create and edit the policy
solongate dlp          secret detection
solongate ratelimit    the rate limit
solongate audit        browse the audit trail
solongate watch        live tail tool calls
solongate trace        what the guard saw in this directory
solongate doctor       health check
solongate repair       restore the guard, hooks and settings
solongate update       pull the newest version and reinstall
```

Each one reads or changes a security posture, so they require a real terminal
and the guard refuses a tool call that invokes them. `solongate --help` is the
full tree.

## Supported agents

<table cellspacing="0" cellpadding="0" border="0" align="center">
  <tr>
    <td><a href="https://claude.com/claude-code"><img src="docs/assets/cells/claude.png" width="200" alt="Claude Code"></a></td>
    <td><a href="https://openai.com/codex"><img src="docs/assets/cells/codex.png" width="200" alt="Codex CLI"></a></td>
    <td><a href="https://antigravity.google"><img src="docs/assets/cells/antigravity.png" width="200" alt="Antigravity CLI"></a></td>
    <td><a href="https://opencode.ai"><img src="docs/assets/cells/opencode.png" width="200" alt="OpenCode"></a></td>
  </tr>
  <tr>
    <td><a href="https://openclaw.ai"><img src="docs/assets/cells/openclaw.png" width="200" alt="OpenClaw (soon)"></a></td>
    <td><a href="https://hermes.nousresearch.com"><img src="docs/assets/cells/hermes.png" width="200" alt="Hermes (soon)"></a></td>
    <td><a href="https://chainabit.com"><img src="docs/assets/cells/chainabit.png" width="200" alt="Chainabit (soon)"></a></td>
    <td><a href="https://github.com/codeyevsky/solongate-oss/issues"><img src="docs/assets/cells/yourtool.png" width="200" alt="Your tool"></a></td>
  </tr>
</table>

## Contributing

Go 1.25 and Node 20+.

```bash
pnpm install
./test.sh
```

There are two implementations of the guard, in Go and in bundled JavaScript, and
which one decides a call depends only on whether a machine has the binary. They
have to agree, so the conformance suite runs against both and a change to the
decision path lands in both. [CONTRIBUTING.md](CONTRIBUTING.md) is the rest.

Reporting a vulnerability: [SECURITY.md](SECURITY.md), privately, never a public
issue. [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies everywhere.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
