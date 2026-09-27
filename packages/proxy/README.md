<div align="center">
  <img src="https://solongate.com/hero.png" alt="SolonGate. For AI agents to execute tools safely. Make agents secure again." width="900" />
</div>

<a href="https://www.npmjs.com/package/@solongate/proxy"><img align="right" alt="npm" src="https://img.shields.io/npm/v/@solongate/proxy?style=flat-square&color=eeeeee&labelColor=111111&logo=npm&logoColor=white" /></a>
<a href="https://nodejs.org"><img align="right" alt="Node.js" src="https://img.shields.io/node/v/@solongate/proxy?style=flat-square&label=Node.js&labelColor=111111&color=eeeeee&logo=nodedotjs&logoColor=white" /></a>
<a href="https://github.com/Solongate"><img src="https://solongate.com/github-w.png" height="20" alt="GitHub" /></a>&nbsp;
<a href="https://www.linkedin.com/company/solongate/"><img src="https://solongate.com/linkedin-w.png" height="20" alt="LinkedIn" /></a>

SolonGate is the guardrail for AI agents. It checks every action an agent takes (each shell command, file read or write, and network request) and allows, blocks, or logs it before it runs, based on a policy you control. No code changes.

**[solongate.com](https://solongate.com)** | [Documentation](https://solongate.com/docs) | [Dashboard](https://dashboard.solongate.com)

<div align="center">
  <img src="https://solongate.com/flow.gif" alt="A tool call from an AI agent passes through SolonGate, which runs a policy check, DLP scan, and rate limit, then allows, blocks, or logs it before the tool runs" width="900" />
</div>

## Get started

You need a free [SolonGate account](https://auth.solongate.com) and Node.js 20+ on the machine you want to protect. There's nothing to import; the two commands below pair your machine.

```sh
npm i -g @solongate/proxy
solongate
```

`solongate` opens your browser to authorize the device. Approve it and SolonGate installs a global guard hook that checks every tool call from every AI session on the machine against your active policy. No API keys to copy.

```
Start a new terminal session afterwards. Hooks load when a
session starts, so already-open terminals aren't guarded yet.
```

## Guarding a live Claude Code session

Drops in front of any MCP-speaking agent over stdio, SSE, or HTTP. Every tool call is checked in real time, and each allow or deny decision streams to your dashboard with the full arguments attached.

<div align="center">
  <img src="https://solongate.com/cc-hd.png" alt="SolonGate guarding a live Claude Code session" width="720" />
</div>

## Command center for every decision area

Live analytics by tool, agent, and policy. Version your policies with cloud sync and one-click rollback. Every decision lands in a tamper-evident, searchable audit trail you can export as CSV.

<div align="center">
  <img src="https://solongate.com/dash-hd.png" alt="SolonGate dashboard: analytics, policies, and audit trail" width="720" />
</div>

## What SolonGate can enforce

- **Policy rules:** allow or block tool calls by path, command, filename, or URL.
- **Ghost paths:** make chosen files and folders invisible to the agent, unlistable and unreadable.
- **Data loss prevention (DLP):** when a call carries a secret (API key, token, private key), block it or hide it from the model.
- **Rate limiting:** cap how many tool calls an agent can make per minute, hour, or day.

Manage everything from the **Policies**, **Audit**, and **Settings** pages in the [dashboard](https://dashboard.solongate.com). When a legitimate action is blocked, click **Whitelist this** to add a narrow exception. Keep logs local instead of in the cloud, and get alerted by Telegram, email, or webhook when blocks spike.

**Compatible with every tool.** SolonGate guards any MCP-speaking agent out of the box. Missing yours? [Reach out](https://solongate.com/contact) and we will consider it.

<table cellspacing="0" cellpadding="0" border="0" align="center">
  <tr>
    <td><a href="https://claude.com/claude-code"><img src="https://solongate.com/cells/claude.png" width="200" alt="Claude Code" /></a></td>
    <td><a href="https://openai.com/codex"><img src="https://solongate.com/cells/codex.png?v=3" width="200" alt="Codex CLI" /></a></td>
    <td><a href="https://antigravity.google"><img src="https://solongate.com/cells/antigravity.png?v=2" width="200" alt="Antigravity CLI" /></a></td>
    <td><a href="https://openclaw.ai"><img src="https://solongate.com/cells/openclaw.png?v=3" width="200" alt="OpenClaw" /></a></td>
  </tr>
  <tr>
    <td><a href="https://opencode.ai"><img src="https://solongate.com/cells/opencode.png?v=3" width="200" alt="OpenCode" /></a></td>
    <td><a href="https://hermes.nousresearch.com"><img src="https://solongate.com/cells/hermes.png" width="200" alt="Hermes (soon)" /></a></td>
    <td><a href="https://chainabit.com"><img src="https://solongate.com/cells/chainabit.png?v=3" width="200" alt="Chainabit (soon)" /></a></td>
    <td><a href="https://solongate.com/contact"><img src="https://solongate.com/cells/yourtool.png" width="200" alt="Your tool" /></a></td>
  </tr>
</table>
